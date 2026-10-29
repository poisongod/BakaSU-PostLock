package com.postlock.boot;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.Base64;

/**
 * PostLock:Boot payload + loopback trigger logic.
 *
 * Architecture (2026-10-20): the app uid (untrusted_app) can NOT run the
 * exploit chain -- tracefs, the mm_struct timing scan and configfs are
 * denied in that domain.  The chain runs with SHELL uid instead: this app
 * connects to adbd's TCP listener on 127.0.0.1:5555 (provisioned once by
 * tools/postlock.sh via the persist.adb.tcp.port protobuf entry + our
 * pubkey in /data/misc/adb/adb_keys), stages the payload, and launches
 * trigger.sh detached (setsid).  The detached chain then survives both
 * the adb session closing and HANS freezing this uid -- shell uid is not
 * on HANS's list, which is exactly why the app-uid rounds kept dying at
 * "prepare storm i=512" while the chain itself was fine.
 */
public final class PostLock {

    public static final String TAG = "PostLockBoot";
    // bump when any asset payload changes -> re-stage on next use
    public static final String PAYLOAD_VERSION = "v2-20261020";

    static final String[] PAYLOAD = {
            "preload.so", "su", "kernelsu.ko", "finitmod", "ocsk.ko", "restore.sh",
            "pp_adb_tcp.bin", "postlock_adbkey.pub",
    };

    /** adbd loopback listener provisioned by tools/postlock.sh. */
    public static final String LOOP_HOST = "127.0.0.1";
    public static final int LOOP_PORT = 5555;
    public static final String STAGE_DIR = "/data/local/tmp/ksu_boot";

    private static final String CHAIN_LOG = "/data/local/tmp/postlock_chain.log";
    private static final String STATE_FILE = "loopback_state.txt";

    // key material lives only in this process (never staged to /data)
    private static PrivateKey sKey;
    private static byte[] sPub;

    private PostLock() {
    }

    // --- assets ------------------------------------------------------------

    /** Extract assets (version-gated) into the app-private postlock dir. */
    public static File ensurePayload(Context context) throws Exception {
        File dir = new File(context.getFilesDir(), "postlock");
        File ver = new File(dir, ".ver");
        File restore = new File(dir, "restore.sh");
        if (ver.isFile() && PAYLOAD_VERSION.equals(readAllText(ver)) && restore.isFile()) {
            return dir;
        }
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new IOException("cannot create " + dir);
        }
        AssetManager am = context.getAssets();
        for (String name : PAYLOAD) {
            File out = new File(dir, name);
            try (InputStream in = am.open("postlock/" + name);
                 OutputStream os = new FileOutputStream(out)) {
                byte[] buf = new byte[65536];
                int n;
                while ((n = in.read(buf)) > 0) {
                    os.write(buf, 0, n);
                }
            }
        }
        try (FileOutputStream os = new FileOutputStream(ver)) {
            os.write(PAYLOAD_VERSION.getBytes());
        }
        return dir;
    }

    private static byte[] readAssetBytes(Context ctx, String name) throws IOException {
        try (InputStream in = ctx.getAssets().open(name);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[65536];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        }
    }

    private static String readAssetText(Context ctx, String name) throws IOException {
        return new String(readAssetBytes(ctx, name), StandardCharsets.UTF_8);
    }

    // --- adb loopback ------------------------------------------------------

    private static synchronized void ensureAdbKey(Context ctx) throws Exception {
        if (sKey != null) {
            return;
        }
        String pem = readAssetText(ctx, "postlock/postlock_adbkey.pem");
        String pub = readAssetText(ctx, "postlock/postlock_adbkey.pub");
        sKey = AdbShell.loadPrivateKey(pem);
        sPub = AdbShell.publicBlob(pub);
    }

    /** Quick round-trip to the loopback listener (UI / gate indicator). */
    public static boolean loopbackReachable(Context ctx) {
        try {
            ensureAdbKey(ctx);
            AdbShell.Result r = AdbShell.runOnce(LOOP_HOST, LOOP_PORT, sKey, sPub,
                    "echo PING", 6000);
            return r.exit == 0 && r.out().contains("PING");
        } catch (Throwable t) {
            Log.i(TAG, "loopback unreachable: " + t);
            return false;
        }
    }

    /**
     * One connection for the status panel: ping + chain-liveness probe +
     * tail of the shell-owned chain log (the app uid cannot read
     * /data/local/tmp itself under Enforcing).
     */
    public static String probeStatus(Context ctx, int tailBytes) {
        try {
            ensureAdbKey(ctx);
            try (AdbShell s = new AdbShell(sKey, sPub).connect(LOOP_HOST, LOOP_PORT)) {
                AdbShell.Result ping = s.exec("echo PING", 5000);
                if (!ping.out().contains("PING")) {
                    return "PING_FAILED";
                }
                AdbShell.Result run = s.exec(
                        "if pgrep -f '[e]cho_CHAIN_EXIT_DONE' >/dev/null 2>&1; "
                                + "then echo CHAIN_RUNNING; fi; "
                                + "if [ -f " + CHAIN_LOG + " ]; then "
                                + "echo LOG_BYTES:$(wc -c < " + CHAIN_LOG + "); "
                                + "tail -c " + tailBytes + " " + CHAIN_LOG + "; fi",
                        8000);
                return run.out();
            }
        } catch (Throwable t) {
            return "PROBE_FAIL:" + t;
        }
    }

    /** Persist a one-line status marker for the UI ("&lt;epoch&gt; &lt;state&gt;"). */
    public static void setState(Context ctx, String state) {
        try (FileOutputStream os = new FileOutputStream(
                new File(ctx.getFilesDir(), STATE_FILE))) {
            long now = System.currentTimeMillis();
            os.write((now + " " + state + "\n").getBytes(StandardCharsets.UTF_8));
            Log.i(TAG, "state -> " + state);
        } catch (Exception e) {
            Log.w(TAG, "state write failed", e);
        }
    }

    /** @return {epochMillis, state}; state is "" when never run. */
    public static String[] readState(Context ctx) {
        String text = null;
        try (FileInputStream in = new FileInputStream(
                new File(ctx.getFilesDir(), STATE_FILE))) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[256];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            text = out.toString("UTF-8").trim();
        } catch (Exception ignored) {
        }
        if (text == null || text.isEmpty()) {
            return new String[]{"0", ""};
        }
        int sp = text.indexOf(' ');
        if (sp < 0) {
            return new String[]{"0", text};
        }
        return new String[]{text.substring(0, sp), text.substring(sp + 1)};
    }

    /**
     * Full loopback dispatch: connect -> locate/stage payload -> write
     * trigger.sh -> guard + setsid-launch it.  Synchronous; call from a
     * background thread.  Progress lands in setState().
     *
     * Serialized in-process: the boot receiver and the manual button must
     * never both pass the device-side pgrep guard, or two chains run on
     * the same boot slot and the kernel panics.
     */
    public static void triggerChainLoopback(Context ctx) throws Exception {
        if (!sDispatching.compareAndSet(false, true)) {
            Log.i(TAG, "dispatch already in progress; refuse reentry");
            setState(ctx, "DISPATCH_IN_PROGRESS");
            return;
        }
        try {
            dispatchLocked(ctx);
        } finally {
            sDispatching.set(false);
        }
    }

    private static final java.util.concurrent.atomic.AtomicBoolean sDispatching =
            new java.util.concurrent.atomic.AtomicBoolean(false);

    private static void dispatchLocked(Context ctx) throws Exception {
        ensureAdbKey(ctx);
        ensurePayload(ctx);
        setState(ctx, "CONNECTING");
        try (AdbShell s = new AdbShell(sKey, sPub).connect(LOOP_HOST, LOOP_PORT)) {
            setState(ctx, "CONNECTED");

            // 1. payload on device: prefer an already-staged copy whose
            // version marker matches; otherwise (re)stage from assets.
            String dir = locatePayload(s);
            if (dir == null) {
                setState(ctx, "STAGING");
                dir = stagePayload(s, ctx);
                setState(ctx, "STAGED");
            }

            // 2. trigger script (base64 round-trip, single chunk)
            writeTriggerScript(s, dir);

            // 3. guard against a concurrent chain (same-boot double run
            // ends in panic), then launch detached: setsid moves the child
            // into its own session so closing this adb stream does not
            // SIGHUP the chain.
            AdbShell.Result g = s.exec(
                    "if pgrep -f '[e]cho_CHAIN_EXIT_DONE' >/dev/null 2>&1; then "
                            + "echo ALREADY_RUNNING; else "
                            + "setsid sh " + dir + "/trigger.sh </dev/null >/dev/null 2>&1 & "
                            + "sleep 1; "
                            + "if pgrep -f '[e]cho_CHAIN_EXIT_DONE' >/dev/null 2>&1; then "
                            + "echo DISPATCHED; else echo LAUNCH_FAILED; fi; fi",
                    15000);
            String verdict = g.out().trim();
            if (verdict.isEmpty()) {
                verdict = "EMPTY_REPLY:" + g.exit + " " + g.stderr;
            }
            setState(ctx, verdict);
        } catch (Exception e) {
            setState(ctx, "FAIL:" + e);
            throw e;
        } catch (Error e) {
            setState(ctx, "FAIL:" + e);
            throw e;
        }
    }

    private static String locatePayload(AdbShell s) throws IOException {
        AdbShell.Result r = s.exec(
                "for d in " + STAGE_DIR + " /data/local/temp; do "
                        + "if [ -f $d/preload.so ] && [ -f $d/restore.sh ] "
                        + "&& [ -f $d/finitmod ] && [ -f $d/kernelsu.ko ] "
                        + "&& [ -f $d/ocsk.ko ] && [ -f $d/su ] "
                        + "&& [ -f $d/pp_adb_tcp.bin ] && [ -f $d/postlock_adbkey.pub ]; then "
                        + "if [ \"$(cat $d/.postlock_ver 2>/dev/null)\" = \""
                        + PAYLOAD_VERSION + "\" ]; then echo PICK:$d; break; fi; fi; done",
                8000);
        String out = r.out();
        int i = out.indexOf("PICK:");
        if (i < 0) {
            Log.i(TAG, "no staged payload (rc=" + r.exit + ")");
            return null;
        }
        String dir = out.substring(i + 5).trim().split("\\s+")[0];
        Log.i(TAG, "staged payload ok at " + dir);
        return dir;
    }

    /** Base64 chunk upload of every asset into STAGE_DIR (shell writable). */
    private static String stagePayload(AdbShell s, Context ctx) throws Exception {
        if (s.exec("mkdir -p " + STAGE_DIR, 5000).exit != 0) {
            throw new IOException("cannot mkdir " + STAGE_DIR);
        }
        int chunk = 110000; // < MAX_ARG_STRLEN (128 KiB) incl. printf wrapper
        for (String name : PAYLOAD) {
            byte[] bytes = readAssetBytes(ctx, "postlock/" + name);
            String b64 = Base64.encodeToString(bytes, Base64.NO_WRAP);
            String target = STAGE_DIR + "/" + name;
            s.exec("rm -f " + target + ".b64", 5000);
            for (int i = 0; i < b64.length(); i += chunk) {
                String part = b64.substring(i, Math.min(i + chunk, b64.length()));
                AdbShell.Result r = s.exec(
                        "printf %s '" + part + "' >> " + target + ".b64", 10000);
                if (r.exit != 0) {
                    throw new IOException("stage chunk failed " + name + "@" + i
                            + ": " + r.stderr);
                }
            }
            AdbShell.Result r = s.exec(
                    "base64 -d " + target + ".b64 > " + target
                            + " && chmod 755 " + target
                            + " && rm -f " + target + ".b64"
                            + " && wc -c < " + target,
                    30000);
            String got = r.out().trim();
            if (r.exit != 0 || !got.equals(String.valueOf(bytes.length))) {
                throw new IOException("stage verify failed " + name
                        + ": want=" + bytes.length + " got=" + got + " " + r.stderr);
            }
            Log.i(TAG, "staged " + name + " (" + bytes.length + "B)");
        }
        s.exec("echo -n " + PAYLOAD_VERSION + " > " + STAGE_DIR + "/.postlock_ver", 5000);
        return STAGE_DIR;
    }

    /**
     * trigger.sh: env mirrors tools/postlock.sh's proven TRIGGER_ENV for
     * the relocked path (no KS_TRACEFS_SUDO -- no su exists before the
     * chain; no KS_LAYOUT_PVO -- the chain's static fallback passes the
     * window check, round 60 root=1).
     */
    private static void writeTriggerScript(AdbShell s, String dir) throws IOException {
        String sh = "#!/system/bin/sh\n"
                + "D=" + dir + "\n"
                + "rm -f $D/ksud $D/skbdelta " + CHAIN_LOG
                + " /data/local/tmp/postlock_restore.log\n"
                + "LD_PRELOAD=$D/preload.so "
                + "KS_LOG_SYNC=1 KS_PSELECT_BSS_LOCK=1 KS_CFGFS_LOG=1 "
                + "KS_PAYLOAD_SCAN=1 KSNITCH_VERBOSE=1 "
                + "KS_RECLAIM_DETERMINISTIC=1 KS_PSELECT_FOPS_VOFF=1 "
                + "KSUD_DST=$D/ksud KSUD_NO_PARENT_INSTALL=1 SU_INSTALL=0 "
                + "KS_COLDSTART=$D/restore.sh KS_FINITMOD=$D/finitmod KS_KO=$D/kernelsu.ko "
                + "KS_PIPE_SLABS=15 KS_PAYLOAD_BASE_FILE=$D/skbdelta "
                + "/system/bin/sh -c echo_CHAIN_EXIT_DONE > " + CHAIN_LOG + " 2>&1\n";
        String b64 = Base64.encodeToString(sh.getBytes(StandardCharsets.UTF_8),
                Base64.NO_WRAP);
        String t = dir + "/trigger.sh";
        s.exec("rm -f " + t + ".b64", 5000);
        s.exec("printf %s '" + b64 + "' > " + t + ".b64", 8000);
        AdbShell.Result r = s.exec(
                "base64 -d " + t + ".b64 > " + t + " && chmod 755 " + t
                        + " && rm -f " + t + ".b64 && sh -n " + t,
                8000);
        if (r.exit != 0) {
            throw new IOException("trigger.sh write failed: " + r.out() + r.stderr);
        }
    }

    /** True when the named module appears in /proc/modules. */
    public static boolean moduleLoaded(String name) {
        try (FileInputStream in = new FileInputStream("/proc/modules");
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[8192];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            for (String line : out.toString("UTF-8").split("\n")) {
                if (line.startsWith(name + " ")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    /** SELinux enforcing flag: true = Enforcing. */
    public static boolean selinuxEnforcing() {
        try (FileInputStream in = new FileInputStream("/sys/fs/selinux/enforce")) {
            return in.read() == '1';
        } catch (Exception ignored) {
            return true; // fail safe: assume enforcing
        }
    }

    static String readAllText(File f) throws Exception {
        try (FileInputStream in = new FileInputStream(f);
             ByteArrayOutputStream out = new ByteArrayOutputStream()) {
            byte[] buf = new byte[256];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toString("UTF-8");
        }
    }
}
