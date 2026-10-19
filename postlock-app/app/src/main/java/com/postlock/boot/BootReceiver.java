package com.postlock.boot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * PostLockBoot: on BOOT_COMPLETED dispatch the CVE-2026-43499 exploit
 * chain via LD_PRELOAD (see PostLock.triggerChain for the mechanics).
 * The chain's KS_COLDSTART fork then runs the extracted restore.sh as
 * uid0 kernel domain: kernelsu.ko (real BakaSU driver) + ocsk.ko (OPPO
 * detector fuse + popup suppression) + su daemon + /product/bin overlay
 * + manager appid.  Restore targets the BakaSU manager app; this app
 * only provides the missing boot trigger on the relocked stock kernel
 * (no APatch/su survives there, and nothing else on the device can
 * re-run the chain).
 *
 * Requires the one-time OPPO auto-start permission for THIS app
 * (Settings -> App management -> PostLock).
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)
                && !"com.postlock.boot.LAUNCH".equals(action)) {
            return;
        }
        // LOCKED_BOOT_COMPLETED is skipped on purpose: the credential
        // encrypted filesDir is unreadable before first unlock.
        if (!Intent.ACTION_BOOT_COMPLETED.equals(action)
                && !"com.postlock.boot.LAUNCH".equals(action)) {
            Log.i(PostLock.TAG, "skip " + action + " (CE storage sealed)");
            return;
        }
        // fresh boot: no same-boot kaslr file -> the app-uid slide route
        // would panic-loop (see PostLock.readyToTrigger).  Do not dispatch.
        // Explicit LAUNCH broadcasts bypass the gate on purpose: they are
        // the manual/debug entry (am broadcast -n .../.BootReceiver) used
        // for app-domain experiments; BOOT_COMPLETED stays protected.
        if (!"com.postlock.boot.LAUNCH".equals(action) && !PostLock.readyToTrigger()) {
            Log.w(PostLock.TAG, "skip " + action
                    + ": no same-boot kaslr file (app-uid first run unsupported)");
            return;
        }
        try {
            // OPPO HANS/OFreezer freezes this uid the moment the LCD turns
            // off (logcat: "freeze uid ... scene: LcdOff") and netd then
            // destroyAllSocketForUid()s our reclaim sockets — the chain
            // died silently at "prepare storm i=512" that way.  Bring the
            // UI up first (turns the screen on, keeps the activity visible)
            // before dispatching: a visible foreground app is never frozen.
            Intent ui = new Intent(context, MainActivity.class);
            ui.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            context.startActivity(ui);
            PostLock.triggerChain(context);
            Log.i(PostLock.TAG, "chain dispatched from " + action);
        } catch (Throwable e) {
            Log.e(PostLock.TAG, "trigger failed", e);
        }
    }
}
