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

    // Static so the GC cannot finalize (and silently release) the wake
    // lock while the chain runs: a receiver-local reference dies with
    // onReceive, which is exactly how the screen went off at +9 min and
    // HANS froze the uid mid-run.  30 min cap covers the slowest round.
    private static android.os.PowerManager.WakeLock sChainWakeLock;

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
            // died silently at "prepare storm i=512" that way.  A wake
            // lock with ACQUIRE_CAUSES_WAKEUP lights the screen and keeps
            // it on for the whole run (10 min cap), so the LcdOff scene
            // never fires.  Starting MainActivity from a receiver is
            // blocked by the background-activity-start check anyway
            // ("allowBackgroundActivityStart: false"), so the wake lock
            // is the primary defence; the UI start below is best effort.
            android.os.PowerManager pm = (android.os.PowerManager)
                    context.getSystemService(Context.POWER_SERVICE);
            if (pm != null) {
                if (sChainWakeLock == null) {
                    sChainWakeLock = pm.newWakeLock(
                            android.os.PowerManager.SCREEN_BRIGHT_WAKE_LOCK
                                    | android.os.PowerManager.ACQUIRE_CAUSES_WAKEUP
                                    | android.os.PowerManager.ON_AFTER_RELEASE,
                            "postlock:chain");
                    sChainWakeLock.setReferenceCounted(false);
                }
                sChainWakeLock.acquire(30 * 60 * 1000L); // 30 min cap
                Log.i(PostLock.TAG, "wake lock acquired for chain run");
            }
            // Last line of defence for getting visible: a full-screen
            // intent (alarm-class path) is the one background activity
            // start the system still honours on ColorOS — a plain
            // startActivity from a receiver is blocked, and a plain wake
            // lock gets proxied by HANS ("unproxy wakelock scene: LcdOff"
            // then refreeze).  Once MainActivity is visible its own
            // FLAG_KEEP_SCREEN_ON pins the display, and a visible
            // foreground activity is never HANS-frozen.
            Intent ui = new Intent(context, MainActivity.class);
            ui.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK
                    | Intent.FLAG_ACTIVITY_CLEAR_TOP);
            try {
                android.app.NotificationManager nm = (android.app.NotificationManager)
                        context.getSystemService(Context.NOTIFICATION_SERVICE);
                if (nm != null) {
                    if (android.os.Build.VERSION.SDK_INT >= 26) {
                        nm.createNotificationChannel(
                                new android.app.NotificationChannel(
                                        "chain",
                                        "Recovery chain",
                                        android.app.NotificationManager
                                                .IMPORTANCE_HIGH));
                    }
                    android.app.PendingIntent pi = android.app.PendingIntent
                            .getActivity(context, 0, ui,
                                    android.app.PendingIntent.FLAG_IMMUTABLE
                                            | android.app.PendingIntent
                                                    .FLAG_UPDATE_CURRENT);
                    android.app.Notification n = new android.app.Notification
                            .Builder(context, "chain")
                            .setSmallIcon(android.R.drawable.ic_lock_idle_alarm)
                            .setContentTitle("PostLock:Boot")
                            .setContentText("恢复链运行中…")
                            .setCategory(android.app.Notification.CATEGORY_ALARM)
                            .setOngoing(true)
                            .setFullScreenIntent(pi, true)
                            .build();
                    nm.notify(1, n);
                    Log.i(PostLock.TAG, "full-screen intent posted");
                }
            } catch (Throwable e) {
                Log.w(PostLock.TAG, "fullscreen intent failed", e);
            }
            PostLock.triggerChain(context);
            Log.i(PostLock.TAG, "chain dispatched from " + action);
        } catch (Throwable e) {
            Log.e(PostLock.TAG, "trigger failed", e);
        }
    }
}
