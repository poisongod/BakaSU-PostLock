package com.postlock.boot;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

/**
 * PostLockBoot: on BOOT_COMPLETED dispatch the CVE-2026-43499 restore
 * chain through the adbd loopback channel.
 *
 * The chain no longer runs under this app's uid: untrusted_app is denied
 * the tracefs / mm_struct / configfs primitives the chain needs (2026-10-20
 * verdict), and OPPO HANS freezes this uid on LcdOff, killing app-uid
 * rounds mid-run.  Instead we authenticate to adbd on 127.0.0.1:5555
 * (provisioned once by tools/postlock.sh) and launch trigger.sh under
 * SHELL uid with setsid, so the chain survives both the socket closing
 * and any freeze of this process.  No wake lock and no full-screen
 * notification are needed anymore: nothing here has to stay alive past
 * the dispatch (a few seconds of background work).
 *
 * BOOT_COMPLETED simply attempts dispatch -- if the loopback listener was
 * never provisioned the failure lands in the state file and the status
 * panel explains it; LAUNCH broadcasts (debug entry) behave the same.
 */
public class BootReceiver extends BroadcastReceiver {

    @Override
    public void onReceive(Context context, Intent intent) {
        if (intent == null) {
            return;
        }
        String action = intent.getAction();
        if (Intent.ACTION_LOCKED_BOOT_COMPLETED.equals(action)) {
            // credential-encrypted filesDir is sealed before first unlock
            Log.i(PostLock.TAG, "skip " + action + " (CE storage sealed)");
            return;
        }
        boolean isBoot = Intent.ACTION_BOOT_COMPLETED.equals(action);
        boolean isLaunch = "com.postlock.boot.LAUNCH".equals(action);
        if (!isBoot && !isLaunch) {
            return;
        }

        final PendingResult pr = goAsync();
        new Thread(() -> {
            try {
                PostLock.triggerChainLoopback(context);
                Log.i(PostLock.TAG, "chain dispatched from " + action);
            } catch (Throwable e) {
                Log.e(PostLock.TAG, "loopback dispatch failed", e);
            } finally {
                pr.finish();
            }
        }, "postlock-dispatch").start();
    }
}
