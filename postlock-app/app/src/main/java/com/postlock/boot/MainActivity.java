package com.postlock.boot;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.format.DateUtils;
import android.util.Log;
import android.view.View;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Status panel for PostLock:Boot: live driver / ocsk / SELinux state, a
 * manual loopback dispatch, and the tail of the shell-owned chain log
 * (fetched over the 127.0.0.1:5555 adb channel -- the app uid cannot
 * read /data/local/tmp itself under Enforcing).
 */
public class MainActivity extends Activity {

    private static final int LOG_TAIL_BYTES = 6000;

    private TextView tvDriver, tvOcsk, tvSelinux, tvReady, tvLastRun, tvLog, tvLogTitle;
    private Button btnTrigger;
    private ScrollView scroll;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private volatile boolean triggerPending = false;

    // refresh every 4s while visible: one short loopback round-trip each
    private final Runnable refresher = new Runnable() {
        @Override
        public void run() {
            refresh();
            ui.postDelayed(this, 4000);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // keep the panel readable while a chain runs; harmless otherwise
        getWindow().addFlags(
                WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON
                        | WindowManager.LayoutParams.FLAG_TURN_SCREEN_ON
                        | WindowManager.LayoutParams.FLAG_SHOW_WHEN_LOCKED
                        | WindowManager.LayoutParams.FLAG_DISMISS_KEYGUARD);

        tvDriver = findViewById(R.id.tv_driver);
        tvOcsk = findViewById(R.id.tv_ocsk);
        tvSelinux = findViewById(R.id.tv_selinux);
        tvReady = findViewById(R.id.tv_ready);
        tvLastRun = findViewById(R.id.tv_last_run);
        tvLog = findViewById(R.id.tv_log);
        tvLogTitle = findViewById(R.id.tv_log_title);
        btnTrigger = findViewById(R.id.btn_trigger);
        scroll = findViewById(R.id.scroll);

        btnTrigger.setOnClickListener(v -> confirmTrigger());
        findViewById(R.id.btn_refresh).setOnClickListener(v -> refresh());

        refresh();
    }

    @Override
    protected void onResume() {
        super.onResume();
        ui.post(refresher);
    }

    @Override
    protected void onPause() {
        super.onPause();
        ui.removeCallbacks(refresher);
    }

    private void confirmTrigger() {
        new AlertDialog.Builder(this)
                .setTitle("触发恢复链？")
                .setMessage("链经回环 adb 以 shell 身份在后台执行（约 40–90 秒），"
                        + "脱离本 app 存活，期间设备可能卡顿。存在内核 panic 导致"
                        + "自动重启的风险；重启后本应用仍会再次自动触发。\n\n"
                        + "驱动已加载（恢复态）时无需手动触发。")
                .setNegativeButton("取消", null)
                .setPositiveButton("触发", (d, w) -> doTrigger())
                .show();
    }

    private void doTrigger() {
        btnTrigger.setEnabled(false);
        triggerPending = true;
        new Thread(() -> {
            try {
                PostLock.triggerChainLoopback(this);
            } catch (Throwable e) {
                Log.e(PostLock.TAG, "manual trigger failed", e);
            }
            ui.post(() -> {
                triggerPending = false;
                refresh();
            });
        }, "postlock-manual-trigger").start();
        Toast.makeText(this, "经回环通道触发中…", Toast.LENGTH_SHORT).show();
    }

    private void refresh() {
        // driver / ocsk from /proc/modules (readable by any app)
        setModule(tvDriver, PostLock.moduleLoaded("kernelsu"));
        setModule(tvOcsk, PostLock.moduleLoaded("ocsk"));

        boolean enforcing = PostLock.selinuxEnforcing();
        tvSelinux.setText(enforcing ? "Enforcing" : "Permissive");
        tvSelinux.setTextColor(enforcing ? Color.parseColor("#C62828")
                : Color.parseColor("#2E7D32"));

        String[] st = PostLock.readState(this);
        String state = st[1];
        long epoch = 0;
        try {
            epoch = Long.parseLong(st[0]);
        } catch (NumberFormatException ignored) {
        }
        tvLastRun.setText(state.isEmpty()
                ? "从未触发"
                : (epoch > 0 ? DateUtils.getRelativeTimeSpanString(epoch) + " " : "")
                        + stateLabel(state));

        // one loopback round-trip: ping + chain liveness + log tail
        String probe = PostLock.probeStatus(this, LOG_TAIL_BYTES);
        boolean up = probe.contains("PING")
                && !probe.startsWith("PROBE_FAIL")
                && !probe.equals("PING_FAILED");
        tvReady.setText(up ? "✓ 回环在线" : "✗ 回环不可达（需一次性 provisioning）");
        tvReady.setTextColor(up ? Color.parseColor("#2E7D32")
                : Color.parseColor("#9AA0A6"));

        boolean running = up && probe.contains("CHAIN_RUNNING");
        String tail = "";
        if (up) {
            StringBuilder sb = new StringBuilder();
            for (String line : probe.split("\n")) {
                if (line.equals("PING") || line.equals("CHAIN_RUNNING")
                        || line.startsWith("LOG_BYTES:")) {
                    continue;
                }
                sb.append(line).append('\n');
            }
            tail = sb.toString().trim();
        }
        if (tail.isEmpty()) {
            tvLog.setText(up
                    ? "回环在线，尚未触发。点上方按钮，或等待开机广播自动触发。"
                    : "回环通道未就绪：adbd 需先由 tools/postlock.sh 一次性"
                            + "provision（persist.adb.tcp.port + 授权密钥）。");
            tvLogTitle.setText("链日志");
        } else {
            tvLog.setText(tail);
            tvLogTitle.setText("链日志 /data/local/tmp/postlock_chain.log"
                    + (running || triggerPending ? "（执行中…）" : ""));
            if (running || triggerPending) {
                scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
            }
        }
        btnTrigger.setEnabled(!running && !triggerPending);
    }

    /** Compact rendering of the loopback state marker. */
    private static String stateLabel(String state) {
        if (state.startsWith("FAIL:")) {
            return "失败 " + state.substring(5);
        }
        return state;
    }

    private static void setModule(TextView tv, boolean loaded) {
        tv.setText(loaded ? "✓ 已加载" : "✗ 未加载");
        tv.setTextColor(loaded ? Color.parseColor("#2E7D32")
                : Color.parseColor("#9AA0A6"));
    }
}
