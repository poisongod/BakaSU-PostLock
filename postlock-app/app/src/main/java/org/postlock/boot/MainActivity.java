package org.postlock.boot;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.format.DateUtils;
import android.view.View;
import android.widget.Button;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

/**
 * Status panel for PostLockBoot: live driver / ocsk / SELinux state, a
 * manual chain trigger (with panic-risk confirmation) and the tail of the
 * chain log so the whole restore loop is observable on-device.
 */
public class MainActivity extends Activity {

    private static final int LOG_TAIL_BYTES = 6000;

    private TextView tvDriver, tvOcsk, tvSelinux, tvLastRun, tvLog, tvLogTitle;
    private Button btnTrigger;
    private ScrollView scroll;
    private final Handler ui = new Handler(Looper.getMainLooper());
    private boolean triggerPending = false;

    // refresh while a chain run is in flight; otherwise on demand only
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

        tvDriver = findViewById(R.id.tv_driver);
        tvOcsk = findViewById(R.id.tv_ocsk);
        tvSelinux = findViewById(R.id.tv_selinux);
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
                .setMessage("链在后台执行（约 40–90 秒），期间设备可能卡顿。"
                        + "存在内核 panic 导致自动重启的风险；重启后 PostLock "
                        + "仍会再次自动触发。\n\n当前状态并非恢复态时才需要手动触发。")
                .setNegativeButton("取消", null)
                .setPositiveButton("触发", (d, w) -> doTrigger())
                .show();
    }

    private void doTrigger() {
        try {
            PostLock.triggerChain(this);
            Toast.makeText(this, "链已触发，日志持续刷新中", Toast.LENGTH_SHORT).show();
            triggerPending = true;
            btnTrigger.setEnabled(false);
            ui.postDelayed(() -> {
                triggerPending = false;
                btnTrigger.setEnabled(true);
            }, 90_000);
            refresh();
        } catch (Throwable e) {
            Toast.makeText(this, "触发失败: " + e, Toast.LENGTH_LONG).show();
        }
    }

    private void refresh() {
        // driver / ocsk from /proc/modules (readable by any app)
        setModule(tvDriver, PostLock.moduleLoaded("kernelsu"));
        setModule(tvOcsk, PostLock.moduleLoaded("ocsk"));

        boolean enforcing = PostLock.selinuxEnforcing();
        tvSelinux.setText(enforcing ? "Enforcing" : "Permissive");
        tvSelinux.setTextColor(enforcing ? Color.parseColor("#C62828")
                : Color.parseColor("#2E7D32"));

        long mtime = PostLock.chainLogMtime(this);
        tvLastRun.setText(mtime == 0
                ? "从未"
                : DateUtils.getRelativeTimeSpanString(mtime).toString());

        String tail = PostLock.chainLogTail(this, LOG_TAIL_BYTES);
        if (tail.isEmpty()) {
            tvLog.setText("尚未触发。点上方按钮，或等待开机广播自动触发。");
        } else {
            tvLog.setText(tail);
            tvLogTitle.setText("链日志 chain.log"
                    + (triggerPending ? "（链执行中…）" : ""));
            if (triggerPending) {
                scroll.post(() -> scroll.fullScroll(View.FOCUS_DOWN));
            }
        }
    }

    private static void setModule(TextView tv, boolean loaded) {
        tv.setText(loaded ? "✓ 已加载" : "✗ 未加载");
        tv.setTextColor(loaded ? Color.parseColor("#2E7D32")
                : Color.parseColor("#9AA0A6"));
    }
}
