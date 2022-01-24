package com.clostra.newnode.vpn;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.drawable.TransitionDrawable;
import android.os.Bundle;
import android.view.View;
import android.view.animation.Animation;
import android.view.animation.AnimationUtils;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentTransaction;

import com.clostra.newnode.vpn.statistics.StatisticsFragment;

public class VpnActivity extends AppCompatActivity {

    public final static String ACTION_STATE = "com.clostra.newnode.vpn.STATE";

    private boolean uiStatus = false;

    private Animation outerRotate;
    private Animation innerRotate;

    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            startTransitionIfNeeded();
            int stateString = intent.getIntExtra("state", 0);

            if (stateString == R.string.connected) {
                stopArcAnimation();
            }

            TextView status = findViewById(R.id.connection_status);
            new BlinkAnimation(getApplicationContext(), status, () -> status.setText(stateString)).start();

            TextView tapTo = findViewById(R.id.tapToConnect);
            new BlinkAnimation(getApplicationContext(), tapTo, () -> {
                if (stateString == R.string.connected) {
                    tapTo.setText(R.string.tap_to_disconnect);
                } else if (stateString == R.string.disconnected) {
                    tapTo.setText(R.string.tap_to_connect);
                }
            }).start();
        }
    };

    private void startTransitionIfNeeded() {
        SharedPreferences prefs = getSharedPreferences("vpn", MODE_PRIVATE);
        if (uiStatus == prefs.getBoolean("enabled", false))
            return;

        TransitionDrawable background = (TransitionDrawable) findViewById(R.id.main_layout).getBackground();
        FadeAnimation grayCircleAnimation = new FadeAnimation(getApplicationContext(), findViewById(R.id.gray_circle));
        FadeAnimation netGlobesAnimation = new FadeAnimation(getApplicationContext(), findViewById(R.id.net_globes));

        if (prefs.getBoolean("enabled", false)) {
            background.startTransition(1000);
            grayCircleAnimation.fadeOut();
            netGlobesAnimation.fadeIn();
        } else {
            background.reverseTransition(1000);
            grayCircleAnimation.fadeIn();
            netGlobesAnimation.fadeOut();
        }

        uiStatus = prefs.getBoolean("enabled", false);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);
        outerRotate = AnimationUtils.loadAnimation(getApplicationContext(), R.anim.outer_rotate);
        innerRotate = AnimationUtils.loadAnimation(getApplicationContext(), R.anim.inner_rotate);

        registerReceiver(receiver, new IntentFilter(ACTION_STATE));

        setVpnState();
        openStatistics();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(receiver);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result == RESULT_OK) {
            sendBroadcast(new Intent(this, VpnActivity.class).setAction(VpnActivity.ACTION_STATE).putExtra("state", R.string.connecting));
            startService(getServiceIntent().setAction(VpnService.ACTION_CONNECT));
        }
    }

    public void connect(View v) {
        SharedPreferences prefs = getSharedPreferences("vpn", MODE_PRIVATE);

        if (!uiStatus) {
            startArcAnimation();
        }

        prefs.edit()
                .putBoolean("enabled", !prefs.getBoolean("enabled", false))
                .apply();

        setVpnState();

    }

    private void openStatistics() {
        Fragment statistics = new StatisticsFragment();
        FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
        transaction
                .setReorderingAllowed(true)
                .add(R.id.stats_fragment_container, statistics)
                .show(statistics)
                .commit();
    }

    public void openInfo(View v) {
        Fragment info = new InfoFragment();
        FragmentTransaction transaction = getSupportFragmentManager().beginTransaction();
        transaction
                .setReorderingAllowed(true)
                .add(R.id.info_fragment_container, info)
                .show(info)
                .commit();
    }

    private void startArcAnimation() {
        View outer_arc = findViewById(R.id.outer_arc);
        outer_arc.setVisibility(View.VISIBLE);
        outer_arc.startAnimation(outerRotate);

        View inner_arc = findViewById(R.id.inner_arc);
        inner_arc.setVisibility(View.VISIBLE);
        inner_arc.startAnimation(innerRotate);
    }

    private void stopArcAnimation() {
        View outer_arc = findViewById(R.id.outer_arc);
        outerRotate.reset();
        outer_arc.clearAnimation();
        outer_arc.setVisibility(View.GONE);

        View inner_arc = findViewById(R.id.inner_arc);
        innerRotate.cancel();
        inner_arc.clearAnimation();
        inner_arc.setVisibility(View.GONE);
    }

    private void setVpnState() {
        SharedPreferences prefs = getSharedPreferences("vpn", MODE_PRIVATE);
        if (!prefs.getBoolean("enabled", false)) {
            startService(getServiceIntent().setAction(VpnService.ACTION_DISCONNECT));
            return;
        }
        Intent intent = VpnService.prepare(VpnActivity.this);
        if (intent != null) {
            startActivityForResult(intent, 0);
        } else {
            onActivityResult(0, RESULT_OK, null);
        }
    }

    private Intent getServiceIntent() {
        return new Intent(this, VpnService.class);
    }
}
