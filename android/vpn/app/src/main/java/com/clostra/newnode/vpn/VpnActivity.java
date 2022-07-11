package com.clostra.newnode.vpn;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.res.Configuration;
import android.graphics.drawable.TransitionDrawable;
import android.os.Bundle;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;
import android.widget.ImageButton;
import android.widget.ImageView;
import android.widget.TextView;

import androidx.appcompat.app.AppCompatActivity;
import androidx.core.content.ContextCompat;
import androidx.fragment.app.Fragment;
import androidx.fragment.app.FragmentTransaction;
import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.clostra.newnode.vpn.statistics.StatisticsFragment;

public class VpnActivity extends AppCompatActivity {

    public final static String ACTION_STATE = "com.clostra.newnode.vpn.STATE";
    private final StatisticsFragment statistics = new StatisticsFragment();
    private boolean uiStatus = false;
    private final AnimationGroup commonTextAnimationGroup = new AnimationGroup(this, R.animator.common_text_to_connected, R.animator.common_text_to_disconnected);
    private final AnimationGroup statusTextAnimationGroup = new AnimationGroup(this, R.animator.status_text_to_connected, R.animator.status_text_to_disconnected);

    private final BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            startTransitionIfNeeded();
            int stateString = intent.getIntExtra("state", 0);

            TextView status = findViewById(R.id.connection_status);
            new BlinkAnimation(getApplicationContext(), status, () -> status.setText(stateString)).start();

            TextView tapTo = findViewById(R.id.tap_to_connect);
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
        TransitionDrawable logo = (TransitionDrawable) ((ImageView) findViewById(R.id.newnode_vpn_logo)).getDrawable();
        TransitionDrawable map = (TransitionDrawable) ((ImageView) findViewById(R.id.map)).getDrawable();
        map.setCrossFadeEnabled(true);
        TransitionDrawable power = (TransitionDrawable) ((ImageButton) findViewById(R.id.powerButton)).getDrawable();
        power.setCrossFadeEnabled(true);
        TransitionDrawable info = (TransitionDrawable) ((ImageButton) findViewById(R.id.infoButton)).getDrawable();
        FadeAnimation citiesAnimation = new FadeAnimation(getApplicationContext(), findViewById(R.id.cities));

        if (prefs.getBoolean("enabled", false)) {
            background.startTransition(1000);
            logo.startTransition(1000);
            map.startTransition(1000);
            power.startTransition(1000);
            info.startTransition(1000);
            citiesAnimation.fadeIn(1000);
            commonTextAnimationGroup.forward();
            statusTextAnimationGroup.forward();
            statistics.textAnimationToConnect();
        } else {
            background.reverseTransition(1000);
            logo.reverseTransition(1000);
            map.reverseTransition(1000);
            power.reverseTransition(1000);
            info.reverseTransition(1000);
            citiesAnimation.fadeOut();
            commonTextAnimationGroup.backward();
            statusTextAnimationGroup.backward();
            statistics.textAnimationToDisconnect();
        }

        uiStatus = prefs.getBoolean("enabled", false);
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

//        SharedPreferences prefs = getSharedPreferences("vpn", MODE_PRIVATE);
//        uiStatus = prefs.getBoolean("enabled", false);

        initSystemBars();
        statusTextAnimationGroup.addTarget(findViewById(R.id.connection_status));
        commonTextAnimationGroup.addTarget(findViewById(R.id.tap_to_connect));

        LocalBroadcastManager locationBroadcastManager = LocalBroadcastManager.getInstance(this);
        IntentFilter intentFilter = new IntentFilter(ACTION_STATE);
        locationBroadcastManager.registerReceiver(receiver, intentFilter);

        setVpnState();
        openStatistics();
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        LocalBroadcastManager locationBroadcastManager = LocalBroadcastManager.getInstance(this);
        locationBroadcastManager.unregisterReceiver(receiver);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        super.onActivityResult(request, result, data);
        if (result == RESULT_OK) {
            LocalBroadcastManager locationBroadcastManager = LocalBroadcastManager.getInstance(this);
            locationBroadcastManager.sendBroadcast(new Intent(VpnActivity.ACTION_STATE).putExtra("state", R.string.connecting));
            startService(getServiceIntent().setAction(VpnService.ACTION_CONNECT));
        }
    }

    public void connect(View v) {
        SharedPreferences prefs = getSharedPreferences("vpn", MODE_PRIVATE);

        prefs.edit()
                .putBoolean("enabled", !prefs.getBoolean("enabled", false))
                .apply();

        setVpnState();
    }

    private void openStatistics() {
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

    private void initSystemBars() {
        Window window = this.getWindow();

        window.clearFlags(WindowManager.LayoutParams.FLAG_TRANSLUCENT_STATUS);

        window.addFlags(WindowManager.LayoutParams.FLAG_DRAWS_SYSTEM_BAR_BACKGROUNDS);

        window.setStatusBarColor(ContextCompat.getColor(this, R.color.nn_system_bar_background));
        window.setNavigationBarColor(ContextCompat.getColor(this, R.color.nn_system_bar_background));
        View decor = window.getDecorView();

        int nightModeFlags = getResources().getConfiguration().uiMode & Configuration.UI_MODE_NIGHT_MASK;

        switch (nightModeFlags) {
            case Configuration.UI_MODE_NIGHT_YES:
                decor.setSystemUiVisibility(0);
                break;

            case Configuration.UI_MODE_NIGHT_NO:
                decor.setSystemUiVisibility(View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
                break;
        }
    }
}
