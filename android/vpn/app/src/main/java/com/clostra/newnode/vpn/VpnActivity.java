package com.clostra.newnode.vpn;

import android.app.Activity;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.widget.Switch;
import android.widget.TextView;

public class VpnActivity extends Activity {

    public final static String ACTION_STATE = "com.clostra.newnode.vpn.STATE";
    private BroadcastReceiver receiver = new BroadcastReceiver() {
        @Override
        public void onReceive(Context context, Intent intent) {
            TextView t = findViewById(R.id.textView);
            t.setText(intent.getIntExtra("state", 0));
        }
    };

    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.main);

        registerReceiver(receiver, new IntentFilter(ACTION_STATE));

        setVpnState();
        SharedPreferences prefs = getSharedPreferences("vpn", MODE_PRIVATE);
        Switch switch1 = findViewById(R.id.switch1);
        switch1.setChecked(prefs.getBoolean("enabled", false));
        switch1.setOnCheckedChangeListener((view, isChecked) -> {
            prefs.edit()
                    .putBoolean("enabled", isChecked)
                    .apply();
            setVpnState();
        });
    }

    @Override
    protected void onDestroy() {
        super.onDestroy();
        unregisterReceiver(receiver);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK) {
            sendBroadcast(new Intent(VpnActivity.ACTION_STATE).putExtra("state", R.string.connecting));
            startService(getServiceIntent().setAction(VpnService.ACTION_CONNECT));
        }
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
