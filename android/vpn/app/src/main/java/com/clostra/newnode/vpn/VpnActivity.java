package com.clostra.newnode.vpn;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;

public class VpnActivity extends Activity {
    @Override
    public void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.form);

        findViewById(R.id.connect).setOnClickListener(v -> {
            SharedPreferences prefs = getSharedPreferences("vpn", MODE_PRIVATE);
            if (prefs.getBoolean("enabled", false)) {
                prefs.edit()
                    .putBoolean("enabled", false)
                    .apply();
                startService(getServiceIntent().setAction(VpnService.ACTION_DISCONNECT));
                return;
            }
            prefs.edit()
                .putBoolean("enabled", true)
                .apply();
            Intent intent = VpnService.prepare(VpnActivity.this);
            if (intent != null) {
                startActivityForResult(intent, 0);
            } else {
                onActivityResult(0, RESULT_OK, null);
            }
        });
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (result == RESULT_OK) {
            startService(getServiceIntent().setAction(VpnService.ACTION_CONNECT));
        }
    }

    private Intent getServiceIntent() {
        return new Intent(this, VpnService.class);
    }
}
