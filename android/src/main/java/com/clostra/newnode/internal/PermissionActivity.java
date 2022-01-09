package com.clostra.newnode.internal;

import android.Manifest;
import android.app.Activity;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;

import java.util.ArrayList;
import java.util.List;


public class PermissionActivity extends Activity {
    static final String TAG = PermissionActivity.class.getSimpleName();

    private static final int PERMISSIONS_REQUEST_CODE = 1001;

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        switch (requestCode) {
        case PERMISSIONS_REQUEST_CODE:
            if (grantResults.length > 0) {
                for (int i = 0; i < permissions.length; i++) {
                    if  (grantResults[i] != PackageManager.PERMISSION_GRANTED) {
                        Log.e(TAG, "Permission " + permissions[i] + " is not granted");
                    } else {
                        Log.e(TAG, "Permission " + permissions[i] + " granted");
                    }
                }
            }
            NewNode.restartNearby();
            finish();
            break;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.e(TAG, "onCreate permission activity starting");
        String[] permissions = new String[]{
            Manifest.permission.ACCESS_COARSE_LOCATION,
            Manifest.permission.ACCESS_FINE_LOCATION,
            Manifest.permission.BLUETOOTH_ADVERTISE,
            Manifest.permission.BLUETOOTH_CONNECT,
            Manifest.permission.BLUETOOTH_SCAN,
        };
        List<String> permissionsToRequest = new ArrayList<>();
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                Log.d(TAG, "requesting " + permission);
                permissionsToRequest.add(permission);
            }
        }
        if (permissionsToRequest.size() > 0) {
            ActivityCompat.requestPermissions(this,
                permissionsToRequest.toArray(new String[permissionsToRequest.size()]),
                PERMISSIONS_REQUEST_CODE);
        }
    }
}
