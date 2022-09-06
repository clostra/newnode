package com.clostra.newnode.internal;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.pm.ApplicationInfo;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import android.content.DialogInterface;
import android.content.pm.PackageManager;
import android.os.Build;
import android.os.Bundle;
import android.util.Log;
import android.view.ContextThemeWrapper;

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
            NewNode.startNearby();
            finish();
            break;
        }
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Log.e(TAG, "onCreate permission activity starting api level:" + Build.VERSION.SDK_INT);
        List<String> permissions = new ArrayList<String>();
        if (Build.VERSION.SDK_INT >= 33) {
            permissions.add(Manifest.permission.NEARBY_WIFI_DEVICES);
        } else if (Build.VERSION.SDK_INT >= 29) {
            permissions.add(Manifest.permission.ACCESS_FINE_LOCATION);
        } else {
            permissions.add(Manifest.permission.ACCESS_COARSE_LOCATION);
        }
        if (Build.VERSION.SDK_INT >= 31) {
            permissions.add(Manifest.permission.BLUETOOTH_ADVERTISE);
            permissions.add(Manifest.permission.BLUETOOTH_CONNECT);
            permissions.add(Manifest.permission.BLUETOOTH_SCAN);
        }
        boolean locationDisclosure = false;
        List<String> permissionsToRequest = new ArrayList<>();
        for (String permission : permissions) {
            if (ContextCompat.checkSelfPermission(this, permission) != PackageManager.PERMISSION_GRANTED) {
                Log.d(TAG, "requesting " + permission);
                permissionsToRequest.add(permission);
                if (permission == Manifest.permission.ACCESS_COARSE_LOCATION ||
                    permission == Manifest.permission.ACCESS_FINE_LOCATION) {
                    locationDisclosure = true;
                }
            }
        }

        if (permissionsToRequest.size() == 0) {
            finish();
            return;
        }

        if (!locationDisclosure) {
            ActivityCompat.requestPermissions(PermissionActivity.this,
                permissionsToRequest.toArray(new String[permissionsToRequest.size()]),
                PERMISSIONS_REQUEST_CODE);
            return;
        }

        DialogInterface.OnClickListener dialogClickListener = new DialogInterface.OnClickListener() {
            @Override
            public void onClick(DialogInterface dialog, int which) {
                switch (which){
                case DialogInterface.BUTTON_POSITIVE:
                    ActivityCompat.requestPermissions(PermissionActivity.this,
                        permissionsToRequest.toArray(new String[permissionsToRequest.size()]),
                        PERMISSIONS_REQUEST_CODE);
                    break;
                case DialogInterface.BUTTON_NEGATIVE:
                    finish();
                    break;
                }
            }
        };

        ApplicationInfo applicationInfo = getApplicationInfo();
        int stringId = applicationInfo.labelRes;
        String appName = stringId == 0 ? applicationInfo.nonLocalizedLabel.toString() : getString(stringId);

        AlertDialog.Builder builder = new AlertDialog.Builder(new ContextThemeWrapper(this, androidx.appcompat.R.style.Theme_AppCompat_Dialog_Alert));
        builder.setMessage(appName + " finds and connects to nearby devices in the background using current location.")
            .setPositiveButton(android.R.string.ok, dialogClickListener)
            .setNegativeButton(android.R.string.cancel, dialogClickListener).show();
    }
}
