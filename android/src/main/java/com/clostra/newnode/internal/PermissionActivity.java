package com.clostra.newnode.internal;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import android.content.DialogInterface;
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
            NewNode.startNearby();
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
            return;
        }
        if (locationDisclosure) {
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
                        //No button clicked
                        break;
                    }
                }
            };

            AlertDialog.Builder builder = new AlertDialog.Builder(this);
            builder.setMessage("This app uses current location to find nearby connections  in the background")
                .setPositiveButton(android.R.string.ok, dialogClickListener)
                .setNegativeButton(android.R.string.cancel, dialogClickListener).show();
        }
    }
}
