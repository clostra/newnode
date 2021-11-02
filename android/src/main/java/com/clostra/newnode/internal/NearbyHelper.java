package com.clostra.newnode.internal;

import android.app.Activity;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.os.BatteryManager;
import android.os.Bundle;
import android.util.Log;

import com.google.android.gms.common.api.ApiException;
import com.google.android.gms.nearby.Nearby;
import com.google.android.gms.nearby.connection.AdvertisingOptions;
import com.google.android.gms.nearby.connection.ConnectionInfo;
import com.google.android.gms.nearby.connection.ConnectionLifecycleCallback;
import com.google.android.gms.nearby.connection.ConnectionResolution;
import com.google.android.gms.nearby.connection.ConnectionsClient;
import com.google.android.gms.nearby.connection.ConnectionsStatusCodes;
import com.google.android.gms.nearby.connection.DiscoveredEndpointInfo;
import com.google.android.gms.nearby.connection.DiscoveryOptions;
import com.google.android.gms.nearby.connection.EndpointDiscoveryCallback;
import com.google.android.gms.nearby.connection.Payload;
import com.google.android.gms.nearby.connection.PayloadCallback;
import com.google.android.gms.nearby.connection.PayloadTransferUpdate;
import com.google.android.gms.nearby.connection.Strategy;
import com.google.android.gms.tasks.OnFailureListener;
import com.google.android.gms.tasks.OnSuccessListener;

import java.nio.charset.Charset;
import java.util.Formatter;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;


public class NearbyHelper implements Application.ActivityLifecycleCallbacks {

    static final String TAG = NearbyHelper.class.getSimpleName();

    static final String SERVICE_ID = "com.clostra.newnode.internal.SERVICE_ID";

    // XXX: maybe use P2P_CLUSTER. better connectivity, but slower
    Strategy STRATEGY = Strategy.P2P_STAR;

    Application app;
    static NearbyHelper nearbyHelper;
    String serviceName = UUID.randomUUID().toString();
    static boolean batteryLow = false;
    Set<String> connections = new HashSet<>();

    public static class BatteryLevelReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d(TAG, "action: " + intent.getAction());
            if (intent.getAction() == Intent.ACTION_BATTERY_LOW) {
                batteryLow = true;
                nearbyHelper.stopDiscovery();
                nearbyHelper.stopAdvertising();
            } else if (intent.getAction() == Intent.ACTION_BATTERY_OKAY) {
                batteryLow = false;
                nearbyHelper.startDiscovery();
                nearbyHelper.startAdvertising();
            }
        }
    }

    PayloadCallback payloadCallback = new PayloadCallback() {
        @Override
        public void onPayloadReceived(String endpointId, Payload payload) {
            //Log.d(TAG, "onPayloadReceived endpointId:" + endpointId + " payload:" + payload);
            if (payload.getType() == Payload.Type.BYTES) {
                byte[] packet = payload.asBytes();
                //Log.d(TAG, "packetReceived:" + packet.length + " endpoint:" + endpointId);
                byte[] endpoint = endpointId.getBytes(Charset.forName("UTF-8"));
                NewNode.packetReceived(packet, endpoint);
            }
        }

        @Override
        public void onPayloadTransferUpdate(String endpointId, PayloadTransferUpdate update) {
            //Log.d(TAG, "onPayloadTransferUpdate endpointId:" + endpointId + " update:" + update);
        }
    };

    ConnectionLifecycleCallback connectionLifecycleCallback = new ConnectionLifecycleCallback() {
        @Override
        public void onConnectionInitiated(String endpointId, ConnectionInfo info) {
            Log.d(TAG, "onConnectionInitiated endpointId:" + endpointId + " info:" + info);
            Nearby.getConnectionsClient(app).stopDiscovery();
            Nearby.getConnectionsClient(app).acceptConnection(endpointId, payloadCallback)
            .addOnFailureListener(new OnFailureListener() {
                @Override
                public void onFailure(Exception e) {
                    Log.d(TAG, "acceptConnection onFailure:" + e);
                }
            });
        }

        @Override
        public void onConnectionResult(String endpointId, ConnectionResolution result) {
            Log.d(TAG, "onConnectionResult endpointId:" + endpointId + " result:" + result);
            if (!result.getStatus().isSuccess()) {
                Log.d(TAG, "Connection failed. status:" + result.getStatus());
            } else {
                Log.d(TAG, "addEndpoint endpoint:" + endpointId);
                connections.add(endpointId);
                byte[] endpoint = endpointId.getBytes(Charset.forName("UTF-8"));
                NewNode.addEndpoint(endpoint);
            }
        }

        @Override
        public void onDisconnected(String endpointId) {
            Log.d(TAG, "onDisconnected endpointId:" + endpointId);
            connections.remove(endpointId);
            byte[] endpoint = endpointId.getBytes(Charset.forName("UTF-8"));
            NewNode.removeEndpoint(endpoint);
            maybeStartDiscovery();
        }
    };

    public NearbyHelper(Application app) {
        this.app = app;
        nearbyHelper = this;
        app.registerActivityLifecycleCallbacks(this);

        IntentFilter iFilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
        Intent batteryStatus = app.registerReceiver(null, iFilter);
        int level = batteryStatus != null ? batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) : -1;
        int scale = batteryStatus != null ? batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1) : -1;
        double batteryPct = 100 * (level / (double)scale);
        Log.d(TAG, "batteryPct: " + batteryPct);
        if (batteryPct < 15) {
            batteryLow = true;
        }

        startDiscovery();
        startAdvertising();
    }

    void startAdvertising() {
        if (batteryLow) {
            return;
        }
        AdvertisingOptions.Builder advertisingOptions = new AdvertisingOptions.Builder();
        advertisingOptions.setStrategy(Strategy.P2P_CLUSTER);
        Nearby.getConnectionsClient(app).startAdvertising(serviceName, SERVICE_ID, connectionLifecycleCallback, advertisingOptions.build())
        .addOnSuccessListener(new OnSuccessListener<Void>() {
            @Override
            public void onSuccess(Void unusedResult) {
                Log.d(TAG, "startAdvertising onSuccess");
            }
        })
        .addOnFailureListener(new OnFailureListener() {
            @Override
            public void onFailure(Exception e) {
                if (e instanceof ApiException) {
                    ApiException ae = (ApiException)e;
                    if (ae.getStatusCode() == ConnectionsStatusCodes.STATUS_ALREADY_ADVERTISING) {
                        return;
                    }
                }
                Log.e(TAG, "startAdvertising onFailure", e);
            }
        });
    }

    void stopAdvertising() {
        Nearby.getConnectionsClient(app).stopAdvertising();
    }

    void startDiscovery() {
        if (batteryLow) {
            return;
        }
        DiscoveryOptions.Builder discoveryOptions = new DiscoveryOptions.Builder();
        discoveryOptions.setStrategy(Strategy.P2P_CLUSTER);
        Nearby.getConnectionsClient(app).startDiscovery(SERVICE_ID, new EndpointDiscoveryCallback() {
            @Override
            public void onEndpointFound(String endpointId, DiscoveredEndpointInfo info) {
                Log.d(TAG, "onEndpointFound endpointId:" + endpointId + " info:" + info);
                if (!SERVICE_ID.equals(info.getServiceId())) {
                    Log.d(TAG, "unknown serviceId: " + info.getServiceId());
                } else if (info.getEndpointName().equals(serviceName)) {
                    Log.d(TAG, "onEndpointFound same name: " + info.getEndpointName());
                } else {
                    Log.d(TAG, "endpoint available: " + info.getEndpointName());
                    Nearby.getConnectionsClient(app).stopDiscovery();
                    Nearby.getConnectionsClient(app).requestConnection(serviceName, endpointId, connectionLifecycleCallback)
                    .addOnFailureListener(new OnFailureListener() {
                        @Override
                        public void onFailure(Exception e) {
                            Log.d(TAG, "requestConnection failed:" + e);
                            maybeStartDiscovery();
                        }
                    });
                }
            }

            @Override
            public void onEndpointLost(String endpointId) {
                Log.d(TAG, "onEndpointLost endpointId:" + endpointId);
            }
        }, discoveryOptions.build())
        .addOnSuccessListener(new OnSuccessListener<Void>() {
            @Override
            public void onSuccess(Void unusedResult) {
                Log.d(TAG, "startDiscovery onSuccess");
            }
        })
        .addOnFailureListener(new OnFailureListener() {
            @Override
            public void onFailure(Exception e) {
                Log.d(TAG, "startDiscovery failed:" + e);
            }
        });
    }

    void maybeStartDiscovery() {
        if (connections.size() < 1) {
            startDiscovery();
        }
    }

    void stopDiscovery() {
        Nearby.getConnectionsClient(app).stopDiscovery();
    }

    void sendPacket(byte[] packet, byte[] endpoint) {
        final String endpointId = new String(endpoint, Charset.forName("UTF-8"));
        //Log.d(TAG, "sendPacket:" + packet.length + " max:" + Nearby.getConnectionsClient(app).MAX_BYTES_DATA_SIZE + " endpoint:" + endpointId);
        Nearby.getConnectionsClient(app).sendPayload(endpointId, Payload.fromBytes(packet))
        .addOnFailureListener(new OnFailureListener() {
            @Override
            public void onFailure(Exception e) {
                Log.d(TAG, "sendPayload endpoint:" + endpointId + " failed:" + e);
            }
        });
    }

    @Override
    public void onActivityResumed(Activity activity) {
        Log.e(TAG, "onActivityResumed");
        startDiscovery();
        startAdvertising();
    }

    @Override
    public void onActivityCreated(Activity activity, Bundle bundle) {}

    @Override
    public void onActivityDestroyed(Activity activity) {}

    @Override
    public void onActivitySaveInstanceState(Activity activity, Bundle bundle) {}

    @Override
    public void onActivityStarted(Activity activity) {}

    @Override
    public void onActivityStopped(Activity activity) {}

    @Override
    public void onActivityPaused(Activity activity) {}
}
