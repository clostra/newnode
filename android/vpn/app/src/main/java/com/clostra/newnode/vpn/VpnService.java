package com.clostra.newnode.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.net.ProxyInfo;
import android.os.Build;
import android.os.Handler;
import android.os.Message;
import android.os.ParcelFileDescriptor;
import android.util.Log;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import com.clostra.newnode.NewNode;

public class VpnService extends android.net.VpnService implements Handler.Callback {
    private static final String TAG = VpnService.class.getSimpleName();

    public static final String ACTION_CONNECT = "com.clostra.newnode.vpn.START";
    public static final String ACTION_DISCONNECT = "com.clostra.newnode.vpn.STOP";

    static VpnService vpnService;

    private Handler mHandler;
    private PendingIntent mConfigureIntent;
    private Thread mTun2SocksThread;

    @SuppressWarnings("unused")
    static public boolean vpnProtect(int socket) {
        Log.d(TAG, "vpnProtect:" + socket);
        return vpnService.protect(socket);
    }

    @Override
    public void onCreate() {
        // The handler is only used to show messages.
        if (mHandler == null) {
            mHandler = new Handler(this);
        }

        vpnService = this;
    }

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        Log.d(TAG, "onStartCommand: " + (intent != null ? intent.getAction() : "null"));
        if (intent != null && ACTION_DISCONNECT.equals(intent.getAction())) {
            disconnect();
            return START_NOT_STICKY;
        } else {
            try {
                connect();
            } catch (IllegalStateException e) {
                Log.e(TAG, "connect", e);
                disconnect();
                return START_NOT_STICKY;
            }
            return START_STICKY;
        }
    }

    @Override
    public void onDestroy() {
        disconnect();
    }

    @Override
    public boolean handleMessage(Message message) {
        LocalBroadcastManager locationBroadcastManager = LocalBroadcastManager.getInstance(this);
        locationBroadcastManager.sendBroadcast(new Intent(VpnActivity.ACTION_STATE).putExtra("state", message.what));
        if (message.what != R.string.disconnected) {
            updateForegroundNotification(message.what);
        }
        return true;
    }

    private void connect() {
        NewNode.init();

        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        mConfigureIntent = PendingIntent.getActivity(this, 0, new Intent(this, VpnActivity.class), flags);

        Builder builder = new Builder();
        builder.addAddress("10.7.0.1", 32);
        builder.addAddress("2001:db8::1", 64);
        builder.addRoute("0.0.0.0", 0);
        builder.addRoute("::", 0);
        builder.addDnsServer("8.8.8.8");
        builder.addDnsServer("1.1.1.1");
        builder.addDnsServer("2001:4860:4860::8888");
        builder.addDnsServer("2606:4700:4700::1111");
        builder.setSession("NewNode");
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            String proxyHost = System.getProperty("proxyHost");
            int proxyPort = Integer.parseInt(System.getProperty("proxyPort"));
            Log.d(TAG, "proxy: " + proxyHost + ":" + proxyPort);
            builder.setHttpProxy(ProxyInfo.buildDirectProxy(proxyHost, proxyPort));
        }
        Log.i(TAG, "builder:" + builder);
        ParcelFileDescriptor fd = builder.establish();

        // Become a foreground service. Background services can be VPN services too, but they can
        // be killed by background check before getting a chance to receive onRevoke().
        mHandler.sendEmptyMessage(R.string.connected);

        if (mTun2SocksThread == null) {
            mTun2SocksThread = new Thread(() ->
               runTun2Socks(
                    fd.detachFd(),
                    1500,
                    "10.7.0.1",
                    "255.255.255.255",
                    System.getProperty("proxyHost") + ":" + System.getProperty("proxyPort"),
                    System.getProperty("proxyHost") + ":" + "7300",
                    1));
            mTun2SocksThread.start();
        }
    }

    private void disconnect() {
        if (mTun2SocksThread != null) {
            try {
                terminateTun2Socks();
                mTun2SocksThread.join();
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            mTun2SocksThread = null;
        }
        mHandler.sendEmptyMessage(R.string.disconnected);
        stopForeground(true);
    }

    private void updateForegroundNotification(final int message) {
        Notification.Builder builder = new Notification.Builder(this)
                .setSmallIcon(R.drawable.ic_vpn)
                .setContentText(getString(message))
                .setContentIntent(mConfigureIntent);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            final String NOTIFICATION_CHANNEL_ID = "NewNode VPN";
            NotificationManager mNotificationManager = (NotificationManager) getSystemService(
                    NOTIFICATION_SERVICE);
            mNotificationManager.createNotificationChannel(new NotificationChannel(
                    NOTIFICATION_CHANNEL_ID, NOTIFICATION_CHANNEL_ID,
                    NotificationManager.IMPORTANCE_DEFAULT));
            builder.setChannelId(NOTIFICATION_CHANNEL_ID);
        }
        startForeground(1, builder.build());
    }

    public native static int runTun2Socks(
            int vpnInterfaceFileDescriptor,
            int vpnInterfaceMTU,
            String vpnIpAddress,
            String vpnNetMask,
            String socksServerAddress,
            String udpgwServerAddress,
            int udpgwTransparentDNS);

    public native static int terminateTun2Socks();

    public static void logTun2Socks(int level, String channel, String msg) {
        switch (level) {
        case 1:
            Log.e(TAG + "_" + channel, msg); break;
        case 2:
            Log.w(TAG + "_" + channel, msg); break;
        case 3:
            Log.i(TAG + "_" + channel, msg); break;
        case 4:
            //Log.v(TAG + "_" + channel, msg); break;
        case 5:
            //Log.d(TAG + "_" + channel, msg); break;
        }
    }

    static {
        System.loadLibrary("tun2socks");
    }
}
