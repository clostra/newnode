package com.clostra.newnode.internal;

import android.app.Activity;
import android.app.Application;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.res.AssetManager;
import android.os.BatteryManager;
import android.os.Build;
import android.os.Bundle;
import android.os.Bundle;
import android.util.Log;

import androidx.localbroadcastmanager.content.LocalBroadcastManager;

import dalvik.system.PathClassLoader;

import com.bugsnag.android.Client;
import com.bugsnag.android.Configuration;
import com.bugsnag.android.NativeInterface;
import com.bugsnag.android.NotifyType;

import com.clostra.newnode.BuildConfig;
import com.clostra.newnode.NewNode.NewNodeInternal;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.ClassLoader;
import java.lang.reflect.Method;
import java.net.HttpURLConnection;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;
import java.util.List;
import java.util.Map;
import java.util.Arrays;
import java.util.Observable;
import java.util.Observer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;



public class NewNode implements NewNodeInternal, Runnable, Application.ActivityLifecycleCallbacks {
    static final String TAG = NearbyHelper.class.getSimpleName();
    public static String VERSION = BuildConfig.VERSION_NAME;

    static Thread t;
    //static Thread updateThread;
    static boolean requestPermission = true;
    static NearbyHelper nearbyHelper;
    static Bluetooth bluetooth;
    static Client bugsnagClient;
    static boolean batteryLow = false;

    static {
        Application app = app();

        File[] files = app.getFilesDir().listFiles();
        Arrays.sort(files);
        for (int i = files.length - 1; i >= 0; i--) {
            File f = files[i];
            try {
                Matcher m = Pattern.compile("^libnewnode.v?([.0-9]*).so$").matcher(f.getName());
                if (!m.find()) {
                    continue;
                }
                String v2 = m.group(1);
                if (VERSION.compareTo(v2) < 0) {
                    Log.d(TAG, "loading "+f.getName());
                    System.load(f.getAbsolutePath());
                    VERSION = v2;
                    break;
                }
            } catch (Exception e) {
                Log.e(TAG, "", e);
            }
        }
        // XXX: might not work in a classes.dex
        if (VERSION.equals(BuildConfig.VERSION_NAME)) {
            try {
                Log.d(TAG, "loading built-in newnode");
                System.loadLibrary("newnode");
            } catch (UnsatisfiedLinkError e) {
                Log.e(TAG, "", e);
            }
        }
        /*
        updateThread = new Thread() { public void run() {
            while (!Thread.interrupted()) {
                try {
                    update();
                } catch(Exception e) {
                    Log.e(TAG, "", e);
                }
                try {
                    sleep((long) (1 + Math.random() * (24 * 60 * 60 * 1000)));
                } catch(InterruptedException e) {
                }
            }
        }};
        updateThread.start();
        */
    }

    static Application app() {
        try {
            return (Application) Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null, (Object[]) null);
        } catch (Exception e) {
        }
        return null;
    }

    /*
    static boolean saveLocally(JSONObject asset, String output) throws Exception {
        Application app = app();
        String downloadUrl = asset.getString("browser_download_url");
        InputStream ins = new URL(downloadUrl).openConnection().getInputStream();
        GZIPInputStream gis = new GZIPInputStream(ins);
        File tmp = File.createTempFile(output, null, app.getFilesDir());
        FileOutputStream fos = new FileOutputStream(tmp);
        byte[] buffer = new byte[8192];
        int len;
        while ((len = gis.read(buffer)) != -1) {
            fos.write(buffer, 0, len);
        }
        fos.close();
        gis.close();
        File updated = new File(app.getFilesDir(), output);
        if (tmp.renameTo(updated)) {
            Log.e(TAG, "Updated to " + output + ", will take effect on restart");
            return true;
        }
        return false;
    }

    @SuppressWarnings("deprecation")
    static String[] abis() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            return Build.SUPPORTED_ABIS;
        }
        return new String[] {Build.CPU_ABI, Build.CPU_ABI2};
    }

    static void update() throws Exception {
        Application app = app();
        URL url = new URL("https://api.github.com/repos/clostra/newnode/releases/latest");
        URLConnection urlConnection = url.openConnection();
        InputStream in = urlConnection.getInputStream();
        BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        String line;
        StringBuilder b = new StringBuilder(in.available());
        while ((line = r.readLine()) != null) {
            b.append(line);
        }
        in.close();
        JSONObject release = new JSONObject(b.toString());
        String version = release.getString("name").replaceAll("^v", "");
        if (VERSION.compareTo(version) >= 0) {
            return;
        }
        JSONArray assets = release.getJSONArray("assets");
        for (int i = 0; i < assets.length(); i++) {
            try {
                JSONObject asset = assets.getJSONObject(i);
                String name = asset.getString("name");
                if (name.equals("classes.dex.gz")) {
                    saveLocally(asset, "newnode." + version + ".dex");
                    break;
                }
            } catch (Exception e) {
                Log.e(TAG, "", e);
            }
        }
        for (String abi : abis()) {
            for (int i = 0; i < assets.length(); i++) {
                try {
                    JSONObject asset = assets.getJSONObject(i);
                    String name = asset.getString("name");
                    String releaseAbi = name.split("\\.")[1];
                    if (!releaseAbi.equals(abi)) {
                        continue;
                    }
                    if (saveLocally(asset, "libnewnode." + version + ".so")) {
                        return;
                    }
                } catch (Exception e) {
                    Log.e(TAG, "", e);
                }
            }
        }
    }
    */

    public void run() {
        newnodeRun();
    }

    public void init() {
        if (t == null) {
            bugsnagClientInit();

            IntentFilter iFilter = new IntentFilter(Intent.ACTION_BATTERY_CHANGED);
            Intent batteryStatus = app().registerReceiver(null, iFilter);
            int level = batteryStatus != null ? batteryStatus.getIntExtra(BatteryManager.EXTRA_LEVEL, -1) : -1;
            int scale = batteryStatus != null ? batteryStatus.getIntExtra(BatteryManager.EXTRA_SCALE, -1) : -1;
            double batteryPct = 100 * (level / (double)scale);
            Log.d(TAG, "batteryPct: " + batteryPct);
            if (batteryPct < 15) {
                batteryLow = true;
            }

            setRequestDiscoveryPermission(requestPermission);
            setCacheDir(app().getCacheDir().getAbsolutePath());
            newnodeInit(this);
            t = new Thread(this, "newnode");
            t.start();
            Log.e(TAG, "version " + VERSION + " started");
            try {
                nearbyHelper = new NearbyHelper();
            } catch (NoClassDefFoundError e) {
                Log.e(TAG, "NearbyHelper", e);
            }
            if (android.os.Build.VERSION.SDK_INT >= 29) {
                bluetooth = new Bluetooth();
            }
            app().registerActivityLifecycleCallbacks(this);
            startNearby();
        }

        registerProxy();
    }

    public void shutdown() {
        unregisterProxy();
    }

    public void setRequestDiscoveryPermission(boolean enabled) {
        requestPermission = enabled;
        if (requestPermission) {
            Intent intent = new Intent(app(), PermissionActivity.class);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
            app().startActivity(intent);
        }
    }

    void sendPacket(byte[] packet, byte[] endpoint) {
        if (nearbyHelper != null) {
            nearbyHelper.sendPacket(packet, endpoint);
        }
        if (bluetooth != null) {
            bluetooth.sendPacket(packet, endpoint);
        }
    }

    void bugsnagClientInit() {
        Configuration config = new Configuration("141ea25aa72c276c49d3a154b82f2b1f");
        config.setAppVersion(VERSION);
        config.setBuildUUID(VERSION);
        config.setSendThreads(true);
        config.setPersistUserBetweenSessions(true);
        config.setAutoCaptureSessions(true);
        config.setEnableExceptionHandler(true);

        bugsnagClient = new Client(app(), config);
        bugsnagClient.setProjectPackages("com.clostra.newnode");
        //bugsnagClient.setLoggingEnabled(true);
        NativeInterface.setClient(bugsnagClient);

        bugsnagClient.addObserver(new BugsnagObserver());
        updateBugsnagDetails(NotifyType.ALL.getValue());
    }

    void displayStats(String type, long direct, long peers) {
        LocalBroadcastManager locationBroadcastManager = LocalBroadcastManager.getInstance(app());
        Intent intent = new Intent("com.clostra.newnode.DISPLAY_STATS");
        intent.putExtra("EXTRA_SCOPE", type);
        intent.putExtra("EXTRA_DIRECT_BYTES", direct);
        intent.putExtra("EXTRA_PEERS_BYTES", peers);
        locationBroadcastManager.sendBroadcast(intent);
    }

    void dnsPrefetch(final String hostname, final int result_index, final int result_id) {
        try {
            new Thread() { public void run() {
                try {
                    Log.i("newnode", String.format("dnsPrefetch(hostname:%s, result_index:%d, result_id:%d)",
                                                   hostname, result_index, result_id));
                    InetAddress[] addrs = InetAddress.getAllByName(hostname);
                    String[] addresses = new String[addrs.length];
                    for (int i = 0; i < addrs.length; ++i)
                        addresses[i] = addrs[i].getHostAddress();
                    storeDnsPrefetchResult(result_index, result_id, hostname, addresses);
                }
                catch (java.net.UnknownHostException e) {
                    Log.i ("newnode", String.format("dnsPrefetch: unknown host %s", hostname), e);
                }
                catch (Exception e) {
                    Log.i ("newnode", "dnsPrefetch inner thread", e);
                }
            }}.start();
        }
        catch (Exception e) {
            Log.i ("newnode", "dnsPrefetch", e);
        }
    }

    void http(final String url, final long callblock) {
        new Thread(){public void run() {
            try {
                URL jUrl = new URL(url);
                HttpURLConnection connection = (HttpURLConnection)jUrl.openConnection();
                connection.setRequestMethod("GET");
                connection.connect();
                callback(callblock, connection.getResponseCode());
            } catch (Exception e) {
                Log.e(TAG, "", e);
                callback(callblock, 0);
            }
        }}.start();
    }

    static void stopNearby() {
        if (nearbyHelper != null) {
            nearbyHelper.stopDiscovery();
            nearbyHelper.stopAdvertising();
        }
        if (bluetooth != null) {
            bluetooth.stopAdvertising();
            bluetooth.stopScan();
        }
    }

    static void startNearby() {
        if (batteryLow) {
            return;
        }
        if (nearbyHelper != null) {
            nearbyHelper.startDiscovery();
            nearbyHelper.startAdvertising();
        }
        if (bluetooth != null) {
            bluetooth.bluetoothOn();
        }
    }

    static class BugsnagObserver implements Observer {
        @Override
        public void update(Observable observable, Object arg) {
            if (arg instanceof Integer) {
                NewNode.updateBugsnagDetails((Integer)arg);
            } else {
                NewNode.updateBugsnagDetails(NotifyType.ALL.getValue());
            }
        }
    }

    public static class BatteryLevelReceiver extends BroadcastReceiver {
        @Override
        public void onReceive(Context context, Intent intent) {
            Log.d(TAG, "action: " + intent.getAction());
            if (intent.getAction() == Intent.ACTION_BATTERY_LOW) {
                batteryLow = true;
                stopNearby();
            } else if (intent.getAction() == Intent.ACTION_BATTERY_OKAY) {
                batteryLow = false;
                startNearby();
            }
        }
    }

    @Override
    public void onActivityResumed(Activity activity) {
        startNearby();
    }

    @Override
    public void onActivityCreated(Activity activity, Bundle bundle) {}

    @Override
    public void onActivityDestroyed(Activity activity) {}

    @Override
    public void onActivitySaveInstanceState(Activity activity, Bundle bundle) {}

    @Override
    public void onActivityStarted(Activity activity) {
    }

    @Override
    public void onActivityStopped(Activity activity) {}

    @Override
    public void onActivityPaused(Activity activity) {}

    static native void setCacheDir(String cacheDir);
    static native void addEndpoint(byte[] endpoint);
    static native void removeEndpoint(byte[] endpoint);
    static native void packetReceived(byte[] packet, byte[] endpoint);
    static native void newnodeInit(NewNode newNode);
    static native void newnodeRun();
    static native void registerProxy();
    static native void unregisterProxy();
    static native void updateBugsnagDetails(int notifyType);
    public native void callback(long callblock, int value);
    public native void setLogLevel(int level);
    public native void storeDnsPrefetchResult(int result_index, int result_id, String host, String[] addresses);
}
