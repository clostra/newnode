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
import java.io.OutputStream;
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
    static final String TAG = NewNode.class.getSimpleName();
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

    void dnsPrefetch(final String hostname, final int result_index, final long result_id) {
        try {
            new Thread() { public void run() {
                try {
                    Log.i(TAG, String.format("dnsPrefetch(hostname:%s, result_index:%d, result_id:%d)",
                                                   hostname, result_index, result_id));
                    InetAddress[] addrs = InetAddress.getAllByName(hostname);
                    String[] addresses = new String[addrs.length];
                    for (int i = 0; i < addrs.length; ++i) {
                        addresses[i] = addrs[i].getHostAddress();
                    }
                    storeDnsPrefetchResult(result_index, result_id, hostname, addresses);
                } catch (java.net.UnknownHostException e) {
                    Log.i (TAG, String.format("dnsPrefetch: unknown host %s", hostname), e);
                } catch (Exception e) {
                    Log.i (TAG, "dnsPrefetch inner thread", e);
                }
            }}.start();
        } catch (Exception e) {
            Log.i (TAG, "dnsPrefetch", e);
        }
    }

    // the following are defined in g_https_cb.h
    static final int HTTPS_NO_ERROR = 0;
    static final int HTTPS_DNS_ERROR = 2;
    static final int HTTPS_HTTP_ERROR = 3;
    static final int HTTPS_TLS_ERROR = 4;
    static final int HTTPS_TLS_CERT_ERROR = 5;
    static final int HTTPS_SOCKET_IO_ERROR = 6;
    static final int HTTPS_TIMEOUT_ERROR = 7;
    static final int HTTPS_PARAMETER_ERROR = 8;
    static final int HTTPS_SYSCALL_ERROR = 9;
    static final int HTTPS_GENERIC_ERROR = 10;
    static final int HTTPS_BLOCKING_ERROR = 11;
    static final int HTTPS_RESOURCE_EXHAUSTED = 12;

    static final int HTTPS_METHOD_MASK = 07;
    static final int HTTPS_METHOD_GET = 00;
    static final int HTTPS_METHOD_PUT = 01;
    static final int HTTPS_METHOD_HEAD = 02;
    static final int HTTPS_METHOD_POST = 03;
    static final int HTTPS_DIRECT = 010;
    static final int HTTPS_ONE_BYTE = 020;
    static final int HTTPS_NO_REDIRECT = 040;
    static final int HTTPS_NO_RETRIES = 0100;
    
    static final int HTTPS_RESULT_TRUNCATED = 01;
    static final int HTTPS_REQUEST_USE_HEAD = 02;
    static final int HTTPS_REQUEST_ONE_BYTE = 04;

    class CallblockThread extends Thread {
        volatile long callblock = 0;
    };

    CallblockThread http(final String url, final long callblock, final int request_flags, final int timeout_msec, final int bufsize, final int http_port, final String request_header_names[], final String request_header_values[], final byte request_body[]) {
        Log.i("newnode",
              String.format("http(url:%s, flags:0x%x, timeout_msec:%d, bufsize:%d, http_port:%d)",
                            url, request_flags, timeout_msec, bufsize, http_port));
        CallblockThread thread = null;
        try {
            thread = new CallblockThread(){public void run() {
                byte response_body[] = new byte[0];
                int https_error = HTTPS_NO_ERROR;
                int result_flags = 0;
                int response_length = 0;
                long start_time_msec = System.currentTimeMillis();
                int http_response_code = 0;
                InputStream inputStream = null;

                try {
                    URL jUrl = new URL(url);

                    long timeout_time_msec = start_time_msec + 15 * 60 * 1000; // 15 minutes
                    if (timeout_msec > 0) {
                        timeout_time_msec = start_time_msec + timeout_msec;
                    }

                    // HTTPS_DIRECT (connect directly to origin server)
                    HttpURLConnection connection;
                    if ((request_flags & HTTPS_DIRECT) != 0) {
                        Log.i(TAG, String.format("direct connection %s", this));
                        connection = (HttpURLConnection)jUrl.openConnection(Proxy.NO_PROXY);
                    } else {
                        Log.i(TAG, String.format("connection via proxy %s", this));

                        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", http_port));
                        connection = (HttpURLConnection)jUrl.openConnection(proxy);
                    }

                    int https_method = request_flags & HTTPS_METHOD_MASK;
                    boolean need_request_body = false;
                    if (https_method == HTTPS_METHOD_GET) {
                        connection.setRequestMethod("GET");
                    } else if (https_method == HTTPS_METHOD_PUT) {
                        connection.setRequestMethod("PUT");
                        need_request_body = true;
                    } else if (https_method == HTTPS_METHOD_HEAD) {
                        connection.setRequestMethod("HEAD");
                        result_flags = result_flags | HTTPS_REQUEST_USE_HEAD;
                    } else if (https_method == HTTPS_METHOD_POST) {
                        connection.setRequestMethod("POST");
                        need_request_body = true;
                    }

                    // option procesing:

                    // HTTPS_ONE_BYTE (explicitly request a one-byte response)
                    if ((request_flags & HTTPS_ONE_BYTE) != 0) {
                        connection.setRequestProperty("Range", "bytes=0,1");
                        result_flags = result_flags | HTTPS_REQUEST_ONE_BYTE;
                    }

                    // HTTPS_NO_REDIRECT
                    if ((request_flags & HTTPS_NO_REDIRECT) != 0) {
                        connection.setFollowRedirects(false);
                    } else {
                        connection.setFollowRedirects(true);
                    }
                    // XXX HTTPS_NO_RETRIES not implemented

                    // https_request->timeout_sec is really supposed
                    // to set the maximum total amount of time we'll
                    // wait before the entire response body is
                    // returned, which is not the same as either
                    // setConnectTimeout or setReadTimeout.  But it
                    // still seems useful to set these as a cheap way
                    // of interrupting the transfer in case either of
                    // these conditions is exceeded.
                    if (timeout_msec > 0) {
                        connection.setConnectTimeout(timeout_msec);
                        connection.setReadTimeout(timeout_msec);
                    } else {
                        connection.setConnectTimeout(15 * 60 * 1000);
                        connection.setReadTimeout(15 * 60 * 1000);
                    }

                    // request headers
                    boolean accept_seen = false;
                    boolean content_type_seen = false;
                    for (int i = 0; i < request_header_names.length; ++i) {
                        if ((request_flags & HTTPS_ONE_BYTE) != 0 &&
                            request_header_names[i].toLowerCase().equals("range")) {
                            continue;
                        }
                        if (request_header_names[i].toLowerCase().equals("content-length")) {
                            continue;
                        }
                        if (content_type_seen && request_header_names[i].toLowerCase().equals("content-type")) {
                            continue;
                        }
                        if (request_header_names[i].toLowerCase().equals("accept")) {
                            accept_seen = true;
                        }
                        Log.i(TAG, String.format("calling setRequestProperty(%s, %s)",
                                                 request_header_names[i], request_header_values[i]));
                        connection.setRequestProperty(request_header_names[i],
                                                      request_header_values[i]);
                        if (request_header_names[i].toLowerCase().equals("content-type")) {
                            content_type_seen = true;
                        }
                    }
                    // convince ipinfo.io to not return html.
                    // 
                    // XXX The accept header should be explicitly set
                    //     in calls to https://ipinfo.io .
                    if (accept_seen == false && (url.equals("https://ipinfo.io") || url.equals("https://ipinfo.io/"))) {
                        connection.setRequestProperty("accept", "application/json");
                    }

                    connection.setAllowUserInteraction(false);
                    if (need_request_body) {
                        connection.setRequestProperty("Content-Length", String.format("%d", request_body.length));
                        connection.setDoOutput(true);
                    }
                    connection.setUseCaches(false);
                    connection.connect();
                    // the http response code is available almost as soon as the connection
                    // is established, but the response body won't be available that soon.
                    // so if a response body was requested, don't call the callback until we have
                    // it, or we have an error.
                    if (need_request_body) {
                        OutputStream outputStream = connection.getOutputStream();
                        outputStream.write(request_body);
                    }
                    // call getResponseCode BEFORE getInputStream
                    http_response_code = connection.getResponseCode();
                    // XXX: if ONE_BYTE, we can stop now
                    if (bufsize > 0 && http_response_code == connection.HTTP_OK) {
                        response_body = new byte[bufsize];
                        inputStream = connection.getInputStream();
                        while (!Thread.interrupted()) {
                            long now_msec = System.currentTimeMillis();
                            if (now_msec > timeout_time_msec) {
                                Log.i(TAG, String.format("t:%s HTTPS_TIMEOUT_ERROR (closing inputStream) %s", t, this));
                                https_error = HTTPS_TIMEOUT_ERROR;
                                break;
                            }
                            int room_left = bufsize - response_length;
                            if (room_left <= 0) {
                                // try to read one more byte to see if response is too big
                                // (so caller will know if response is incomplete)
                                if (inputStream.read() == -1) {
                                    result_flags |= HTTPS_RESULT_TRUNCATED;
                                }
                                Log.i(TAG, String.format("result larger than bufsize %s", this));
                                break;
                            }
                            int nread = inputStream.read(response_body, response_length, room_left);
                            if (nread == -1) {
                                break;
                            }
                            response_length += nread;
                        }
                        inputStream.close();
                    }
                } catch (java.net.SocketException e) {
                    Log.e(TAG, String.format("HTTPS_SOCKET_IO_ERROR %s", this), e);
                    https_error = HTTPS_SOCKET_IO_ERROR;
                    return;
                } catch (java.net.UnknownHostException e) {
                    Log.e(TAG, String.format("HTTPS_DNS_ERROR (%s) %s", e.toString(), this), e);
                    https_error = HTTPS_DNS_ERROR;
                    return;
                } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
                    Log.e(TAG, String.format("HTTPS_TLS_CERT_ERROR %s", this), e);
                    https_error = HTTPS_TLS_CERT_ERROR;
                    return;
                } catch (javax.net.ssl.SSLException e) {
                    Log.e(TAG, String.format("HTTPS_TLS_ERROR %s", this), e);
                    https_error = HTTPS_TLS_ERROR;
                    return;
                } catch (java.net.SocketTimeoutException e) {
                    long now_msec = System.currentTimeMillis();
                    Log.e(TAG, 
                          String.format("HTTPS_TIMEOUT_ERROR elapsed:%d ms", 
                                        now_msec - start_time_msec), e);
                    https_error = HTTPS_TIMEOUT_ERROR;
                    return;
                } catch (Exception e) {
                    if (http_response_code == 451 || http_response_code == 403) {
                        Log.e(TAG, String.format("HTTPS_BLOCKING_ERROR %s", this), e);
                        https_error = HTTPS_BLOCKING_ERROR;
                    } else {
                        Log.e(TAG, String.format("HTTPS_GENERIC_ERROR %s", this), e);
                        https_error = HTTPS_GENERIC_ERROR;
                    }
                } finally {
                    try {
                        if (inputStream != null) {
                            inputStream.close();
                        }
                    } catch (java.io.IOException e) {
                    }
                    response_body = Arrays.copyOf(response_body, response_length);
                    httpCallback(this.callblock, https_error, http_response_code, result_flags, response_body);
                }
            }};
            thread.callblock = callblock;
            thread.start();
        } catch (Exception e) {
            Log.e(TAG, "exception starting https thread", e);
            return null;
        }
        return thread;
    }

    static void httpCancel(CallblockThread t) {
        t.callblock = 0;
        t.interrupt();
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
    public void onActivityStarted(Activity activity) {}

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
    static native void httpCallback(long callblock, int https_error, int http_status_code, int result_flags, byte response_body[]);
    static native void storeDnsPrefetchResult(int result_index, long result_id, String host, String[] addresses);

    public native void setLogLevel(int level);
}
