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

    static final int HTTPS_DIRECT = 01;
    static final int HTTPS_USE_HEAD = 020;
    static final int HTTPS_ONE_BYTE = 040;
    static final int HTTPS_NO_REDIRECT = 0100;
    static final int HTTPS_NO_RETRIES = 0200;
    
    static final int HTTPS_RESULT_TRUNCATED = 02;
    static final int HTTPS_REQUEST_USE_HEAD = 04;
    static final int HTTPS_REQUEST_ONE_BYTE = 010;

    void http(final String url, final long callblock, final int request_flags, final int timeout_msec, final int bufsize, final long request_id, final int http_port) {
        Log.i("newnode",
              String.format("http(url:%s, flags:0x%x, timeout_msec:%d, bufsize:%d, request_id:%d, http_port:%d)",
                            url, request_flags, timeout_msec, bufsize, request_id, http_port));
        final byte dummy_response[] = new byte[1];

        try {
            new Thread(){public void run() {
                int response_length = 0;
                int https_error = HTTPS_NO_ERROR;
                int http_response_code = 0;
                int result_flags = 0;
                byte response_body[];
                long timeout_time_msec;
                InputStream inputStream = null;
                HttpURLConnection connection;
                URL jUrl;
                int fakebufsize;

                long start_time_msec = System.currentTimeMillis();

                try {
                    // not sure how useful this is as it rarely seems
                    // to occur, but maybe useful if the CPU gets
                    // swamped.
                    if (isCancelled (request_id) != 0) {
                        Log.i(TAG, String.format("request_id:%s cancelled, callback skipped", request_id));
                        // call native callback function so the link
                        // and blocks callback will be properly freed.
                        // it won't call the completion_callback
                        // because the cancelled flag is set
                        callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                        return;
                    }
                    // CONNECTION SETUP PHASE
                    jUrl = new URL(url);
                    
                    if (timeout_msec >= 0) {
                        timeout_time_msec = start_time_msec + timeout_msec;
                    } else {
                        timeout_time_msec = start_time_msec + 15 * 60 * 1000; // 15 minutes
                    }

                    // not sure whether allocating an array of 0 bytes
                    // is a Bad Idea, but before I made this change
                    // there were indications of huge memory
                    // allocations in logcat output
                    if (bufsize > 0) {
                        fakebufsize = bufsize;
                    } else {
                        fakebufsize = 1;
                    }
                    response_body = new byte[fakebufsize];

                    // HTTPS_DIRECT (connect directly to origin server)
                    if ((request_flags & HTTPS_DIRECT) != 0) {
                        Log.i(TAG, String.format("direct connection request_id:%d", request_id));
                        connection = (HttpURLConnection)jUrl.openConnection(Proxy.NO_PROXY);
                    } else {
                        Log.i(TAG, String.format("connection via proxy request_id:%d", request_id));

                        Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("127.0.0.1", http_port));
                        connection = (HttpURLConnection)jUrl.openConnection(proxy);
                    }

                    // option procesing:
                    //
                    // HTTPS_USE_HEAD (issue HEAD request rather than GET)
                    // (XXX maybe not useful any more but easy to do)
                    if ((request_flags & HTTPS_USE_HEAD) != 0) {
                        connection.setRequestMethod("HEAD");
                    } else {e
                        connection.setRequestMethod("GET");
                    }

                    // HTTPS_ONE_BYTE (explicitly request a one-byte response)
                    if ((request_flags & HTTPS_ONE_BYTE) != 0) {
                        connection.setRequestProperty("Range", "bytes=0,1");
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
                    connection.setConnectTimeout(timeout_msec);
                    connection.setReadTimeout(timeout_msec);

                    connection.setAllowUserInteraction(false);
                    // connection.setDoInput(true);             // should not be needed (this is default)
                    // connection.setDoOutput(false);           // should not be needed (this is default)
                    connection.setUseCaches(false);

                    // XXX HACK
                    // need to convince ipinfo.io that we're not a web browser so it shouldn't
                    // return html. The accept header should probably be a request option.
                    if (url.equals("https://ipinfo.io") || url.equals("https://ipinfo.io/")) {
                        connection.setRequestProperty("accept", "application/json");
                    }

                    // XXX TEMPORARY list request headers
                    // Map<String, List<String>> request_headers = connection.getRequestProperties();
                    // for (Map.Entry<String, List<String>> property: request_headers.entrySet()) {
                    //     Log.i(TAG, 
                    //           String.format("%s:%s", property.getKey(), Arrays.toString(property.getValue().toArray())));
                    // }

                    connection.connect();
                    // the http response code is available almost as soon as the connection
                    // is established, but the response body won't be available that soon.
                    // so if a response body was requested, don't call the callback until we have
                    // it, or we have an error.
                } catch (java.net.SocketException e) {
                    Log.e(TAG, String.format("HTTPS_SOCKET_IO_ERROR request_id:%d", request_id));
                    https_error = HTTPS_SOCKET_IO_ERROR;
                    callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                    return;
                } catch (java.net.UnknownHostException e) {
                    Log.e(TAG, String.format("HTTPS_DNS_ERROR (%s) request_id:%d", e.toString(), request_id));
                    https_error = HTTPS_DNS_ERROR;
                    callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                    return;
                } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
                    Log.e(TAG, String.format("HTTPS_TLS_CERT_ERROR request_id:%d", request_id), e);
                    https_error = HTTPS_TLS_CERT_ERROR;
                    callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                    return;
                } catch (javax.net.ssl.SSLException e) {
                    Log.e(TAG, String.format("HTTPS_TLS_ERROR request_id:%d", request_id));
                    https_error = HTTPS_TLS_ERROR;
                    callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                    return;
                } catch (java.net.SocketTimeoutException e) {
                    long now_msec = System.currentTimeMillis();
                    Log.e(TAG, 
                          String.format("HTTPS_TIMEOUT_ERROR request_id:%d elapsed:%d ms", 
                                        request_id, now_msec - start_time_msec));
                    https_error = HTTPS_TIMEOUT_ERROR;
                    callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                    return;
                } catch (Exception e) {
                    Log.e(TAG, 
                          String.format("HTTPS_GENERIC_ERROR(1) exception:%s request_id:%d",
                    e.toString(), request_id), e);
                    https_error = HTTPS_GENERIC_ERROR;
                    callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                    return;
                }
                // TRANSFER PHASE
                try {
                    // call getResponseCode BEFORE getInputStream
                    http_response_code = connection.getResponseCode();
                    if (bufsize > 0 && http_response_code == connection.HTTP_OK) {
                        inputStream = connection.getInputStream();
                        // XXX force a check of the server certificate 
                        // (is this necessary to detect bogus certs?)
                        // Object principal = connection.getPeerPrincipal();
                        while (true) {
                            long now_msec = System.currentTimeMillis();
                            if (now_msec > timeout_time_msec) {
                                https_error = HTTPS_TIMEOUT_ERROR;
                                inputStream.close();
                                callback(callblock, (long) response_length, https_error, http_response_code,
                                         result_flags, request_id, response_body);
                            }
                            
                            // exit loop if cancelled by NN
                            //
                            // XXX maybe don't check too often because
                            //     of the overhead of doing C language
                            //     calls from java
                            
                            if (isCancelled (request_id) != 0) {
                                Log.i(TAG, String.format("request_id:%s cancelled, callback skipped",
                                   request_id));
                                // call native callback function.   it won't call completion callback because
                                // the cancelled flag is set in links[link_index] corresponding to request_id
                                callback(callblock, 0, https_error, 0, result_flags, request_id, dummy_response);
                                return;
                            }

                            int room_left = bufsize - response_length;
                            if (room_left <= 0) {
                                // try to read one more byte to see if response is too big
                                // (so caller will know if response is incomplete)
                                byte buf[];
                                buf = new byte[1];
                                int nread = inputStream.read(buf, 0, 1);
                                if (nread > 0) {
                                    result_flags |= HTTPS_RESULT_TRUNCATED;
                                }
                                inputStream.close();
                                break;
                            }
                            // Log.i("newnode",
                            //      String.format("request_id:%d inputStream.read(xxx, response_length:%d, room_left:%d",
                            //                    request_id, response_length, room_left));
                            int nread = inputStream.read(response_body, response_length, room_left);
                            // Log.i("newnode",
                            //      String.format("request_id:%d inputStream.read returned %d\n",
                            //                    request_id, nread));
                            // EOF or error
                            if (nread < 0) {
                                break;
                            }
                            response_length += nread;
                        }
                        inputStream.close();
                    }
                } catch (java.net.SocketException e) {
                    Log.e(TAG, String.format("HTTPS_SOCKET_IO_ERROR request_id:%d", request_id));
                    https_error = HTTPS_SOCKET_IO_ERROR;
                } catch (java.net.UnknownHostException e) {
                    Log.e(TAG, String.format("HTTPS_DNS_ERROR (%s) request_id:%d", e.toString(),
                          request_id));
                    https_error = HTTPS_DNS_ERROR;
                } catch (javax.net.ssl.SSLPeerUnverifiedException e) {
                    Log.e(TAG, String.format("HTTPS_TLS_CERT_ERROR request_id:%d", request_id), e);
                    https_error = HTTPS_TLS_CERT_ERROR;
                } catch (javax.net.ssl.SSLException e) {
                    Log.e(TAG, String.format("HTTPS_TLS_ERROR request_id:%d", request_id));
                    https_error = HTTPS_TLS_ERROR;
                } catch (java.net.SocketTimeoutException e) {
                    long now_msec = System.currentTimeMillis();
                    Log.e(TAG, 
                          String.format("HTTPS_TIMEOUT_ERROR request_id:%d elapsed:%d ms", 
                                        request_id, now_msec - start_time_msec));
                    https_error = HTTPS_TIMEOUT_ERROR;
                } catch (Exception e) {
                    Log.e(TAG, String.format("HTTPS_GENERIC_ERROR request_id:%d", request_id), e);
                    https_error = HTTPS_GENERIC_ERROR;
                }
                finally {
                    try {
                        if (inputStream != null) {
                            inputStream.close();
                        }
                    } catch (java.io.IOException e) {
                    }
                    callback(callblock, (long) response_length, https_error, http_response_code,
                             result_flags, request_id, response_body);
                }
            }}.start();
        } catch (Exception e) {
            Log.e(TAG, "exception starting https thread", e);
        }
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
    public native void callback(long callblock, long response_length, int https_error, int http_status_code, int result_flags, long request_id, byte response_body[]);
    public native void setLogLevel(int level);
    public native int isCancelled(long request_id);
    public native void storeDnsPrefetchResult(int result_index, int result_id, String host, String[] addresses);
}
