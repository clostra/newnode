package com.clostra.newnode.internal;

import android.app.Application;
import android.content.res.AssetManager;
import android.os.Build;
import android.os.FileUtils;
import android.util.Log;

import dalvik.system.PathClassLoader;

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
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.Observable;
import java.util.Observer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;



public class NewNode implements NewNodeInternal, Runnable {
    public static String VERSION = BuildConfig.VERSION_NAME;

    static Thread t;
    static Thread updateThread;
    static NearbyHelper nearbyHelper;

    static {
        Application app = app();

        File[] files = app.getFilesDir().listFiles();
        Arrays.sort(files);
        for (int i = files.length - 1; i >= 0; i--) {
            File f = files[i];
            try {
                String v2 = Pattern.compile("^libnewnode.v?([\\.0-9]*).so$").matcher(f.getName()).group(1);
                if (VERSION.compareTo(v2) < 0) {
                    System.load(f.getAbsolutePath());
                    VERSION = v2;
                    break;
                }
            } catch (Exception e) {
                Log.e("newnode", "", e);
            }
        }
        // XXX: might not work in a classes.dex
        if (VERSION.equals(BuildConfig.VERSION_NAME)) {
            try {
                System.loadLibrary("newnode");
            } catch (UnsatisfiedLinkError e) {
                Log.e("newnode", "", e);
            }
        }
        updateThread = new Thread() { public void run() {
            while (!Thread.interrupted()) {
                try {
                    update();
                } catch(Exception e) {
                    Log.e("newnode", "", e);
                }
                try {
                    sleep((long) (1 + Math.random() * (24 * 60 * 60 * 1000)));
                } catch(InterruptedException e) {
                }
            }
        }};
        updateThread.start();
    }

    static Application app() {
        try {
            return (Application) Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null, (Object[]) null);
        } catch (Exception e) {
        }
        return null;
    }

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
            Log.e("newnode", "Updated to " + output + ", will take effect on restart");
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
                if (name.equals("classes.dex")) {
                    saveLocally(asset, "newnode." + version + ".dex");
                    break;
                }
            } catch (Exception e) {
                Log.e("newnode", "", e);
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
                    Log.e("newnode", "", e);
                }
            }
        }
    }

    public void run() {
        newnodeRun();
    }

    public void init() {
        if (t == null) {
            setCacheDir(app().getCacheDir().getAbsolutePath());
            newnodeInit(this);
            t = new Thread(this, "newnode");
            t.start();
            Log.e("newnode", "version " + VERSION + " started");
            nearbyHelper = new NearbyHelper(app());
        }

        registerProxy();
    }

    public void shutdown() {
        unregisterProxy();
    }

    void sendPacket(byte[] packet, String endpoint) {
        if (nearbyHelper != null) {
            nearbyHelper.sendPacket(packet, endpoint);
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

    static native void setCacheDir(String cacheDir);
    static native void addEndpoint(String endpoint);
    static native void packetReceived(byte[] packet, String endpoint);
    static native void newnodeInit(NewNode newNode);
    static native void newnodeRun();
    static native void registerProxy();
    static native void unregisterProxy();
    static native void updateBugsnagDetails(int notifyType);
    public native void setLogLevel(int level);
}
