package com.clostra.newnode;

import android.app.Application;
import android.os.Build;
import android.util.Log;

import com.bugsnag.android.Bugsnag;
import com.bugsnag.android.Configuration;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;


public class NewNode {
    static String VERSION = BuildConfig.VERSION_NAME;

    static {
        Application app = app();
        File[] files = app.getFilesDir().listFiles();
        Arrays.sort(files);
        for (int i = files.length - 1; i >= 0; i--) {
            File f = files[i];
            String name = f.getName();
            Pattern p = Pattern.compile("^libnewnode.v?([\\.0-9]*).so$");
            Matcher m = p.matcher(name);
            if (!m.find()) {
                continue;
            }
            String v2 = m.group(1);
            if (VERSION.compareTo(v2) >= 0) {
                break;
            }
            try {
                System.load(f.getAbsolutePath());
                VERSION = v2;
                break;
            } catch (UnsatisfiedLinkError e) {
            }
        }
        if (VERSION.equals(BuildConfig.VERSION_NAME)) {
            try {
                System.loadLibrary("newnode");
            } catch (UnsatisfiedLinkError e) {
                Log.e("newnode", "", e);
            }
        }
    }

    private static Application app() {
        try {
            return (Application) Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null, (Object[]) null);
        } catch (Exception e) {
        }
        return null;
    }

    private static void update() throws Exception {
        Application app = app();
        URL url = new URL("https://api.github.com/repos/clostra/newnode/releases");
        URLConnection urlConnection = url.openConnection();
        InputStream in = urlConnection.getInputStream();
        BufferedReader r = new BufferedReader(new InputStreamReader(in, "UTF-8"));
        String line;
        StringBuilder b = new StringBuilder(in.available());
        while ((line = r.readLine()) != null) {
            b.append(line);
        }
        in.close();
        JSONArray a = new JSONArray(b.toString());
        JSONObject release = a.getJSONObject(0);
        String version = release.getString("name").replaceAll("^v", "");
        if (VERSION.compareTo(version) >= 0) {
            return;
        }
        JSONArray assets = release.getJSONArray("assets");
        String[] abis = {Build.CPU_ABI, Build.CPU_ABI2};
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP) {
            abis = Build.SUPPORTED_ABIS;
        }
        for (String abi : abis) {
            for (int i = 0; i < assets.length(); i++) {
                try {
                    JSONObject asset = assets.getJSONObject(i);
                    String name = asset.getString("name");
                    String releaseAbi = name.split("\\.")[1];
                    if (!releaseAbi.equals(abi)) {
                        continue;
                    }
                    String downloadUrl = asset.getString("browser_download_url");
                    InputStream ins = new URL(downloadUrl).openConnection().getInputStream();
                    GZIPInputStream gis = new GZIPInputStream(ins);
                    File tmp = File.createTempFile("libnewnode", null, app.getFilesDir());
                    FileOutputStream fos = new FileOutputStream(tmp);
                    byte[] buffer = new byte[4096];
                    int len;
                    while ((len = gis.read(buffer)) != -1) {
                        fos.write(buffer, 0, len);
                    }
                    fos.close();
                    gis.close();
                    File updated = new File(app.getFilesDir(), "libnewnode." + version + ".so");
                    if (tmp.renameTo(updated)) {
                        Log.e("newnode", "Updated to " + version + ", will take effect on restart");
                        return;
                    }
                } catch (Exception e) {
                    Log.e("newnode", "", e);
                }
            }
        }
    }

    private static Thread updateThread;
    private static boolean started = false;

    public static void init() {
        if (!started) {

            Configuration config = new Configuration(BuildConfig.BUGSNAG_API_KEY);
            config.setAppVersion(VERSION);
            config.setPersistUserBetweenSessions(true);
            config.setAutoCaptureSessions(true);
            Bugsnag.init(app(), config);

            try {
                setCacheDir(app().getCacheDir().getAbsolutePath());
                Log.e("newnode", "version " + VERSION + " started");
                started = true;
            } catch (UnsatisfiedLinkError e) {
                Log.e("newnode", "", e);
            }
        }

        if (started) {
            System.setProperty("http.proxyHost", "127.0.0.1");
            System.setProperty("https.proxyHost", "127.0.0.1");
            System.setProperty("http.proxyPort", "8006");
            System.setProperty("https.proxyPort", "8006");
        }

        if (updateThread == null) {
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
    }

    public static void shutdown() {
        System.clearProperty("http.proxyHost");
        System.clearProperty("https.proxyHost");
        System.clearProperty("http.proxyPort");
        System.clearProperty("https.proxyPort");

        if (updateThread != null) {
            updateThread.interrupt();
            updateThread = null;
        }
    }

    public static native void setCacheDir(String cacheDir);
}
