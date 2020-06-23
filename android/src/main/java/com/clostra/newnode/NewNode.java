package com.clostra.newnode;

import android.app.Application;
import android.os.Build;
import android.util.Log;

import dalvik.system.PathClassLoader;

import com.bugsnag.android.NotifyType;

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
import java.util.Observable;
import java.util.Observer;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;


public class NewNode {
    public static String VERSION = BuildConfig.VERSION_NAME;

    public interface NewNodeInternal {
        void init();
        void shutdown();
        void setLogLevel(int level);
        void setRequestDiscoveryPermission(boolean enabled);
    }
    static NewNodeInternal newNode;

    static {
        Application app = app();

        File[] files = app.getFilesDir().listFiles();
        Arrays.sort(files);
        for (int i = files.length - 1; i >= 0; i--) {
            File f = files[i];
            try {
                Matcher m = Pattern.compile("^newnode.v?([\\.0-9]*).dex$").matcher(f.getName());
                if (!m.find()) {
                    continue;
                }
                String v2 = m.group(1);
                if (VERSION.compareTo(v2) < 0) {
                    Log.d("newnode", "Loading " + f.getAbsolutePath());
                    PathClassLoader classLoader = new PathClassLoader(f.getAbsolutePath(), NewNode.class.getClassLoader().getParent());
                    newNode = (NewNodeInternal)classLoader.loadClass("com.clostra.newnode.internal.NewNode").newInstance();
                    VERSION = v2;
                    break;
                }
            } catch (Exception e) {
                Log.e("newnode", "", e);
            }
        }
        if (newNode == null) {
            try {
                Log.d("newnode", "Loading built-in NewNodeInternal");
                newNode = (NewNodeInternal)NewNode.class.getClassLoader().loadClass("com.clostra.newnode.internal.NewNode").newInstance();
            } catch (Exception e) {
                Log.e("newnode", "", e);
            }
        }
    }

    static Application app() {
        try {
            return (Application) Class.forName("android.app.ActivityThread")
                    .getMethod("currentApplication").invoke(null, (Object[]) null);
        } catch (Exception e) {
        }
        return null;
    }

    public static void setRequestDiscoveryPermission(boolean enabled) {
        newNode.setRequestDiscoveryPermission(enabled);
    }

    public static void init() {
        newNode.init();
    }

    public static void shutdown() {
        newNode.shutdown();
    }

    public static void setLogLevel(int level) {
        newNode.setLogLevel(level);
    }
}
