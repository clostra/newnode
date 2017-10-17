package com.clostra.dcdn;

public class Dcdn {
    static {
        System.loadLibrary("dcdn");
    }

    public static void init() {
        System.setProperty("http.proxyHost", "127.0.0.1");
        System.setProperty("https.proxyHost", "127.0.0.1");
        System.setProperty("http.proxyPort", "8006");
        System.setProperty("https.proxyPort", "8006");
    }

    public static void shutdown() {
        System.clearProperty("http.proxyHost");
        System.clearProperty("https.proxyHost");
        System.clearProperty("http.proxyPort");
        System.clearProperty("https.proxyPort");
    }
}
