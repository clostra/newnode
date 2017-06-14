package com.clostra.dcdn;

public class Dcdn {
    static {
        System.loadLibrary("dcdn");
        System.setProperty("http.proxyHost", "127.0.0.1");
        System.setProperty("https.proxyHost", "127.0.0.1");
        System.setProperty("http.proxyPort", "8006");
        System.setProperty("https.proxyPort", "8006");
    }
    public static void init() {
    }
}
