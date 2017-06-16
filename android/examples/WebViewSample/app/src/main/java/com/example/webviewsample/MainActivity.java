package com.example.webviewsample;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.Menu;
import android.view.MenuItem;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import com.clostra.dcdn.Dcdn;

public class MainActivity extends AppCompatActivity {

    private WebView mWebView;

    void load() {
        mWebView.loadUrl("http://clostra.com");
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Dcdn.init();
        setContentView(R.layout.activity_main);
        mWebView = (WebView) findViewById(R.id.activity_main_webview);
        mWebView.setWebViewClient(new WebViewClient());
        WebSettings webSettings = mWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        load();
    }

    @Override
    public void onBackPressed() {
        if(mWebView.canGoBack()) {
            mWebView.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    public boolean onCreateOptionsMenu(Menu menu) {
        menu.add(Menu.NONE, 1, Menu.NONE, "Refresh").setShowAsAction(MenuItem.SHOW_AS_ACTION_ALWAYS);
        return true;
    }

    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case 1:
                load();
                return true;
            default:
                return super.onOptionsItemSelected(item);
        }
    }
}
