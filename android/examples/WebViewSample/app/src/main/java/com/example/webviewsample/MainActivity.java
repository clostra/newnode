package com.example.webviewsample;

import android.content.Context;
import android.graphics.Bitmap;
import android.net.Uri;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.view.KeyEvent;
import android.view.Menu;
import android.view.MenuItem;
import android.view.inputmethod.EditorInfo;
import android.view.inputmethod.InputMethodManager;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.TextView;

import com.clostra.dcdn.Dcdn;

public class MainActivity extends AppCompatActivity {

    private EditText mEditText;
    private ProgressBar mProgressBar;
    private WebView mWebView;

    void load() {
        String url = mEditText.getText().toString();
        if (!url.isEmpty()) {
            if (Uri.parse(url).getScheme() == null) {
                url = "http://" + url;
                mEditText.setText(url, TextView.BufferType.EDITABLE);
            }
            mWebView.loadUrl(url);
        }
        InputMethodManager imm = (InputMethodManager) mEditText.getContext().getSystemService(Context.INPUT_METHOD_SERVICE);
        imm.hideSoftInputFromWindow(mEditText.getWindowToken(), 0);
        mWebView.requestFocus();
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        Dcdn.init();
        setContentView(R.layout.activity_main);
        mEditText = (EditText) findViewById(R.id.editText);
        mEditText.setOnEditorActionListener(new TextView.OnEditorActionListener() {
            @Override
            public boolean onEditorAction(TextView v, int actionId, KeyEvent event) {
                if (actionId == EditorInfo.IME_ACTION_GO) {
                    load();
                }
                return false;
            }
        });
        mProgressBar = (ProgressBar) findViewById(R.id.progressBar);
        mWebView = (WebView) findViewById(R.id.webView);
        mWebView.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageStarted(WebView view, String url, Bitmap favicon) {
                super.onPageStarted(view, url, favicon);
                mEditText.setText(url, TextView.BufferType.EDITABLE);
            }
        });
        mWebView.setWebChromeClient(new WebChromeClient() {
            public void onProgressChanged(WebView view, int progress) {
                if (progress < 100 && mProgressBar.getVisibility() == ProgressBar.GONE) {
                    mProgressBar.setVisibility(ProgressBar.VISIBLE);
                }
                mProgressBar.setProgress(progress);
                if (progress == 100) {
                    mProgressBar.setVisibility(ProgressBar.GONE);
                }
            }
        });
        WebSettings webSettings = mWebView.getSettings();
        webSettings.setJavaScriptEnabled(true);
        mEditText.setText("http://newnode.com", TextView.BufferType.EDITABLE);
        load();
    }

    @Override
    public void onBackPressed() {
        if (mWebView.canGoBack()) {
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
