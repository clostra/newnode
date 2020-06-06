package io.flutter.plugins.webviewflutterexample;

import android.os.Bundle;
import io.flutter.embedding.android.FlutterActivity;
import com.clostra.newnode.NewNode;

public class MainActivity extends FlutterActivity {
  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    NewNode.init();
  }
}
