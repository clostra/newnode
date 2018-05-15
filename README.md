# NewNode

## Integration status

[![Stories in Ready](https://badge.waffle.io/clostra/newnode.svg?label=ready&title=Ready)](http://waffle.io/clostra/newnode)
[![Codacy Badge](https://api.codacy.com/project/badge/Grade/fbeb689ec190470a90645fb016cbcfb7)](https://www.codacy.com/app/shalunov/newnode)
[ ![Download](https://api.bintray.com/packages/clostra/NewNode/newnode/images/download.svg) ](https://bintray.com/clostra/NewNode/newnode/_latestVersion)

## Android

Add to your build.gradle:
```groovy
implementation 'com.clostra.newnode:newnode:+'
```

Add to your Application or Activity:

```java
import com.clostra.newnode.NewNode;

@Override
protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    NewNode.init();
    ...
}
```

See [`android/examples/WebViewSample`](https://github.com/clostra/newnode/tree/master/android/examples/WebViewSample) for an example.

## iOS

Add to your Podfile:
```cocoapods
pod 'NewNode'
```

Add to your `NSURLSession`:

```objc
NSURLSessionConfiguration *config = NSURLSessionConfiguration.defaultSessionConfiguration;
config.connectionProxyDictionary = NewNode.connectionProxyDictionary;
NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
```

See [`ios/examples/CustomHTTPProtocol`](https://github.com/clostra/newnode/tree/master/ios/examples/CustomHTTPProtocol) for an example.

## macOS / Linux
```bash
./build.sh
```
`client` (and `injector`) are the resulting binaries.

