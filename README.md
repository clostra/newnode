# NewNode

## Integration status

[![GitHub release](https://img.shields.io/github/release/clostra/newnode.svg)](https://github.com/clostra/newnode/releases/)
[![Carthage compatible](https://img.shields.io/badge/Carthage-compatible-4BC51D.svg?style=flat)](https://github.com/Carthage/Carthage)

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
}
```

See [`android/examples/WebViewSample`](https://github.com/clostra/newnode/tree/master/android/examples/WebViewSample) for an example.

## iOS

Add this repo as a Swift Package.

ObjC:
```objc
NSURLSessionConfiguration *config = NSURLSessionConfiguration.defaultSessionConfiguration;
config.connectionProxyDictionary = NewNode.connectionProxyDictionary;
NSURLSession *session = [NSURLSession sessionWithConfiguration:config];
```

Swift:
```swift
let config = URLSessionConfiguration.default
config.connectionProxyDictionary = NewNode.connectionProxyDictionary
let session = URLSession(configuration: config)
```

See [`ios/examples/CustomHTTPProtocol`](https://github.com/clostra/newnode/tree/master/ios/examples/CustomHTTPProtocol) for an example.

## macOS / Linux

Clone this repo and build NewNode:
```bash
git clone --recurse-submodules https://github.com/clostra/newnode.git
cd newnode
./build.sh
```

Then, run it:
```bash
./client
```
