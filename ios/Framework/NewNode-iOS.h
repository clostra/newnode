#import <Foundation/Foundation.h>

@interface NewNode : NSObject

@property (class, readonly) NSDictionary* connectionProxyDictionary;
@property (class) int logLevel;

@end

@interface NewNodeExperimental : NSObject

+ (void)setRequestBluetoothPermission:(bool)enabled;
+ (void)setRequestDiscoveryPermission:(bool)enabled;
+ (void)setD2dReceivedCallback:(d2d_received_callback)cb;

@end
