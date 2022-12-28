#import <Foundation/Foundation.h>

typedef bool (^d2dReceivedCallback)(const uint8_t *buf, size_t len, const struct sockaddr *sa, socklen_t salen);

@interface NewNode : NSObject

@property (class, readonly) NSDictionary* connectionProxyDictionary;
@property (class) int logLevel;

@end

@interface NewNodeExperimental : NSObject

+ (void)setRequestBluetoothPermission:(bool)enabled;
+ (void)setRequestDiscoveryPermission:(bool)enabled;
+ (void)setD2dReceivedCallback:(d2dReceivedCallback)cb;

@end
