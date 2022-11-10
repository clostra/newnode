#include "newnode.h"
#include "constants.h"
#include "log.h"
#import "NetService.h"
#import "Bluetooth.h"
#import "HTTPSRequest.h"
#import "NewNode-iOS.h"
#define BSG_KSLogger_Level TRACE
#define BSG_LOG_LEVEL BSG_LOGLEVEL_DEBUG
#import <BugsnagStatic/Bugsnag.h>


NetService *ns;
Bluetooth *bt;
network *g_n;
bool request_bluetooth_permission = true;
bool request_discovery_permission = true;

@implementation NewNode

+ (void)initialize
{
    BugsnagConfiguration *config = [BugsnagConfiguration.alloc initWithApiKey:@"f5ce7103ec0ed93bee065269e8c2b676"];
    config.appVersion = @(VERSION);
    /*
    NSURLSessionConfiguration *urlConfig = NSURLSessionConfiguration.defaultSessionConfiguration;
    urlConfig.connectionProxyDictionary = NewNode.connectionProxyDictionary;
    config.session = [NSURLSession sessionWithConfiguration:urlConfig];
    */
    [Bugsnag startWithConfiguration:config];

    NSString *cachesPath = NSSearchPathForDirectoriesInDomains(NSCachesDirectory, NSUserDomainMask, YES).lastObject;
    chdir(cachesPath.UTF8String);

    NSString *appName = NSBundle.mainBundle.infoDictionary[@"CFBundleDisplayName"];
    if (!appName) {
        appName = NSBundle.mainBundle.infoDictionary[@"CFBundleName"];
    }
    NSString *appId = NSBundle.mainBundle.infoDictionary[@"CFBundleIdentifier"];

    port_t port = 0;
    g_n = newnode_init(appName.UTF8String, appId.UTF8String, &port, ^(const https_request *request, const char *url, const https_complete_callback cb) {
        network *n = g_n;
        return do_https(n, request, url, cb);
    });
    if (!g_n) {
        NSLog(@"Error: NewNode could not be initialized");
        return;
    }
    NewNodeExperimental.requestBluetoothPermission = request_bluetooth_permission;
    NewNodeExperimental.requestDiscoveryPermission = request_discovery_permission;
    newnode_thread(g_n);
}

+ (NSDictionary*)connectionProxyDictionary
{
    port_t port = newnode_get_port(g_n);
    if (!port) {
        return @{};
    }
    return @{
        @"HTTPEnable": @1,
        @"HTTPProxy": @"127.0.0.1",
        @"HTTPPort": @(port),
        @"HTTPSEnable": @1,
        @"HTTPSProxy": @"127.0.0.1",
        @"HTTPSPort": @(port),
        @"SOCKSEnable": @1,
        @"SOCKSProxy": @"127.0.0.1",
        @"SOCKSPort": @(port)
    };
}

+ (int)logLevel
{
    return o_debug;
}

+ (void)setLogLevel:(int)level
{
    network_set_log_level(level);
}

@end


@implementation NewNodeExperimental

+ (void)setRequestBluetoothPermission:(bool)enabled
{
    request_bluetooth_permission = enabled;
    if (!bt && request_bluetooth_permission) {
        bt = [Bluetooth.alloc initWithNetwork:g_n];
    }
}

+ (void)setRequestDiscoveryPermission:(bool)enabled
{
    request_discovery_permission = enabled;
    if (g_n) {
        g_n->request_discovery_permission = request_discovery_permission;
    }
    if (!ns && request_discovery_permission) {
        ns = [NetService.alloc initWithNetwork:g_n];
    }
}

@end


void ui_display_stats(const char *type, uint64_t direct, uint64_t peers)
{
    @autoreleasepool {
        [NSNotificationCenter.defaultCenter
            postNotificationName:@"DisplayStats"
                          object:nil
                        userInfo:@{@"scope": @(type), @"direct_bytes": @(direct), @"peers_bytes": @(peers)}];
    }
}

bool network_process_udp_cb(const uint8_t *buf, size_t len, const sockaddr *sa, socklen_t salen) { return false; }
