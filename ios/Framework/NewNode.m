#include "newnode.h"
#include "constants.h"
#include "log.h"
#define BSG_KSLogger_Level TRACE
#define BSG_LOG_LEVEL BSG_LOGLEVEL_DEBUG
#import "NetService.h"
#import "NewNode-iOS.h"
#import <BugsnagStatic/Bugsnag.h>

port_t http_port;
port_t socks_port;
NetService *ns = nil;

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

    network *n = newnode_init(appName.UTF8String, appId.UTF8String, &http_port, &socks_port, ^(const char *url, https_complete_callback cb) {
        debug("https: %s\n", url);
        [[NSURLSession.sharedSession downloadTaskWithURL:[NSURL URLWithString:@(url)]
                                       completionHandler:^(NSURL *location, NSURLResponse *response, NSError *error) {
            cb(!!error);
        }] resume];
    });
    if (!http_port || !socks_port) {
        NSLog(@"Error: NewNode could not be initialized");
    }
    ns = [NetService.alloc initWithNetwork:n];
    newnode_thread(n);
}

+ (NSDictionary*)connectionProxyDictionary
{
    if (!http_port || !socks_port) {
        return @{};
    }
    return @{
        @"HTTPEnable": @1,
        @"HTTPProxy": @"127.0.0.1",
        @"HTTPPort": @(http_port),
        @"HTTPSEnable": @1,
        @"HTTPSProxy": @"127.0.0.1",
        @"HTTPSPort": @(http_port),
        @"SOCKSEnable": @1,
        @"SOCKSProxy": @"127.0.0.1",
        @"SOCKSPort": @(socks_port)
    };
}

+ (int)logLevel
{
    return o_debug;
}

+ (void)setLogLevel:(int)level
{
    o_debug = level;
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
