#include "newnode.h"
#include "constants.h"
#define BSG_KSLogger_Level TRACE
#define BSG_LOG_LEVEL BSG_LOGLEVEL_DEBUG
#include "NewNode-iOS.h"
#import <BugsnagStatic/Bugsnag.h>

@implementation NewNode

+ (void)initialize
{
    BugsnagConfiguration *config = BugsnagConfiguration.new;
    config.apiKey = @"f5ce7103ec0ed93bee065269e8c2b676";
    config.shouldAutoCaptureSessions = YES;
    config.appVersion = @(VERSION);
    /*
    NSURLSessionConfiguration *urlConfig = NSURLSessionConfiguration.defaultSessionConfiguration;
    urlConfig.connectionProxyDictionary = NewNode.connectionProxyDictionary;
    config.session = [NSURLSession sessionWithConfiguration:urlConfig];
    */
    [Bugsnag startBugsnagWithConfiguration:config];
    newnode_init();
}

+ (NSDictionary*)connectionProxyDictionary
{
    return @{
        @"HTTPEnable": @1,
        @"HTTPProxy": @"127.0.0.1",
        @"HTTPPort": @8006,
        @"HTTPSEnable": @1,
        @"HTTPSProxy": @"127.0.0.1",
        @"HTTPSPort": @8006
    };
}

@end
