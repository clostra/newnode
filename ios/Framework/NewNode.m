#include "newnode.h"
#include "NewNode-iOS.h"

@implementation NewNode

+ (void)initialize
{
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
