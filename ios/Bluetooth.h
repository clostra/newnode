@import Foundation;
#include "network.h"


@interface Bluetooth : NSObject

- (instancetype)initWithNetwork:(network*)n;
- (void)initPeerDiscovery;
- (void)restartPeerDiscovery;
- (void)stop;

@end
