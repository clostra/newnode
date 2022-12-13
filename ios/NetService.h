@import Foundation;

#include "network.h"


@interface NetService : NSObject

- (instancetype)initWithNetwork:(network*)n;
- (void)restart;

@end
