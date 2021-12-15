#import "NetService.h"
#include "network.h"
#include "lsd.h"

@import UIKit;

#define ServiceType @"_newnode._udp."

@interface NetService () <NSNetServiceDelegate, NSNetServiceBrowserDelegate>

@property (nonatomic) NSNetService *service;
@property (nonatomic) NSNetServiceBrowser *browser;
@property (nonatomic) NSMutableSet<NSNetService*> *discovering;
@property (nonatomic) network *n;

@end

@implementation NetService

- (instancetype)initWithNetwork:(network*)n
{
    self = super.init;
    if (self != nil) {
        UIDevice.currentDevice.batteryMonitoringEnabled = true;
        [NSNotificationCenter.defaultCenter addObserver:self
                                               selector:@selector(batteryLevelChanged)
                                                   name:UIDeviceBatteryLevelDidChangeNotification
                                                 object:self];
        _n = n;
        _discovering = NSMutableSet.new;
        // XXX: NSNetService is deprecated. Switch to NWParameters.includePeerToPeer = true
        // https://github.com/clostra/newnode_private/issues/30
        _service = [NSNetService.alloc initWithDomain:@"local" type:ServiceType name:NSProcessInfo.processInfo.globallyUniqueString port:_n->port];
        _service.includesPeerToPeer = YES;
        _service.delegate = self;

        _browser = NSNetServiceBrowser.new;
        _browser.includesPeerToPeer = YES;
        _browser.delegate = self;

        if (![self batteryLow]) {
            [_service publishWithOptions:0];
            [_browser searchForServicesOfType:ServiceType inDomain:@"local"];
        }
    }
    return self;
}

- (void)dealloc
{
    // XXX: work around a 10.12 bug where delegates aren't actually weak references http://www.openradar.me/28943305
    _service.delegate = nil;
    _browser.delegate = nil;
}

- (bool)batteryLow
{
    return UIDevice.currentDevice.batteryLevel < 0.15;
}

- (void)batteryLevelChanged
{
    if ([self batteryLow]) {
        [_service stop];
        [_browser stop];
    } else {
        [_service publishWithOptions:0];
        [_browser searchForServicesOfType:ServiceType inDomain:@"local"];
    }
}

- (void)gotAddresses:(NSNetService *)service
{
    NSLog(@"gotAddresses:%@ %@:%ld %@", service, service.hostName, (long)service.port, service.addresses);
    network *n = _n;
    network_async(n, ^{
        for (NSData *addr in service.addresses) {
            add_sockaddr(n, (const sockaddr *)addr.bytes, (socklen_t)addr.length);
        }
    });
}

#pragma mark - NSNetServiceDelegate

/* Sent to the NSNetService instance's delegate prior to advertising the service on the network. If for some reason the service cannot be published, the delegate will not receive this message, and an error will be delivered to the delegate via the delegate's -netService:didNotPublish: method.
 */
- (void)netServiceWillPublish:(NSNetService *)sender
{
    NSLog(@"netServiceWillPublish:%@", sender);
}

/* Sent to the NSNetService instance's delegate when the publication of the instance is complete and successful.
 */
- (void)netServiceDidPublish:(NSNetService *)sender
{
    NSLog(@"netServiceDidPublish:%@", sender);
}

/* Sent to the NSNetService instance's delegate when an error in publishing the instance occurs. The error dictionary will contain two key/value pairs representing the error domain and code (see the NSNetServicesError enumeration above for error code constants). It is possible for an error to occur after a successful publication.
 */
- (void)netService:(NSNetService *)sender didNotPublish:(NSDictionary<NSString *, NSNumber *> *)errorDict
{
    NSLog(@"netService:%@ didNotPublish:%@", sender, errorDict);
}

/* Sent to the NSNetService instance's delegate prior to resolving a service on the network. If for some reason the resolution cannot occur, the delegate will not receive this message, and an error will be delivered to the delegate via the delegate's -netService:didNotResolve: method.
 */
- (void)netServiceWillResolve:(NSNetService *)sender
{;
    NSLog(@"netServiceWillResolve:%@", sender);
}

/* Sent to the NSNetService instance's delegate when one or more addresses have been resolved for an NSNetService instance. Some NSNetService methods will return different results before and after a successful resolution. An NSNetService instance may get resolved more than once; truly robust clients may wish to resolve again after an error, or to resolve more than once.
 */
- (void)netServiceDidResolveAddress:(NSNetService *)sender
{
    NSLog(@"netServiceDidResolveAddress:%@", sender);
    [self gotAddresses:sender];
    [_discovering removeObject:sender];
}

/* Sent to the NSNetService instance's delegate when an error in resolving the instance occurs. The error dictionary will contain two key/value pairs representing the error domain and code (see the NSNetServicesError enumeration above for error code constants).
 */
- (void)netService:(NSNetService *)sender didNotResolve:(NSDictionary<NSString *, NSNumber *> *)errorDict
{
    NSLog(@"netService:%@ didNotResolve:%@", sender, errorDict);
    [_discovering removeObject:sender];
}

/* Sent to the NSNetService instance's delegate when the instance's previously running publication or resolution request has stopped.
 */
- (void)netServiceDidStop:(NSNetService *)sender
{
    NSLog(@"netServiceDidStop:%@", sender);
}

/* Sent to the NSNetService instance's delegate when the instance is being monitored and the instance's TXT record has been updated. The new record is contained in the data parameter.
 */
- (void)netService:(NSNetService *)sender didUpdateTXTRecordData:(NSData *)data
{
    NSLog(@"netService:%@ didUpdateTXTRecordData:%@", sender, data);
}

/* Sent to a published NSNetService instance's delegate when a new connection is
 * received. Before you can communicate with the connecting client, you must -open
 * and schedule the streams. To reject a connection, just -open both streams and
 * then immediately -close them.

 * To enable TLS on the stream, set the various TLS settings using
 * kCFStreamPropertySSLSettings before calling -open. You must also specify
 * kCFBooleanTrue for kCFStreamSSLIsServer in the settings dictionary along with
 * a valid SecIdentityRef as the first entry of kCFStreamSSLCertificates.
 */
- (void)netService:(NSNetService *)sender didAcceptConnectionWithInputStream:(NSInputStream *)inputStream outputStream:(NSOutputStream *)outputStream
{
    NSLog(@"netService:%@ didAcceptConnectionWithInputStream:%@ outputStream:%@", sender, inputStream, outputStream);
}

#pragma mark - NSNetServiceBrowserDelegate

/* Sent to the NSNetServiceBrowser instance's delegate before the instance begins a search. The delegate will not receive this message if the instance is unable to begin a search. Instead, the delegate will receive the -netServiceBrowser:didNotSearch: message.
 */
- (void)netServiceBrowserWillSearch:(NSNetServiceBrowser *)browser
{
    NSLog(@"netServiceBrowserWillSearch:%@", browser);
}

/* Sent to the NSNetServiceBrowser instance's delegate when the instance's previous running search request has stopped.
 */
- (void)netServiceBrowserDidStopSearch:(NSNetServiceBrowser *)browser
{
    NSLog(@"netServiceBrowserDidStopSearch:%@", browser);
}

/* Sent to the NSNetServiceBrowser instance's delegate when an error in searching for domains or services has occurred. The error dictionary will contain two key/value pairs representing the error domain and code (see the NSNetServicesError enumeration above for error code constants). It is possible for an error to occur after a search has been started successfully.
 */
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didNotSearch:(NSDictionary<NSString *, NSNumber *> *)errorDict
{
    NSLog(@"netServiceBrowser:%@ didNotSearch:%@", browser, errorDict);
}

/* Sent to the NSNetServiceBrowser instance's delegate for each domain discovered. If there are more domains, moreComing will be YES. If for some reason handling discovered domains requires significant processing, accumulating domains until moreComing is NO and then doing the processing in bulk fashion may be desirable.
 */
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didFindDomain:(NSString *)domainString moreComing:(BOOL)moreComing
{
    NSLog(@"netServiceBrowser:%@ didFindDomain:%@ moreComing:%d", browser, domainString, moreComing);
}

/* Sent to the NSNetServiceBrowser instance's delegate for each service discovered. If there are more services, moreComing will be YES. If for some reason handling discovered services requires significant processing, accumulating services until moreComing is NO and then doing the processing in bulk fashion may be desirable.
 */
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didFindService:(NSNetService *)service moreComing:(BOOL)moreComing
{
    if ([service.name isEqualToString:_service.name]) {
        return;
    }
    NSLog(@"netServiceBrowser:%@ didFindService:%@ moreComing:%d %@:%ld %@", browser, service, moreComing, service.hostName, (long)service.port, service.addresses);
    if (service.addresses.count) {
        [self gotAddresses:service];
        return;
    }
    [_discovering addObject:service];
    service.delegate = self;
    [service resolveWithTimeout:5];
}

/* Sent to the NSNetServiceBrowser instance's delegate when a previously discovered domain is no longer available.
 */
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didRemoveDomain:(NSString *)domainString moreComing:(BOOL)moreComing
{
    NSLog(@"netServiceBrowser:%@ didRemoveDomain:%@ moreComing:%d", browser, domainString, moreComing);
}

/* Sent to the NSNetServiceBrowser instance's delegate when a previously discovered service is no longer published.
 */
- (void)netServiceBrowser:(NSNetServiceBrowser *)browser didRemoveService:(NSNetService *)service moreComing:(BOOL)moreComing
{
    NSLog(@"netServiceBrowser:%@ didRemoveService:%@ moreComing:%d", browser, service, moreComing);
}

@end
