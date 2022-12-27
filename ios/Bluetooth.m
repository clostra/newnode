@import CoreBluetooth;
#import "Bluetooth.h"
#include <netinet/ip.h>
#include "network.h"
#include "d2d.h"


@class Bluetooth;

@interface Peer : NSObject <NSStreamDelegate>
@property (nonatomic) CBPeripheral *peripheral;
@property (nonatomic) CBL2CAPChannel *channel;
@property (nonatomic) NSMutableData *outputBuffer;
@property (nonatomic) NSMutableData *inputBuffer;
@property (nonatomic) bool hasLengthPrefix;
@property (nonatomic) uint16_t lengthPrefix;
@end


@interface Bluetooth () <CBCentralManagerDelegate, CBPeripheralDelegate, CBPeripheralManagerDelegate>

@property (nonatomic) CBUUID *service_uuid;
@property (nonatomic) CBMutableCharacteristic *characteristic;
@property (nonatomic) CBCentralManager *centralManager;
@property (nonatomic) CBPeripheralManager *peripheralManager;
@property (nonatomic) NSMutableDictionary<NSUUID *, Peer *> *peers;
@property (nonatomic) CBL2CAPPSM psm;
@property (nonatomic) network *n;

@end


static Bluetooth *gBluetooth = nil;

@implementation Bluetooth

- (instancetype)initWithNetwork:(network*)n
{
    if (self = [super init]) {
        _service_uuid = [CBUUID UUIDWithString:@"08076b03-983b-4154-93a5-4a6376b87993"];
        _peers = NSMutableDictionary.new;
        _n = n;
        gBluetooth = self;
        [self initPeerDiscovery];
    }
    return self;
}

- (void)initPeerDiscovery
{
    NSMutableDictionary *options = NSMutableDictionary.dictionary;
#if !(TARGET_OS_IPHONE && TUNNEL)
    // doesn't work in an extension on iOS
    //options[CBCentralManagerOptionRestoreIdentifierKey] = @"com.clostra.newnode.central";
#endif
    _centralManager = [CBCentralManager.alloc initWithDelegate:self queue:nil options:options];

    options = NSMutableDictionary.dictionary;
#if !(TARGET_OS_IPHONE && TUNNEL)
    // doesn't work in an extension on iOS
    //options[CBPeripheralManagerOptionRestoreIdentifierKey] = @"com.clostra.newnode.peripheral";
#endif
    _peripheralManager = [CBPeripheralManager.alloc initWithDelegate:self queue:nil options:options];
}

- (void)restartCentral
{
    [_centralManager scanForPeripheralsWithServices:@[_service_uuid]
                                            options:@{CBCentralManagerScanOptionAllowDuplicatesKey:@NO}];
}

- (void)restartPeripheral
{
    if (_psm != 0) {
        // didUnpublishL2CAPChannel will re-publish
        [_peripheralManager unpublishL2CAPChannel:_psm];
    }
}

- (void)restart
{
    [self restartCentral];
    [self restartPeripheral];
}

- (void)stop
{
    [_centralManager stopScan];
    [_peripheralManager stopAdvertising];
}

- (void)newChannel:(CBL2CAPChannel *)channel uuid:(NSUUID*)nsuuid
{
    dispatch_assert_queue(dispatch_get_main_queue());

    Peer *peer = _peers[nsuuid];
    if (peer.channel) {
        NSLog(@"newChannel:%@ uuid:%@ duplicate", channel, nsuuid);
        return;
    }
    NSLog(@"newChannel:%@ uuid:%@", channel, nsuuid);
    _peers[nsuuid].channel = channel;
    const endpoint e = [self UUIDToEndpoint:nsuuid];
    const sockaddr_in6 sin6 = endpoint_to_addr(&e);
    network *n = _n;
    network_async(n, ^{
        if (n->sockaddr_cb) {
            n->sockaddr_cb((const sockaddr *)&sin6, sizeof(sin6));
        }
    });

    channel.inputStream.delegate = peer;
    [channel.inputStream scheduleInRunLoop:NSRunLoop.mainRunLoop forMode:NSDefaultRunLoopMode];
    [channel.inputStream open];

    channel.outputStream.delegate = peer;
    [channel.outputStream scheduleInRunLoop:NSRunLoop.mainRunLoop forMode:NSDefaultRunLoopMode];
    [channel.outputStream open];
}

- (endpoint)UUIDToEndpoint:(NSUUID*)uuid
{
    endpoint e = {0};
    assert(sizeof(uuid_t) <= sizeof(e));
    [uuid getUUIDBytes:(unsigned char*)&e];
    return e;
}

#pragma mark - CBCentralManagerDelegate

- (void)centralManagerDidUpdateState:(CBCentralManager *)central
{
    NSLog(@"centralManagerDidUpdateState:%@ state:%ld", central, (long)self.centralManager.state);

    assert(_centralManager == central);

    if (self.centralManager.state != CBManagerStatePoweredOn) {
        return;
    }

    [self restartCentral];
}

- (void)centralManager:(CBCentralManager *)central willRestoreState:(NSDictionary<NSString *, id> *)dict
{
    NSLog(@"centralManager:%@ willRestoreState:%@", central, dict);
}

- (void)centralManager:(CBCentralManager *)central didDiscoverPeripheral:(CBPeripheral *)peripheral advertisementData:(NSDictionary<NSString *, id> *)advertisementData RSSI:(NSNumber *)RSSI
{
    NSLog(@"centralManager:%@ didDiscoverPeripheral:%@ advertisementData:%@ RSSI:%@", central, peripheral, advertisementData, RSSI);
    if (_peers[peripheral.identifier]) {
        assert(_peers[peripheral.identifier].peripheral == peripheral);
        return;
    }
    peripheral.delegate = self;
    Peer *peer = Peer.new;
    peer.peripheral = peripheral;
    _peers[peripheral.identifier] = peer;

    if (peripheral.state == CBPeripheralStateDisconnected) {
        [_centralManager stopScan];
        [_centralManager connectPeripheral:peripheral options:nil];
    }
}

- (void)centralManager:(CBCentralManager *)central didConnectPeripheral:(CBPeripheral *)peripheral
{
    NSLog(@"centralManager:%@ didConnectPeripheral:%@", central, peripheral);
    assert(_peers[peripheral.identifier].peripheral == peripheral);
    [peripheral discoverServices:@[_service_uuid]];
    [_centralManager stopScan];
}

- (void)centralManager:(CBCentralManager *)central didFailToConnectPeripheral:(CBPeripheral *)peripheral error:(nullable NSError *)error
{
    NSLog(@"centralManager:%@ didFailToConnectPeripheral:%@ error:%@", central, peripheral, error);
    // TODO: remove_sockaddr
    [_peers removeObjectForKey:peripheral.identifier];
    [self restartCentral];
}


- (void)centralManager:(CBCentralManager *)central didDisconnectPeripheral:(CBPeripheral *)peripheral error:(nullable NSError *)error
{
    NSLog(@"centralManager:%@ didDisconnectPeripheral:%@ error:%@", central, peripheral, error);
    // 431: Peer device requested an L2CAP disconnection
    // 436: Local device requested an L2CAP disconnection
    // TODO: remove_sockaddr
    [_peers removeObjectForKey:peripheral.identifier];
    [self restartCentral];
}

#pragma mark -- CBPeripheralDelegate

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverServices:(nullable NSError *)error
{
    NSLog(@"peripheral:%@ didDiscoverServices error:%@", peripheral, error);
    if (error) {
        return;
    }
    for (CBService *service in peripheral.services) {
        if ([service.UUID.data isEqual:_service_uuid.data]) {
            [peripheral discoverCharacteristics:@[[CBUUID UUIDWithString:CBUUIDL2CAPPSMCharacteristicString]] forService:service];
        }
    }
}

- (void)peripheral:(CBPeripheral *)peripheral didDiscoverCharacteristicsForService:(CBService *)service error:(nullable NSError *)error
{
    if ([service.UUID.data isEqual:_service_uuid.data]) {
        CBUUID *l2cap = [CBUUID UUIDWithString:CBUUIDL2CAPPSMCharacteristicString];
        for (CBCharacteristic *characteristic in service.characteristics) {
            if ([characteristic.UUID.data isEqual:l2cap.data]) {
                [peripheral readValueForCharacteristic:characteristic];
            }
        }
    }
}

- (void)peripheral:(CBPeripheral *)peripheral didUpdateValueForCharacteristic:(CBCharacteristic *)characteristic error:(nullable NSError *)error
{
    NSLog(@"didUpdateValueForCharacteristic:%@ error:%@", characteristic, error);
    if (error) {
        return;
    }
    CBL2CAPPSM PSM;
    [characteristic.value getBytes:&PSM length:sizeof(PSM)];
    NSLog(@"characteristic.value %@ %d", characteristic.value, PSM);
    [peripheral openL2CAPChannel:PSM];
}

- (void)peripheral:(CBPeripheral *)peripheral didOpenL2CAPChannel:(nullable CBL2CAPChannel *)channel error:(nullable NSError *)error
{
    NSLog(@"peripheral:%@ didOpenL2CAPChannel:%@ error:%@", peripheral, channel, error);
    if (error) {
        return;
    }

    assert(_peers[peripheral.identifier].peripheral == peripheral);

    for (CBService *service in peripheral.services) {
        if ([service.UUID.data isEqual:_service_uuid.data]) {
            NSUUID *nsuuid = peripheral.identifier;
            [self newChannel:channel uuid:nsuuid];
            break;
        }
    }
}

#pragma mark -- CBPeripheralManagerDelegate

- (void)peripheralManagerDidUpdateState:(CBPeripheralManager *)peripheral
{
    NSLog(@"peripheralManagerDidUpdateState:%@ state:%ld", peripheral, peripheral.state);

    assert(_peripheralManager == peripheral);

    if (peripheral.state != CBManagerStatePoweredOn) {
        return;
    }

    [self restartPeripheral];

    // XXX: should we unpublish and republish?
    if (!_psm) {
        [_peripheralManager publishL2CAPChannelWithEncryption:NO];
    }
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral willRestoreState:(NSDictionary<NSString *, id> *)dict
{
    NSLog(@"peripheralManager:%@ willRestoreState:%@", peripheral, dict);
}

- (void)peripheralManagerDidStartAdvertising:(CBPeripheralManager *)peripheral error:(nullable NSError *)error
{
    NSLog(@"peripheralManagerDidStartAdvertising:%@ error:%@", peripheral, error);
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral didAddService:(CBService *)service error:(nullable NSError *)error
{
    NSLog(@"peripheralManager:%@ didAddService:%@ error:%@", peripheral, service, error);

    NSDictionary *advertisingDictionary = @{CBAdvertisementDataServiceUUIDsKey:@[_service_uuid],
                                            CBAdvertisementDataLocalNameKey:@"newnode"};
    [_peripheralManager startAdvertising:advertisingDictionary];
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral didPublishL2CAPChannel:(CBL2CAPPSM)PSM error:(nullable NSError *)error
{
    NSLog(@"peripheralManager:%@ didPublishL2CAPChannel:%hu error:%@", peripheral, PSM, error);

    // maybe overkill
    [_peripheralManager stopAdvertising];
    [_peripheralManager removeAllServices];

    _psm = PSM;

    CBMutableService *service = [CBMutableService.alloc initWithType:_service_uuid primary:YES];
    CBMutableCharacteristic *l2cap = [CBMutableCharacteristic.alloc initWithType:[CBUUID UUIDWithString:CBUUIDL2CAPPSMCharacteristicString]
                                                                       properties:CBCharacteristicPropertyRead
                                                                           value:[NSData dataWithBytes:&PSM length:sizeof(PSM)]
                                                                     permissions:CBAttributePermissionsReadable];
    service.characteristics = @[l2cap];
    // didAddService will start adversiting
    [_peripheralManager addService:service];
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral didUnpublishL2CAPChannel:(CBL2CAPPSM)PSM error:(nullable NSError *)error
{
    NSLog(@"peripheralManager:%@ didUnpublishL2CAPChannel:%hu error:%@", peripheral, PSM, error);
    assert(_psm == PSM);
    _psm = 0;
    [_peripheralManager publishL2CAPChannelWithEncryption:NO];
}

- (void)peripheralManager:(CBPeripheralManager *)peripheral didOpenL2CAPChannel:(nullable CBL2CAPChannel *)channel error:(nullable NSError *)error
{
    NSLog(@"peripheralManager:%@ didOpenL2CAPChannel:%@ error:%@", peripheral, channel, error);
    if (error) {
        return;
    }
    NSUUID *nsuuid = channel.peer.identifier;
    [self newChannel:channel uuid:nsuuid];
}

@end


@implementation Peer

#pragma mark -- NSStreamDelegate

- (NSString*)streamEvent:(NSStreamEvent)eventCode
{
    switch (eventCode) {
    case NSStreamEventNone: return @"None";
    case NSStreamEventOpenCompleted: return @"OpenCompleted";
    case NSStreamEventHasBytesAvailable: return @"HasBytesAvailable";
    case NSStreamEventHasSpaceAvailable: return @"HasSpaceAvailable";
    case NSStreamEventErrorOccurred: return @"ErrorOccurred";
    case NSStreamEventEndEncountered: return @"EndEncountered";
    }
    return @"Unknown";
}

- (void)stream:(NSStream *)stream handleEvent:(NSStreamEvent)eventCode
{
    dispatch_assert_queue(dispatch_get_main_queue());
    //NSLog(@"NSStream:%@ event:%@ %@", stream, [self streamEvent:eventCode],
    //      eventCode == NSStreamEventErrorOccurred ? [NSString stringWithFormat:@"error:%@", stream.streamError] : @"");
    switch (eventCode) {
    case NSStreamEventNone:
        break;
    case NSStreamEventOpenCompleted:
        break;
    case NSStreamEventHasSpaceAvailable:
        [self write:(NSOutputStream*)stream];
        break;
    case NSStreamEventHasBytesAvailable:
        [self read:(NSInputStream*)stream];
        break;
    case NSStreamEventErrorOccurred:
    case NSStreamEventEndEncountered:
        [_channel.inputStream close];
        [_channel.outputStream close];
        [gBluetooth.centralManager cancelPeripheralConnection:_peripheral];
        break;
    }
}

- (void)write:(NSOutputStream*)outputStream
{
    dispatch_assert_queue(dispatch_get_main_queue());

    while (_outputBuffer.length > 0) {
        NSInteger l = [outputStream write:_outputBuffer.bytes maxLength:_outputBuffer.length];
        if (l <= 0) {
            if (l < 0) {
                NSLog(@"write error: %ld %@", (long)l, outputStream.streamError);
            }
            break;
        }
        //NSLog(@"wrote: %ld", (long)l);
        [_outputBuffer replaceBytesInRange:NSMakeRange(0, l) withBytes:nil length:0];
    }
}

- (void)read:(NSInputStream*)inputStream
{
    dispatch_assert_queue(dispatch_get_main_queue());

    const size_t capacity = 65536;
    if (!_inputBuffer) {
        _inputBuffer = [NSMutableData dataWithCapacity:capacity];
    }
    uint8_t buf[capacity];
    NSInteger l = [inputStream read:buf maxLength:sizeof(buf)];
    //NSLog(@"read: %ld", (long)l);
    if (l <= 0) {
        return;
    }
    [_inputBuffer appendBytes:buf length:l];

    network *n = gBluetooth.n;

    const endpoint e = [gBluetooth UUIDToEndpoint:_peripheral.identifier];
    const sockaddr_in6 sin6 = endpoint_to_addr(&e);

    while (_inputBuffer.length != 0) {
        if (!_hasLengthPrefix) {
            if (_inputBuffer.length < sizeof(_lengthPrefix)) {
                //NSLog(@"waiting _lengthPrefix");
                break;
            }
            _lengthPrefix = *(uint16_t*)_inputBuffer.bytes;
            // XXX: this might be expensive just to drop two bytes
            [_inputBuffer replaceBytesInRange:NSMakeRange(0, sizeof(_lengthPrefix)) withBytes:nil length:0];
            _hasLengthPrefix = true;
            //NSLog(@"got lengthPrefix:%d", _lengthPrefix);
        }
        if (_inputBuffer.length < _lengthPrefix) {
            //NSLog(@"waiting length:%lu/%d", _inputBuffer.length, _lengthPrefix);
            break;
        }
        size_t len = _lengthPrefix;
        uint8_t *b = malloc(len);
        memcpy((void*)b, _inputBuffer.bytes, len);
        [_inputBuffer replaceBytesInRange:NSMakeRange(0, len) withBytes:nil length:0];
        _hasLengthPrefix = false;
        network_async(n, ^{
            d2d_received(n, b, len, (const sockaddr *)&sin6, sizeof(sin6));
            free(b);
        });
    }

    network_async(n, ^{
        utp_issue_deferred_acks(n->utp);
    });
}

@end

ssize_t d2d_sendto(const uint8_t* buf, size_t len, const sockaddr_in6 *sin6)
{
    __block ssize_t r = -1;
    if (!IN6_IS_ADDR_UNIQUE_LOCAL(&sin6->sin6_addr)) {
        return r;
    }

    const endpoint e = addr_to_endpoint(sin6);
    assert(sizeof(uuid_t) <= sizeof(e));
    NSUUID *nsuuid = [NSUUID.alloc initWithUUIDBytes:(const unsigned char*)&e];
    dispatch_sync(dispatch_get_main_queue(), ^{
        Peer *peer = gBluetooth.peers[nsuuid];
        if (!peer) {
            //NSLog(@"endpoint not found: %@", nsuuid);
            r = -1;
            return;
        }
        if (!peer.outputBuffer) {
            peer.outputBuffer = [NSMutableData dataWithCapacity:len];
        }
        assert(len <= UINT16_MAX);
        uint16_t length = (uint16_t)len;
        [peer.outputBuffer appendBytes:(void*)&length length:sizeof(length)];
        [peer.outputBuffer appendBytes:(void *)buf length:len];
        [peer write:peer.channel.outputStream];
        r = len;
    });
    return r;
}

