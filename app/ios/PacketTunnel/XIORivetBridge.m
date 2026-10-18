#import "XIORivetBridge.h"
#import <XIORivet/XIORivet.h>
@interface XIOGoProtector : NSObject<AppleProtector>
@property(nonatomic,strong) id<XIOPhysicalSockets> delegate;
@end
@implementation XIOGoProtector
- (BOOL)protect:(int64_t)fd { return [_delegate protect:fd]; }
- (NSString *)resolve:(NSString *)host { return [_delegate resolve:host ?: @""]; }
@end
@interface XIOGoSink : NSObject<ApplePacketSink>
@property(nonatomic,strong) id<XIOPacketSink> delegate;
@end
@implementation XIOGoSink
- (BOOL)writePacket:(NSData *)packet { return packet && [_delegate writePacket:packet]; }
@end
@implementation XIORivetBridge
+ (NSString *)start:(NSString *)config protector:(id<XIOPhysicalSockets>)protector sink:(id<XIOPacketSink>)sink timeout:(int64_t)timeout error:(NSError **)error {
  XIOGoProtector *p = [XIOGoProtector new]; p.delegate = protector;
  XIOGoSink *s = [XIOGoSink new]; s.delegate = sink;
  NSString *result = AppleStart(config, p, s, timeout, error);
  return error && *error ? nil : result;
}
+ (BOOL)input:(NSData *)packet { return AppleInput(packet); }
+ (NSString *)status { return AppleStatus(); }
+ (void)stop { AppleStop(); }
@end
