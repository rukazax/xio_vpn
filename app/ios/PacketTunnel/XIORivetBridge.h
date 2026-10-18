#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
@protocol XIOPhysicalSockets <NSObject>
- (BOOL)protect:(int64_t)socket;
- (NSString *)resolve:(NSString *)host;
@end
@protocol XIOPacketSink <NSObject>
- (BOOL)writePacket:(NSData *)packet;
@end
@interface XIORivetBridge : NSObject
+ (nullable NSString *)start:(NSString *)config protector:(id<XIOPhysicalSockets>)protector sink:(id<XIOPacketSink>)sink timeout:(int64_t)timeout error:(NSError **)error;
+ (BOOL)input:(NSData *)packet;
+ (NSString *)status;
+ (void)stop;
@end
NS_ASSUME_NONNULL_END
