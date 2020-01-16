//
//  DTLSNetworkManager.h
//  SSDPDemo
//
//  Created by yuchern on 2019/11/15.
//  Copyright © 2019 yuchern. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Network/Network.h>

NS_ASSUME_NONNULL_BEGIN

#ifdef __IPHONE_13_0

typedef void (^DTLSMessageHandle)(NSData *_Nullable data, NSError *_Nullable error);

typedef void (^DTLSSessionCompletedHandle)(NSError *_Nullable error);

/*
 nw_connection_state_invalid = 0,
 @const nw_connection_state_waiting The connection is waiting for a usable network before re-attempting
 nw_connection_state_waiting = 1,
 @const nw_connection_state_preparing The connection is in the process of establishing
 nw_connection_state_preparing = 2,
 @const nw_connection_state_ready The connection is established and ready to send and receive data upon
 nw_connection_state_ready = 3,
 @const nw_connection_state_failed The connection has irrecoverably closed or failed
 nw_connection_state_failed = 4,
 @const nw_connection_state_cancelled The connection has been cancelled by the caller
 nw_connection_state_cancelled = 5,
 */
typedef void (^DTLSConnectStateHandle)(nw_connection_state_t state, NSError  *_Nullable error);

@interface DTLSNetworkManager : NSObject

/// Config nw_parameters which include pskId, psk, ciphersuite
/// @param pskId pskId
/// @param psk psk
/// @param ciphersuite ciphersuite
- (void)setDTLSParamWithPskId:(NSString *)pskId
                          psk:(NSString *)psk
                  ciphersuite:(tls_ciphersuite_t)ciphersuite;

/// Connect to host
/// @param host IP
/// @param port port
/// @param queue queue
/// @param stateHandle callback
- (void)connectDTLSToHost:(NSString *)host
                     port:(NSString *)port
                    queue:(dispatch_queue_t)queue
              stateHandle:(DTLSConnectStateHandle)stateHandle;

/// Cancel nw_connection and set nil
- (void)closeDTLSConnect;

/// Send message
/// @param message message
/// @param complete complete
- (void)sendDTLSMessage:(NSData *)message
               complete:(DTLSSessionCompletedHandle)complete;

/// Receive message
/// @param receiveMessageHandle callback
- (void)receiveDTLSMessage:(DTLSMessageHandle)receiveMessageHandle;

@end
#endif

NS_ASSUME_NONNULL_END
