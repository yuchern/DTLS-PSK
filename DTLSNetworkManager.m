//
//  DTLSNetworkManager.m
//  SSDPDemo
//
//  Created by yuchern on 2019/11/15.
//  Copyright © 2019 yuchern. All rights reserved.
//

#import "DTLSNetworkManager.h"


#ifdef __IPHONE_13_0

NSErrorDomain const DTLSConnectErrorDomain = @"com.home.DTLS.Network.connectHost.error";
NSErrorDomain const DTLSReceiveMessageErrorDomain = @"com..home.DTLS.Network.receiveMessage.error";
NSErrorDomain const DTLSSendMessageErrorDomain = @"com.home.DTLS.Network.sendMessage.error";

@interface DTLSNetworkManager()
@property (nonatomic, strong) nw_parameters_t params;
@property (nonatomic, strong) nw_connection_t connection;
@property (nonatomic, strong) dispatch_queue_t connectQueue;
@property (nonatomic, copy) DTLSMessageHandle receiveMessage;
@property (nonatomic, strong) NSMutableData *readBuf;
@end

@implementation DTLSNetworkManager

#pragma mark - Public

/// Config nw_parameters which include pskId, psk, ciphersuite
/// @param pskId pskId
/// @param psk psk
/// @param ciphersuite ciphersuite
- (void)setDTLSParamWithPskId:(NSString *)pskId
                          psk:(NSString *)psk
                  ciphersuite:(tls_ciphersuite_t)ciphersuite API_AVAILABLE(ios(13.0)){
    if (pskId == nil || [pskId isEqualToString:@""]) {
        return;
    }
    if (psk == nil || [psk isEqualToString:@""]) {
        return;
    }
    self.params = nw_parameters_create_secure_udp(^(nw_protocol_options_t  _Nonnull options) {
        sec_protocol_options_t option = nw_tls_copy_sec_protocol_options(options);
        dispatch_data_t pskIdData = [self dispatchDataFromNsdata:[pskId dataUsingEncoding:NSUTF8StringEncoding]];
        dispatch_data_t pskData = [self dispatchDataFromNsdata:[psk dataUsingEncoding:NSUTF8StringEncoding]];
        if (pskIdData == nil || pskData == nil) {
            return;
        }
        sec_protocol_options_add_pre_shared_key(option, pskData, pskIdData);
        sec_protocol_options_append_tls_ciphersuite(option, ciphersuite);
        sec_protocol_options_set_min_tls_protocol_version(option, tls_protocol_version_DTLSv12);
    }, ^(nw_protocol_options_t  _Nonnull options) {
        NW_PARAMETERS_DEFAULT_CONFIGURATION;
    });
}

/// Connect to host
/// @param host IP
/// @param port port
/// @param queue queue
/// @param stateHandle callback
- (void)connectDTLSToHost:(NSString *)host
                     port:(NSString *)port
                    queue:(dispatch_queue_t)queue
              stateHandle:(DTLSConnectStateHandle)stateHandle API_AVAILABLE(ios(13.0)) {
    if (host == nil || [host isEqualToString:@""]) {
        return;
    }
    if (port == nil || [port isEqualToString:@""]) {
        return;
    }
    nw_endpoint_t endpoint = nw_endpoint_create_host([host UTF8String], [port UTF8String]);
    self.connection = nw_connection_create(endpoint, self.params);
    nw_connection_set_queue(self.connection, queue);
    nw_connection_start(self.connection);
    nw_connection_set_state_changed_handler(self.connection, ^(nw_connection_state_t state, nw_error_t  _Nullable error) {
        NSError *nserror;
        if (error != nil) {
            nserror = [[NSError alloc] initWithDomain:DTLSConnectErrorDomain code:nw_error_get_error_code(error) userInfo:@{@"nw_connection_set_state_changed_handler: nw_error_get_error_domain": @(nw_error_get_error_domain(error))}];
        }
        if (stateHandle) {
            stateHandle(state, nserror);
        }
    });
    
    [self receiveMsg];
}

/// Cancel nw_connection and set nil
- (void)closeDTLSConnect API_AVAILABLE(ios(13.0)){
    nw_connection_cancel(self.connection);
    //    self.connection = nil;//置nil会报错
    //    self.params = nil;
}

/// Send message
/// @param message message
/// @param complete complete
- (void)sendDTLSMessage:(NSData *)message
               complete:(DTLSSessionCompletedHandle)complete API_AVAILABLE(ios(13.0)) {
    NSData *sendMessage = [self sendMessagePack:message];
    dispatch_data_t data = [self dispatchDataFromNsdata:sendMessage];
    nw_connection_send(self.connection, data, NW_CONNECTION_FINAL_MESSAGE_CONTEXT, true, ^(nw_error_t  _Nullable error) {
        NSError *nserror;
        if (error != nil) {
            nserror = [[NSError alloc] initWithDomain:DTLSSendMessageErrorDomain code:nw_error_get_error_code(error) userInfo:@{@"nw_connection_send: nw_error_get_error_domain": @(nw_error_get_error_domain(error))}];
        }
        DEVELOPER_LOG_FORMAT(@"DTLS发送数据：%@",sendMessage);
        DDLogDebug(@"DTLS发送数据：%@",sendMessage);
        if (complete) {
            complete(nserror);
        }
    });
}

- (void)receiveDTLSMessage:(DTLSMessageHandle)receiveMessageHandle {
    self.receiveMessage = receiveMessageHandle;
}


#pragma mark - Private
/// Receive message
- (void)receiveMsg API_AVAILABLE(ios(13.0)) {
    __weak typeof (self)weakSelf = self;
    nw_connection_receive_message(self.connection, ^(dispatch_data_t  _Nullable content, nw_content_context_t  _Nullable context, bool is_complete, nw_error_t  _Nullable error) {
        DEVELOPER_LOG_FORMAT(@"DTLS接收数据：content=%@, context=%@, is_complete=%d, error=%@",content, context, is_complete, error);
        DDLogDebug(@"DTLS接收数据：content=%@, context=%@, is_complete=%d, error=%@",content, context, is_complete, error);
        __strong typeof (weakSelf)strongSelf = weakSelf;
        if (error == nil && content != nil) {
            NSData *data = [strongSelf nsdataFromDispatchData:content];
            if (data != nil) {
                [self receiveMessagePack:data];
            } else {
                NSError *nserror = [[NSError alloc] initWithDomain:DTLSReceiveMessageErrorDomain code:nw_error_get_error_code(error) userInfo:@{@"nw_connection_receive_message: nw_error_get_error_domain": @(nw_error_get_error_domain(error))}];
                if (strongSelf.receiveMessage) {
                    strongSelf.receiveMessage(nil, nserror);
                }
            }
            //nw_connection_receive_message函数只读取一次消息，读取完需要再次调用继续读取
        }else{
            NSError *nserror = [[NSError alloc] initWithDomain:DTLSReceiveMessageErrorDomain code:nw_error_get_error_code(error) userInfo:@{@"nw_connection_receive_message: nw_error_get_error_domain": @(nw_error_get_error_domain(error))}];
            if (strongSelf.receiveMessage) {
                strongSelf.receiveMessage(nil, nserror);
            }
        }
    });
}

/// 发送消息前进行组包，拼接包头，0xfefe + 包长2字节。4个字节
/// @param data 数据
- (NSData *)sendMessagePack:(NSData *)data {
    NSInteger length = data.length;
    Byte byte[4] = {0xfe, 0xfe, length >> 8, length & 0x00ff};
    NSMutableData *mulData = [[NSMutableData alloc] init];
    [mulData appendData:[NSData dataWithBytes:byte length:sizeof(byte)]];
    [mulData appendData:data];
    return mulData;
}

/// 接收数据的拼包，解决粘包问题
/// @param data 数据
- (void)receiveMessagePack:(NSData *)data API_AVAILABLE(ios(13.0)) {
    //将数据存入缓存区
    [self.readBuf appendData:data];
    //包头4个字节，2个字节fefe，2个字节包总长度
    while (self.readBuf.length > 4) {
        //将消息转化成byte，计算总长度 = 数据的内容长度 + 前面4个字节的头长度
        Byte *bytes = (Byte *)[self.readBuf bytes];
        if ((bytes[0]<<8) + bytes[1] == 0xfefe) {
            NSUInteger allLength = (bytes[2]<<8) + bytes[3] + 4;
            //缓存区的长度大于总长度，证明有完整的数据包在缓存区，然后进行处理
            if (self.readBuf.length >= allLength) {
                //提取出前面4个字节的头内容，之所以提取出来，是因为在处理数据问题的时候，比如data转json的时候，
                //头内容里面包含非法字符，会导致转化出来的json内容为空，所以要先去掉再处理数据问题
                NSMutableData *msgData = [[self.readBuf subdataWithRange:NSMakeRange(0, allLength)] mutableCopy];
                [msgData replaceBytesInRange:NSMakeRange(0, 4) withBytes:NULL length:0];
                
                if (self.receiveMessage) {
                    self.receiveMessage(msgData, nil);
                }
                //处理完数据后将处理过的数据移出缓存区
                self.readBuf = [NSMutableData dataWithData:[self.readBuf subdataWithRange:NSMakeRange(allLength, self.readBuf.length - allLength)]];
            }else{
                //缓存区内数据包不是完整的，再次从服务器获取数据，中断while循环
                [self receiveMsg];
                break;
            }
        } else {
            //如果包头不符合要求则丢弃
            self.readBuf = nil;
            DDLogDebug(@"DTLS拼包数据错误:%@",self.readBuf);
            break;
        }
    }
    //读取到服务端数据值后,能再次读取
    [self receiveMsg];
}


#pragma mark - 转换方法
/// Convert NSData to dispatch_data_t
/// @param nsdata NSData
- (dispatch_data_t)dispatchDataFromNsdata:(NSData *)nsdata API_AVAILABLE(ios(13.0)) {
    if (nsdata == nil) {
        return nil;
    }
    Byte byte[nsdata.length];
    [nsdata getBytes:byte length:nsdata.length];
    dispatch_data_t data = dispatch_data_create(byte, nsdata.length, nil, DISPATCH_DATA_DESTRUCTOR_DEFAULT);
    return data;
}

/// Convert dispatch_data_t to NSData
/// @param dispatchData dispatch_data_t
- (NSData *)nsdataFromDispatchData:(dispatch_data_t)dispatchData API_AVAILABLE(ios(13.0)) {
    if (dispatchData == nil) {
        return nil;
    }
    const void *buffer = NULL;
    size_t size = 0;
    dispatch_data_t new_data_file = dispatch_data_create_map(dispatchData, &buffer, &size);
    if(new_data_file) {/* to avoid warning really - since dispatch_data_create_map demands we
                        care about the return arg */}
    NSData *nsdata = [[NSData alloc] initWithBytes:buffer length:size];
    return nsdata;
}

#pragma mark - 懒加载
- (NSMutableData *)readBuf {
    if (_readBuf == nil) {
        _readBuf = [[NSMutableData alloc] init];
    }
    return _readBuf;
}

@end
#endif
