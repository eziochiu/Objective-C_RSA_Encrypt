//
//  RSAEncrypt.h
//  Objective-C_RSA_Encrypt
//
//  Created by Ezio Chiu on 5/16/20.
//  Copyright © 2020 Ezio Chiu. All rights reserved.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface RSAEncrypt : NSObject

/// 通过公钥加密字符串 -- 返回base64
/// @param string 需要加密的字符串
/// @param pubKey 公钥
+ (NSString *)encryptString:(NSString *)string publicKey:(NSString *)pubKey;

/// 通过公钥加密二进制
/// @param data 需要加密的二进制
/// @param pubKey 公钥
+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey;

/// 通过私钥加密字符串 -- 返回base64
/// @param string 需要加密的字符串
/// @param privKey 私钥
+ (NSString *)encryptString:(NSString *)string privateKey:(NSString *)privKey;

/// 通过私钥加密二进制
/// @param data 需要加密的二进制
/// @param privKey 私钥
+ (NSData *)encryptData:(NSData *)data privateKey:(NSString *)privKey;


/// 解密base64
/// @param string 需要解密的字符串
/// @param pubKey 公钥
+ (NSString *)decryptString:(NSString *)string publicKey:(NSString *)pubKey;

/// 解密data
/// @param data 需要解密的data
/// @param pubKey 公钥
+ (NSData *)decryptData:(NSData *)data publicKey:(NSString *)pubKey;

/// 解密base64
/// @param string 需要解密的字符串
/// @param privKey 私钥
+ (NSString *)decryptString:(NSString *)string privateKey:(NSString *)privKey;

/// 解密data
/// @param data 需要解密的data
/// @param privKey 私钥
+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey;
@end

NS_ASSUME_NONNULL_END
