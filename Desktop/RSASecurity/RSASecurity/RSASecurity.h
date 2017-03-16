//
//  RSASecurity.h
//  test
//
//  Created by 杨勇 on 17/3/15.
//  Copyright © 2017年 qqqq. All rights reserved.
//

#import <Foundation/Foundation.h>
#define kChosenDigestLength CC_SHA1_DIGEST_LENGTH  // SHA-1消息摘要的数据位数160位
#define kSecPaddingRSA kSecPaddingPKCS1SHA1 //SecKeyRawSign/SecKeyRawVerify
@interface RSASecurity : NSObject

/**
 对字符串使用私钥加签
 @param str 需要加签的字符串
 @param privKey 私钥字符串
 @return 加签后的字符串
 */
+(NSString*)signString:(NSString*)str withPrivKey:(NSString*)privKey;

/**
 解密
 @param str 需要解密的字符串
 @param privKey 私钥字符串
 @return 解密后的字符串
 */
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey;

/**
 加密
 @param str 需要加密的字符串
 @param pubKey 公钥字符串
 @return 加密后的字符串
 */
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey;

/**
 验签
 @param str 需要验证的字符串
 @param pucKey 公钥字符串
 @return 验签后的字符串
 */
+(NSString*)vertifyString:(NSString*)str withPucKey:(NSString*)pucKey;
@end
