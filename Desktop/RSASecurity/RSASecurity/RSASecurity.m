//
//  RSASecurity.m
//  test
//
//  Created by 杨勇 on 17/3/15.
//  Copyright © 2017年 qqqq. All rights reserved.
//

#import "RSASecurity.h"
#import <security/SecKey.h>
#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonCryptor.h>

static inline NSString* base64_encode_data(NSData* data);
static inline NSData* base64_decode(NSString* str);
@implementation RSASecurity
//把二进制用hash包装一层
+ (NSData *)getHashBytes:(NSData *)plainText {
    CC_SHA1_CTX ctx;
    uint8_t * hashBytes = NULL;
    NSData * hash = nil;
    
    // Malloc a buffer to hold hash.
    hashBytes = malloc( kChosenDigestLength * sizeof(uint8_t) );
    memset((void *)hashBytes, 0x0, kChosenDigestLength);
    //初始化
    CC_SHA1_Init(&ctx);
    // 装载数据
    CC_SHA1_Update(&ctx, (void *)[plainText bytes], (CC_LONG)[plainText length]);
    // 输出进hash转化后的数据
    CC_SHA1_Final(hashBytes, &ctx);
    
    // Build up the SHA1 blob.
    hash = [NSData dataWithBytes:(const void *)hashBytes length:(NSUInteger)kChosenDigestLength];
    if (hashBytes){
        free(hashBytes);
        hashBytes = NULL;
    }
    return hash;
}
//剔除公钥的头部信息
+(NSData*)stripPublicKeyHeader:(NSData *)d_key{
    if(d_key == nil){return nil;}
    unsigned long len = [d_key length];
    if (!len) {
        return nil;
    }
    unsigned char* c_key = (unsigned char*)[d_key bytes];
    unsigned int idx;
    if (c_key[idx++] != 0x30) {
        return nil;
    }
    if (c_key[idx]>0x80) {
        idx += c_key[idx] - 0x80 + 1;
    }
    else{
        idx++;
    }
    static unsigned char seqiod[] =
    { 0x30,   0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
        0x01, 0x05, 0x00 };
    if (memcmp(&c_key[idx], seqiod, 15)) {
        return nil;
    }
    idx += 15;
    if (c_key[idx++] != 0x30) {
        return nil;
    }
    if (c_key[idx] > 0x80) {
        idx += c_key[idx] - 0x80 + 1;
    }
    if (c_key[idx++] != '\0') {
        return nil;
    }
    return [NSData dataWithBytes:&c_key[idx] length:len - idx];
}
//剔除私钥的头部信息
+(NSData*)stripPrivateKeyHeader:(NSData *)d_key{
    if (d_key == nil) {
        return nil;
    }
    unsigned long len = [d_key length];
    if (!len) {
        return nil;
    }
    unsigned char* c_key = (unsigned char*)[d_key bytes];
    unsigned int idx = 22;
    if (0x04 != c_key[idx++]) {
        return nil;
    }
    unsigned int c_len = c_key[idx++];
    int det = c_len & 0x80;
    if (!det) {
        c_len = c_len & 0x7f;
    }else{
        int byteCount = c_len & 0x7f;
        if (byteCount + idx > len) {
            return nil;
        }
        unsigned int accum = 0;
        unsigned char *ptr = &c_key[idx];
        idx += byteCount;
        while (byteCount) {
            accum = (accum<<8)+ *ptr;
            ptr++;
            byteCount--;
        }
        c_len = accum;
    }
    return [d_key subdataWithRange:NSMakeRange(idx, c_len)];
}
//添加公钥
+(SecKeyRef)addPublicKey:(NSString *)key{
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    NSData* data = base64_decode(key);
    data = [self stripPublicKeyHeader:data];
    if (!data) {
        return nil;
    }
    NSString* tag = @"RSASecurity_Pubkey";
    NSData* d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    NSMutableDictionary* publicKey = [[NSMutableDictionary alloc] init];
    [publicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:(__bridge id)kSecAttrKeyClassPublic forKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);
    [publicKey setObject:data forKey:(__bridge id)kSecValueData];
    [publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id)
     kSecAttrKeyClass];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey,&persistKey);
    if (persistKey != nil) {
        CFRelease(persistKey);
    }
    if (status != noErr && status != errSecDuplicateItem) {
        return nil;
    }
    [publicKey removeObjectForKey:(__bridge id)kSecValueData];
    [publicKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}
//添加私钥
+ (SecKeyRef)addPrivateKey:(NSString *)key{
    key = [key stringByReplacingOccurrencesOfString:@"\r" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\n" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@"\t" withString:@""];
    key = [key stringByReplacingOccurrencesOfString:@" "  withString:@""];
    NSData* data = base64_decode(key);
    data = [self stripPrivateKeyHeader:data];
    if (!data) {
        return nil;
    }
    NSString* tag = @"RSASecurity_Prikey";
    NSData* d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
    NSMutableDictionary* privateKey = [[NSMutableDictionary alloc] init];
    [privateKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [privateKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)privateKey);
    
    [privateKey setObject:data forKey:(__bridge id)kSecValueData];
    [privateKey setObject:(__bridge id) kSecAttrKeyClassPrivate forKey:(__bridge id)
     kSecAttrKeyClass];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)
     kSecReturnPersistentRef];
    
    CFTypeRef persistKey = nil;
    OSStatus status = SecItemAdd((__bridge CFDictionaryRef)privateKey, &persistKey);
    if (persistKey != nil){
        CFRelease(persistKey);
    }
    if ((status != noErr) && (status != errSecDuplicateItem)) {
        return nil;
    }
    [privateKey removeObjectForKey:(__bridge id)kSecValueData];
    [privateKey removeObjectForKey:(__bridge id)kSecReturnPersistentRef];
    [privateKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    [privateKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];

    SecKeyRef keyRef = nil;
    status = SecItemCopyMatching((__bridge CFDictionaryRef)privateKey, (CFTypeRef *)&keyRef);
    if(status != noErr){
        return nil;
    }
    return keyRef;
}
//加密二进制
+(NSData*)encryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef{
    const uint8_t* srcbuf = (const uint8_t*)[data bytes];
    size_t srclen = (size_t)data.length;
    size_t block_size = (size_t)SecKeyGetBlockSize(keyRef);
    void* outbuf = malloc(block_size);
    size_t scr_block_size = block_size - 11;
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < srclen; idx+=scr_block_size) {
        size_t data_len = srclen - idx;
        if (data_len > scr_block_size) {
            data_len = scr_block_size;
        }
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(keyRef,  kSecPaddingPKCS1, srcbuf, data_len, outbuf, &outlen);
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}
//解密二进制
+ (NSData *)decryptData:(NSData *)data withKeyRef:(SecKeyRef) keyRef{
    const uint8_t* scrbuf = (const uint8_t*)[data bytes];
    size_t scrlen = [data length];
    size_t block_size = (size_t)SecKeyGetBlockSize(keyRef);
    UInt8* outbuf = malloc(block_size);
    size_t scr_block_size = block_size;
    NSMutableData *ret = [[NSMutableData alloc] init];
    for (int idx = 0; idx < scrlen; idx+=scr_block_size) {
        size_t data_len = scrlen - idx;
        if (data_len > scr_block_size) {
            data_len = scr_block_size;
        }
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(keyRef, kSecPaddingNone, scrbuf + idx, data_len, outbuf, &outlen);
        if (status != 0) {
            ret = nil;
            break;
        }else{
            int idxFirstZero = -1;
            int idxNextZero = (int)outlen;
            for (int i = 0; i<outlen; i++) {
                if (outbuf[i] == 0) {
                    if (idxFirstZero < 0) {
                        idxFirstZero = i;
                    }else{
                        idxNextZero = i;
                        break;
                    }
                }
            }
            [ret appendBytes:&outbuf[idxFirstZero+1] length:idxNextZero-idxFirstZero-1];
        }
    }
    free(outbuf);
    CFRelease(keyRef);
    return ret;
}
//验签
+(NSData*)vertifyData:(NSData*)data withKeyRef:(SecKeyRef)keyRef{
    const uint8_t* bytes = (const uint8_t*)[[self getHashBytes:data] bytes];
    size_t block_size = SecKeyGetBlockSize(keyRef);
    uint8_t* outbuf = (uint8_t*)malloc(block_size);
    memset((void *)outbuf, 0x0, block_size);
    OSStatus status = noErr;
    status = SecKeyRawVerify(keyRef, kSecPaddingPKCS1SHA1, bytes, kChosenDigestLength, outbuf, block_size);
    
    NSData* vertifyData;
    if (status == noErr) {
        vertifyData = [NSData dataWithBytes:outbuf length:(NSUInteger)block_size];
    }else{
        return nil;
    }
    if (outbuf)
    {
        free(outbuf);
        outbuf = NULL;
    }
    return vertifyData;
}
//加签二进制
+ (NSData*)signData:(NSData*)data withKeyRef:(SecKeyRef)keyRef{
    const uint8_t* bytes = (const uint8_t*)[[self getHashBytes:data] bytes];
    size_t block_size = SecKeyGetBlockSize(keyRef);
    uint8_t* outbuf = (uint8_t*)malloc(block_size);
    memset((void *)outbuf, 0x0, block_size);
    OSStatus status = noErr;
    status = SecKeyRawSign(keyRef, kSecPaddingPKCS1SHA1, bytes , kChosenDigestLength, outbuf, &block_size);
    NSData* signData;
    if (status == noErr)
    {
        signData = [NSData dataWithBytes:(const void *)outbuf length:(NSUInteger)block_size];
    }
    else
    {
        return nil;
    }
    
    if (outbuf)
    {
        free(outbuf);
        outbuf = NULL;
    }
    return signData;
}

//验签
+(NSString*)vertifyString:(NSString*)str withPucKey:(NSString*)pucKey{
    if (!str || !pucKey) {
        return nil;
    }
    SecKeyRef keyRef = [self addPublicKey:pucKey];
    if (!keyRef) {
        return nil;
    }
    NSData* data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData* vertifyData = [self vertifyData:data withKeyRef:keyRef];
    return base64_encode_data(vertifyData);
}
//加签
+(NSString*)signString:(NSString*)str withPrivKey:(NSString*)privKey{
    if (!str || !privKey) {
        return nil;
    }
    SecKeyRef keyRef = [self addPrivateKey:privKey];
    if (!keyRef) {
        return nil;
    }
    
    NSData* data = [str dataUsingEncoding:NSUTF8StringEncoding];
    NSData* signData = [self signData:data withKeyRef:keyRef];
    return base64_encode_data(signData);
}
+ (NSData *)decryptData:(NSData *)data privateKey:(NSString *)privKey{
    if(!data || !privKey){
        return nil;
    }
    SecKeyRef keyRef = [self addPrivateKey:privKey];
    if(!keyRef){
        return nil;
    }
    return [self decryptData:data withKeyRef:keyRef];
}
+ (NSString *)decryptString:(NSString *)str privateKey:(NSString *)privKey{
    NSData *data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    data = [self decryptData:data privateKey:privKey];
    NSString *ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}
+ (NSString *)encryptString:(NSString *)str publicKey:(NSString *)pubKey{
    NSData *data = [self encryptData:[str dataUsingEncoding:NSUTF8StringEncoding] publicKey:pubKey];
    NSString *ret = base64_encode_data(data);
    return ret;
}

+ (NSData *)encryptData:(NSData *)data publicKey:(NSString *)pubKey{
    if(!data || !pubKey){
        return nil;
    }
    SecKeyRef keyRef = [self addPublicKey:pubKey];
    if(!keyRef){
        return nil;
    }
    return [self encryptData:data withKeyRef:keyRef];
}

@end
//编码base64字符串
static NSString* base64_encode_data(NSData* data){
    data = [data base64EncodedDataWithOptions:0];
    NSString* ret = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return ret;
}
//base64编码字符串
static NSData* base64_decode(NSString* str){
    NSData* data = [[NSData alloc] initWithBase64EncodedString:str options:NSDataBase64DecodingIgnoreUnknownCharacters];
    return data;
}
