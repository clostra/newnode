#ifndef __SHA1_H__
#define __SHA1_H__

/*
   SHA-1 in C
   By Steve Reid <steve@edmweb.com>
   100% Public Domain
*/

#ifdef __APPLE__
#import <CommonCrypto/CommonDigest.h>
#endif

#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef struct {
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

void SHA1Transform(uint32_t state[5], const unsigned char buffer[64]);

void SHA1Init(SHA1_CTX *context);

void SHA1Update(SHA1_CTX *context, const unsigned char *data, uint32_t len);

void SHA1Final(unsigned char digest[20], SHA1_CTX *context);

// TODO: Why use different implementations on different platforms?
#ifdef __APPLE__
#define SHA1(digest, buf, len) CC_SHA1(buf, len, digest)
#else
void SHA1(unsigned char *hash_out, const unsigned char *str, int len);
#endif

#ifdef __cplusplus
}
#endif

#endif // __SHA1_H__
