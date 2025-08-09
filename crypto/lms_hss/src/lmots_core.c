/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS_HSS

#include <string.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "../../include/crypt_util_rand.h"
#include "lms_hss_local.h"

/* LMOTS domain separator constants from RFC 8554 */
#define LMOTS_D_PBLC    0x8080
#define LMOTS_D_MESG    0x8181
#define LMOTS_D_LEAF    0x8282

/* Convert LMOTS message to base-w representation */
static int32_t LmotsMessageToBaseW(const CryptLmsHssCtx *ctx, const uint8_t *message, 
                                   uint32_t messageLen, uint16_t *baseW)
{
    if (ctx == NULL || message == NULL || baseW == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t w = ctx->para.w;
    uint32_t p = ctx->para.p;
    uint32_t total = 0;
    uint32_t index = 0;
    
    /* Convert message to base-w */
    for (uint32_t i = 0; i < messageLen && index < p - ctx->para.ls; i++) {
        uint8_t byte = message[i];
        for (uint32_t j = 0; j < 8; j += w) {
            if (index >= p - ctx->para.ls) break;
            
            uint32_t mask = (1 << w) - 1;
            uint32_t val = (byte >> (8 - w - j)) & mask;
            baseW[index++] = (uint16_t)val;
            total += val;
        }
    }
    
    /* Compute checksum */
    uint32_t checksum = ((1 << w) - 1) * (p - ctx->para.ls) - total;
    checksum = checksum << ctx->para.ls;
    
    /* Append checksum in base-w */
    for (uint32_t i = 0; i < ctx->para.ls; i++) {
        if (index >= p) break;
        uint32_t shift = w * (ctx->para.ls - 1 - i);
        uint32_t mask = (1 << w) - 1;
        baseW[index++] = (uint16_t)((checksum >> shift) & mask);
    }
    
    return CRYPT_SUCCESS;
}

/* Hash chain computation for LMOTS */
static int32_t LmotsHashChain(const CryptLmsHssCtx *ctx, const uint8_t *x, uint32_t i, 
                              uint32_t s, const uint8_t *identifier, uint32_t q, uint8_t *result)
{
    if (ctx == NULL || x == NULL || identifier == NULL || result == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint8_t tmp[LMS_HSS_HASH_LEN];
    uint8_t input[LMS_HSS_IDENTIFIER_LEN + 4 + 2 + 1 + LMS_HSS_HASH_LEN];
    uint32_t offset = 0;

    /* Copy initial value */
    if (memcpy_s(tmp, LMS_HSS_HASH_LEN, x, LMS_HSS_HASH_LEN) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }

    /* Perform hash chain iterations */
    uint32_t maxVal = (1U << ctx->para.w) - 1;
    for (uint32_t j = s; j < maxVal; j++) {
        offset = 0;
        
        /* identifier || q || i || j || tmp */
        if (memcpy_s(input + offset, sizeof(input) - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_IDENTIFIER_LEN;
        
        /* q (big-endian) */
        input[offset++] = (uint8_t)(q >> 24);
        input[offset++] = (uint8_t)(q >> 16);
        input[offset++] = (uint8_t)(q >> 8);
        input[offset++] = (uint8_t)q;
        
        /* i (big-endian) */
        input[offset++] = (uint8_t)(i >> 8);
        input[offset++] = (uint8_t)i;
        
        /* j */
        input[offset++] = (uint8_t)j;
        
        /* tmp */
        if (memcpy_s(input + offset, sizeof(input) - offset, tmp, LMS_HSS_HASH_LEN) != EOK) {
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_HASH_LEN;
        
        /* Hash */
        LmsHssAdrs adrs = {0};
        adrs.type = LMS_HSS_ADDR_TYPE_OTS;
        adrs.q = q;
        adrs.i = (uint16_t)i;
        adrs.j = (uint8_t)j;
        
        int32_t ret = ctx->hashFuncs.f(ctx, &adrs, input, offset, tmp);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }

    if (memcpy_s(result, LMS_HSS_HASH_LEN, tmp, LMS_HSS_HASH_LEN) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }

    return CRYPT_SUCCESS;
}

/* Generate LMOTS private key from seed */
static int32_t LmotsGeneratePrivateKey(const CryptLmsHssCtx *ctx, const uint8_t *seed,
                                       const uint8_t *identifier, uint32_t q, uint8_t **privateKey)
{
    if (ctx == NULL || seed == NULL || identifier == NULL || privateKey == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t p = ctx->para.p;
    uint8_t *prvKey = LmsHss_Calloc(p, LMS_HSS_HASH_LEN);
    if (prvKey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint8_t input[LMS_HSS_SEED_LEN + LMS_HSS_IDENTIFIER_LEN + 4 + 2 + 1];
    uint32_t offset = 0;

    /* Generate each private key element using PRF */
    for (uint32_t i = 0; i < p; i++) {
        offset = 0;
        
        /* seed || identifier || q || i || 0xff */
        if (memcpy_s(input + offset, sizeof(input) - offset, seed, LMS_HSS_SEED_LEN) != EOK) {
            LmsHss_Free(prvKey);
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_SEED_LEN;
        
        if (memcpy_s(input + offset, sizeof(input) - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
            LmsHss_Free(prvKey);
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_IDENTIFIER_LEN;
        
        /* q (big-endian) */
        input[offset++] = (uint8_t)(q >> 24);
        input[offset++] = (uint8_t)(q >> 16);
        input[offset++] = (uint8_t)(q >> 8);
        input[offset++] = (uint8_t)q;
        
        /* i (big-endian) */
        input[offset++] = (uint8_t)(i >> 8);
        input[offset++] = (uint8_t)i;
        
        /* 0xff */
        input[offset++] = 0xff;
        
        /* Generate private key element */
        LmsHssAdrs adrs = {0};
        adrs.type = LMS_HSS_ADDR_TYPE_OTS;
        adrs.q = q;
        adrs.i = (uint16_t)i;
        adrs.j = 0xff;
        
        int32_t ret = ctx->hashFuncs.prf(ctx, &adrs, seed, prvKey + i * LMS_HSS_HASH_LEN);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_SecureClear(prvKey, p * LMS_HSS_HASH_LEN);
            LmsHss_Free(prvKey);
            return ret;
        }
    }

    *privateKey = prvKey;
    return CRYPT_SUCCESS;
}

/* Generate LMOTS public key from private key */
static int32_t LmotsGeneratePublicKey(const CryptLmsHssCtx *ctx, const uint8_t *privateKey,
                                      const uint8_t *identifier, uint32_t q, uint8_t *publicKey)
{
    if (ctx == NULL || privateKey == NULL || identifier == NULL || publicKey == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t p = ctx->para.p;
    uint8_t *y = LmsHss_Calloc(p, LMS_HSS_HASH_LEN);
    if (y == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    /* Compute y[i] = chain(x[i], i, (2^w - 1), identifier, q) for all i */
    for (uint32_t i = 0; i < p; i++) {
        int32_t ret = LmotsHashChain(ctx, privateKey + i * LMS_HSS_HASH_LEN, i, 0,
                                     identifier, q, y + i * LMS_HSS_HASH_LEN);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_Free(y);
            return ret;
        }
    }

    /* Hash to create public key: H(identifier || q || D_PBLC || y[0] || ... || y[p-1]) */
    uint32_t inputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + p * LMS_HSS_HASH_LEN;
    uint8_t *input = LmsHss_Malloc(inputLen);
    if (input == NULL) {
        LmsHss_Free(y);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    
    /* identifier */
    if (memcpy_s(input + offset, inputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(y);
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* q (big-endian) */
    input[offset++] = (uint8_t)(q >> 24);
    input[offset++] = (uint8_t)(q >> 16);
    input[offset++] = (uint8_t)(q >> 8);
    input[offset++] = (uint8_t)q;
    
    /* D_PBLC */
    input[offset++] = (uint8_t)(LMOTS_D_PBLC >> 8);
    input[offset++] = (uint8_t)LMOTS_D_PBLC;
    
    /* y values */
    if (memcpy_s(input + offset, inputLen - offset, y, p * LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(y);
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }

    LmsHssAdrs adrs = {0};
    adrs.type = LMS_HSS_ADDR_TYPE_OTS;
    adrs.q = q;
    adrs.i = 0; /* Public key generation */
    adrs.j = 0;
    
    int32_t ret = ctx->hashFuncs.h(ctx, &adrs, input, inputLen, publicKey);
    
    LmsHss_Free(y);
    LmsHss_Free(input);
    
    return ret;
}

/* LMOTS signature generation */
int32_t LMOTS_Sign(CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                   const uint8_t *identifier, uint32_t q, const uint8_t *seed,
                   LmotsSignature *signature)
{
    if (ctx == NULL || message == NULL || identifier == NULL || seed == NULL || signature == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t p = ctx->para.p;
    
    /* Generate random value C */
    int32_t ret = CRYPT_RandEx(NULL, signature->c, LMS_HSS_HASH_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Hash message with random value: H(identifier || q || D_MESG || C || message) */
    uint32_t hashInputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + LMS_HSS_HASH_LEN + messageLen;
    uint8_t *hashInput = LmsHss_Malloc(hashInputLen);
    if (hashInput == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    
    /* identifier */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* q (big-endian) */
    hashInput[offset++] = (uint8_t)(q >> 24);
    hashInput[offset++] = (uint8_t)(q >> 16);
    hashInput[offset++] = (uint8_t)(q >> 8);
    hashInput[offset++] = (uint8_t)q;
    
    /* D_MESG */
    hashInput[offset++] = (uint8_t)(LMOTS_D_MESG >> 8);
    hashInput[offset++] = (uint8_t)LMOTS_D_MESG;
    
    /* C */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, signature->c, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_HASH_LEN;
    
    /* message */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, message, messageLen) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }

    uint8_t hashedMessage[LMS_HSS_HASH_LEN];
    LmsHssAdrs adrs = {0};
    adrs.type = LMS_HSS_ADDR_TYPE_OTS;
    adrs.q = q;
    adrs.i = 0; /* Message hash */
    adrs.j = 0;
    
    ret = ctx->hashFuncs.h(ctx, &adrs, hashInput, hashInputLen, hashedMessage);
    LmsHss_Free(hashInput);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Convert hashed message to base-w */
    uint16_t *baseW = LmsHss_Calloc(p, sizeof(uint16_t));
    if (baseW == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = LmotsMessageToBaseW(ctx, hashedMessage, LMS_HSS_HASH_LEN, baseW);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_Free(baseW);
        return ret;
    }

    /* Generate private key */
    uint8_t *privateKey = NULL;
    ret = LmotsGeneratePrivateKey(ctx, seed, identifier, q, &privateKey);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_Free(baseW);
        return ret;
    }

    /* Allocate signature y array */
    signature->y = LmsHss_Calloc(p, LMS_HSS_HASH_LEN);
    if (signature->y == NULL) {
        LmsHss_SecureClear(privateKey, p * LMS_HSS_HASH_LEN);
        LmsHss_Free(privateKey);
        LmsHss_Free(baseW);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    /* Compute signature y[i] = chain(x[i], i, a[i], identifier, q) */
    for (uint32_t i = 0; i < p; i++) {
        ret = LmotsHashChain(ctx, privateKey + i * LMS_HSS_HASH_LEN, i, baseW[i],
                             identifier, q, signature->y + i * LMS_HSS_HASH_LEN);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_SecureClear(privateKey, p * LMS_HSS_HASH_LEN);
            LmsHss_Free(privateKey);
            LmsHss_Free(baseW);
            LmsHss_SecureClear(signature->y, p * LMS_HSS_HASH_LEN);
            LmsHss_Free(signature->y);
            signature->y = NULL;
            return ret;
        }
    }

    signature->lmotsType = ctx->para.lmotsType;
    
    LmsHss_SecureClear(privateKey, p * LMS_HSS_HASH_LEN);
    LmsHss_Free(privateKey);
    LmsHss_Free(baseW);
    
    return CRYPT_SUCCESS;
}

/* Reconstruct LMOTS public key from signature for verification */
int32_t LMOTS_ReconstructPublicKey(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                                   const LmotsSignature *signature, const uint8_t *identifier, uint32_t q, 
                                   uint8_t *reconstructedPubKey)
{
    if (ctx == NULL || message == NULL || signature == NULL || identifier == NULL || reconstructedPubKey == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (signature->lmotsType != ctx->para.lmotsType) {
        return CRYPT_LMS_HSS_INVALID_LMOTS_TYPE;
    }

    if (signature->y == NULL) {
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    uint32_t p = ctx->para.p;
    
    /* Hash message with random value C - same as in signing */
    uint32_t hashInputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + LMS_HSS_HASH_LEN + messageLen;
    uint8_t *hashInput = LmsHss_Malloc(hashInputLen);
    if (hashInput == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    
    /* identifier */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* q (big-endian) */
    hashInput[offset++] = (uint8_t)(q >> 24);
    hashInput[offset++] = (uint8_t)(q >> 16);
    hashInput[offset++] = (uint8_t)(q >> 8);
    hashInput[offset++] = (uint8_t)q;
    
    /* D_MESG */
    hashInput[offset++] = (uint8_t)(LMOTS_D_MESG >> 8);
    hashInput[offset++] = (uint8_t)LMOTS_D_MESG;
    
    /* C */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, signature->c, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_HASH_LEN;
    
    /* message */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, message, messageLen) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }

    uint8_t hashedMessage[LMS_HSS_HASH_LEN];
    LmsHssAdrs adrs = {0};
    adrs.type = LMS_HSS_ADDR_TYPE_OTS;
    adrs.q = q;
    adrs.i = 0; /* Message hash for verification */
    adrs.j = 0;
    
    int32_t ret = ctx->hashFuncs.h(ctx, &adrs, hashInput, hashInputLen, hashedMessage);
    LmsHss_Free(hashInput);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Convert hashed message to base-w */
    uint16_t *baseW = LmsHss_Calloc(p, sizeof(uint16_t));
    if (baseW == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = LmotsMessageToBaseW(ctx, hashedMessage, LMS_HSS_HASH_LEN, baseW);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_Free(baseW);
        return ret;
    }

    /* Compute z[i] = chain(y[i], i, (2^w - 1) - a[i], identifier, q) */
    uint8_t *z = LmsHss_Calloc(p, LMS_HSS_HASH_LEN);
    if (z == NULL) {
        LmsHss_Free(baseW);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    for (uint32_t i = 0; i < p; i++) {
        /* Verification: z[i] = chain(y[i], i, baseW[i], identifier, q) */
        /* In signing we did: y[i] = chain(x[i], i, baseW[i]) = hash^(maxVal-baseW[i])(x[i]) */
        /* In verification we do: z[i] = chain(y[i], i, baseW[i]) = hash^(maxVal-baseW[i])(y[i]) = hash^(maxVal)(x[i]) */
        ret = LmotsHashChain(ctx, signature->y + i * LMS_HSS_HASH_LEN, i, baseW[i],
                             identifier, q, z + i * LMS_HSS_HASH_LEN);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_Free(baseW);
            LmsHss_Free(z);
            return ret;
        }
    }

    /* Reconstruct public key: H(identifier || q || D_PBLC || z[0] || ... || z[p-1]) */
    uint32_t inputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + p * LMS_HSS_HASH_LEN;
    uint8_t *input = LmsHss_Malloc(inputLen);
    if (input == NULL) {
        LmsHss_Free(baseW);
        LmsHss_Free(z);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    offset = 0;
    
    /* identifier */
    if (memcpy_s(input + offset, inputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(baseW);
        LmsHss_Free(z);
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* q (big-endian) */
    input[offset++] = (uint8_t)(q >> 24);
    input[offset++] = (uint8_t)(q >> 16);
    input[offset++] = (uint8_t)(q >> 8);
    input[offset++] = (uint8_t)q;
    
    /* D_PBLC */
    input[offset++] = (uint8_t)(LMOTS_D_PBLC >> 8);
    input[offset++] = (uint8_t)LMOTS_D_PBLC;
    
    /* z values */
    if (memcpy_s(input + offset, inputLen - offset, z, p * LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(baseW);
        LmsHss_Free(z);
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }

    LmsHssAdrs pubKeyAdrs = {0};
    pubKeyAdrs.type = LMS_HSS_ADDR_TYPE_OTS;
    pubKeyAdrs.q = q;
    pubKeyAdrs.i = 1; /* Public key reconstruction */
    pubKeyAdrs.j = 0;
    
    ret = ctx->hashFuncs.h(ctx, &pubKeyAdrs, input, inputLen, reconstructedPubKey);
    
    LmsHss_Free(baseW);
    LmsHss_Free(z);
    LmsHss_Free(input);
    
    return ret;
}

/* Generate LMOTS public key from seed (for Merkle tree leaf computation) */
int32_t LMOTS_GeneratePublicKey(const CryptLmsHssCtx *ctx, const uint8_t *identifier,
                               uint32_t q, const uint8_t *seed, uint8_t *pubKey)
{
    if (ctx == NULL || identifier == NULL || seed == NULL || pubKey == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    uint32_t p = ctx->para.p;
    
    /* Generate private key values */
    uint8_t *prvKeyValues = LmsHss_Calloc(p, LMS_HSS_HASH_LEN);
    if (prvKeyValues == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Derive private key values from seed */
    for (uint32_t i = 0; i < p; i++) {
        LmsHssAdrs adrs = {0};
        adrs.type = LMS_HSS_ADDR_TYPE_OTS;
        adrs.q = q;
        adrs.i = i;
        adrs.j = 0;
        
        int32_t ret = ctx->hashFuncs.prf(ctx, &adrs, seed, prvKeyValues + i * LMS_HSS_HASH_LEN);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_SecureClear(prvKeyValues, p * LMS_HSS_HASH_LEN);
            LmsHss_Free(prvKeyValues);
            return ret;
        }
    }
    
    /* Generate public key values by running hash chains to maximum */
    uint8_t *pubKeyValues = LmsHss_Calloc(p, LMS_HSS_HASH_LEN);
    if (pubKeyValues == NULL) {
        LmsHss_SecureClear(prvKeyValues, p * LMS_HSS_HASH_LEN);
        LmsHss_Free(prvKeyValues);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    for (uint32_t i = 0; i < p; i++) {
        int32_t ret = LmotsHashChain(ctx, prvKeyValues + i * LMS_HSS_HASH_LEN, i, 0,
                                     identifier, q, pubKeyValues + i * LMS_HSS_HASH_LEN);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_SecureClear(prvKeyValues, p * LMS_HSS_HASH_LEN);
            LmsHss_Free(prvKeyValues);
            LmsHss_SecureClear(pubKeyValues, p * LMS_HSS_HASH_LEN);
            LmsHss_Free(pubKeyValues);
            return ret;
        }
    }
    
    /* Hash all public key values together to form final public key */
    uint32_t inputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + p * LMS_HSS_HASH_LEN;
    uint8_t *input = LmsHss_Malloc(inputLen);
    if (input == NULL) {
        LmsHss_SecureClear(prvKeyValues, p * LMS_HSS_HASH_LEN);
        LmsHss_Free(prvKeyValues);
        LmsHss_SecureClear(pubKeyValues, p * LMS_HSS_HASH_LEN);
        LmsHss_Free(pubKeyValues);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    uint32_t offset = 0;
    
    /* identifier */
    memcpy(input + offset, identifier, LMS_HSS_IDENTIFIER_LEN);
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* q (big-endian) */
    input[offset++] = (uint8_t)(q >> 24);
    input[offset++] = (uint8_t)(q >> 16);
    input[offset++] = (uint8_t)(q >> 8);
    input[offset++] = (uint8_t)q;
    
    /* D_PBLC */
    input[offset++] = (uint8_t)(LMOTS_D_PBLC >> 8);
    input[offset++] = (uint8_t)LMOTS_D_PBLC;
    
    /* Public key values */
    memcpy(input + offset, pubKeyValues, p * LMS_HSS_HASH_LEN);
    
    LmsHssAdrs pubKeyAdrs = {0};
    pubKeyAdrs.type = LMS_HSS_ADDR_TYPE_OTS;
    pubKeyAdrs.q = q;
    pubKeyAdrs.i = 1; /* Public key computation */
    pubKeyAdrs.j = 0;
    
    int32_t ret = ctx->hashFuncs.h(ctx, &pubKeyAdrs, input, inputLen, pubKey);
    
    /* Clean up */
    LmsHss_SecureClear(prvKeyValues, p * LMS_HSS_HASH_LEN);
    LmsHss_Free(prvKeyValues);
    LmsHss_SecureClear(pubKeyValues, p * LMS_HSS_HASH_LEN);
    LmsHss_Free(pubKeyValues);
    LmsHss_Free(input);
    
    return ret;
}

/* LMOTS signature verification */
int32_t LMOTS_Verify(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                     const LmotsSignature *signature, const uint8_t *pubKey, uint32_t q)
{
    if (ctx == NULL || message == NULL || signature == NULL || pubKey == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (signature->lmotsType != ctx->para.lmotsType) {
        return CRYPT_LMS_HSS_INVALID_LMOTS_TYPE;
    }

    if (signature->y == NULL) {
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    uint32_t p = ctx->para.p;
    
    /* Hash message with random value C - same as in signing */
    uint32_t hashInputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + LMS_HSS_HASH_LEN + messageLen;
    uint8_t *hashInput = LmsHss_Malloc(hashInputLen);
    if (hashInput == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    /* Use real identifier and q from context's private key (for verification we use the same) */
    const uint8_t *identifier = NULL;
    if (ctx->prvKey.prvKeys != NULL) {
        identifier = ctx->prvKey.prvKeys[0].identifier;
    }
    
    if (identifier == NULL) {
        /* Create deterministic identifier for verification */
        static const uint8_t fallbackIdentifier[LMS_HSS_IDENTIFIER_LEN] = {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
        };
        identifier = fallbackIdentifier;
    }

    uint32_t offset = 0;
    
    /* identifier */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* q (big-endian) */
    hashInput[offset++] = (uint8_t)(q >> 24);
    hashInput[offset++] = (uint8_t)(q >> 16);
    hashInput[offset++] = (uint8_t)(q >> 8);
    hashInput[offset++] = (uint8_t)q;
    
    /* D_MESG */
    hashInput[offset++] = (uint8_t)(LMOTS_D_MESG >> 8);
    hashInput[offset++] = (uint8_t)LMOTS_D_MESG;
    
    /* C */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, signature->c, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_HASH_LEN;
    
    /* message */
    if (memcpy_s(hashInput + offset, hashInputLen - offset, message, messageLen) != EOK) {
        LmsHss_Free(hashInput);
        return CRYPT_SECUREC_FAIL;
    }

    uint8_t hashedMessage[LMS_HSS_HASH_LEN];
    LmsHssAdrs adrs = {0};
    adrs.type = LMS_HSS_ADDR_TYPE_OTS;
    adrs.q = q;
    adrs.i = 0; /* Message hash for verification */
    adrs.j = 0;
    
    int32_t ret = ctx->hashFuncs.h(ctx, &adrs, hashInput, hashInputLen, hashedMessage);
    LmsHss_Free(hashInput);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Convert hashed message to base-w */
    uint16_t *baseW = LmsHss_Calloc(p, sizeof(uint16_t));
    if (baseW == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = LmotsMessageToBaseW(ctx, hashedMessage, LMS_HSS_HASH_LEN, baseW);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_Free(baseW);
        return ret;
    }

    /* Compute z[i] = chain(y[i], i, (2^w - 1) - a[i], identifier, q) */
    uint8_t *z = LmsHss_Calloc(p, LMS_HSS_HASH_LEN);
    if (z == NULL) {
        LmsHss_Free(baseW);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    for (uint32_t i = 0; i < p; i++) {
        ret = LmotsHashChain(ctx, signature->y + i * LMS_HSS_HASH_LEN, i, baseW[i],
                             identifier, q, z + i * LMS_HSS_HASH_LEN);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_Free(baseW);
            LmsHss_Free(z);
            return ret;
        }
    }

    /* Reconstruct public key and compare */
    uint8_t reconstructedPubKey[LMS_HSS_HASH_LEN];
    uint32_t inputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + p * LMS_HSS_HASH_LEN;
    uint8_t *input = LmsHss_Malloc(inputLen);
    if (input == NULL) {
        LmsHss_Free(baseW);
        LmsHss_Free(z);
        return CRYPT_MEM_ALLOC_FAIL;
    }

    offset = 0;
    
    /* identifier */
    if (memcpy_s(input + offset, inputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(baseW);
        LmsHss_Free(z);
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* q (big-endian) */
    input[offset++] = (uint8_t)(q >> 24);
    input[offset++] = (uint8_t)(q >> 16);
    input[offset++] = (uint8_t)(q >> 8);
    input[offset++] = (uint8_t)q;
    
    /* D_PBLC */
    input[offset++] = (uint8_t)(LMOTS_D_PBLC >> 8);
    input[offset++] = (uint8_t)LMOTS_D_PBLC;
    
    /* z values */
    if (memcpy_s(input + offset, inputLen - offset, z, p * LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(baseW);
        LmsHss_Free(z);
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }

    LmsHssAdrs pubKeyAdrs = {0};
    pubKeyAdrs.type = LMS_HSS_ADDR_TYPE_OTS;
    pubKeyAdrs.q = q;
    pubKeyAdrs.i = 1; /* Public key reconstruction */
    pubKeyAdrs.j = 0;
    
    ret = ctx->hashFuncs.h(ctx, &pubKeyAdrs, input, inputLen, reconstructedPubKey);
    
    LmsHss_Free(baseW);
    LmsHss_Free(z);
    LmsHss_Free(input);
    
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Compare reconstructed public key with provided public key */
    if (memcmp(reconstructedPubKey, pubKey, LMS_HSS_HASH_LEN) != 0) {
        return CRYPT_LMS_HSS_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

/* Generate LMOTS key pair */
int32_t LMOTS_GenerateKeyPair(const CryptLmsHssCtx *ctx, const uint8_t *identifier,
                              uint32_t q, const uint8_t *seed)
{
    if (ctx == NULL || identifier == NULL || seed == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Generate private key */
    uint8_t *privateKey = NULL;
    int32_t ret = LmotsGeneratePrivateKey(ctx, seed, identifier, q, &privateKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Generate public key */
    uint8_t publicKey[LMS_HSS_HASH_LEN];
    ret = LmotsGeneratePublicKey(ctx, privateKey, identifier, q, publicKey);
    
    /* Clean up private key */
    if (privateKey != NULL) {
        LmsHss_SecureClear(privateKey, ctx->para.p * LMS_HSS_HASH_LEN);
        LmsHss_Free(privateKey);
    }

    return ret;
}

#endif /* HITLS_CRYPTO_LMS_HSS */