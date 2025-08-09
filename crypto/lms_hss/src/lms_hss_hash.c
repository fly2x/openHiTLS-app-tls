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
#include <arpa/inet.h>
#include "securec.h"
#include "bsl_err.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_utils.h"
#include "eal_md_local.h"
#include "lms_hss_local.h"
#include "crypt_lms_hss.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"

#define MAX_MDSIZE 64
#define LMS_HSS_DOMAIN_SEPARATOR_LEN 2

/* Multi-message hash calculation - reused from SLH-DSA design */
static int32_t LmsHss_CalcMultiMsgHash(CRYPT_MD_AlgId mdId, const CRYPT_ConstData *hashData, uint32_t hashDataLen,
                                       uint8_t *out, uint32_t outLen)
{
    uint8_t tmp[MAX_MDSIZE] = {0};
    uint32_t tmpLen = sizeof(tmp);
    int32_t ret = CRYPT_CalcHash(NULL, EAL_MdFindDefaultMethod(mdId), hashData, hashDataLen, tmp, &tmpLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (outLen > tmpLen) {
        outLen = tmpLen;
    }
    (void)memcpy_s(out, outLen, tmp, outLen);
    return CRYPT_SUCCESS;
}

/* LMS PRF function - deterministic pseudorandom function */
static int32_t LmsHss_Prf(const CryptLmsHssCtx *ctx, const LmsHssAdrs *adrs, const uint8_t *seed, uint8_t *out)
{
    if (ctx == NULL || adrs == NULL || seed == NULL || out == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    uint32_t n = ctx->para.n;
    uint32_t qBE = htonl(adrs->q);  /* Convert to big-endian */
    uint16_t iBE = htons(adrs->i);  /* Convert to big-endian */
    uint8_t j = adrs->j;
    
    const CRYPT_ConstData hashData[] = {
        {ctx->prvKey.prvKeys[0].identifier, LMS_HSS_IDENTIFIER_LEN}, // I
        {(const uint8_t *)&qBE, 4},                                  // q (4 bytes big-endian)
        {(const uint8_t *)&iBE, 2},                                  // i (2 bytes big-endian)  
        {&j, 1},                                                     // j (1 byte)
        {seed, LMS_HSS_SEED_LEN}                                     // SEED
    };
    
    return LmsHss_CalcMultiMsgHash(CRYPT_MD_SHA256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

/* LMS hash function for tree nodes */
static int32_t LmsHss_H(const CryptLmsHssCtx *ctx, const LmsHssAdrs *adrs, const uint8_t *msg, uint32_t msgLen,
                        uint8_t *out)
{
    if (ctx == NULL || adrs == NULL || msg == NULL || out == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    uint32_t n = ctx->para.n;
    uint8_t domainSep[LMS_HSS_DOMAIN_SEPARATOR_LEN] = {0};
    uint32_t qBE = htonl(adrs->q);
    uint16_t iBE = htons(adrs->i);
    uint8_t j = adrs->j;
    
    /* Set domain separator based on address type */
    domainSep[0] = 0x80 | (uint8_t)adrs->type; /* High bit set for LMS */
    domainSep[1] = 0x00;
    
    const CRYPT_ConstData hashData[] = {
        {ctx->prvKey.prvKeys[0].identifier, LMS_HSS_IDENTIFIER_LEN}, // I
        {(const uint8_t *)&qBE, 4},                                  // q
        {(const uint8_t *)&iBE, 2},                                  // i
        {&j, 1},                                                     // j
        {domainSep, LMS_HSS_DOMAIN_SEPARATOR_LEN},                   // Domain separator
        {msg, msgLen}                                                // Message/data
    };
    
    return LmsHss_CalcMultiMsgHash(CRYPT_MD_SHA256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

/* LMOTS hash function for one-time signatures */
static int32_t LmsHss_F(const CryptLmsHssCtx *ctx, const LmsHssAdrs *adrs, const uint8_t *msg, uint32_t msgLen,
                        uint8_t *out)
{
    if (ctx == NULL || adrs == NULL || msg == NULL || out == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    uint32_t n = ctx->para.n;
    uint8_t domainSep[LMS_HSS_DOMAIN_SEPARATOR_LEN] = {0};
    uint32_t qBE = htonl(adrs->q);
    uint16_t iBE = htons(adrs->i);
    uint8_t j = adrs->j;
    
    /* Set domain separator for LMOTS */
    domainSep[0] = 0x40 | (uint8_t)adrs->type; /* Different pattern for LMOTS */
    domainSep[1] = j; /* Chain position in LMOTS */
    
    const CRYPT_ConstData hashData[] = {
        {ctx->prvKey.prvKeys[0].identifier, LMS_HSS_IDENTIFIER_LEN}, // I
        {(const uint8_t *)&qBE, 4},                                  // q
        {(const uint8_t *)&iBE, 2},                                  // i
        {domainSep, LMS_HSS_DOMAIN_SEPARATOR_LEN},                   // Domain separator
        {msg, msgLen}                                                // Message/data
    };
    
    return LmsHss_CalcMultiMsgHash(CRYPT_MD_SHA256, hashData, sizeof(hashData) / sizeof(hashData[0]), out, n);
}

/* Initialize hash functions for LMS/HSS context */
int32_t LmsHss_InitHashFuncs(CryptLmsHssCtx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Set up hash function pointers - following SLH-DSA pattern */
    ctx->hashFuncs.h = LmsHss_H;     /* Tree hash function */
    ctx->hashFuncs.f = LmsHss_F;     /* LMOTS chain function */
    ctx->hashFuncs.prf = LmsHss_Prf; /* Deterministic PRF */

    return CRYPT_SUCCESS;
}

/* Deterministic key generation using seed */
int32_t LmsHss_GenerateFromSeed(CryptLmsHssCtx *ctx, const uint8_t *seed, uint32_t seedLen)
{
    if (ctx == NULL || seed == NULL || seedLen < LMS_HSS_SEED_LEN) {
        return CRYPT_NULL_INPUT;
    }

    /* Initialize deterministic random state using provided seed */
    for (uint32_t level = 0; level < ctx->para.levels; level++) {
        if (ctx->prvKey.prvKeys == NULL) {
            ctx->prvKey.prvKeys = BSL_SAL_Calloc(ctx->para.levels, sizeof(LmsPrvKey));
            if (ctx->prvKey.prvKeys == NULL) {
                return CRYPT_MEM_ALLOC_FAIL;
            }
            ctx->prvKey.levels = ctx->para.levels;
        }
        
        LmsPrvKey *prvKey = &ctx->prvKey.prvKeys[level];
        
        /* Copy seed and derive level-specific parameters */
        (void)memcpy_s(prvKey->seed, LMS_HSS_SEED_LEN, seed, LMS_HSS_SEED_LEN);
        
        /* Generate level-specific identifier from seed and level */
        uint8_t levelBytes[4];
        levelBytes[0] = (uint8_t)(level >> 24);
        levelBytes[1] = (uint8_t)(level >> 16);
        levelBytes[2] = (uint8_t)(level >> 8);
        levelBytes[3] = (uint8_t)(level);
        
        const CRYPT_ConstData identData[] = {
            {seed, LMS_HSS_SEED_LEN},
            {levelBytes, 4}
        };
        
        uint8_t tmp[MAX_MDSIZE];
        int32_t ret = LmsHss_CalcMultiMsgHash(CRYPT_MD_SHA256, identData, 2, tmp, LMS_HSS_IDENTIFIER_LEN);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        (void)memcpy_s(prvKey->identifier, LMS_HSS_IDENTIFIER_LEN, tmp, LMS_HSS_IDENTIFIER_LEN);
        
        /* Set algorithm parameters */
        prvKey->lmsType = ctx->para.lmsType;
        prvKey->lmotsType = ctx->para.lmotsType;
        prvKey->q = 0; /* Start signature counter at 0 */
    }
    
    ctx->keyType |= LMS_HSS_PRVKEY;
    return CRYPT_SUCCESS;
}

/* Backward compatibility hash function */
int32_t LmsHss_Hash(const CryptLmsHssCtx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *hash)
{
    if (ctx == NULL || data == NULL || hash == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Use simple address for compatibility */
    LmsHssAdrs adrs = {0};
    adrs.type = 0; /* Generic hash */
    return ctx->hashFuncs.h(ctx, &adrs, data, dataLen, hash);
}

/* Backward compatibility PRF function */
int32_t LmsHss_PRF(const CryptLmsHssCtx *ctx, const uint8_t *key, const uint8_t *data, 
                   uint32_t dataLen, uint8_t *out)
{
    (void)dataLen; /* Unused parameter */
    if (ctx == NULL || key == NULL || data == NULL || out == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Use simple address for compatibility */
    LmsHssAdrs adrs = {0};
    adrs.type = 1; /* PRF type */
    return ctx->hashFuncs.prf(ctx, &adrs, key, out);
}

#endif /* HITLS_CRYPTO_LMS_HSS */