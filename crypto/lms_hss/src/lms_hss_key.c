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
#include "crypt_lms_hss.h"
#include "lms_hss_local.h"

/* Serialize HSS public key to binary format (RFC 8554) */
int32_t LmsHss_SerializePublicKey(const CryptLmsHssCtx *ctx, uint8_t **data, uint32_t *dataLen)
{
    if (ctx == NULL || data == NULL || dataLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (!(ctx->keyType & LMS_HSS_PUBKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* HSS public key format: levels(4) + LMS_pubkey */
    /* LMS_pubkey format: lms_type(4) + lmots_type(4) + identifier(16) + T[1](32) */
    uint32_t keyLen = 4 + 4 + 4 + LMS_HSS_IDENTIFIER_LEN + LMS_HSS_HASH_LEN;
    
    uint8_t *keyData = LmsHss_Malloc(keyLen);
    if (keyData == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    
    /* levels (big-endian) */
    keyData[offset++] = (uint8_t)(ctx->pubKey.levels >> 24);
    keyData[offset++] = (uint8_t)(ctx->pubKey.levels >> 16);
    keyData[offset++] = (uint8_t)(ctx->pubKey.levels >> 8);
    keyData[offset++] = (uint8_t)ctx->pubKey.levels;
    
    /* lms_type (big-endian) */
    keyData[offset++] = (uint8_t)(ctx->pubKey.topLevelPubKey.lmsType >> 24);
    keyData[offset++] = (uint8_t)(ctx->pubKey.topLevelPubKey.lmsType >> 16);
    keyData[offset++] = (uint8_t)(ctx->pubKey.topLevelPubKey.lmsType >> 8);
    keyData[offset++] = (uint8_t)ctx->pubKey.topLevelPubKey.lmsType;
    
    /* lmots_type (big-endian) */
    keyData[offset++] = (uint8_t)(ctx->pubKey.topLevelPubKey.lmotsType >> 24);
    keyData[offset++] = (uint8_t)(ctx->pubKey.topLevelPubKey.lmotsType >> 16);
    keyData[offset++] = (uint8_t)(ctx->pubKey.topLevelPubKey.lmotsType >> 8);
    keyData[offset++] = (uint8_t)ctx->pubKey.topLevelPubKey.lmotsType;
    
    /* identifier */
    if (memcpy_s(keyData + offset, keyLen - offset, 
                 ctx->pubKey.topLevelPubKey.identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(keyData);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* root (T[1]) */
    if (memcpy_s(keyData + offset, keyLen - offset, 
                 ctx->pubKey.topLevelPubKey.root, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(keyData);
        return CRYPT_SECUREC_FAIL;
    }
    
    *data = keyData;
    *dataLen = keyLen;
    
    return CRYPT_SUCCESS;
}

/* Deserialize HSS public key from binary format */
int32_t LmsHss_DeserializePublicKey(CryptLmsHssCtx *ctx, const uint8_t *data, uint32_t dataLen)
{
    if (ctx == NULL || data == NULL || dataLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    /* Minimum size check */
    uint32_t minLen = 4 + 4 + 4 + LMS_HSS_IDENTIFIER_LEN + LMS_HSS_HASH_LEN;
    if (dataLen < minLen) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    uint32_t offset = 0;
    
    /* levels (big-endian) */
    ctx->pubKey.levels = ((uint32_t)data[offset] << 24) |
                        ((uint32_t)data[offset + 1] << 16) |
                        ((uint32_t)data[offset + 2] << 8) |
                        (uint32_t)data[offset + 3];
    offset += 4;
    
    /* Validate levels */
    if (ctx->pubKey.levels == 0 || ctx->pubKey.levels > LMS_HSS_MAX_LEVELS) {
        return CRYPT_LMS_HSS_INVALID_LEVEL;
    }
    
    /* lms_type (big-endian) */
    ctx->pubKey.topLevelPubKey.lmsType = ((uint32_t)data[offset] << 24) |
                                        ((uint32_t)data[offset + 1] << 16) |
                                        ((uint32_t)data[offset + 2] << 8) |
                                        (uint32_t)data[offset + 3];
    offset += 4;
    
    /* lmots_type (big-endian) */
    ctx->pubKey.topLevelPubKey.lmotsType = ((uint32_t)data[offset] << 24) |
                                          ((uint32_t)data[offset + 1] << 16) |
                                          ((uint32_t)data[offset + 2] << 8) |
                                          (uint32_t)data[offset + 3];
    offset += 4;
    
    /* identifier */
    if (memcpy_s(ctx->pubKey.topLevelPubKey.identifier, LMS_HSS_IDENTIFIER_LEN,
                 data + offset, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* root (T[1]) */
    if (memcpy_s(ctx->pubKey.topLevelPubKey.root, LMS_HSS_HASH_LEN,
                 data + offset, LMS_HSS_HASH_LEN) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }
    
    /* Initialize parameters based on key data */
    int32_t ret = LmsHss_InitPara(&ctx->para, ctx->pubKey.topLevelPubKey.lmsType, 
                                  ctx->pubKey.topLevelPubKey.lmotsType, ctx->pubKey.levels);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    /* Mark public key as set */
    ctx->keyType |= LMS_HSS_PUBKEY;
    
    return CRYPT_SUCCESS;
}

/* Serialize HSS private key to binary format */
int32_t LmsHss_SerializePrivateKey(const CryptLmsHssCtx *ctx, uint8_t **data, uint32_t *dataLen)
{
    if (ctx == NULL || data == NULL || dataLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (!(ctx->keyType & LMS_HSS_PRVKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* HSS private key format: levels(4) + array of LMS private keys */
    /* LMS_prvkey format: lms_type(4) + lmots_type(4) + identifier(16) + q(4) + seed(32) */
    uint32_t lmsPrvLen = 4 + 4 + LMS_HSS_IDENTIFIER_LEN + 4 + LMS_HSS_SEED_LEN;
    uint32_t keyLen = 4 + ctx->prvKey.levels * lmsPrvLen;
    
    uint8_t *keyData = LmsHss_Malloc(keyLen);
    if (keyData == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    
    /* levels (big-endian) */
    keyData[offset++] = (uint8_t)(ctx->prvKey.levels >> 24);
    keyData[offset++] = (uint8_t)(ctx->prvKey.levels >> 16);
    keyData[offset++] = (uint8_t)(ctx->prvKey.levels >> 8);
    keyData[offset++] = (uint8_t)ctx->prvKey.levels;
    
    /* Serialize each LMS private key */
    for (uint32_t i = 0; i < ctx->prvKey.levels; i++) {
        const LmsPrvKey *prvKey = &ctx->prvKey.prvKeys[i];
        
        /* lms_type (big-endian) */
        keyData[offset++] = (uint8_t)(prvKey->lmsType >> 24);
        keyData[offset++] = (uint8_t)(prvKey->lmsType >> 16);
        keyData[offset++] = (uint8_t)(prvKey->lmsType >> 8);
        keyData[offset++] = (uint8_t)prvKey->lmsType;
        
        /* lmots_type (big-endian) */
        keyData[offset++] = (uint8_t)(prvKey->lmotsType >> 24);
        keyData[offset++] = (uint8_t)(prvKey->lmotsType >> 16);
        keyData[offset++] = (uint8_t)(prvKey->lmotsType >> 8);
        keyData[offset++] = (uint8_t)prvKey->lmotsType;
        
        /* identifier */
        if (memcpy_s(keyData + offset, keyLen - offset, prvKey->identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
            LmsHss_SecureClear(keyData, keyLen);
            LmsHss_Free(keyData);
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_IDENTIFIER_LEN;
        
        /* q (big-endian) */
        keyData[offset++] = (uint8_t)(prvKey->q >> 24);
        keyData[offset++] = (uint8_t)(prvKey->q >> 16);
        keyData[offset++] = (uint8_t)(prvKey->q >> 8);
        keyData[offset++] = (uint8_t)prvKey->q;
        
        /* seed */
        if (memcpy_s(keyData + offset, keyLen - offset, prvKey->seed, LMS_HSS_SEED_LEN) != EOK) {
            LmsHss_SecureClear(keyData, keyLen);
            LmsHss_Free(keyData);
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_SEED_LEN;
    }
    
    *data = keyData;
    *dataLen = keyLen;
    
    return CRYPT_SUCCESS;
}

/* Deserialize HSS private key from binary format */
int32_t LmsHss_DeserializePrivateKey(CryptLmsHssCtx *ctx, const uint8_t *data, uint32_t dataLen)
{
    if (ctx == NULL || data == NULL || dataLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t offset = 0;
    
    /* levels (big-endian) */
    if (dataLen < 4) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }
    
    uint32_t levels = ((uint32_t)data[offset] << 24) |
                     ((uint32_t)data[offset + 1] << 16) |
                     ((uint32_t)data[offset + 2] << 8) |
                     (uint32_t)data[offset + 3];
    offset += 4;
    
    /* Validate levels */
    if (levels == 0 || levels > LMS_HSS_MAX_LEVELS) {
        return CRYPT_LMS_HSS_INVALID_LEVEL;
    }
    
    /* Check remaining data length */
    uint32_t lmsPrvLen = 4 + 4 + LMS_HSS_IDENTIFIER_LEN + 4 + LMS_HSS_SEED_LEN;
    uint32_t expectedLen = 4 + levels * lmsPrvLen;
    if (dataLen < expectedLen) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }
    
    /* Allocate private key array */
    ctx->prvKey.levels = levels;
    ctx->prvKey.prvKeys = LmsHss_Calloc(levels, sizeof(LmsPrvKey));
    if (ctx->prvKey.prvKeys == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Deserialize each LMS private key */
    for (uint32_t i = 0; i < levels; i++) {
        LmsPrvKey *prvKey = &ctx->prvKey.prvKeys[i];
        
        /* lms_type (big-endian) */
        prvKey->lmsType = ((uint32_t)data[offset] << 24) |
                         ((uint32_t)data[offset + 1] << 16) |
                         ((uint32_t)data[offset + 2] << 8) |
                         (uint32_t)data[offset + 3];
        offset += 4;
        
        /* lmots_type (big-endian) */
        prvKey->lmotsType = ((uint32_t)data[offset] << 24) |
                           ((uint32_t)data[offset + 1] << 16) |
                           ((uint32_t)data[offset + 2] << 8) |
                           (uint32_t)data[offset + 3];
        offset += 4;
        
        /* identifier */
        if (memcpy_s(prvKey->identifier, LMS_HSS_IDENTIFIER_LEN,
                     data + offset, LMS_HSS_IDENTIFIER_LEN) != EOK) {
            LmsHss_Free(ctx->prvKey.prvKeys);
            ctx->prvKey.prvKeys = NULL;
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_IDENTIFIER_LEN;
        
        /* q (big-endian) */
        prvKey->q = ((uint32_t)data[offset] << 24) |
                   ((uint32_t)data[offset + 1] << 16) |
                   ((uint32_t)data[offset + 2] << 8) |
                   (uint32_t)data[offset + 3];
        offset += 4;
        
        /* seed */
        if (memcpy_s(prvKey->seed, LMS_HSS_SEED_LEN,
                     data + offset, LMS_HSS_SEED_LEN) != EOK) {
            LmsHss_Free(ctx->prvKey.prvKeys);
            ctx->prvKey.prvKeys = NULL;
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_SEED_LEN;
    }
    
    /* Initialize parameters based on first level key */
    int32_t ret = LmsHss_InitPara(&ctx->para, ctx->prvKey.prvKeys[0].lmsType,
                                  ctx->prvKey.prvKeys[0].lmotsType, levels);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_Free(ctx->prvKey.prvKeys);
        ctx->prvKey.prvKeys = NULL;
        return ret;
    }
    
    /* Mark private key as set */
    ctx->keyType |= LMS_HSS_PRVKEY;
    
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_LMS_HSS */