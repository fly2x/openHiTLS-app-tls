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

/* Hash functions initialization is now in lms_hss_hash.c */

/* Allocate HSS private key structure */
static int32_t HssAllocatePrivateKey(HssPrvKey *prvKey, uint32_t levels)
{
    if (prvKey == NULL || levels == 0 || levels > LMS_HSS_MAX_LEVELS) {
        return CRYPT_INVALID_ARG;
    }

    prvKey->levels = levels;
    
    /* Allocate array of LMS private keys */
    prvKey->prvKeys = LmsHss_Calloc(levels, sizeof(LmsPrvKey));
    if (prvKey->prvKeys == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    /* Allocate array of signatures for intermediate levels */
    if (levels > 1) {
        prvKey->signatures = LmsHss_Calloc(levels - 1, sizeof(uint8_t *));
        if (prvKey->signatures == NULL) {
            LmsHss_Free(prvKey->prvKeys);
            prvKey->prvKeys = NULL;
            return CRYPT_MEM_ALLOC_FAIL;
        }
    } else {
        prvKey->signatures = NULL;
    }

    return CRYPT_SUCCESS;
}

/* Free HSS private key structure */
static void HssFreePrivateKey(HssPrvKey *prvKey)
{
    if (prvKey == NULL) {
        return;
    }

    if (prvKey->prvKeys != NULL) {
        /* Clear sensitive data */
        for (uint32_t i = 0; i < prvKey->levels; i++) {
            LmsHss_SecureClear(&prvKey->prvKeys[i], sizeof(LmsPrvKey));
        }
        LmsHss_Free(prvKey->prvKeys);
        prvKey->prvKeys = NULL;
    }

    if (prvKey->signatures != NULL) {
        for (uint32_t i = 0; i < prvKey->levels - 1; i++) {
            if (prvKey->signatures[i] != NULL) {
                /* Assuming we know the signature length */
                LmsHss_SecureClear(prvKey->signatures[i], 1000); /* TODO: use actual length */
                LmsHss_Free(prvKey->signatures[i]);
                prvKey->signatures[i] = NULL;
            }
        }
        LmsHss_Free(prvKey->signatures);
        prvKey->signatures = NULL;
    }

    prvKey->levels = 0;
}

/* Generate HSS key pair */
int32_t HSS_GenerateKeyPair(CryptLmsHssCtx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    int32_t ret = LmsHss_ValidatePara(&ctx->para);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Initialize hash functions */
    ret = LmsHss_InitHashFuncs(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Set up HSS public key structure */
    ctx->pubKey.levels = ctx->para.levels;

    /* Allocate HSS private key structure */
    ret = HssAllocatePrivateKey(&ctx->prvKey, ctx->para.levels);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Generate LMS key pairs for each level */
    for (uint32_t level = 0; level < ctx->para.levels; level++) {
        ret = LMS_GenerateKeyPair(ctx, level);
        if (ret != CRYPT_SUCCESS) {
            HssFreePrivateKey(&ctx->prvKey);
            return ret;
        }
    }

    /* For multi-level HSS, generate signatures for intermediate levels */
    for (uint32_t level = 0; level < ctx->para.levels - 1; level++) {
        /* Serialize the public key of the next level */
        LmsPubKey *nextLevelPubKey = &ctx->prvKey.prvKeys[level + 1].pubKey;
        
        /* Create message to sign (serialized public key) */
        uint32_t pubKeyMsgLen = 4 + 4 + LMS_HSS_IDENTIFIER_LEN + LMS_HSS_HASH_LEN;
        uint8_t *pubKeyMsg = LmsHss_Malloc(pubKeyMsgLen);
        if (pubKeyMsg == NULL) {
            HssFreePrivateKey(&ctx->prvKey);
            return CRYPT_MEM_ALLOC_FAIL;
        }

        uint32_t offset = 0;
        
        /* LMS type (big-endian) */
        pubKeyMsg[offset++] = (uint8_t)(nextLevelPubKey->lmsType >> 24);
        pubKeyMsg[offset++] = (uint8_t)(nextLevelPubKey->lmsType >> 16);
        pubKeyMsg[offset++] = (uint8_t)(nextLevelPubKey->lmsType >> 8);
        pubKeyMsg[offset++] = (uint8_t)nextLevelPubKey->lmsType;
        
        /* LMOTS type (big-endian) */
        pubKeyMsg[offset++] = (uint8_t)(nextLevelPubKey->lmotsType >> 24);
        pubKeyMsg[offset++] = (uint8_t)(nextLevelPubKey->lmotsType >> 16);
        pubKeyMsg[offset++] = (uint8_t)(nextLevelPubKey->lmotsType >> 8);
        pubKeyMsg[offset++] = (uint8_t)nextLevelPubKey->lmotsType;
        
        /* Identifier */
        if (memcpy_s(pubKeyMsg + offset, pubKeyMsgLen - offset, 
                     nextLevelPubKey->identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
            LmsHss_Free(pubKeyMsg);
            HssFreePrivateKey(&ctx->prvKey);
            return CRYPT_SECUREC_FAIL;
        }
        offset += LMS_HSS_IDENTIFIER_LEN;
        
        /* Root hash */
        if (memcpy_s(pubKeyMsg + offset, pubKeyMsgLen - offset,
                     nextLevelPubKey->root, LMS_HSS_HASH_LEN) != EOK) {
            LmsHss_Free(pubKeyMsg);
            HssFreePrivateKey(&ctx->prvKey);
            return CRYPT_SECUREC_FAIL;
        }

        /* Generate LMS signature for this public key */
        LmsSignature signature;
        ret = LMS_Sign(ctx, pubKeyMsg, pubKeyMsgLen, level, &signature);
        
        LmsHss_Free(pubKeyMsg);
        
        if (ret != CRYPT_SUCCESS) {
            HssFreePrivateKey(&ctx->prvKey);
            return ret;
        }

        /* Serialize and store the signature */
        uint32_t sigLen = ctx->para.sigLen;
        ctx->prvKey.signatures[level] = LmsHss_Malloc(sigLen);
        if (ctx->prvKey.signatures[level] == NULL) {
            /* Clean up signature */
            if (signature.lmotsSignature.y != NULL) {
                LmsHss_SecureClear(signature.lmotsSignature.y, ctx->para.p * LMS_HSS_HASH_LEN);
                LmsHss_Free(signature.lmotsSignature.y);
            }
            HssFreePrivateKey(&ctx->prvKey);
            return CRYPT_MEM_ALLOC_FAIL;
        }

        /* TODO: Implement proper signature serialization */
        /* For now, just store a placeholder */
        (void)memset_s(ctx->prvKey.signatures[level], sigLen, 0, sigLen);
        
        /* Clean up temporary signature structure */
        if (signature.lmotsSignature.y != NULL) {
            LmsHss_SecureClear(signature.lmotsSignature.y, ctx->para.p * LMS_HSS_HASH_LEN);
            LmsHss_Free(signature.lmotsSignature.y);
        }
    }

    ctx->keyType = LMS_HSS_KEYPAIR;
    
    return CRYPT_SUCCESS;
}

/* HSS signature generation */
int32_t HSS_Sign(CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                 HssSignature *signature)
{
    if (ctx == NULL || message == NULL || signature == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (!(ctx->keyType & LMS_HSS_PRVKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    uint32_t levels = ctx->para.levels;
    
    /* Check if we can still sign (bottom level tree not exhausted) */
    uint32_t bottomLevel = levels - 1;
    uint32_t maxSignatures = 1 << ctx->para.h;
    
    if (ctx->prvKey.prvKeys[bottomLevel].q >= maxSignatures) {
        /* Check if we can advance to next tree */
        bool canAdvance = false;
        for (uint32_t level = bottomLevel; level > 0; level--) {
            if (ctx->prvKey.prvKeys[level - 1].q < maxSignatures - 1) {
                canAdvance = true;
                break;
            }
        }
        
        if (!canAdvance) {
            return CRYPT_LMS_HSS_TREE_EXHAUSTED;
        }
        
        /* TODO: Implement tree advancement logic */
        /* For now, just return exhausted */
        return CRYPT_LMS_HSS_TREE_EXHAUSTED;
    }

    /* Set up signature structure */
    if (levels == 1) {
        signature->nspk = 0;
        signature->lmsSignatures = NULL;
        signature->pubKeys = NULL;
    } else {
        signature->nspk = levels - 1;
        
        /* Allocate arrays */
        signature->lmsSignatures = LmsHss_Calloc(levels, sizeof(LmsSignature));
        if (signature->lmsSignatures == NULL) {
            return CRYPT_MEM_ALLOC_FAIL;
        }
        
        signature->pubKeys = LmsHss_Calloc(levels - 1, sizeof(LmsPubKey));
        if (signature->pubKeys == NULL) {
            LmsHss_Free(signature->lmsSignatures);
            signature->lmsSignatures = NULL;
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }

    /* Generate the bottom-level LMS signature */
    int32_t ret = LMS_Sign(ctx, message, messageLen, bottomLevel, 
                           &signature->lmsSignatures[levels - 1]);
    if (ret != CRYPT_SUCCESS) {
        if (signature->lmsSignatures != NULL) {
            LmsHss_Free(signature->lmsSignatures);
            signature->lmsSignatures = NULL;
        }
        if (signature->pubKeys != NULL) {
            LmsHss_Free(signature->pubKeys);
            signature->pubKeys = NULL;
        }
        return ret;
    }

    /* For multi-level HSS, include the intermediate signatures and public keys */
    for (uint32_t level = 0; level < levels - 1; level++) {
        /* Copy the stored signature for this level */
        /* TODO: Implement proper signature deserialization */
        /* For now, create a minimal signature structure */
        signature->lmsSignatures[level].q = ctx->prvKey.prvKeys[level].q;
        signature->lmsSignatures[level].lmsType = ctx->para.lmsType;
        signature->lmsSignatures[level].lmotsSignature.lmotsType = ctx->para.lmotsType;
        
        /* Copy public key for next level */
        if (memcpy_s(&signature->pubKeys[level], sizeof(LmsPubKey),
                     &ctx->prvKey.prvKeys[level + 1].pubKey, sizeof(LmsPubKey)) != EOK) {
            /* Clean up on error */
            if (signature->lmsSignatures[levels - 1].lmotsSignature.y != NULL) {
                LmsHss_SecureClear(signature->lmsSignatures[levels - 1].lmotsSignature.y,
                                   ctx->para.p * LMS_HSS_HASH_LEN);
                LmsHss_Free(signature->lmsSignatures[levels - 1].lmotsSignature.y);
            }
            LmsHss_Free(signature->lmsSignatures);
            LmsHss_Free(signature->pubKeys);
            signature->lmsSignatures = NULL;
            signature->pubKeys = NULL;
            return CRYPT_SECUREC_FAIL;
        }
    }

    return CRYPT_SUCCESS;
}

/* HSS signature verification */
int32_t HSS_Verify(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                   const HssSignature *signature)
{
    if (ctx == NULL || message == NULL || signature == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (!(ctx->keyType & LMS_HSS_PUBKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    uint32_t levels = ctx->pubKey.levels;
    
    /* For single-level HSS, just verify the LMS signature */
    if (levels == 1) {
        if (signature->nspk != 0 || signature->lmsSignatures == NULL) {
            return CRYPT_LMS_HSS_INVALID_SIGNATURE;
        }
        
        return LMS_Verify(ctx, message, messageLen, &signature->lmsSignatures[0],
                          &ctx->pubKey.topLevelPubKey);
    }

    /* For multi-level HSS, verify the signature chain */
    if (signature->nspk != levels - 1) {
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    if (signature->lmsSignatures == NULL || signature->pubKeys == NULL) {
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    /* Verify intermediate signatures */
    LmsPubKey currentPubKey = ctx->pubKey.topLevelPubKey;
    
    for (uint32_t level = 0; level < levels - 1; level++) {
        /* Create message from next level's public key */
        LmsPubKey *nextPubKey = &signature->pubKeys[level];
        
        uint32_t pubKeyMsgLen = 4 + 4 + LMS_HSS_IDENTIFIER_LEN + LMS_HSS_HASH_LEN;
        uint8_t *pubKeyMsg = LmsHss_Malloc(pubKeyMsgLen);
        if (pubKeyMsg == NULL) {
            return CRYPT_MEM_ALLOC_FAIL;
        }

        uint32_t offset = 0;
        
        /* Serialize public key */
        pubKeyMsg[offset++] = (uint8_t)(nextPubKey->lmsType >> 24);
        pubKeyMsg[offset++] = (uint8_t)(nextPubKey->lmsType >> 16);
        pubKeyMsg[offset++] = (uint8_t)(nextPubKey->lmsType >> 8);
        pubKeyMsg[offset++] = (uint8_t)nextPubKey->lmsType;
        
        pubKeyMsg[offset++] = (uint8_t)(nextPubKey->lmotsType >> 24);
        pubKeyMsg[offset++] = (uint8_t)(nextPubKey->lmotsType >> 16);
        pubKeyMsg[offset++] = (uint8_t)(nextPubKey->lmotsType >> 8);
        pubKeyMsg[offset++] = (uint8_t)nextPubKey->lmotsType;
        
        if (memcpy_s(pubKeyMsg + offset, pubKeyMsgLen - offset,
                     nextPubKey->identifier, LMS_HSS_IDENTIFIER_LEN) != EOK ||
            memcpy_s(pubKeyMsg + offset + LMS_HSS_IDENTIFIER_LEN, 
                     pubKeyMsgLen - offset - LMS_HSS_IDENTIFIER_LEN,
                     nextPubKey->root, LMS_HSS_HASH_LEN) != EOK) {
            LmsHss_Free(pubKeyMsg);
            return CRYPT_SECUREC_FAIL;
        }

        /* Verify signature */
        int32_t ret = LMS_Verify(ctx, pubKeyMsg, pubKeyMsgLen, 
                                 &signature->lmsSignatures[level], &currentPubKey);
        
        LmsHss_Free(pubKeyMsg);
        
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }

        /* Move to next level */
        currentPubKey = *nextPubKey;
    }

    /* Verify the final message signature */
    return LMS_Verify(ctx, message, messageLen, &signature->lmsSignatures[levels - 1],
                      &currentPubKey);
}

#endif /* HITLS_CRYPTO_LMS_HSS */

