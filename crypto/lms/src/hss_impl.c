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
#ifdef HITLS_CRYPTO_LMS

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_hss.h"
#include "lms_local.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"

/* Generate HSS key pair */
int32_t CRYPT_HSS_Gen(CRYPT_HSS_Ctx *ctx, const CRYPT_HSS_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (param->levels < 1 || param->levels > CRYPT_HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_HSS_LEVEL);
        return CRYPT_LMS_ERR_INVALID_HSS_LEVEL;
    }
    
    /* Store parameters */
    (void)memcpy_s(&ctx->param, sizeof(CRYPT_HSS_Param), param, sizeof(CRYPT_HSS_Param));
    
    /* Free existing keys */
    if (ctx->hssPrv != NULL) {
        FreeHssPrivateKey(ctx->hssPrv);
        ctx->hssPrv = NULL;
    }
    if (ctx->hssPub != NULL) {
        FreeHssPublicKey(ctx->hssPub);
        ctx->hssPub = NULL;
    }
    
    /* Allocate private key */
    ctx->hssPrv = BSL_SAL_Calloc(1, sizeof(HssPrivateKey));
    if (ctx->hssPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    ctx->hssPrv->levels = param->levels;
    
    /* Generate seed */
    if (CRYPT_Rand(ctx->hssPrv->seed, SEED_LEN) != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_RAND_FAIL);
        FreeHssPrivateKey(ctx->hssPrv);
        ctx->hssPrv = NULL;
        return CRYPT_LMS_ERR_RAND_FAIL;
    }
    
    /* Generate keys for each level */
    for (uint32_t i = 0; i < param->levels; i++) {
        ctx->hssPrv->lmsParam[i] = GetLmsParam(param->lmsParam[i]);
        ctx->hssPrv->lmotsParam[i] = GetLmotsParam(param->lmotsParam[i]);
        
        if (ctx->hssPrv->lmsParam[i] == NULL || ctx->hssPrv->lmotsParam[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
            FreeHssPrivateKey(ctx->hssPrv);
            ctx->hssPrv = NULL;
            return CRYPT_LMS_ERR_INVALID_ALGID;
        }
        
        /* Generate LMS tree for this level */
        int32_t ret = GenerateLmsTree(ctx->hssPrv, i);
        if (ret != CRYPT_SUCCESS) {
            FreeHssPrivateKey(ctx->hssPrv);
            ctx->hssPrv = NULL;
            return ret;
        }
    }
    
    /* Generate public key */
    ctx->hssPub = BSL_SAL_Calloc(1, sizeof(HssPublicKey));
    if (ctx->hssPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        FreeHssPrivateKey(ctx->hssPrv);
        ctx->hssPrv = NULL;
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    ctx->hssPub->levels = param->levels;
    ctx->hssPub->lmsParam = ctx->hssPrv->lmsParam[0];
    ctx->hssPub->lmotsParam = ctx->hssPrv->lmotsParam[0];
    (void)memcpy_s(ctx->hssPub->rootPub, sizeof(ctx->hssPub->rootPub), 
                   ctx->hssPrv->trees[0]->root, ctx->hssPrv->lmsParam[0]->n);
    
    return CRYPT_SUCCESS;
}

/* Sign a message using HSS */
int32_t CRYPT_HSS_Sign(CRYPT_HSS_Ctx *ctx, CRYPT_MD_AlgId mdId, 
                       const uint8_t *data, uint32_t dataLen,
                       uint8_t *sign, uint32_t *signLen)
{
    (void)mdId; /* HSS uses SHA-256 */
    
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->hssPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_NO_PRIVATE_KEY);
        return CRYPT_LMS_ERR_NO_PRIVATE_KEY;
    }
    
    /* Calculate signature size */
    uint32_t sigSize = sizeof(uint32_t); /* levels - 1 */
    for (uint32_t i = 0; i < ctx->hssPrv->levels; i++) {
        if (i < ctx->hssPrv->levels - 1) {
            /* Signed public key */
            sigSize += ctx->hssPrv->lmsParam[i]->sigLen;
            sigSize += sizeof(uint32_t) * 2; /* LMS/LM-OTS types */
            sigSize += ctx->hssPrv->lmsParam[i+1]->n;
        } else {
            /* Final LMS signature */
            sigSize += ctx->hssPrv->lmsParam[i]->sigLen;
        }
    }
    
    if (*signLen < sigSize) {
        *signLen = sigSize;
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    /* Generate HSS signature */
    uint8_t *sigPtr = sign;
    
    /* Write levels - 1 */
    uint32_t levelsMinusOne = ctx->hssPrv->levels - 1;
    CRYPT_PutBE32(levelsMinusOne, sigPtr);
    sigPtr += sizeof(uint32_t);
    
    /* Sign message with bottom tree */
    uint32_t bottomLevel = ctx->hssPrv->levels - 1;
    int32_t ret = LmsSignMessage(ctx->hssPrv->trees[bottomLevel], data, dataLen,
                                 sigPtr + (levelsMinusOne * (ctx->hssPrv->lmsParam[0]->sigLen + 
                                          sizeof(uint32_t) * 2 + ctx->hssPrv->lmsParam[0]->n)));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    /* Generate intermediate signatures */
    for (uint32_t i = 0; i < levelsMinusOne; i++) {
        /* Sign public key of next level */
        uint8_t pubKey[MAX_LMS_PUBLIC_KEY_SIZE];
        uint32_t pubKeyLen = sizeof(uint32_t) * 2 + ctx->hssPrv->lmsParam[i+1]->n;
        
        CRYPT_PutBE32(ctx->hssPrv->lmsParam[i+1]->algId, pubKey);
        CRYPT_PutBE32(ctx->hssPrv->lmotsParam[i+1]->algId, pubKey + sizeof(uint32_t));
        (void)memcpy_s(pubKey + sizeof(uint32_t) * 2, sizeof(pubKey) - sizeof(uint32_t) * 2,
                       ctx->hssPrv->trees[i+1]->root, ctx->hssPrv->lmsParam[i+1]->n);
        
        ret = LmsSignMessage(ctx->hssPrv->trees[i], pubKey, pubKeyLen, sigPtr);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        sigPtr += ctx->hssPrv->lmsParam[i]->sigLen;
        
        /* Append public key */
        (void)memcpy_s(sigPtr, sigSize - (sigPtr - sign), pubKey, pubKeyLen);
        sigPtr += pubKeyLen;
    }
    
    *signLen = sigSize;
    return CRYPT_SUCCESS;
}

/* Verify an HSS signature */
int32_t CRYPT_HSS_Verify(CRYPT_HSS_Ctx *ctx, CRYPT_MD_AlgId mdId,
                         const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen)
{
    (void)mdId; /* HSS uses SHA-256 */
    
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->hssPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_NO_PUBLIC_KEY);
        return CRYPT_LMS_ERR_NO_PUBLIC_KEY;
    }
    
    if (signLen < sizeof(uint32_t)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    /* Read levels - 1 */
    uint32_t levelsMinusOne = CRYPT_GetBE32(sign);
    const uint8_t *sigPtr = sign + sizeof(uint32_t);
    
    if (levelsMinusOne + 1 != ctx->hssPub->levels) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_HSS_LEVEL);
        return CRYPT_LMS_ERR_INVALID_HSS_LEVEL;
    }
    
    /* Verify chain of signatures */
    uint8_t currentPubKey[MAX_LMS_PUBLIC_KEY_SIZE];
    uint32_t currentPubKeyLen = sizeof(uint32_t) * 2 + ctx->hssPub->lmsParam->n;
    
    /* Start with root public key */
    CRYPT_PutBE32(ctx->hssPub->lmsParam->algId, currentPubKey);
    CRYPT_PutBE32(ctx->hssPub->lmotsParam->algId, currentPubKey + sizeof(uint32_t));
    (void)memcpy_s(currentPubKey + sizeof(uint32_t) * 2, sizeof(currentPubKey) - sizeof(uint32_t) * 2,
                   ctx->hssPub->rootPub, ctx->hssPub->lmsParam->n);
    
    /* Verify intermediate signatures */
    for (uint32_t i = 0; i < levelsMinusOne; i++) {
        /* Verify signature on next public key */
        const uint8_t *nextPubKey = sigPtr + ctx->hssPub->lmsParam->sigLen;
        
        int32_t ret = LmsVerifySignature(currentPubKey, currentPubKeyLen, 
                                         nextPubKey, 
                                         sizeof(uint32_t) * 2 + ctx->hssPub->lmsParam->n,
                                         sigPtr, ctx->hssPub->lmsParam->sigLen);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_SIGNATURE_VERIFY_FAIL);
            return CRYPT_LMS_ERR_SIGNATURE_VERIFY_FAIL;
        }
        
        /* Move to next level */
        (void)memcpy_s(currentPubKey, sizeof(currentPubKey), nextPubKey, 
                       sizeof(uint32_t) * 2 + ctx->hssPub->lmsParam->n);
        sigPtr = nextPubKey + sizeof(uint32_t) * 2 + ctx->hssPub->lmsParam->n;
    }
    
    /* Verify final signature on message */
    int32_t ret = LmsVerifySignature(currentPubKey, currentPubKeyLen,
                                     data, dataLen,
                                     sigPtr, signLen - (sigPtr - sign));
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_SIGNATURE_VERIFY_FAIL);
        return CRYPT_LMS_ERR_SIGNATURE_VERIFY_FAIL;
    }
    
    return CRYPT_SUCCESS;
}

/* Set HSS private key */
int32_t CRYPT_HSS_SetPrvKey(CRYPT_HSS_Ctx *ctx, const CRYPT_HssPrv *prv)
{
    if (ctx == NULL || prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* Free existing private key */
    if (ctx->hssPrv != NULL) {
        FreeHssPrivateKey(ctx->hssPrv);
        ctx->hssPrv = NULL;
    }
    
    /* Parse private key from bytes */
    ctx->hssPrv = ParseHssPrivateKey(prv->prvKey, prv->prvKeyLen);
    if (ctx->hssPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    /* Also set public key from private key */
    if (ctx->hssPub != NULL) {
        FreeHssPublicKey(ctx->hssPub);
    }
    
    ctx->hssPub = BSL_SAL_Calloc(1, sizeof(HssPublicKey));
    if (ctx->hssPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    ctx->hssPub->levels = ctx->hssPrv->levels;
    ctx->hssPub->lmsParam = ctx->hssPrv->lmsParam[0];
    ctx->hssPub->lmotsParam = ctx->hssPrv->lmotsParam[0];
    (void)memcpy_s(ctx->hssPub->rootPub, sizeof(ctx->hssPub->rootPub),
                   ctx->hssPrv->trees[0]->root, ctx->hssPrv->lmsParam[0]->n);
    
    /* Update parameters */
    ctx->param.levels = prv->levels;
    
    return CRYPT_SUCCESS;
}

/* Set HSS public key */
int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, const CRYPT_HssPub *pub)
{
    if (ctx == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* Free existing public key */
    if (ctx->hssPub != NULL) {
        FreeHssPublicKey(ctx->hssPub);
        ctx->hssPub = NULL;
    }
    
    /* Parse public key from bytes */
    ctx->hssPub = ParseHssPublicKey(pub->pubKey, pub->pubKeyLen);
    if (ctx->hssPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    /* Update parameters */
    ctx->param.levels = pub->levels;
    
    return CRYPT_SUCCESS;
}

/* Get HSS private key */
int32_t CRYPT_HSS_GetPrvKey(const CRYPT_HSS_Ctx *ctx, CRYPT_HssPrv *prv)
{
    if (ctx == NULL || prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->hssPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_NO_PRIVATE_KEY);
        return CRYPT_LMS_ERR_NO_PRIVATE_KEY;
    }
    
    /* Serialize private key */
    uint32_t prvKeyLen = GetHssPrivateKeySize(ctx->hssPrv);
    prv->prvKey = BSL_SAL_Malloc(prvKeyLen);
    if (prv->prvKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    SerializeHssPrivateKey(ctx->hssPrv, prv->prvKey, prvKeyLen);
    prv->prvKeyLen = prvKeyLen;
    prv->levels = ctx->hssPrv->levels;
    
    /* Also copy public key */
    prv->pub.levels = ctx->hssPrv->levels;
    prv->pub.pubKeyLen = sizeof(uint32_t) + sizeof(uint32_t) * 2 + ctx->hssPrv->lmsParam[0]->n;
    prv->pub.pubKey = BSL_SAL_Malloc(prv->pub.pubKeyLen);
    if (prv->pub.pubKey == NULL) {
        BSL_SAL_Free(prv->prvKey);
        prv->prvKey = NULL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    uint8_t *ptr = prv->pub.pubKey;
    CRYPT_PutBE32(ctx->hssPrv->levels, ptr);
    ptr += sizeof(uint32_t);
    CRYPT_PutBE32(ctx->hssPrv->lmsParam[0]->algId, ptr);
    ptr += sizeof(uint32_t);
    CRYPT_PutBE32(ctx->hssPrv->lmotsParam[0]->algId, ptr);
    ptr += sizeof(uint32_t);
    (void)memcpy_s(ptr, prv->pub.pubKeyLen - (ptr - prv->pub.pubKey),
                   ctx->hssPrv->trees[0]->root, ctx->hssPrv->lmsParam[0]->n);
    
    return CRYPT_SUCCESS;
}

/* Get HSS public key */
int32_t CRYPT_HSS_GetPubKey(const CRYPT_HSS_Ctx *ctx, CRYPT_HssPub *pub)
{
    if (ctx == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->hssPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_NO_PUBLIC_KEY);
        return CRYPT_LMS_ERR_NO_PUBLIC_KEY;
    }
    
    pub->levels = ctx->hssPub->levels;
    pub->pubKeyLen = sizeof(uint32_t) + sizeof(uint32_t) * 2 + ctx->hssPub->lmsParam->n;
    pub->pubKey = BSL_SAL_Malloc(pub->pubKeyLen);
    if (pub->pubKey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    uint8_t *ptr = pub->pubKey;
    CRYPT_PutBE32(ctx->hssPub->levels, ptr);
    ptr += sizeof(uint32_t);
    CRYPT_PutBE32(ctx->hssPub->lmsParam->algId, ptr);
    ptr += sizeof(uint32_t);
    CRYPT_PutBE32(ctx->hssPub->lmotsParam->algId, ptr);
    ptr += sizeof(uint32_t);
    (void)memcpy_s(ptr, pub->pubKeyLen - (ptr - pub->pubKey),
                   ctx->hssPub->rootPub, ctx->hssPub->lmsParam->n);
    
    return CRYPT_SUCCESS;
}

/* Get HSS signature size for given parameters */
uint32_t CRYPT_HSS_GetSignatureSize(const CRYPT_HSS_Param *param)
{
    if (param == NULL || param->levels < 1 || param->levels > CRYPT_HSS_MAX_LEVELS) {
        return 0;
    }
    
    uint32_t sigSize = sizeof(uint32_t); /* levels - 1 */
    
    for (uint32_t i = 0; i < param->levels; i++) {
        const LmsParam *lmsParam = GetLmsParam(param->lmsParam[i]);
        if (lmsParam == NULL) {
            return 0;
        }
        
        if (i < param->levels - 1) {
            /* Signed public key */
            sigSize += lmsParam->sigLen;
            sigSize += sizeof(uint32_t) * 2; /* LMS/LM-OTS types */
            const LmsParam *nextParam = GetLmsParam(param->lmsParam[i+1]);
            if (nextParam == NULL) {
                return 0;
            }
            sigSize += nextParam->n;
        } else {
            /* Final LMS signature */
            sigSize += lmsParam->sigLen;
        }
    }
    
    return sigSize;
}

/* Get HSS public key size for given parameters */
uint32_t CRYPT_HSS_GetPublicKeySize(const CRYPT_HSS_Param *param)
{
    if (param == NULL || param->levels < 1 || param->levels > CRYPT_HSS_MAX_LEVELS) {
        return 0;
    }
    
    const LmsParam *lmsParam = GetLmsParam(param->lmsParam[0]);
    if (lmsParam == NULL) {
        return 0;
    }
    
    return sizeof(uint32_t) + sizeof(uint32_t) * 2 + lmsParam->n;
}

#endif /* HITLS_CRYPTO_LMS */