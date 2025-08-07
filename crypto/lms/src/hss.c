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
#include "crypt_lms.h"
#include "lms_local.h"
#include "crypt_util_rand.h"
#include "crypt_utils.h"

/* Generate HSS key pair */
int32_t CRYPT_HSS_Gen(CryptLmsCtx *ctx, uint32_t level, const int32_t *lmsAlgIds, const int32_t *lmotsAlgIds)
{
    if (ctx == NULL || lmsAlgIds == NULL || lmotsAlgIds == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (level < 1 || level > HSS_MAX_LEVELS) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_HSS_LEVEL);
        return CRYPT_LMS_ERR_INVALID_HSS_LEVEL;
    }
    
    /* Free existing keys */
    if (ctx->hssPrv != NULL) {
        FreeHssPrivateKey(ctx->hssPrv);
        ctx->hssPrv = NULL;
    }
    if (ctx->hssPub != NULL) {
        FreeHssPublicKey(ctx->hssPub);
        ctx->hssPub = NULL;
    }
    
    /* Allocate HSS private key */
    ctx->hssPrv = BSL_SAL_Calloc(1, sizeof(HssPrivateKey));
    if (ctx->hssPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    ctx->hssPrv->L = level;
    
    /* Generate private keys */
    int32_t ret = HssGeneratePrivateKey(ctx->hssPrv, level, (const uint32_t *)lmsAlgIds, 
                                       (const uint32_t *)lmotsAlgIds);
    if (ret != CRYPT_SUCCESS) {
        FreeHssPrivateKey(ctx->hssPrv);
        ctx->hssPrv = NULL;
        return ret;
    }
    
    /* Allocate HSS public key */
    ctx->hssPub = BSL_SAL_Calloc(1, sizeof(HssPublicKey));
    if (ctx->hssPub == NULL) {
        FreeHssPrivateKey(ctx->hssPrv);
        ctx->hssPrv = NULL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Generate public key */
    ret = HssGeneratePublicKey(ctx->hssPrv, ctx->hssPub);
    if (ret != CRYPT_SUCCESS) {
        FreeHssPrivateKey(ctx->hssPrv);
        FreeHssPublicKey(ctx->hssPub);
        ctx->hssPrv = NULL;
        ctx->hssPub = NULL;
        return ret;
    }
    
    ctx->keyType = LMS_PRVKEY | LMS_PUBKEY;
    return CRYPT_SUCCESS;
}

/* Generate HSS private key */
int32_t HssGeneratePrivateKey(HssPrivateKey *prv, uint32_t L, const uint32_t *lmsAlgIds,
                              const uint32_t *otsAlgIds)
{
    if (prv == NULL || lmsAlgIds == NULL || otsAlgIds == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* Generate L levels of LMS keys */
    for (uint32_t i = 0; i < L; i++) {
        /* Allocate LMS private key */
        prv->lmsKeys[i] = BSL_SAL_Calloc(1, sizeof(LmsPrivateKey));
        if (prv->lmsKeys[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        
        /* Generate LMS private key */
        int32_t ret = LmsGeneratePrivateKey(prv->lmsKeys[i], lmsAlgIds[i], otsAlgIds[i]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        /* Allocate LMS public key */
        prv->lmsPubs[i] = BSL_SAL_Calloc(1, sizeof(LmsPublicKey));
        if (prv->lmsPubs[i] == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        
        /* Generate LMS public key */
        ret = LmsGeneratePublicKey(prv->lmsKeys[i], prv->lmsPubs[i]);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        /* Pre-allocate signature storage for levels 0 to L-2 */
        if (i < L - 1) {
            const LmsParam *lmsParam = GetLmsParam(lmsAlgIds[i]);
            const LmotsParam *otsParam = GetLmotsParam(otsAlgIds[i]);
            if (lmsParam == NULL || otsParam == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
                return CRYPT_LMS_ERR_INVALID_ALGID;
            }
            
            uint32_t sigLen = 4 + otsParam->sigLen + 4 + lmsParam->h * LMS_M_VALUE;
            prv->sigList[i] = BSL_SAL_Malloc(sigLen);
            if (prv->sigList[i] == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
        }
    }
    
    /* Sign public keys of lower levels */
    for (uint32_t i = 0; i < L - 1; i++) {
        /* Serialize public key i+1 */
        uint8_t pubKeyData[4 + 4 + 16 + LMS_M_VALUE];
        size_t offset = 0;
        
        CRYPT_PutBE32(pubKeyData + offset, prv->lmsPubs[i + 1]->algId);
        offset += 4;
        
        CRYPT_PutBE32(pubKeyData + offset, prv->lmsPubs[i + 1]->otsAlgId);
        offset += 4;
        
        (void)memcpy_s(pubKeyData + offset, sizeof(pubKeyData) - offset, 
                      prv->lmsPubs[i + 1]->I, 16);
        offset += 16;
        
        (void)memcpy_s(pubKeyData + offset, sizeof(pubKeyData) - offset,
                      prv->lmsPubs[i + 1]->T1, LMS_M_VALUE);
        offset += LMS_M_VALUE;
        
        /* Sign with level i private key */
        const LmsParam *lmsParam = GetLmsParam(prv->lmsKeys[i]->algId);
        const LmotsParam *otsParam = GetLmotsParam(prv->lmsKeys[i]->otsAlgId);
        if (lmsParam == NULL || otsParam == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
            return CRYPT_LMS_ERR_INVALID_ALGID;
        }
        
        uint32_t sigLen = 4 + otsParam->sigLen + 4 + lmsParam->h * LMS_M_VALUE;
        int32_t ret = LmsSign(prv->lmsKeys[i], pubKeyData, offset, prv->sigList[i], &sigLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    
    return CRYPT_SUCCESS;
}

/* Generate HSS public key */
int32_t HssGeneratePublicKey(const HssPrivateKey *prv, HssPublicKey *pub)
{
    if (prv == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (prv->L == 0 || prv->lmsPubs[0] == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_PARAM);
        return CRYPT_LMS_ERR_INVALID_PARAM;
    }
    
    pub->L = prv->L;
    
    /* Copy top-level public key */
    pub->pubKey.algId = prv->lmsPubs[0]->algId;
    pub->pubKey.otsAlgId = prv->lmsPubs[0]->otsAlgId;
    (void)memcpy_s(pub->pubKey.I, sizeof(pub->pubKey.I), 
                  prv->lmsPubs[0]->I, sizeof(prv->lmsPubs[0]->I));
    (void)memcpy_s(pub->pubKey.T1, sizeof(pub->pubKey.T1),
                  prv->lmsPubs[0]->T1, sizeof(prv->lmsPubs[0]->T1));
    
    return CRYPT_SUCCESS;
}

/* HSS sign */
int32_t CRYPT_HSS_Sign(CryptLmsCtx *ctx, const uint8_t *data, uint32_t dataLen,
                       uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if ((ctx->keyType & LMS_PRVKEY) == 0 || ctx->hssPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    return HssSign(ctx->hssPrv, data, dataLen, sign, signLen);
}

/* HSS sign implementation */
int32_t HssSign(HssPrivateKey *prv, const uint8_t *message, uint32_t msgLen,
                uint8_t *signature, uint32_t *sigLen)
{
    if (prv == NULL || message == NULL || signature == NULL || sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (prv->L == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_PARAM);
        return CRYPT_LMS_ERR_INVALID_PARAM;
    }
    
    /* Calculate total signature length */
    uint32_t totalLen = 4;  /* L-1 */
    
    /* Add stored signature lengths */
    for (uint32_t i = 0; i < prv->L - 1; i++) {
        const LmsParam *lmsParam = GetLmsParam(prv->lmsKeys[i]->algId);
        const LmotsParam *otsParam = GetLmotsParam(prv->lmsKeys[i]->otsAlgId);
        if (lmsParam == NULL || otsParam == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
            return CRYPT_LMS_ERR_INVALID_ALGID;
        }
        
        /* Stored signature length */
        totalLen += 4 + otsParam->sigLen + 4 + lmsParam->h * LMS_M_VALUE;
        /* Public key length */
        totalLen += 4 + 4 + 16 + LMS_M_VALUE;
    }
    
    /* Add bottom level signature length */
    const LmsParam *bottomLmsParam = GetLmsParam(prv->lmsKeys[prv->L - 1]->algId);
    const LmotsParam *bottomOtsParam = GetLmotsParam(prv->lmsKeys[prv->L - 1]->otsAlgId);
    if (bottomLmsParam == NULL || bottomOtsParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    totalLen += 4 + bottomOtsParam->sigLen + 4 + bottomLmsParam->h * LMS_M_VALUE;
    
    if (*sigLen < totalLen) {
        *sigLen = totalLen;
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    uint32_t offset = 0;
    
    /* Write L-1 */
    CRYPT_PutBE32(signature + offset, prv->L - 1);
    offset += 4;
    
    /* Copy stored signatures and public keys */
    for (uint32_t i = 0; i < prv->L - 1; i++) {
        const LmsParam *lmsParam = GetLmsParam(prv->lmsKeys[i]->algId);
        const LmotsParam *otsParam = GetLmotsParam(prv->lmsKeys[i]->otsAlgId);
        
        /* Copy stored signature */
        uint32_t storedSigLen = 4 + otsParam->sigLen + 4 + lmsParam->h * LMS_M_VALUE;
        (void)memcpy_s(signature + offset, *sigLen - offset, prv->sigList[i], storedSigLen);
        offset += storedSigLen;
        
        /* Write public key i+1 */
        CRYPT_PutBE32(signature + offset, prv->lmsPubs[i + 1]->algId);
        offset += 4;
        
        CRYPT_PutBE32(signature + offset, prv->lmsPubs[i + 1]->otsAlgId);
        offset += 4;
        
        (void)memcpy_s(signature + offset, *sigLen - offset, prv->lmsPubs[i + 1]->I, 16);
        offset += 16;
        
        (void)memcpy_s(signature + offset, *sigLen - offset, prv->lmsPubs[i + 1]->T1, LMS_M_VALUE);
        offset += LMS_M_VALUE;
    }
    
    /* Sign message with bottom level */
    uint32_t bottomSigLen = *sigLen - offset;
    int32_t ret = LmsSign(prv->lmsKeys[prv->L - 1], message, msgLen, 
                         signature + offset, &bottomSigLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    offset += bottomSigLen;
    
    *sigLen = offset;
    
    /* Check if we need to update higher levels */
    /* This is a simplified version - real implementation would handle key updates */
    
    return CRYPT_SUCCESS;
}

/* HSS verify */
int32_t CRYPT_HSS_Verify(const CryptLmsCtx *ctx, const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if ((ctx->keyType & LMS_PUBKEY) == 0 || ctx->hssPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    return HssVerify(ctx->hssPub, data, dataLen, sign, signLen);
}

/* HSS verify implementation */
int32_t HssVerify(const HssPublicKey *pub, const uint8_t *message, uint32_t msgLen,
                  const uint8_t *signature, uint32_t sigLen)
{
    if (pub == NULL || message == NULL || signature == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (sigLen < 4) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    uint32_t offset = 0;
    
    /* Read L-1 */
    uint32_t Lm1 = CRYPT_GetBE32(signature + offset);
    offset += 4;
    
    if (Lm1 != pub->L - 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_HSS_LEVEL);
        return CRYPT_LMS_ERR_INVALID_HSS_LEVEL;
    }
    
    /* Current public key starts with top level */
    LmsPublicKey currentPub = pub->pubKey;
    
    /* Verify chain of signatures */
    for (uint32_t i = 0; i < Lm1; i++) {
        /* Read LMS signature */
        if (offset + 8 > sigLen) {  /* Need at least q and algId */
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
            return CRYPT_LMS_ERR_INVALID_SIG_LEN;
        }
        
        /* Get parameters to calculate signature length */
        uint32_t q = CRYPT_GetBE32(signature + offset);
        const LmsParam *lmsParam = GetLmsParam(currentPub.algId);
        const LmotsParam *otsParam = GetLmotsParam(currentPub.otsAlgId);
        
        if (lmsParam == NULL || otsParam == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
            return CRYPT_LMS_ERR_INVALID_ALGID;
        }
        
        if (q >= (1u << lmsParam->h)) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_PARAM);
            return CRYPT_LMS_ERR_INVALID_PARAM;
        }
        
        uint32_t lmsSigLen = 4 + otsParam->sigLen + 4 + lmsParam->h * LMS_M_VALUE;
        if (offset + lmsSigLen > sigLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
            return CRYPT_LMS_ERR_INVALID_SIG_LEN;
        }
        
        /* Read next public key */
        if (offset + lmsSigLen + 4 + 4 + 16 + LMS_M_VALUE > sigLen) {
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
            return CRYPT_LMS_ERR_INVALID_SIG_LEN;
        }
        
        /* Serialize next public key for verification */
        uint8_t nextPubData[4 + 4 + 16 + LMS_M_VALUE];
        (void)memcpy_s(nextPubData, sizeof(nextPubData), 
                      signature + offset + lmsSigLen, sizeof(nextPubData));
        
        /* Verify signature on next public key */
        int32_t ret = LmsVerify(&currentPub, nextPubData, sizeof(nextPubData),
                               signature + offset, lmsSigLen);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        offset += lmsSigLen;
        
        /* Parse next public key */
        currentPub.algId = CRYPT_GetBE32(signature + offset);
        offset += 4;
        
        currentPub.otsAlgId = CRYPT_GetBE32(signature + offset);
        offset += 4;
        
        (void)memcpy_s(currentPub.I, sizeof(currentPub.I), signature + offset, 16);
        offset += 16;
        
        (void)memcpy_s(currentPub.T1, sizeof(currentPub.T1), signature + offset, LMS_M_VALUE);
        offset += LMS_M_VALUE;
    }
    
    /* Verify final signature on message */
    return LmsVerify(&currentPub, message, msgLen, signature + offset, sigLen - offset);
}

/* ========================= Public HSS API Implementation ========================= */

#include "crypt_hss.h"

typedef struct CryptHssCtx {
    void *libCtx;
    CRYPT_HSS_Param param;
    HssPrivateKey *hssPrv;
    HssPublicKey *hssPub;
    BSL_SAL_RefCount references;
} CryptHssCtx;

/* Create a new HSS context */
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtx(void)
{
    return CRYPT_HSS_NewCtxEx(NULL);
}

/* Create a new HSS context with library context */
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtxEx(void *libCtx)
{
    CryptHssCtx *ctx = BSL_SAL_Calloc(1, sizeof(CryptHssCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    ctx->libCtx = libCtx;
    BSL_SAL_ReferencesInit(&ctx->references);
    
    return ctx;
}

/* Free an HSS context */
void CRYPT_HSS_FreeCtx(CRYPT_HSS_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    int32_t refs = 0;
    BSL_SAL_AtomicDownReferences(&ctx->references, &refs);
    if (refs > 0) {
        return;
    }
    
    if (ctx->hssPrv != NULL) {
        FreeHssPrivateKey(ctx->hssPrv);
    }
    if (ctx->hssPub != NULL) {
        FreeHssPublicKey(ctx->hssPub);
    }
    
    BSL_SAL_ReferencesFree(&ctx->references);
    BSL_SAL_FREE(ctx);
}

/* Duplicate an HSS context */
CRYPT_HSS_Ctx *CRYPT_HSS_DupCtx(const CRYPT_HSS_Ctx *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }
    
    CryptHssCtx *newCtx = CRYPT_HSS_NewCtxEx(ctx->libCtx);
    if (newCtx == NULL) {
        return NULL;
    }
    
    (void)memcpy_s(&newCtx->param, sizeof(CRYPT_HSS_Param), &ctx->param, sizeof(CRYPT_HSS_Param));
    
    /* Duplicate keys if present */
    if (ctx->hssPub != NULL) {
        newCtx->hssPub = DupHssPublicKey(ctx->hssPub);
        if (newCtx->hssPub == NULL) {
            CRYPT_HSS_FreeCtx(newCtx);
            return NULL;
        }
    }
    
    if (ctx->hssPrv != NULL) {
        newCtx->hssPrv = DupHssPrivateKey(ctx->hssPrv);
        if (newCtx->hssPrv == NULL) {
            CRYPT_HSS_FreeCtx(newCtx);
            return NULL;
        }
    }
    
    return newCtx;
}

/* Control function for HSS context */
int32_t CRYPT_HSS_Ctrl(CRYPT_HSS_Ctx *ctx, int32_t cmd, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    switch (cmd) {
        case CRYPT_CTRL_UP_REFERENCES:
            if (val == NULL || len != sizeof(int32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            BSL_SAL_AtomicUpReferences(&ctx->references, (int32_t *)val);
            return CRYPT_SUCCESS;
            
        case CRYPT_CTRL_GET_BITS:
            if (val == NULL || len != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            /* Return security bits - HSS with SHA-256 provides 128-bit security per level */
            *(uint32_t *)val = 128;
            return CRYPT_SUCCESS;
            
        case CRYPT_CTRL_GET_SIGNLEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = CRYPT_HSS_GetSignatureSize(&ctx->param);
            return CRYPT_SUCCESS;
            
        case CRYPT_CTRL_GET_PUBKEY_LEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = CRYPT_HSS_GetPublicKeySize(&ctx->param);
            return CRYPT_SUCCESS;
            
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_EAL_ERR_ALGID);
            return CRYPT_EAL_ERR_ALGID;
    }
}

#endif // HITLS_CRYPTO_LMS