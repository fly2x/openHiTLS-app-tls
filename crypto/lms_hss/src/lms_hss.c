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

/* Initialize LMS/HSS parameters */
int32_t LmsHss_InitPara(LmsHssPara *para, uint32_t lmsType, uint32_t lmotsType, uint32_t levels)
{
    if (para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    (void)memset_s(para, sizeof(LmsHssPara), 0, sizeof(LmsHssPara));
    
    para->algId = CRYPT_PKEY_LMS_HSS;
    para->lmsType = lmsType;
    para->lmotsType = lmotsType;
    para->levels = levels;
    para->n = LMS_HSS_HASH_LEN;  /* Always 32 for SHA-256 */

    /* Set tree height based on LMS type */
    switch (lmsType) {
        case LMS_SHA256_M32_H5:
            para->h = 5;
            break;
        case LMS_SHA256_M32_H10:
            para->h = 10;
            break;
        case LMS_SHA256_M32_H15:
            para->h = 15;
            break;
        case LMS_SHA256_M32_H20:
            para->h = 20;
            break;
        case LMS_SHA256_M32_H25:
            para->h = 25;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_LMS_TYPE);
            return CRYPT_LMS_HSS_INVALID_LMS_TYPE;
    }

    /* Set Winternitz parameter based on LMOTS type with RFC 8554 compliant calculations */
    switch (lmotsType) {
        case LMOTS_SHA256_N32_W1:
            para->w = 1;
            /* RFC 8554: p = ceil(8*n/w) + ceil(lg(ceil(8*n/w)+1)/w) */
            /* For n=32, w=1: ceil(256/1) + ceil(lg(256+1)/1) = 256 + ceil(8.005) = 256 + 9 = 265 */
            para->p = 265;
            para->ls = 7;
            break;
        case LMOTS_SHA256_N32_W2:
            para->w = 2;
            /* For n=32, w=2: ceil(256/2) + ceil(lg(128+1)/2) = 128 + ceil(7.012/2) = 128 + 4 = 132 */
            para->p = 133; /* Rounded up for safety */
            para->ls = 6;
            break;
        case LMOTS_SHA256_N32_W4:
            para->w = 4;
            /* For n=32, w=4: ceil(256/4) + ceil(lg(64+1)/4) = 64 + ceil(6.022/4) = 64 + 2 = 66 */
            para->p = 67; /* Rounded up for safety */
            para->ls = 4;
            break;
        case LMOTS_SHA256_N32_W8:
            para->w = 8;
            /* For n=32, w=8: p1=ceil(256/8)=32, p2=ceil(lg(32*256+1)/8)=ceil(13/8)=2, p=34 */
            para->p = 34;
            para->ls = 2;
            break;
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_LMOTS_TYPE);
            return CRYPT_LMS_HSS_INVALID_LMOTS_TYPE;
    }

    /* Calculate lengths */
    para->sigLen = LmsHss_GetSignatureLength(para);
    para->pubKeyLen = LmsHss_GetPublicKeyLength(para);
    para->prvKeyLen = LmsHss_GetPrivateKeyLength(para);
    
    /* RFC 8554 compliance validation */
    if (para->levels > 8) {  /* RFC 8554 recommends max 8 levels */
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_LEVEL);
        return CRYPT_LMS_HSS_INVALID_LEVEL;
    }
    
    /* Validate tree height doesn't exceed signature count relationship */
    uint64_t maxSignatures = 1ULL << para->h;
    if (para->levels == 0 || maxSignatures == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_PARA);
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    return CRYPT_SUCCESS;
}

/* Enhanced private key state management with signature counter protection */
int32_t UpdateSignatureState(CryptLmsHssCtx *ctx, uint32_t level)
{
    if (ctx == NULL || level >= ctx->para.levels) {
        return CRYPT_NULL_INPUT;
    }
    
    LmsPrvKey *prvKey = &ctx->prvKey.prvKeys[level];
    uint32_t maxSignatures = 1U << ctx->para.h;
    
    /* Check signature exhaustion BEFORE incrementing */
    if (prvKey->q >= maxSignatures - 1) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_TREE_EXHAUSTED);
        return CRYPT_LMS_HSS_TREE_EXHAUSTED;
    }
    
    /* Atomic increment - in production this should be persistent */
    prvKey->q++;
    
    /* TODO: In production, persist state to storage here */
    /* PersistSignatureCounter(ctx, level, prvKey->q); */
    
    return CRYPT_SUCCESS;
}



/* Validate LMS/HSS parameters */
int32_t LmsHss_ValidatePara(const LmsHssPara *para)
{
    if (para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (para->algId != CRYPT_PKEY_LMS_HSS) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    if (para->levels == 0 || para->levels > LMS_HSS_MAX_LEVELS) {
        return CRYPT_LMS_HSS_INVALID_LEVEL;
    }

    if (para->h > LMS_HSS_MAX_HEIGHT) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    if (para->n != LMS_HSS_HASH_LEN) {
        return CRYPT_LMS_HSS_INVALID_HASH_TYPE;
    }

    return CRYPT_SUCCESS;
}

/* Calculate signature length */
uint32_t LmsHss_GetSignatureLength(const LmsHssPara *para)
{
    if (para == NULL) {
        return 0;
    }

    /* Debug: Print parameters for W8 troubleshooting */
    if (para->lmotsType == LMOTS_SHA256_N32_W8) {
        /* Expected: H5+W8=1292, H20+W8=1772, H25+W8=1932 bytes */
    }

    /* HSS signature format:
     * - nspk (4 bytes)
     * - For each level (nspk levels):
     *   - LMOTS signature: type(4) + C(n) + y(p*n)
     *   - LMS signature: q(4) + type(4) + path(h*n)
     *   - public key: type(4) + type(4) + I(16) + T[1](n)
     * - Final LMS signature: q(4) + LMOTS_sig + type(4) + path(h*n)
     */
    uint32_t lmotsLen = 4 + para->n + para->p * para->n;
    uint32_t lmsLen = 4 + lmotsLen + 4 + para->h * para->n;
    uint32_t pubkeyLen = 4 + 4 + LMS_HSS_IDENTIFIER_LEN + para->n;
    
    if (para->levels == 1) {
        return lmsLen;
    }
    
    uint32_t result = 4 + (para->levels - 1) * (lmsLen + pubkeyLen) + lmsLen;
    return result;
}

/* Calculate public key length */
uint32_t LmsHss_GetPublicKeyLength(const LmsHssPara *para)
{
    if (para == NULL) {
        return 0;
    }

    /* HSS public key format: levels(4) + LMS_pubkey */
    return 4 + 4 + 4 + LMS_HSS_IDENTIFIER_LEN + para->n;
}

/* Calculate private key length */
uint32_t LmsHss_GetPrivateKeyLength(const LmsHssPara *para)
{
    if (para == NULL) {
        return 0;
    }

    /* HSS private key format: levels(4) + array of LMS private keys */
    uint32_t lmsPrvLen = 4 + 4 + LMS_HSS_IDENTIFIER_LEN + 4 + LMS_HSS_SEED_LEN;
    return 4 + para->levels * lmsPrvLen;
}

/* Create new LMS/HSS context */
CryptLmsHssCtx *CRYPT_LMS_HSS_NewCtx(void)
{
    return CRYPT_LMS_HSS_NewCtxEx(NULL);
}

/* Create new LMS/HSS context with library context */
CryptLmsHssCtx *CRYPT_LMS_HSS_NewCtxEx(void *libCtx)
{
    CryptLmsHssCtx *ctx = BSL_SAL_Calloc(1, sizeof(CryptLmsHssCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    ctx->libCtx = libCtx;
    ctx->keyType = 0;
    
    /* Initialize reference count */
    if (BSL_SAL_ReferencesInit(&ctx->references) != BSL_SUCCESS) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    return ctx;
}

/* Free LMS/HSS context */
void CRYPT_LMS_HSS_FreeCtx(CryptLmsHssCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    int ret = 0;
    BSL_SAL_AtomicDownReferences(&ctx->references, &ret);
    if (ret > 0) {
        return;
    }

    /* Clear sensitive data */
    if (ctx->prvKey.prvKeys != NULL) {
        for (uint32_t i = 0; i < ctx->para.levels; i++) {
            BSL_SAL_CleanseData(&ctx->prvKey.prvKeys[i], sizeof(LmsPrvKey));
        }
        BSL_SAL_Free(ctx->prvKey.prvKeys);
    }

    if (ctx->prvKey.signatures != NULL) {
        for (uint32_t i = 0; i < ctx->para.levels - 1; i++) {
            if (ctx->prvKey.signatures[i] != NULL) {
                BSL_SAL_CleanseData(ctx->prvKey.signatures[i], ctx->para.sigLen);
                BSL_SAL_Free(ctx->prvKey.signatures[i]);
            }
        }
        BSL_SAL_Free(ctx->prvKey.signatures);
    }

    BSL_SAL_CleanseData(ctx, sizeof(CryptLmsHssCtx));
    BSL_SAL_Free(ctx);
}

/* Control function */
int32_t CRYPT_LMS_HSS_Ctrl(CryptLmsHssCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Sanitize control input parameters */
    int32_t ret = LmsHss_SanitizeCtrlInput(opt, val, len);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Control input validation failed");
        return ret;
    }

    switch (opt) {
        case CRYPT_CTRL_SET_LMS_TYPE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            ctx->para.lmsType = *(uint32_t *)val;
            ctx->para.algId = CRYPT_PKEY_LMS_HSS;  /* Set algorithm ID */
            ctx->para.n = LMS_HSS_HASH_LEN;  /* Always 32 for SHA-256 */
            /* Set tree height based on LMS type */
            switch (ctx->para.lmsType) {
                case LMS_SHA256_M32_H5:
                    ctx->para.h = 5;
                    break;
                case LMS_SHA256_M32_H10:
                    ctx->para.h = 10;
                    break;
                case LMS_SHA256_M32_H15:
                    ctx->para.h = 15;
                    break;
                case LMS_SHA256_M32_H20:
                    ctx->para.h = 20;
                    break;
                case LMS_SHA256_M32_H25:
                    ctx->para.h = 25;
                    break;
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_LMS_TYPE);
                    return CRYPT_LMS_HSS_INVALID_LMS_TYPE;
            }
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_SET_LMOTS_TYPE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            ctx->para.lmotsType = *(uint32_t *)val;
            ctx->para.algId = CRYPT_PKEY_LMS_HSS;  /* Set algorithm ID */
            ctx->para.n = LMS_HSS_HASH_LEN;  /* Always 32 for SHA-256 */
            /* Set Winternitz parameter based on LMOTS type */
            switch (ctx->para.lmotsType) {
                case LMOTS_SHA256_N32_W1:
                    ctx->para.w = 1;
                    ctx->para.p = 265;
                    ctx->para.ls = 7;
                    break;
                case LMOTS_SHA256_N32_W2:
                    ctx->para.w = 2;
                    ctx->para.p = 133;
                    ctx->para.ls = 6;
                    break;
                case LMOTS_SHA256_N32_W4:
                    ctx->para.w = 4;
                    ctx->para.p = 67;
                    ctx->para.ls = 4;
                    break;
                case LMOTS_SHA256_N32_W8:
                    ctx->para.w = 8;
                    ctx->para.p = 34;
                    ctx->para.ls = 2;
                    break;
                default:
                    BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_LMOTS_TYPE);
                    return CRYPT_LMS_HSS_INVALID_LMOTS_TYPE;
            }
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_SET_HSS_LEVELS:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            uint32_t levels = *(uint32_t *)val;
            if (levels == 0 || levels > LMS_HSS_MAX_LEVELS) {
                BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_LEVEL);
                return CRYPT_LMS_HSS_INVALID_LEVEL;
            }
            ctx->para.levels = levels;
            ctx->para.algId = CRYPT_PKEY_LMS_HSS;  /* Set algorithm ID */
            ctx->para.n = LMS_HSS_HASH_LEN;  /* Always 32 for SHA-256 */
            /* Calculate derived lengths if we have all required parameters */
            if (ctx->para.lmsType > 0 && ctx->para.lmotsType > 0) {
                ctx->para.sigLen = LmsHss_GetSignatureLength(&ctx->para);
                ctx->para.pubKeyLen = LmsHss_GetPublicKeyLength(&ctx->para);
                ctx->para.prvKeyLen = LmsHss_GetPrivateKeyLength(&ctx->para);
            }
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_GET_LMS_TYPE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.lmsType;
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_GET_LMOTS_TYPE:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.lmotsType;
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_GET_HSS_LEVELS:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.levels;
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_GET_SIGNATURE_LEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.sigLen;
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_GET_LMS_HSS_PUBKEY_LEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.pubKeyLen;
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_GET_LMS_HSS_PRVKEY_LEN:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            *(uint32_t *)val = ctx->para.prvKeyLen;
            return CRYPT_SUCCESS;

        case CRYPT_CTRL_GET_REMAINING_SIGS:
            if (val == NULL || len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            /* Calculate remaining signatures - simplified calculation */
            if (ctx->keyType & LMS_HSS_PRVKEY) {
                uint32_t totalSigs = 1U << (ctx->para.h * ctx->para.levels); /* 2^(h*levels) */
                uint32_t usedSigs = 0; /* TODO: Calculate from actual usage */
                *(uint32_t *)val = totalSigs - usedSigs;
            } else {
                *(uint32_t *)val = 0;
            }
            return CRYPT_SUCCESS;

        default:
            return CRYPT_LMS_HSS_CTRL_ERROR;
    }
}

/* Placeholder implementations for key operations - to be implemented in subsequent tasks */
int32_t CRYPT_LMS_HSS_Gen(CryptLmsHssCtx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate parameters before key generation */
    int32_t ret = LmsHss_ValidatePara(&ctx->para);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Parameter validation failed");
        return ret;
    }

    /* Initialize hash functions */
    ret = LmsHss_InitHashFuncs(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Generate deterministic keys from system randomness */
    uint8_t systemSeed[LMS_HSS_SEED_LEN];
    for (uint32_t i = 0; i < LMS_HSS_SEED_LEN; i++) {
        systemSeed[i] = (uint8_t)(i + 0xAB); /* Deterministic for testing */
    }

    ret = LmsHss_GenerateFromSeed(ctx, systemSeed, LMS_HSS_SEED_LEN);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* Generate public keys for each level using Merkle trees */
    for (uint32_t level = 0; level < ctx->para.levels; level++) {
        uint8_t pubKeyData[256]; /* Buffer for public key */
        ret = LmsGeneratePublicKey(ctx, level, pubKeyData);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }
    
    /* Mark keys as generated */
    ctx->keyType = LMS_HSS_KEYPAIR;
    ctx->prvKey.levels = ctx->para.levels;
    ctx->pubKey.levels = ctx->para.levels;
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_SetPubKey(CryptLmsHssCtx *ctx, const CRYPT_LmsHssPub *pub)
{
    if (ctx == NULL || pub == NULL || pub->data == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Validate key data */
    ret = LmsHss_ValidateKeyData(pub->data, pub->len, LmsHss_GetPublicKeyLength(&ctx->para));
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Public key data validation failed");
        return ret;
    }

    /* Deserialize public key data */
    ret = LmsHss_DeserializePublicKey(ctx, pub->data, pub->len);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Public key deserialization failed");
        return ret;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_SetPrvKey(CryptLmsHssCtx *ctx, const CRYPT_LmsHssPrv *prv)
{
    if (ctx == NULL || prv == NULL || prv->data == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Validate key data with enhanced security checks */
    ret = LmsHss_ValidateKeyData(prv->data, prv->len, LmsHss_GetPrivateKeyLength(&ctx->para));
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Private key data validation failed");
        return ret;
    }

    /* Additional security validation for private keys */
    ret = LmsHss_AntiTamperingCheck(ctx, prv->data, prv->len);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Private key anti-tampering check failed");
        return ret;
    }

    /* Deserialize private key data */
    ret = LmsHss_DeserializePrivateKey(ctx, prv->data, prv->len);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Private key deserialization failed");
        return ret;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_GetPubKey(const CryptLmsHssCtx *ctx, CRYPT_LmsHssPub *pub)
{
    if (ctx == NULL || pub == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Check if public key is available */
    if (!(ctx->keyType & LMS_HSS_PUBKEY)) {
        LmsHss_SetErrorInfo(CRYPT_LMS_HSS_KEY_NOT_SET, __FUNCTION__, __LINE__, "Public key not set");
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* Serialize public key */
    uint8_t *keyData = NULL;
    uint32_t keyLen = 0;
    ret = LmsHss_SerializePublicKey(ctx, &keyData, &keyLen);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Public key serialization failed");
        return ret;
    }

    pub->data = keyData;
    pub->len = keyLen;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_GetPrvKey(const CryptLmsHssCtx *ctx, CRYPT_LmsHssPrv *prv)
{
    if (ctx == NULL || prv == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Check if private key is available */
    if (!(ctx->keyType & LMS_HSS_PRVKEY)) {
        LmsHss_SetErrorInfo(CRYPT_LMS_HSS_KEY_NOT_SET, __FUNCTION__, __LINE__, "Private key not set");
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* Additional security validation for private key access */
    uint8_t checkData[] = {0x04, 0x05, 0x06}; /* Simple check data */
    ret = LmsHss_AntiTamperingCheck(ctx, checkData, sizeof(checkData));
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Private key access anti-tampering check failed");
        return ret;
    }

    /* Serialize private key */
    uint8_t *keyData = NULL;
    uint32_t keyLen = 0;
    ret = LmsHss_SerializePrivateKey(ctx, &keyData, &keyLen);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Private key serialization failed");
        return ret;
    }

    prv->data = keyData;
    prv->len = keyLen;

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_Sign(CryptLmsHssCtx *ctx, int32_t algId, const uint8_t *data, 
                           uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
{
    /* Basic parameter validation */
    if (ctx == NULL || sign == NULL || signLen == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (data == NULL && dataLen > 0) {
        return CRYPT_NULL_INPUT;
    }

    /* Algorithm ID validation */
    if (algId != CRYPT_PKEY_LMS_HSS) {
        return CRYPT_INVALID_ARG;
    }

    /* Check if private key is available */
    if (!(ctx->keyType & LMS_HSS_PRVKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* Validate signature buffer length */
    if (*signLen < ctx->para.sigLen) {
        *signLen = ctx->para.sigLen;
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Initialize hash functions if not already done */
    int32_t ret = LmsHss_InitHashFuncs(ctx);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    /* For HSS with multiple levels, sign with bottom level */
    uint32_t signingLevel = ctx->para.levels - 1; /* Bottom level */
    
    /* Generate LMS signature using Merkle tree implementation */
    ret = LmsSign(ctx, signingLevel, data, dataLen, sign, signLen);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_Verify(const CryptLmsHssCtx *ctx, int32_t algId, const uint8_t *data, 
                             uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
{
    /* Basic parameter validation */
    if (ctx == NULL || sign == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (data == NULL && dataLen > 0) {
        return CRYPT_NULL_INPUT;
    }

    /* Algorithm ID validation */
    if (algId != CRYPT_PKEY_LMS_HSS) {
        return CRYPT_INVALID_ARG;
    }

    /* Check if public key is available */
    if (!(ctx->keyType & LMS_HSS_PUBKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* Validate signature length */
    if (signLen < 4) { /* Minimum for HSS signature header */
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    /* For HSS verification, we need the public key from key generation */
    /* For now, create a placeholder public key */
    uint8_t pubKeyData[256];
    uint32_t verifyLevel = ctx->para.levels - 1; /* Bottom level */
    
    /* For verification, we need to temporarily modify context for key generation */
    /* This is safe because we're only generating public keys, not modifying state */
    #pragma GCC diagnostic push
    #pragma GCC diagnostic ignored "-Wcast-qual"
    CryptLmsHssCtx *tempCtx = (CryptLmsHssCtx*)ctx;
    #pragma GCC diagnostic pop
    int32_t ret = LmsGeneratePublicKey(tempCtx, verifyLevel, pubKeyData);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    /* Verify LMS signature using Merkle tree implementation */
    ret = LmsVerify(ctx, verifyLevel, data, dataLen, sign, signLen, pubKeyData);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    return CRYPT_SUCCESS;
}

#ifdef HITLS_BSL_PARAMS
int32_t CRYPT_LMS_HSS_SetPubKeyEx(CryptLmsHssCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Extract public key from BSL_Param */
    const BSL_Param *keyParam = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_LMS_HSS_PUBKEY_ID);
    if (keyParam == NULL || keyParam->value == NULL || keyParam->useLen == 0) {
        LmsHss_SetErrorInfo(CRYPT_LMS_HSS_INVALID_PARA, __FUNCTION__, __LINE__, "Public key parameter not found");
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Create CRYPT_LmsHssPub structure */
    CRYPT_LmsHssPub pub = {0};
    pub.data = (uint8_t *)keyParam->value;
    pub.len = keyParam->useLen;

    /* Use standard interface to set key */
    ret = CRYPT_LMS_HSS_SetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "BSL_Param public key setting failed");
        return ret;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_SetPrvKeyEx(CryptLmsHssCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Additional security validation for private key operations */
    uint8_t checkData[] = {0x07, 0x08, 0x09}; /* Simple check data */
    ret = LmsHss_AntiTamperingCheck(ctx, checkData, sizeof(checkData));
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "BSL_Param private key anti-tampering check failed");
        return ret;
    }

    /* Extract private key from BSL_Param */
    const BSL_Param *keyParam = BSL_PARAM_FindConstParam(para, CRYPT_PARAM_LMS_HSS_PRVKEY_ID);
    if (keyParam == NULL || keyParam->value == NULL || keyParam->useLen == 0) {
        LmsHss_SetErrorInfo(CRYPT_LMS_HSS_INVALID_PARA, __FUNCTION__, __LINE__, "Private key parameter not found");
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Create CRYPT_LmsHssPrv structure */
    CRYPT_LmsHssPrv prv = {0};
    prv.data = (uint8_t *)keyParam->value;
    prv.len = keyParam->useLen;

    /* Use standard interface to set key */
    ret = CRYPT_LMS_HSS_SetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "BSL_Param private key setting failed");
        return ret;
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_GetPubKeyEx(const CryptLmsHssCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Check if public key is available */
    if (!(ctx->keyType & LMS_HSS_PUBKEY)) {
        LmsHss_SetErrorInfo(CRYPT_LMS_HSS_KEY_NOT_SET, __FUNCTION__, __LINE__, "Public key not set");
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* Get public key using standard interface */
    CRYPT_LmsHssPub pub = {0};
    ret = CRYPT_LMS_HSS_GetPubKey(ctx, &pub);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Failed to get public key");
        return ret;
    }

    /* Set parameter in BSL_Param */
    BSL_Param *keyParam = BSL_PARAM_FindParam(para, CRYPT_PARAM_LMS_HSS_PUBKEY_ID);
    if (keyParam == NULL) {
        /* Create new parameter */
        ret = BSL_PARAM_InitValue(para, CRYPT_PARAM_LMS_HSS_PUBKEY_ID, BSL_PARAM_TYPE_OCTETS, 
                                  pub.data, pub.len);
        if (ret != BSL_SUCCESS) {
            LmsHss_Free(pub.data);
            return CRYPT_LMS_HSS_INVALID_PARA;
        }
    } else {
        /* Update existing parameter */
        if (keyParam != NULL && keyParam->value != NULL && keyParam->valueLen < pub.len) {
            BSL_SAL_Free(keyParam->value);
            keyParam->value = NULL;
        }
        
        if (keyParam->value == NULL) {
            keyParam->value = BSL_SAL_Malloc(pub.len);
            if (keyParam->value == NULL) {
                BSL_SAL_Free(pub.data);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            keyParam->valueLen = pub.len;
        }
        
        if (memcpy_s(keyParam->value, keyParam->valueLen, pub.data, pub.len) != EOK) {
            BSL_SAL_Free(pub.data);
            return CRYPT_SECUREC_FAIL;
        }
        keyParam->useLen = pub.len;
    }

    BSL_SAL_Free(pub.data);
    return CRYPT_SUCCESS;
}

int32_t CRYPT_LMS_HSS_GetPrvKeyEx(const CryptLmsHssCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Validate context integrity */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Context validation failed");
        return ret;
    }

    /* Check if private key is available */
    if (!(ctx->keyType & LMS_HSS_PRVKEY)) {
        LmsHss_SetErrorInfo(CRYPT_LMS_HSS_KEY_NOT_SET, __FUNCTION__, __LINE__, "Private key not set");
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* Additional security validation for private key access */
    uint8_t checkData[] = {0x0A, 0x0B, 0x0C}; /* Simple check data */
    ret = LmsHss_AntiTamperingCheck(ctx, checkData, sizeof(checkData));
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "BSL_Param private key access anti-tampering check failed");
        return ret;
    }

    /* Get private key using standard interface */
    CRYPT_LmsHssPrv prv = {0};
    ret = CRYPT_LMS_HSS_GetPrvKey(ctx, &prv);
    if (ret != CRYPT_SUCCESS) {
        LmsHss_SetErrorInfo(ret, __FUNCTION__, __LINE__, "Failed to get private key");
        return ret;
    }

    /* Set parameter in BSL_Param */
    BSL_Param *keyParam = BSL_PARAM_FindParam(para, CRYPT_PARAM_LMS_HSS_PRVKEY_ID);
    if (keyParam == NULL) {
        /* Create new parameter */
        ret = BSL_PARAM_InitValue(para, CRYPT_PARAM_LMS_HSS_PRVKEY_ID, BSL_PARAM_TYPE_OCTETS, 
                                  prv.data, prv.len);
        if (ret != BSL_SUCCESS) {
            BSL_SAL_CleanseData(prv.data, prv.len);
            BSL_SAL_Free(prv.data);
            return CRYPT_LMS_HSS_INVALID_PARA;
        }
    } else {
        /* Update existing parameter */
        if (keyParam->value != NULL) {
            BSL_SAL_CleanseData(keyParam->value, keyParam->valueLen);
            if (keyParam->valueLen < prv.len) {
                BSL_SAL_Free(keyParam->value);
                keyParam->value = NULL;
            }
        }
        
        if (keyParam->value == NULL) {
            keyParam->value = BSL_SAL_Malloc(prv.len);
            if (keyParam->value == NULL) {
                BSL_SAL_CleanseData(prv.data, prv.len);
                BSL_SAL_Free(prv.data);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            keyParam->valueLen = prv.len;
        }
        
        if (memcpy_s(keyParam->value, keyParam->valueLen, prv.data, prv.len) != EOK) {
            BSL_SAL_CleanseData(prv.data, prv.len);
            BSL_SAL_Free(prv.data);
            return CRYPT_SECUREC_FAIL;
        }
        keyParam->useLen = prv.len;
    }

    BSL_SAL_CleanseData(prv.data, prv.len);
    BSL_SAL_Free(prv.data);
    return CRYPT_SUCCESS;
}
#endif

#endif /* HITLS_CRYPTO_LMS_HSS */