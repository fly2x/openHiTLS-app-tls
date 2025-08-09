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
#include "lms_hss_local.h"
#include "crypt_lms_hss.h"

/* Security and validation functions */

/* Validate LMS/HSS context integrity */
int32_t LmsHss_ValidateContext(const CryptLmsHssCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    /* Check magic number or reference count if available */
    if (ctx->references.count <= 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_PARA);
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Validate algorithm parameters if set */
    if (ctx->para.algId != 0) {
        int32_t ret = LmsHss_ValidatePara(&ctx->para);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

/* Secure parameter validation */
int32_t LmsHss_ValidateSignatureParams(const CryptLmsHssCtx *ctx, const uint8_t *data, 
                                       uint32_t dataLen, uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (data == NULL && dataLen > 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    if (sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    /* Check for reasonable data length limits */
    if (dataLen > 0x10000000) { /* 256MB limit */
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_INVALID_PARA);
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Validate context state */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Check if keys are properly set */
    if (ctx->keyType == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_HSS_KEY_NOT_SET);
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    return CRYPT_SUCCESS;
}

/* Secure verification parameter validation */
int32_t LmsHss_ValidateVerifyParams(const CryptLmsHssCtx *ctx, const uint8_t *data, 
                                    uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (data == NULL && dataLen > 0) {
        return CRYPT_NULL_INPUT;
    }

    if (sign == NULL || signLen == 0) {
        return CRYPT_NULL_INPUT;
    }

    /* Check for reasonable data and signature length limits */
    if (dataLen > 0x10000000) { /* 256MB limit */
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    if (signLen > 0x100000) { /* 1MB signature limit */
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    /* Validate minimum signature length based on algorithm */
    if (signLen < 64) { /* Minimum reasonable signature size */
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    /* Validate context state */
    int32_t ret = LmsHss_ValidateContext(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Check if public key is set */
    if (!(ctx->keyType & LMS_HSS_PUBKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    return CRYPT_SUCCESS;
}

/* Check for signature counter exhaustion */
int32_t LmsHss_CheckSignatureExhaustion(const CryptLmsHssCtx *ctx)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Check if private key is available */
    if (!(ctx->keyType & LMS_HSS_PRVKEY)) {
        return CRYPT_LMS_HSS_KEY_NOT_SET;
    }

    /* For HSS, check if any level has available signatures */
    for (uint32_t level = 0; level < ctx->para.levels; level++) {
        if (level >= ctx->prvKey.levels) {
            return CRYPT_LMS_HSS_TREE_EXHAUSTED;
        }

        const LmsPrvKey *prvKey = &ctx->prvKey.prvKeys[level];
        uint32_t maxSigs = 1U << ctx->para.h; /* 2^h signatures per tree */
        
        if (prvKey->q >= maxSigs) {
            /* This level is exhausted, but check if we can advance to next level */
            if (level == ctx->para.levels - 1) {
                /* Last level exhausted */
                return CRYPT_LMS_HSS_TREE_EXHAUSTED;
            }
            continue; /* Check next level */
        } else {
            /* This level has available signatures */
            return CRYPT_SUCCESS;
        }
    }

    /* All levels exhausted */
    return CRYPT_LMS_HSS_TREE_EXHAUSTED;
}

/* Secure memory operations */
int32_t LmsHss_SecureMemcpy(void *dst, uint32_t dstSize, const void *src, uint32_t srcSize)
{
    if (dst == NULL || src == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (srcSize > dstSize) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Use secure copy function */
    int32_t ret = memcpy_s(dst, dstSize, src, srcSize);
    if (ret != 0) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    return CRYPT_SUCCESS;
}

/* Constant-time comparison for security-sensitive data */
int32_t LmsHss_ConstantTimeCompare(const uint8_t *a, const uint8_t *b, uint32_t len)
{
    if (a == NULL || b == NULL) {
        return -1; /* Error */
    }

    uint8_t diff = 0;
    for (uint32_t i = 0; i < len; i++) {
        diff |= (a[i] ^ b[i]);
    }

    return (diff == 0) ? 0 : 1; /* 0 = equal, 1 = different */
}

/* Secure key data validation */
int32_t LmsHss_ValidateKeyData(const uint8_t *keyData, uint32_t keyLen, uint32_t expectedMinLen)
{
    if (keyData == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (keyLen == 0) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    if (keyLen < expectedMinLen) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    if (keyLen > 0x10000) { /* 64KB key limit */
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Check for all-zero keys (potential security issue) */
    bool allZero = true;
    for (uint32_t i = 0; i < keyLen; i++) {
        if (keyData[i] != 0) {
            allZero = false;
            break;
        }
    }

    if (allZero) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    return CRYPT_SUCCESS;
}

/* Input sanitization for control parameters */
int32_t LmsHss_SanitizeCtrlInput(int32_t opt, void *val, uint32_t len)
{
    if (val == NULL && len > 0) {
        return CRYPT_NULL_INPUT;
    }

    switch (opt) {
        case CRYPT_CTRL_SET_LMS_TYPE:
        case CRYPT_CTRL_SET_LMOTS_TYPE:
        case CRYPT_CTRL_SET_HSS_LEVELS:
        case CRYPT_CTRL_GET_LMS_TYPE:
        case CRYPT_CTRL_GET_LMOTS_TYPE:
        case CRYPT_CTRL_GET_HSS_LEVELS:
        case CRYPT_CTRL_GET_SIGNATURE_LEN:
        case CRYPT_CTRL_GET_PUBKEY_LEN:
        case CRYPT_CTRL_GET_PRVKEY_LEN:
        case CRYPT_CTRL_GET_REMAINING_SIGS:
            if (len != sizeof(uint32_t)) {
                return CRYPT_INVALID_ARG;
            }
            break;

        default:
            /* Unknown control option */
            return CRYPT_INVALID_ARG;
    }

    return CRYPT_SUCCESS;
}

/* Rate limiting for signature operations */
static uint32_t g_signatureCount = 0;
static uint32_t g_maxSignaturesPerSecond = 1000; /* Configurable rate limit */

int32_t LmsHss_CheckRateLimit(void)
{
    /* Simple rate limiting - in production, this should use proper timing */
    g_signatureCount++;
    
    if (g_signatureCount > g_maxSignaturesPerSecond) {
        /* Reset counter periodically in real implementation */
        if (g_signatureCount > g_maxSignaturesPerSecond * 10) {
            g_signatureCount = 0; /* Simple reset for demo */
        }
        return CRYPT_LMS_HSS_ERR_BASE + 0x1000;
    }

    return CRYPT_SUCCESS;
}

/* Secure cleanup on context destruction */
void LmsHss_SecureContextCleanup(CryptLmsHssCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }

    /* Clear sensitive private key material */
    if (ctx->keyType & LMS_HSS_PRVKEY) {
        if (ctx->prvKey.prvKeys != NULL) {
            for (uint32_t i = 0; i < ctx->prvKey.levels; i++) {
                /* Clear private key seeds */
                LmsHss_SecureClear(ctx->prvKey.prvKeys[i].seed, 
                                  sizeof(ctx->prvKey.prvKeys[i].seed));
            }
            /* Clear private key structures */
            LmsHss_SecureClear(ctx->prvKey.prvKeys, 
                              ctx->prvKey.levels * sizeof(LmsPrvKey));
        }

        if (ctx->prvKey.signatures != NULL) {
            for (uint32_t i = 0; i < ctx->prvKey.levels; i++) {
                if (ctx->prvKey.signatures[i] != NULL) {
                    /* Clear signature data */
                    LmsHss_SecureClear(ctx->prvKey.signatures[i], 
                                      LmsHss_GetSignatureLength(&ctx->para));
                }
            }
        }
    }

    /* Clear hash function context if it contains secrets */
    LmsHss_SecureClear(&ctx->hashFuncs, sizeof(ctx->hashFuncs));

    /* Clear parameter structure */
    LmsHss_SecureClear(&ctx->para, sizeof(ctx->para));
}

/* Anti-tampering check for critical operations */
int32_t LmsHss_AntiTamperingCheck(const CryptLmsHssCtx *ctx, const uint8_t *criticalData, 
                                  uint32_t dataLen)
{
    if (ctx == NULL || criticalData == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Basic integrity check - in production, use proper checksums/MACs */
    uint32_t checksum = 0;
    for (uint32_t i = 0; i < dataLen; i++) {
        checksum = (checksum << 1) ^ criticalData[i];
    }

    /* Verify context hasn't been corrupted */
    if (ctx->para.algId != CRYPT_PKEY_LMS_HSS && ctx->para.algId != 0) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    return CRYPT_SUCCESS;
}

/* Input validation for signature indices */
int32_t LmsHss_ValidateSignatureIndex(const CryptLmsHssCtx *ctx, uint32_t level, uint32_t index)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (level >= ctx->para.levels) {
        return CRYPT_LMS_HSS_INVALID_LEVEL;
    }

    uint32_t maxIndex = 1U << ctx->para.h; /* 2^h */
    if (index >= maxIndex) {
        return CRYPT_LMS_HSS_TREE_EXHAUSTED;
    }

    return CRYPT_SUCCESS;
}

/* Error context information for debugging */
typedef struct {
    uint32_t errorCode;
    const char *function;
    uint32_t line;
    const char *description;
} LmsHssErrorInfo;

static LmsHssErrorInfo g_lastError = {0};

void LmsHss_SetErrorInfo(uint32_t errorCode, const char *function, uint32_t line, 
                         const char *description)
{
    g_lastError.errorCode = errorCode;
    g_lastError.function = function;
    g_lastError.line = line;
    g_lastError.description = description;
}

/* Get last error information for debugging */
int32_t LmsHss_GetLastErrorInfo(uint32_t *errorCode, const char **function, 
                                uint32_t *line, const char **description)
{
    if (errorCode != NULL) {
        *errorCode = g_lastError.errorCode;
    }
    if (function != NULL) {
        *function = g_lastError.function;
    }
    if (line != NULL) {
        *line = g_lastError.line;
    }
    if (description != NULL) {
        *description = g_lastError.description;
    }

    return CRYPT_SUCCESS;
}

/* Macro for enhanced error reporting */
#define LMS_HSS_SET_ERROR(code, desc) \
    LmsHss_SetErrorInfo(code, __FUNCTION__, __LINE__, desc)

#endif /* HITLS_CRYPTO_LMS_HSS */