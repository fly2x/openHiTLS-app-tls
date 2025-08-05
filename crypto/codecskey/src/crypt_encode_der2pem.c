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

#if defined(HITLS_CRYPTO_CODECSKEY) && defined(HITLS_CRYPTO_KEY_ENCODE)
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_pem_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_params_key.h"
#include "crypt_encode_decode_key.h"
#include "crypt_encode_key_impl.h"
#include "bsl_types.h"

typedef struct {
    void *provCtx;
    CRYPT_EAL_ProvMgrCtx *mgrCtx;
    const char *inputFormat;
    const char *inputType;
    const char *outputFormat;
    const char *outputType;
    BSL_Buffer *derData;
    BSL_Buffer *password;
} CRYPT_ENCODE_DER2PEM_Ctx;

void *CRYPT_ENCODE_DER2PEM_NewCtx(void *provCtx)
{
    CRYPT_ENCODE_DER2PEM_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_ENCODE_DER2PEM_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->provCtx = provCtx;
    return ctx;
}

int32_t CRYPT_ENCODE_DER2PEM_SetParam(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_ENCODE_DER2PEM_Ctx *der2pemCtx = (CRYPT_ENCODE_DER2PEM_Ctx *)ctx;
    
    for (const BSL_Param *p = param; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_ENCODE_PROVIDER_CTX:
                der2pemCtx->mgrCtx = (CRYPT_EAL_ProvMgrCtx *)p->value;
                break;
            case CRYPT_PARAM_ENCODE_PASSWORD:
                der2pemCtx->password = (BSL_Buffer *)p->value;
                break;
            default:
                break;
        }
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ENCODE_DER2PEM_GetParam(void *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_ENCODE_DER2PEM_Ctx *der2pemCtx = (CRYPT_ENCODE_DER2PEM_Ctx *)ctx;
    
    for (BSL_Param *p = param; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_ENCODE_OUTPUT_FORMAT:
                p->value = (void *)(uintptr_t)der2pemCtx->outputFormat;
                break;
            case CRYPT_PARAM_ENCODE_OUTPUT_TYPE:
                p->value = (void *)(uintptr_t)der2pemCtx->outputType;
                break;
            default:
                break;
        }
    }
    
    return CRYPT_SUCCESS;
}

static const char *GetPemLabel(const char *type)
{
    if (type == NULL) {
        return "UNKNOWN";
    }
    
    if (strcmp(type, "PKCS8") == 0) {
        return "PRIVATE KEY";
    } else if (strcmp(type, "SubjectPublicKeyInfo") == 0) {
        return "PUBLIC KEY";
    } else if (strcmp(type, "RSAPublicKey") == 0) {
        return "RSA PUBLIC KEY";
    } else if (strcmp(type, "RSAPrivateKey") == 0) {
        return "RSA PRIVATE KEY";
    } else if (strcmp(type, "ECPrivateKey") == 0) {
        return "EC PRIVATE KEY";
    } else if (strcmp(type, "DSAPrivateKey") == 0) {
        return "DSA PRIVATE KEY";
    }
    
    return "UNKNOWN";
}

int32_t CRYPT_ENCODE_DER2PEM_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_ENCODE_DER2PEM_Ctx *der2pemCtx = (CRYPT_ENCODE_DER2PEM_Ctx *)ctx;
    int32_t ret = CRYPT_SUCCESS;
    const char *inputType = NULL;
    
    /* Extract input parameters */
    for (const BSL_Param *p = inParam; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_ENCODE_BUFFER_DATA:
                der2pemCtx->derData = (BSL_Buffer *)p->value;
                break;
            case CRYPT_PARAM_ENCODE_OBJECT_TYPE:
                inputType = (const char *)p->value;
                break;
            default:
                break;
        }
    }
    
    if (der2pemCtx->derData == NULL || der2pemCtx->derData->data == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* Create output buffer */
    BSL_Buffer *outBuf = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    if (outBuf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Get PEM label based on input type */
    const char *pemLabel = GetPemLabel(inputType);
    
    /* Convert DER to PEM */
    BSL_PEM_Symbol symbol = {
        .head = (strcmp(pemLabel, "PRIVATE KEY") == 0) ? BSL_PEM_PRI_KEY_BEGIN_STR :
                (strcmp(pemLabel, "PUBLIC KEY") == 0) ? BSL_PEM_PUB_KEY_BEGIN_STR :
                (strcmp(pemLabel, "RSA PRIVATE KEY") == 0) ? BSL_PEM_RSA_PRI_KEY_BEGIN_STR :
                (strcmp(pemLabel, "RSA PUBLIC KEY") == 0) ? BSL_PEM_RSA_PUB_KEY_BEGIN_STR :
                (strcmp(pemLabel, "EC PRIVATE KEY") == 0) ? BSL_PEM_EC_PRI_KEY_BEGIN_STR :
                BSL_PEM_PUB_KEY_BEGIN_STR,
        .tail = (strcmp(pemLabel, "PRIVATE KEY") == 0) ? BSL_PEM_PRI_KEY_END_STR :
                (strcmp(pemLabel, "PUBLIC KEY") == 0) ? BSL_PEM_PUB_KEY_END_STR :
                (strcmp(pemLabel, "RSA PRIVATE KEY") == 0) ? BSL_PEM_RSA_PRI_KEY_END_STR :
                (strcmp(pemLabel, "RSA PUBLIC KEY") == 0) ? BSL_PEM_RSA_PUB_KEY_END_STR :
                (strcmp(pemLabel, "EC PRIVATE KEY") == 0) ? BSL_PEM_EC_PRI_KEY_END_STR :
                BSL_PEM_PUB_KEY_END_STR
    };
    
    char *pemData = NULL;
    uint32_t pemLen = 0;
    ret = BSL_PEM_EncodeAsn1ToPem(der2pemCtx->derData->data, der2pemCtx->derData->dataLen, 
                                  &symbol, &pemData, &pemLen);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_Free(outBuf);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    outBuf->data = (uint8_t *)pemData;
    outBuf->dataLen = pemLen;
    
    /* Create output parameter */
    BSL_Param *result = BSL_SAL_Calloc(2, sizeof(BSL_Param));
    if (result == NULL) {
        BSL_SAL_Free(outBuf->data);
        BSL_SAL_Free(outBuf);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    result[0].key = CRYPT_PARAM_ENCODE_BUFFER_DATA;
    result[0].value = outBuf;
    result[0].valueLen = sizeof(BSL_Buffer);
    result[1].key = 0;
    result[1].valueType = 0;
    result[1].value = NULL;
    result[1].valueLen = 0;
    result[1].useLen = 0;
    
    /* Set output format and type */
    der2pemCtx->outputFormat = "PEM";
    der2pemCtx->outputType = inputType; /* Keep the same type */
    
    *outParam = result;
    return CRYPT_SUCCESS;
}

void CRYPT_ENCODE_DER2PEM_FreeOutData(void *ctx, BSL_Param *outData)
{
    if (ctx == NULL || outData == NULL) {
        return;
    }
    
    for (BSL_Param *p = outData; p->key != 0; p++) {
        if (p->key == CRYPT_PARAM_ENCODE_BUFFER_DATA && p->value != NULL) {
            BSL_Buffer *buf = (BSL_Buffer *)p->value;
            BSL_SAL_Free(buf->data);
            BSL_SAL_Free(buf);
        }
    }
    BSL_SAL_Free(outData);
}

void CRYPT_ENCODE_DER2PEM_FreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx);
}

#endif /* HITLS_CRYPTO_CODECSKEY && HITLS_CRYPTO_KEY_ENCODE */