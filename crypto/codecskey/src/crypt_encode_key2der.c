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
    CRYPT_EAL_PkeyCtx *pkey;
    BSL_Buffer *password;
} CRYPT_ENCODE_KEY2DER_Ctx;

void *CRYPT_ENCODE_KEY2DER_NewCtx(void *provCtx)
{
    CRYPT_ENCODE_KEY2DER_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_ENCODE_KEY2DER_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    ctx->provCtx = provCtx;
    return ctx;
}

int32_t CRYPT_ENCODE_KEY2DER_SetParam(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_ENCODE_KEY2DER_Ctx *key2derCtx = (CRYPT_ENCODE_KEY2DER_Ctx *)ctx;
    
    for (const BSL_Param *p = param; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_ENCODE_PROVIDER_CTX:
                key2derCtx->mgrCtx = (CRYPT_EAL_ProvMgrCtx *)p->value;
                break;
            case CRYPT_PARAM_ENCODE_PASSWORD:
                key2derCtx->password = (BSL_Buffer *)p->value;
                break;
            default:
                break;
        }
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ENCODE_KEY2DER_GetParam(void *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_ENCODE_KEY2DER_Ctx *key2derCtx = (CRYPT_ENCODE_KEY2DER_Ctx *)ctx;
    
    for (BSL_Param *p = param; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_ENCODE_OUTPUT_FORMAT:
                p->value = (void *)key2derCtx->outputFormat;
                break;
            case CRYPT_PARAM_ENCODE_OUTPUT_TYPE:
                p->value = (void *)key2derCtx->outputType;
                break;
            default:
                break;
        }
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ENCODE_KEY2DER_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_ENCODE_KEY2DER_Ctx *key2derCtx = (CRYPT_ENCODE_KEY2DER_Ctx *)ctx;
    int32_t ret = CRYPT_SUCCESS;
    
    /* Extract input parameters */
    for (const BSL_Param *p = inParam; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_ENCODE_OBJECT_DATA:
                key2derCtx->pkey = (CRYPT_EAL_PkeyCtx *)p->value;
                break;
            default:
                break;
        }
    }
    
    if (key2derCtx->pkey == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* Create output buffer */
    BSL_Buffer *outBuf = BSL_SAL_Calloc(1, sizeof(BSL_Buffer));
    if (outBuf == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Encode key to DER format */
    CRYPT_EncodeParam encodeParam = {0};
    CRYPT_Pbkdf2Param pbkdfParam = {0};
    if (key2derCtx->password != NULL) {
        pbkdfParam.pwd = key2derCtx->password->data;
        pbkdfParam.pwdLen = key2derCtx->password->dataLen;
        pbkdfParam.itCnt = 2048;
        pbkdfParam.saltLen = 16;
        encodeParam.deriveMode = CRYPT_DERIVE_PBKDF2;
        encodeParam.param = &pbkdfParam;
    }
    
    /* Determine key type by checking if private key data exists */
    CRYPT_EAL_PkeyPrv prvKeyCheck = {0};
    int32_t keyType = (CRYPT_EAL_PkeyGetPrv(key2derCtx->pkey, &prvKeyCheck) == CRYPT_SUCCESS) ? 
                      CRYPT_PRIKEY_PKCS8_UNENCRYPT : CRYPT_PUBKEY_SUBKEY;
                      
    ret = CRYPT_EAL_EncodeBuffKey(key2derCtx->pkey, 
                                  key2derCtx->password != NULL ? &encodeParam : NULL, 
                                  BSL_FORMAT_ASN1, keyType, outBuf);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(outBuf);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
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
    result[1] = BSL_PARAM_END;
    
    /* Set output format and type */
    key2derCtx->outputFormat = "DER";
    key2derCtx->outputType = (keyType == CRYPT_PRIKEY_PKCS8_UNENCRYPT) ? "PKCS8" : "SubjectPublicKeyInfo";
    
    *outParam = result;
    return CRYPT_SUCCESS;
}

void CRYPT_ENCODE_KEY2DER_FreeOutData(void *ctx, BSL_Param *outData)
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

void CRYPT_ENCODE_KEY2DER_FreeCtx(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    BSL_SAL_Free(ctx);
}

#endif /* HITLS_CRYPTO_CODECSKEY && HITLS_CRYPTO_KEY_ENCODE */