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

#include "bsl_sal.h"
#include "bsl_list.h"
#include "crypt_errno.h"
#include "crypt_params_key.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_pkey.h"
#include "bsl_types.h"
#include "crypt_types.h"
#include "provider_test_utils.h"
#include <stdlib.h>
#include <string.h>

#define PARAMISNULL(a) ((a) == NULL || (a)->value == NULL)
#define PARAMISNULLLENIS0(a) ((a) == NULL || (a)->value == NULL || (a)->valueLen == 0)

/* Simple PEM to JSON encoder context for testing */
typedef struct {
    const char *outFormat;
    const char *outType;
} PEM_JSON_EncoderCtx;

/* PEM to JSON encoder implementation */
static void *PEM_JSON_NewCtx(void *provCtx)
{
    (void)provCtx;
    PEM_JSON_EncoderCtx *ctx = calloc(1, sizeof(PEM_JSON_EncoderCtx));
    if (ctx == NULL) {
        return NULL;
    }
    ctx->outFormat = "JSON";
    ctx->outType = "KEY_DATA";
    return ctx;
}

static int32_t PEM_JSON_SetParam(void *ctx, const BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    return CRYPT_SUCCESS;
}

static int32_t PEM_JSON_GetParam(void *ctx, BSL_Param *param)
{
    if (ctx == NULL || param == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    PEM_JSON_EncoderCtx *encoderCtx = (PEM_JSON_EncoderCtx *)ctx;
    
    for (BSL_Param *p = param; p->key != NULL; p++) {
        switch (p->key) {
            case CRYPT_PARAM_ENCODE_OUTPUT_FORMAT:
                p->value = (void *)encoderCtx->outFormat;
                break;
            case CRYPT_PARAM_ENCODE_OUTPUT_TYPE:
                p->value = (void *)encoderCtx->outType;
                break;
            default:
                break;
        }
    }
    
    return CRYPT_SUCCESS;
}

static int32_t PEM_JSON_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (ctx == NULL || inParam == NULL || outParam == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    /* Find input buffer */
    BSL_Buffer *inputBuf = NULL;
    for (const BSL_Param *p = inParam; p->key != NULL; p++) {
        if (p->key == CRYPT_PARAM_ENCODE_BUFFER_DATA) {
            inputBuf = (BSL_Buffer *)p->value;
            break;
        }
    }
    
    if (inputBuf == NULL || inputBuf->data == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    /* Create simple JSON output */
    const char *jsonTemplate = "{\"format\":\"PEM\",\"type\":\"test\",\"data\":\"%.*s\"}";
    int jsonLen = snprintf(NULL, 0, jsonTemplate, (int)inputBuf->dataLen, (char *)inputBuf->data) + 1;
    
    BSL_Buffer *outBuf = calloc(1, sizeof(BSL_Buffer));
    if (outBuf == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    outBuf->data = calloc(1, jsonLen);
    if (outBuf->data == NULL) {
        free(outBuf);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    snprintf((char *)outBuf->data, jsonLen, jsonTemplate, (int)inputBuf->dataLen, (char *)inputBuf->data);
    outBuf->dataLen = jsonLen - 1;
    
    /* Create output parameter */
    BSL_Param *result = calloc(2, sizeof(BSL_Param));
    if (result == NULL) {
        free(outBuf->data);
        free(outBuf);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    result[0].key = CRYPT_PARAM_ENCODE_BUFFER_DATA;
    result[0].value = outBuf;
    result[0].valueLen = sizeof(BSL_Buffer);
    result[1] = BSL_PARAM_END;
    
    *outParam = result;
    return CRYPT_SUCCESS;
}

static void PEM_JSON_FreeOutData(void *ctx, BSL_Param *outData)
{
    (void)ctx;
    if (outData == NULL) {
        return;
    }
    
    for (BSL_Param *p = outData; p->key != NULL; p++) {
        if (p->key == CRYPT_PARAM_ENCODE_BUFFER_DATA && p->value != NULL) {
            BSL_Buffer *buf = (BSL_Buffer *)p->value;
            free(buf->data);
            free(buf);
        }
    }
    free(outData);
}

static void PEM_JSON_FreeCtx(void *ctx)
{
    if (ctx != NULL) {
        free(ctx);
    }
}

/* Test encoder function table */
static const CRYPT_EAL_Func g_testPemJsonEncoder[] = {
    {CRYPT_ENCODER_IMPL_NEWCTX, (CRYPT_ENCODER_IMPL_NewCtx)PEM_JSON_NewCtx},
    {CRYPT_ENCODER_IMPL_SETPARAM, (CRYPT_ENCODER_IMPL_SetParam)PEM_JSON_SetParam},
    {CRYPT_ENCODER_IMPL_GETPARAM, (CRYPT_ENCODER_IMPL_GetParam)PEM_JSON_GetParam},
    {CRYPT_ENCODER_IMPL_ENCODE, (CRYPT_ENCODER_IMPL_Encode)PEM_JSON_Encode},
    {CRYPT_ENCODER_IMPL_FREEOUTDATA, (CRYPT_ENCODER_IMPL_FreeOutData)PEM_JSON_FreeOutData},
    {CRYPT_ENCODER_IMPL_FREECTX, (CRYPT_ENCODER_IMPL_FreeCtx)PEM_JSON_FreeCtx},
    CRYPT_EAL_FUNC_END,
};

/* Test encoder algorithm info */
static const CRYPT_EAL_AlgInfo g_testEncoders[] = {
    {BSL_CID_UNKNOWN, g_testPemJsonEncoder,
        "provider=test, inFormat=PEM, outFormat=JSON"},
    CRYPT_EAL_ALGINFO_END
};

/* Test provider query function */
static int32_t TestProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    if (operaId == CRYPT_EAL_OPERAID_ENCODER) {
        *algInfos = g_testEncoders;
        return CRYPT_SUCCESS;
    }
    return CRYPT_NOT_SUPPORT;
}

/* Test provider implementation */
static const CRYPT_EAL_Func g_testProvFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, (CRYPT_EAL_CvtVoid *)TestProvQuery},
    CRYPT_EAL_FUNC_END,
};

/* Basic encoder test */
int32_t TestBasicEncoder(void)
{
    printf("Testing Basic Encoder Functionality...\n");
    
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_ENCODER_Ctx *encoderCtx = NULL;
    BSL_Param *inputParam = NULL;
    BSL_Param *outputParam = NULL;
    int32_t ret = CRYPT_SUCCESS;
    
    /* Create library context */
    libCtx = CRYPT_EAL_LibCtxNew();
    if (libCtx == NULL) {
        printf("Failed to create library context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Load test provider */
    ret = CRYPT_EAL_ProviderLoad(libCtx, NULL, g_testProvFuncs, NULL);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to load test provider: %d\n", ret);
        goto ERR;
    }
    
    /* Create encoder context */
    encoderCtx = CRYPT_ENCODE_ProviderNewCtx(libCtx, BSL_CID_UNKNOWN, 
                                             "provider=test, inFormat=PEM, outFormat=JSON");
    if (encoderCtx == NULL) {
        printf("Failed to create encoder context\n");
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    
    /* Prepare test input */
    const char *testPemData = "-----BEGIN TEST-----\nVGVzdCBkYXRh\n-----END TEST-----\n";
    BSL_Buffer inputBuf = {
        .data = (uint8_t *)testPemData,
        .dataLen = strlen(testPemData)
    };
    
    inputParam = calloc(2, sizeof(BSL_Param));
    if (inputParam == NULL) {
        printf("Failed to allocate input parameter\n");
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    
    inputParam[0].key = CRYPT_PARAM_ENCODE_BUFFER_DATA;
    inputParam[0].value = &inputBuf;
    inputParam[0].valueLen = sizeof(BSL_Buffer);
    inputParam[1] = BSL_PARAM_END;
    
    /* Perform encoding */
    ret = CRYPT_ENCODE_Encode(encoderCtx, inputParam, &outputParam);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to encode data: %d\n", ret);
        goto ERR;
    }
    
    /* Verify output */
    if (outputParam != NULL && outputParam[0].key == CRYPT_PARAM_ENCODE_BUFFER_DATA) {
        BSL_Buffer *outBuf = (BSL_Buffer *)outputParam[0].value;
        if (outBuf && outBuf->data && outBuf->dataLen > 0) {
            printf("Encoding successful! Output size: %u bytes\n", outBuf->dataLen);
            printf("JSON output: %.*s\n", (int)outBuf->dataLen, (char *)outBuf->data);
        } else {
            printf("Invalid output buffer\n");
            ret = CRYPT_ENCODE_ERR_NO_USABLE_ENCODER;
        }
    } else {
        printf("No output data received\n");
        ret = CRYPT_ENCODE_ERR_NO_USABLE_ENCODER;
    }
    
ERR:
    /* Cleanup */
    if (outputParam != NULL && encoderCtx != NULL) {
        CRYPT_ENCODE_FreeOutData(encoderCtx, outputParam);
    }
    free(inputParam);
    CRYPT_ENCODE_Free(encoderCtx);
    CRYPT_EAL_LibCtxFree(libCtx);
    
    return ret;
}

/* Main test function */
int main(void)
{
    printf("Starting openHiTLS Encoder Provider Tests\n");
    printf("==========================================\n");
    
    int32_t ret = TestBasicEncoder();
    
    printf("==========================================\n");
    if (ret == CRYPT_SUCCESS) {
        printf("All encoder tests passed!\n");
    } else {
        printf("Encoder tests failed with error code: %d\n", ret);
    }
    
    return ret;
}