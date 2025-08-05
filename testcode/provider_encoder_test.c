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

#if defined(HITLS_CRYPTO_PROVIDER) && defined(HITLS_CRYPTO_CODECS)
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "crypt_errno.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "encode_local.h"
#include "bsl_types.h"

/**
 * Test case to demonstrate encoder functionality
 */
int32_t TestEncoderChain(void)
{
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_LibCtx *libCtx = NULL;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    CRYPT_ENCODER_PoolCtx *poolCtx = NULL;
    BSL_Param *inputParam = NULL;
    BSL_Param *outputParam = NULL;
    
    printf("Testing Encoder Chain Functionality\n");
    
    /* Initialize library context */
    libCtx = CRYPT_EAL_LibCtxNew();
    if (libCtx == NULL) {
        printf("Failed to create library context\n");
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Generate an RSA key for testing */
    pkey = CRYPT_EAL_PkeyNewCtx(libCtx, CRYPT_PKEY_RSA);
    if (pkey == NULL) {
        printf("Failed to create RSA key context\n");
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    
    ret = CRYPT_EAL_PkeyGen(pkey);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to generate RSA key\n");
        goto ERR;
    }
    
    /* Create encoder pool for key-to-PEM conversion */
    poolCtx = CRYPT_ENCODE_PoolNewCtx(libCtx, NULL, CRYPT_PKEY_RSA, "OBJECT", "HIGH_KEY");
    if (poolCtx == NULL) {
        printf("Failed to create encoder pool\n");
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    
    /* Set target format to PEM */
    const char *targetFormat = "PEM";
    const char *targetType = "PKCS8";
    ret = CRYPT_ENCODE_PoolCtrl(poolCtx, CRYPT_ENCODE_POOL_CMD_SET_TARGET_FORMAT, 
                                (void *)targetFormat, strlen(targetFormat) + 1);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set target format\n");
        goto ERR;
    }
    
    ret = CRYPT_ENCODE_PoolCtrl(poolCtx, CRYPT_ENCODE_POOL_CMD_SET_TARGET_TYPE,
                                (void *)targetType, strlen(targetType) + 1);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to set target type\n");
        goto ERR;
    }
    
    /* Prepare input parameter */
    inputParam = BSL_SAL_Calloc(2, sizeof(BSL_Param));
    if (inputParam == NULL) {
        printf("Failed to allocate input parameter\n");
        ret = CRYPT_MEM_ALLOC_FAIL;
        goto ERR;
    }
    
    inputParam[0].key = CRYPT_PARAM_ENCODE_OBJECT_DATA;
    inputParam[0].value = pkey;
    inputParam[0].valueLen = sizeof(CRYPT_EAL_PkeyCtx);
    inputParam[1] = BSL_PARAM_END;
    
    /* Perform encoding */
    ret = CRYPT_ENCODE_PoolEncode(poolCtx, inputParam, &outputParam);
    if (ret != CRYPT_SUCCESS) {
        printf("Failed to encode key to PEM: error code %d\n", ret);
        goto ERR;
    }
    
    /* Verify output */
    if (outputParam != NULL && outputParam[0].key == CRYPT_PARAM_ENCODE_BUFFER_DATA) {
        BSL_Buffer *outBuf = (BSL_Buffer *)outputParam[0].value;
        if (outBuf && outBuf->data && outBuf->dataLen > 0) {
            printf("Encoding successful! Output size: %u bytes\n", outBuf->dataLen);
            printf("First 100 characters of PEM output:\n");
            printf("%.100s\n", (char *)outBuf->data);
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
    if (outputParam != NULL) {
        if (poolCtx != NULL && outputParam[0].value != NULL) {
            /* Free output data using encoder pool */
            BSL_Buffer *outBuf = (BSL_Buffer *)outputParam[0].value;
            BSL_SAL_Free(outBuf->data);
            BSL_SAL_Free(outBuf);
        }
        BSL_SAL_Free(outputParam);
    }
    BSL_SAL_Free(inputParam);
    CRYPT_ENCODE_PoolFreeCtx(poolCtx);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_LibCtxFree(libCtx);
    
    if (ret == CRYPT_SUCCESS) {
        printf("Encoder test completed successfully!\n");
    } else {
        printf("Encoder test failed with error: %d\n", ret);
    }
    
    return ret;
}

/* Simple test runner */
int main(void)
{
    printf("Starting openHiTLS Encoder Tests\n");
    printf("=================================\n");
    
    int32_t ret = TestEncoderChain();
    
    printf("=================================\n");
    if (ret == CRYPT_SUCCESS) {
        printf("All tests passed!\n");
    } else {
        printf("Tests failed with error code: %d\n", ret);
    }
    
    return ret;
}

#else
int main(void)
{
    printf("Encoder tests skipped - required features not enabled\n");
    return 0;
}
#endif /* HITLS_CRYPTO_PROVIDER && HITLS_CRYPTO_CODECS */