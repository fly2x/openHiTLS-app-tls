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
#ifdef HITLS_CRYPTO_CODECS

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "crypt_errno.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_codecs_unified.h"
#include "codec_local.h"

static void FreeCodecNode(void *node)
{
    if (node == NULL) {
        return;
    }
    
    CRYPT_CODEC_Node *codecNode = (CRYPT_CODEC_Node *)node;
    if (codecNode->codecCtx != NULL) {
        CRYPT_CODEC_Free(codecNode->codecCtx);
    }
    BSL_SAL_Free(codecNode);
}

static int32_t CreateCodecPath(CRYPT_CODEC_PoolCtx *poolCtx)
{
    if (poolCtx == NULL || poolCtx->codecs == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Simple implementation - create direct path from input to target
    BslList *path = BSL_LIST_New(sizeof(CRYPT_CODEC_Node));
    if (path == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    BSL_LIST_FREE_FUNC(path, FreeCodecNode);
    
    // Find suitable codec from pool
    BSL_ListNode *node = BSL_LIST_GET_FIRST(poolCtx->codecs);
    while (node != NULL) {
        CRYPT_CODEC_Ctx *codecCtx = (CRYPT_CODEC_Ctx *)BSL_LIST_GET_DATA(node);
        if (codecCtx != NULL && codecCtx->opType == poolCtx->opType) {
            CRYPT_CODEC_Node *codecNode = BSL_SAL_Calloc(1, sizeof(CRYPT_CODEC_Node));
            if (codecNode == NULL) {
                BSL_LIST_FREE(path);
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            
            codecNode->codecCtx = codecCtx;
            codecNode->inData.format = poolCtx->inputFormat;
            codecNode->inData.type = poolCtx->inputType;
            codecNode->outData.format = poolCtx->targetFormat;
            codecNode->outData.type = poolCtx->targetType;
            
            if (BSL_LIST_AddElement(path, codecNode, BSL_LIST_POS_END) != BSL_SUCCESS) {
                BSL_SAL_Free(codecNode);
                BSL_LIST_FREE(path);
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            break;
        }
        node = BSL_LIST_GET_NEXT(poolCtx->codecs, node);
    }
    
    poolCtx->codecPath = path;
    return CRYPT_SUCCESS;
}

CRYPT_CODEC_PoolCtx *CRYPT_CODEC_PoolNewCtx(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
    const char *attrName, int32_t keyType, const char *format, const char *type)
{
    if (libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    
    CRYPT_CODEC_PoolCtx *poolCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_CODEC_PoolCtx));
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    poolCtx->libCtx = libCtx;
    poolCtx->opType = opType;
    poolCtx->inputKeyType = keyType;
    poolCtx->targetKeyType = keyType;
    poolCtx->freeOutData = true;
    
    if (attrName != NULL) {
        poolCtx->attrName = BSL_SAL_Strdup(attrName);
        if (poolCtx->attrName == NULL) {
            BSL_SAL_Free(poolCtx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }
    
    if (format != NULL) {
        poolCtx->inputFormat = BSL_SAL_Strdup(format);
        poolCtx->targetFormat = BSL_SAL_Strdup(format);
        if (poolCtx->inputFormat == NULL || poolCtx->targetFormat == NULL) {
            BSL_SAL_Free((void*)poolCtx->attrName);
            BSL_SAL_Free((void*)poolCtx->inputFormat);
            BSL_SAL_Free((void*)poolCtx->targetFormat);
            BSL_SAL_Free(poolCtx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }
    
    if (type != NULL) {
        poolCtx->inputType = BSL_SAL_Strdup(type);
        poolCtx->targetType = BSL_SAL_Strdup(type);
        if (poolCtx->inputType == NULL || poolCtx->targetType == NULL) {
            BSL_SAL_Free((void*)poolCtx->attrName);
            BSL_SAL_Free((void*)poolCtx->inputFormat);
            BSL_SAL_Free((void*)poolCtx->targetFormat);
            BSL_SAL_Free((void*)poolCtx->inputType);
            BSL_SAL_Free((void*)poolCtx->targetType);
            BSL_SAL_Free(poolCtx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }
    
    // Create codec pool list
    poolCtx->codecs = BSL_LIST_New(sizeof(CRYPT_CODEC_Ctx *));
    if (poolCtx->codecs == NULL) {
        CRYPT_CODEC_PoolFreeCtx(poolCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    return poolCtx;
}

void CRYPT_CODEC_PoolFreeCtx(CRYPT_CODEC_PoolCtx *poolCtx)
{
    if (poolCtx == NULL) {
        return;
    }
    
    BSL_SAL_Free((void*)poolCtx->attrName);
    BSL_SAL_Free((void*)poolCtx->inputFormat);
    BSL_SAL_Free((void*)poolCtx->targetFormat);
    BSL_SAL_Free((void*)poolCtx->inputType);
    BSL_SAL_Free((void*)poolCtx->targetType);
    
    if (poolCtx->codecs != NULL) {
        BSL_LIST_FREE(poolCtx->codecs);
    }
    
    if (poolCtx->codecPath != NULL) {
        BSL_LIST_FREE(poolCtx->codecPath);
    }
    
    BSL_SAL_Free(poolCtx);
}

int32_t CRYPT_CODEC_PoolProcess(CRYPT_CODEC_PoolCtx *poolCtx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (poolCtx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Create codec path if not exists
    if (poolCtx->codecPath == NULL) {
        int32_t ret = CreateCodecPath(poolCtx);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    
    // Process through codec chain
    BSL_ListNode *node = BSL_LIST_GET_FIRST(poolCtx->codecPath);
    const BSL_Param *currentInput = inParam;
    BSL_Param *currentOutput = NULL;
    
    while (node != NULL) {
        CRYPT_CODEC_Node *codecNode = (CRYPT_CODEC_Node *)BSL_LIST_GET_DATA(node);
        if (codecNode == NULL || codecNode->codecCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        
        int32_t ret = CRYPT_CODEC_Process(codecNode->codecCtx, currentInput, &currentOutput);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        // For chained processing, output becomes input for next stage
        currentInput = currentOutput;
        node = BSL_LIST_GET_NEXT(poolCtx->codecPath, node);
    }
    
    *outParam = currentOutput;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CODEC_PoolCtrl(CRYPT_CODEC_PoolCtx *poolCtx, int32_t cmd, void *val, int32_t valLen)
{
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    switch (cmd) {
        case CRYPT_CODEC_CMD_SET_OPERATION_TYPE:
            if (val == NULL || valLen != sizeof(CRYPT_CODEC_OP_TYPE)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            poolCtx->opType = *(CRYPT_CODEC_OP_TYPE*)val;
            // Invalidate existing path when operation type changes
            if (poolCtx->codecPath != NULL) {
                BSL_LIST_FREE(poolCtx->codecPath);
                poolCtx->codecPath = NULL;
            }
            break;
            
        case CRYPT_CODEC_CMD_SET_TARGET_FORMAT:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            BSL_SAL_Free((void*)poolCtx->targetFormat);
            poolCtx->targetFormat = BSL_SAL_Strdup((const char*)val);
            if (poolCtx->targetFormat == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            break;
            
        case CRYPT_CODEC_CMD_SET_TARGET_TYPE:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            BSL_SAL_Free((void*)poolCtx->targetType);
            poolCtx->targetType = BSL_SAL_Strdup((const char*)val);
            if (poolCtx->targetType == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            break;
            
        case CRYPT_CODEC_CMD_SET_FLAG_FREE_OUT_DATA:
            if (val == NULL || valLen != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            poolCtx->freeOutData = *(bool*)val;
            break;
            
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
    
    return CRYPT_SUCCESS;
}

// Unified high-level functions
int32_t CRYPT_EAL_CodecBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type, const BSL_Buffer *inputBuf, 
    const void *auxParam, void **outputData)
{
    if (libCtx == NULL || inputBuf == NULL || outputData == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_CODEC_PoolCtx *poolCtx = CRYPT_CODEC_PoolNewCtx(libCtx, opType, attrName, keyType, format, type);
    if (poolCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    // Create input parameter
    BSL_Param inParam[2];
    inParam[0].key = CRYPT_PARAM_CODEC_INPUT_DATA;
    inParam[0].value = (void*)inputBuf;
    inParam[0].valueLen = sizeof(BSL_Buffer);
    inParam[0].useLen = sizeof(BSL_Buffer);
    inParam[1].key = 0;
    inParam[1].value = NULL;
    inParam[1].valueLen = 0;
    inParam[1].useLen = 0;
    
    BSL_Param *outParam = NULL;
    int32_t ret = CRYPT_CODEC_PoolProcess(poolCtx, inParam, &outParam);
    
    if (ret == CRYPT_SUCCESS && outParam != NULL) {
        *outputData = outParam->value;
    }
    
    CRYPT_CODEC_PoolFreeCtx(poolCtx);
    return ret;
}

int32_t CRYPT_EAL_CodecFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type, const char *path,
    const void *auxParam, void **outputData)
{
    if (libCtx == NULL || path == NULL || outputData == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Read file into buffer first
    BSL_Buffer fileBuf = {0};
    // This would typically use BSL file I/O functions
    // For now, we'll return an error as file I/O implementation is needed
    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
    return CRYPT_PROVIDER_NOT_SUPPORT;
}

#endif /* HITLS_CRYPTO_CODECS */