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
 * See the Mulan PSLv2 for more details.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECS

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err_internal.h"
#include "bsl_list.h"
#include "crypt_errno.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_codec_unified.h"
#include "codec_unified_local.h"

/* === POOL IMPLEMENTATION === */

static void FreeCodecNode(void *node)
{
    if (node == NULL) {
        return;
    }
    
    CODEC_Node *codecNode = (CODEC_Node*)node;
    if (codecNode->codecCtx != NULL) {
        CRYPT_CODEC_Free(codecNode->codecCtx);
    }
    CODEC_FreeDataInfo(&codecNode->input);
    CODEC_FreeDataInfo(&codecNode->output);
    BSL_SAL_Free(codecNode);
}

static void FreeCodecCtxWrapper(void *ctx)
{
    if (ctx != NULL) {
        CRYPT_CODEC_Free((CRYPT_CODEC_Ctx*)ctx);
    }
}

CRYPT_CODEC_PoolCtx *CRYPT_CODEC_PoolNew(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
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
    poolCtx->keyType = keyType;
    poolCtx->autoFreeOutput = true;
    poolCtx->optimizeChain = true;
    poolCtx->maxChainDepth = 10; // Reasonable default
    
    // Copy string parameters
    if (attrName != NULL) {
        poolCtx->attrName = BSL_SAL_Strdup(attrName);
        if (poolCtx->attrName == NULL) {
            CRYPT_CODEC_PoolFree(poolCtx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }
    
    if (format != NULL) {
        poolCtx->inputFormat = BSL_SAL_Strdup(format);
        poolCtx->targetFormat = BSL_SAL_Strdup(format);
        if (poolCtx->inputFormat == NULL || poolCtx->targetFormat == NULL) {
            CRYPT_CODEC_PoolFree(poolCtx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }
    
    if (type != NULL) {
        poolCtx->inputType = BSL_SAL_Strdup(type);
        poolCtx->targetType = BSL_SAL_Strdup(type);
        if (poolCtx->inputType == NULL || poolCtx->targetType == NULL) {
            CRYPT_CODEC_PoolFree(poolCtx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }
    
    // Create codec list
    poolCtx->availableCodecs = BSL_LIST_New(sizeof(CRYPT_CODEC_Ctx*));
    if (poolCtx->availableCodecs == NULL) {
        CRYPT_CODEC_PoolFree(poolCtx);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    BSL_LIST_FREE_FUNC(poolCtx->availableCodecs, FreeCodecCtxWrapper);
    
    return poolCtx;
}

void CRYPT_CODEC_PoolFree(CRYPT_CODEC_PoolCtx *poolCtx)
{
    if (poolCtx == NULL) {
        return;
    }
    
    BSL_SAL_Free(poolCtx->attrName);
    BSL_SAL_Free(poolCtx->inputFormat);
    BSL_SAL_Free(poolCtx->inputType);
    BSL_SAL_Free(poolCtx->targetFormat);
    BSL_SAL_Free(poolCtx->targetType);
    
    if (poolCtx->availableCodecs != NULL) {
        BSL_LIST_FREE(poolCtx->availableCodecs);
    }
    
    CODEC_FreeChain(poolCtx->processingChain);
    
    BSL_SAL_Free(poolCtx);
}

int32_t CODEC_BuildChain(CRYPT_CODEC_PoolCtx *poolCtx, const char *fromFormat, 
    const char *fromType, const char *toFormat, const char *toType)
{
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Simple direct mapping for now - can be enhanced with pathfinding algorithms
    CODEC_Node *node = BSL_SAL_Calloc(1, sizeof(CODEC_Node));
    if (node == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    // Create codec context for this transformation
    node->codecCtx = CRYPT_CODEC_NewCtx(poolCtx->libCtx, poolCtx->opType, 
        poolCtx->keyType, poolCtx->attrName);
    if (node->codecCtx == NULL) {
        BSL_SAL_Free(node);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    // Set up input/output info
    node->input.format = fromFormat;
    node->input.type = fromType;
    node->output.format = toFormat;
    node->output.type = toType;
    
    poolCtx->processingChain = node;
    return CRYPT_SUCCESS;
}

int32_t CODEC_ExecuteChain(CODEC_Node *chain, const BSL_Param *input, BSL_Param **output)
{
    if (chain == NULL || input == NULL || output == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    const BSL_Param *currentInput = input;
    BSL_Param *currentOutput = NULL;
    
    CODEC_Node *node = chain;
    while (node != NULL) {
        if (node->codecCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
        }
        
        int32_t ret = CRYPT_CODEC_Process(node->codecCtx, currentInput, &currentOutput);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        // For chained processing, output becomes input for next stage
        currentInput = currentOutput;
        node = node->next;
    }
    
    *output = currentOutput;
    return CRYPT_SUCCESS;
}

void CODEC_FreeChain(CODEC_Node *chain)
{
    CODEC_Node *current = chain;
    while (current != NULL) {
        CODEC_Node *next = current->next;
        FreeCodecNode(current);
        current = next;
    }
}

int32_t CRYPT_CODEC_PoolProcess(CRYPT_CODEC_PoolCtx *poolCtx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (poolCtx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Build processing chain if not exists
    if (poolCtx->processingChain == NULL) {
        int32_t ret = CODEC_BuildChain(poolCtx, 
            poolCtx->inputFormat, poolCtx->inputType,
            poolCtx->targetFormat, poolCtx->targetType);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    
    // Execute the processing chain
    return CODEC_ExecuteChain(poolCtx->processingChain, inParam, outParam);
}

int32_t CRYPT_CODEC_PoolCtrl(CRYPT_CODEC_PoolCtx *poolCtx, int32_t cmd, void *val, int32_t valLen)
{
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    switch (cmd) {
        case CRYPT_CODEC_CMD_SET_OPERATION:
            if (val == NULL || valLen != sizeof(CRYPT_CODEC_OP_TYPE)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            poolCtx->opType = *(CRYPT_CODEC_OP_TYPE*)val;
            // Invalidate existing chain when operation changes
            CODEC_FreeChain(poolCtx->processingChain);
            poolCtx->processingChain = NULL;
            break;
            
        case CRYPT_CODEC_CMD_GET_OPERATION:
            if (val == NULL || valLen != sizeof(CRYPT_CODEC_OP_TYPE)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(CRYPT_CODEC_OP_TYPE*)val = poolCtx->opType;
            break;
            
        case CRYPT_CODEC_CMD_SET_FORMAT:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            BSL_SAL_Free(poolCtx->targetFormat);
            poolCtx->targetFormat = BSL_SAL_Strdup((const char*)val);
            if (poolCtx->targetFormat == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            break;
            
        case CRYPT_CODEC_CMD_SET_TYPE:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            BSL_SAL_Free(poolCtx->targetType);
            poolCtx->targetType = BSL_SAL_Strdup((const char*)val);
            if (poolCtx->targetType == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
                return CRYPT_MEM_ALLOC_FAIL;
            }
            break;
            
        case CRYPT_CODEC_CMD_SET_FREE_FLAG:
            if (val == NULL || valLen != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            poolCtx->autoFreeOutput = *(bool*)val;
            break;
            
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
    
    return CRYPT_SUCCESS;
}

/* === UTILITY FUNCTIONS === */

int32_t CODEC_CopyDataInfo(const CODEC_DataInfo *src, CODEC_DataInfo *dst)
{
    if (src == NULL || dst == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    memset_s(dst, sizeof(CODEC_DataInfo), 0, sizeof(CODEC_DataInfo));
    
    if (src->format != NULL) {
        dst->format = BSL_SAL_Strdup(src->format);
        if (dst->format == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    
    if (src->type != NULL) {
        dst->type = BSL_SAL_Strdup(src->type);
        if (dst->type == NULL) {
            BSL_SAL_Free((void*)dst->format);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
    }
    
    dst->data = src->data; // Shallow copy - caller manages data lifetime
    dst->dataLen = src->dataLen;
    
    return CRYPT_SUCCESS;
}

void CODEC_FreeDataInfo(CODEC_DataInfo *info)
{
    if (info == NULL) {
        return;
    }
    
    BSL_SAL_Free((void*)info->format);
    BSL_SAL_Free((void*)info->type);
    // Note: Don't free data - it's managed by caller
    
    memset_s(info, sizeof(CODEC_DataInfo), 0, sizeof(CODEC_DataInfo));
}

/* === HIGH-LEVEL FUNCTIONS === */

int32_t CRYPT_EAL_CodecBuff(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type, 
    const BSL_Buffer *input, const void *params, void **output)
{
    if (libCtx == NULL || input == NULL || output == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    CRYPT_CODEC_PoolCtx *poolCtx = CRYPT_CODEC_PoolNew(libCtx, opType, NULL, keyType, format, type);
    if (poolCtx == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    // Create input parameter
    BSL_Param inParam[3];
    inParam[0].key = CRYPT_PARAM_CODEC_INPUT_DATA;
    inParam[0].value = (void*)input;
    inParam[0].valueLen = sizeof(BSL_Buffer);
    inParam[0].useLen = sizeof(BSL_Buffer);
    
    if (params != NULL) {
        inParam[1].key = CRYPT_PARAM_CODEC_PASSWORD; // or other param type based on operation
        inParam[1].value = (void*)params;
        inParam[1].valueLen = sizeof(void*);
        inParam[1].useLen = sizeof(void*);
        inParam[2].key = 0;
    } else {
        inParam[1].key = 0;
    }
    
    BSL_Param *outParam = NULL;
    int32_t ret = CRYPT_CODEC_PoolProcess(poolCtx, inParam, &outParam);
    
    if (ret == CRYPT_SUCCESS && outParam != NULL) {
        *output = outParam->value;
    }
    
    CRYPT_CODEC_PoolFree(poolCtx);
    return ret;
}

int32_t CRYPT_EAL_CodecFile(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type,
    const char *path, const void *params, void **output)
{
    if (libCtx == NULL || path == NULL || output == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // File I/O implementation would go here
    // For now, return not supported
    BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
    return CRYPT_PROVIDER_NOT_SUPPORT;
}

#endif /* HITLS_CRYPTO_CODECS */