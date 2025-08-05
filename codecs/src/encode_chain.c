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
#if defined(HITLS_CRYPTO_CODECS) && defined(HITLS_CRYPTO_PROVIDER)
#include <stdint.h>
#include <string.h>
#include "securec.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_implprovider.h"
#include "crypt_provider.h"
#include "crypt_params_key.h"
#include "crypt_types.h"
#include "crypt_errno.h"
#include "codec_unified_local.h"
#include "bsl_list.h"
#include "bsl_errno.h"
#include "bsl_err_internal.h"

static CRYPT_ENCODER_Node *CreateEncoderNode(const char *format, const char *type, const char *targetFormat,
    const char *targetType, const BSL_Param *input)
{
    CRYPT_ENCODER_Node *encoderNode = BSL_SAL_Calloc(1, sizeof(CRYPT_ENCODER_Node));
    if (encoderNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }

    encoderNode->inData.format = format;
    encoderNode->inData.type = type;
    encoderNode->inData.data = (BSL_Param *)(uintptr_t)input;
    encoderNode->outData.format = targetFormat;
    encoderNode->outData.type = targetType;
    return encoderNode;
}

static void FreeEncoderNode(CRYPT_ENCODER_Node *encoderNode)
{
    if (encoderNode == NULL) {
        return;
    }
    CRYPT_ENCODE_FreeOutData(encoderNode->encoderCtx, encoderNode->outData.data);
    BSL_SAL_Free(encoderNode);
}

CRYPT_ENCODER_PoolCtx *CRYPT_ENCODE_PoolNewCtx(CRYPT_EAL_LibCtx *libCtx, const char *attrName,
    int32_t keyType, const char *format, const char *type)
{
    CRYPT_ENCODER_PoolCtx *poolCtx = BSL_SAL_Calloc(1, sizeof(CRYPT_ENCODER_PoolCtx));
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    poolCtx->libCtx = libCtx;
    poolCtx->attrName = attrName;
    poolCtx->encoders = BSL_LIST_New(sizeof(CRYPT_ENCODER_Ctx));
    if (poolCtx->encoders == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        BSL_SAL_Free(poolCtx);
        return NULL;
    }

    poolCtx->encoderPath = BSL_LIST_New(sizeof(CRYPT_ENCODER_Node));
    if (poolCtx->encoderPath == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        goto ERR;
    }
    poolCtx->inputFormat = format;
    poolCtx->inputType = type;
    poolCtx->inputKeyType = keyType;
    poolCtx->targetFormat = NULL;
    poolCtx->targetType = NULL;
    return poolCtx;
ERR:
    BSL_LIST_FREE(poolCtx->encoders, NULL);
    BSL_SAL_Free(poolCtx);
    return NULL;
}

void CRYPT_ENCODE_PoolFreeCtx(CRYPT_ENCODER_PoolCtx *poolCtx)
{
    if (poolCtx == NULL) {
        return;
    }
    
    /* Free encoder path list and all encoder nodes */
    if (poolCtx->encoderPath != NULL) {
        BSL_LIST_FREE(poolCtx->encoderPath, (BSL_LIST_PFUNC_FREE)FreeEncoderNode);
    }
    /* Free encoder list and all encoder contexts */
    if (poolCtx->encoders != NULL) {
        BSL_LIST_FREE(poolCtx->encoders, (BSL_LIST_PFUNC_FREE)CRYPT_ENCODE_Free);
    }

    BSL_SAL_Free(poolCtx);
}

static int32_t SetEncodeType(void *val, int32_t valLen, const char **targetValue)
{
    if (valLen == 0 || valLen > MAX_CRYPT_ENCODE_FORMAT_TYPE_SIZE) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    *targetValue = val;
    return CRYPT_SUCCESS;
}

static int32_t SetFlagFreeOutData(CRYPT_ENCODER_PoolCtx *poolCtx, void *val, int32_t valLen)
{
    if (valLen != sizeof(bool)) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    if (poolCtx->encoderPath == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    CRYPT_ENCODER_Node *prevNode = BSL_LIST_GET_PREV(poolCtx->encoderPath);
    if (prevNode == NULL) {
        return CRYPT_SUCCESS;
    }
    bool isFreeOutData = *(bool *)val;
    if (!isFreeOutData) {
        prevNode->outData.data = NULL;
    }
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ENCODE_PoolCtrl(CRYPT_ENCODER_PoolCtx *poolCtx, int32_t cmd, void *val, int32_t valLen)
{
    if (poolCtx == NULL || val == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    switch (cmd) {
        case CRYPT_ENCODE_POOL_CMD_SET_TARGET_TYPE:
            return SetEncodeType(val, valLen, &poolCtx->targetType);
        case CRYPT_ENCODE_POOL_CMD_SET_TARGET_FORMAT:
            return SetEncodeType(val, valLen, &poolCtx->targetFormat);
        case CRYPT_ENCODE_POOL_CMD_SET_FLAG_FREE_OUT_DATA:
            return SetFlagFreeOutData(poolCtx, val, valLen);
        default:
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
}

static int32_t CollectEncoder(CRYPT_ENCODER_Ctx *encoderCtx, void *args)
{
    int32_t ret;
    CRYPT_ENCODER_PoolCtx *poolCtx = (CRYPT_ENCODER_PoolCtx *)args;
    if (poolCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    // TODO: Filter the encoder by input format and type According to poolCtx
    BSL_Param param[3] = {
        {CRYPT_PARAM_ENCODE_LIB_CTX, BSL_PARAM_TYPE_CTX_PTR, poolCtx->libCtx, 0, 0},
        {CRYPT_PARAM_ENCODE_TARGET_ATTR_NAME, BSL_PARAM_TYPE_OCTETS_PTR, (void *)(uintptr_t)poolCtx->attrName, 0, 0},
        BSL_PARAM_END
    };
    ret = CRYPT_ENCODE_SetParam(encoderCtx, param);
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    ret = BSL_LIST_AddElement(poolCtx->encoders, encoderCtx, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    return CRYPT_SUCCESS;
}

static CRYPT_ENCODER_Ctx* GetUsableEncoderFromPool(CRYPT_ENCODER_PoolCtx *poolCtx, CRYPT_ENCODER_Node *currNode)
{
    CRYPT_ENCODER_Ctx *encoderCtx = NULL;
    const char *curFormat = currNode->inData.format;
    const char *curType = currNode->inData.type;
    CRYPT_ENCODER_Ctx *node = BSL_LIST_GET_FIRST(poolCtx->encoders);
    while (node != NULL) {
        encoderCtx = node;
        if (encoderCtx == NULL || encoderCtx->encoderState != CRYPT_ENCODER_STATE_UNTRIED) {
            node = BSL_LIST_GET_NEXT(poolCtx->encoders);
            continue;
        }
        /* Check if encoder matches the current node's input format and type */
        if (curFormat != NULL && curType != NULL) {
            if ((encoderCtx->inFormat != NULL && BSL_SAL_StrcaseCmp(encoderCtx->inFormat, curFormat) == 0) &&
                (encoderCtx->inType == NULL || BSL_SAL_StrcaseCmp(encoderCtx->inType, curType) == 0)) {
                break;
            }
        } else if (curFormat == NULL && curType != NULL) {
            if (encoderCtx->inType == NULL || BSL_SAL_StrcaseCmp(encoderCtx->inType, curType) == 0) {
                break;
            }
        } else if (curFormat != NULL && curType == NULL) {
            if (encoderCtx->inFormat != NULL && BSL_SAL_StrcaseCmp(encoderCtx->inFormat, curFormat) == 0) {
                break;
            }
        } else {
            break;
        }
        node = BSL_LIST_GET_NEXT(poolCtx->encoders);
    }
    if (node != NULL) {
        encoderCtx = node;
        encoderCtx->encoderState = CRYPT_ENCODER_STATE_TRING;
    }
    return node != NULL ? encoderCtx : NULL;
}

static int32_t UpdateEncoderPath(CRYPT_ENCODER_PoolCtx *poolCtx, CRYPT_ENCODER_Node *currNode)
{
    /* Create new node */
    CRYPT_ENCODER_Node *newNode = CreateEncoderNode(currNode->outData.format, currNode->outData.type,
        poolCtx->targetFormat, poolCtx->targetType, currNode->outData.data);
    if (newNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    int32_t ret = BSL_LIST_AddElement(poolCtx->encoderPath, newNode, BSL_LIST_POS_END);
    if (ret != BSL_SUCCESS) {
        BSL_SAL_FREE(newNode);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return CRYPT_SUCCESS;
}

static int32_t TryEncodeWithEncoder(CRYPT_ENCODER_PoolCtx *poolCtx, CRYPT_ENCODER_Node *currNode)
{
    /* Convert password buffer to parameter if provided */
    BSL_Param *encoderParam = NULL;
    int32_t ret = CRYPT_ENCODE_Encode(currNode->encoderCtx, currNode->inData.data, &encoderParam);
    if (ret == CRYPT_SUCCESS) {
        /* Get output format and type from encoder */
        BSL_Param outParam[3] = {
            {CRYPT_PARAM_ENCODE_OUTPUT_FORMAT, BSL_PARAM_TYPE_OCTETS_PTR, NULL, 0, 0},
            {CRYPT_PARAM_ENCODE_OUTPUT_TYPE, BSL_PARAM_TYPE_OCTETS_PTR, NULL, 0, 0},
            BSL_PARAM_END
        };
        ret = CRYPT_ENCODE_GetParam(currNode->encoderCtx, outParam);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        
        currNode->outData.data = encoderParam;
        currNode->outData.format = outParam[0].value;
        currNode->outData.type = outParam[1].value;
        currNode->encoderCtx->encoderState = CRYPT_ENCODER_STATE_SUCCESS;
        ret = UpdateEncoderPath(poolCtx, currNode);
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }

        return CRYPT_SUCCESS;
    } else {
        /* Mark the node as tried */
        currNode->encoderCtx->encoderState = CRYPT_ENCODER_STATE_TRIED;
        return CRYPT_ENCODE_RETRY;
    }
}

static void ResetLastNode(CRYPT_ENCODER_PoolCtx *poolCtx, CRYPT_ENCODER_Node *currNode)
{
    (void)currNode;
    CRYPT_ENCODER_Node *prevNode = BSL_LIST_GET_PREV(poolCtx->encoderPath);
    /* Reset the out data of previous node if found */
    if (prevNode != NULL) {
        CRYPT_ENCODE_FreeOutData(prevNode->encoderCtx, prevNode->outData.data);
        prevNode->outData.data = NULL;
        prevNode->encoderCtx = NULL;
        prevNode->outData.format = poolCtx->targetFormat;
        prevNode->outData.type = poolCtx->targetType;
        (void)BSL_LIST_GET_NEXT(poolCtx->encoderPath);
    } else {
        (void)BSL_LIST_GET_FIRST(poolCtx->encoderPath);
    }
    BSL_LIST_DeleteCurrent(poolCtx->encoderPath, (BSL_LIST_PFUNC_FREE)FreeEncoderNode);
    (void)BSL_LIST_GET_LAST(poolCtx->encoderPath);
}

static int32_t BackToLastLayerEncodeNode(CRYPT_ENCODER_PoolCtx *poolCtx, CRYPT_ENCODER_Node *currNode)
{
    if (poolCtx == NULL || currNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    ResetLastNode(poolCtx, currNode);
    /* Reset all encoders marked as tried to untried state */
    CRYPT_ENCODER_Ctx *encoderCtx = BSL_LIST_GET_FIRST(poolCtx->encoders);
    while (encoderCtx != NULL) {
        if (encoderCtx->encoderState == CRYPT_ENCODER_STATE_TRIED) {
            encoderCtx->encoderState = CRYPT_ENCODER_STATE_UNTRIED;
        }
        encoderCtx = BSL_LIST_GET_NEXT(poolCtx->encoders);
    }

    return CRYPT_SUCCESS;
}

static bool IsStrMatch(const char *source, const char *target)
{
    if (source == NULL && target == NULL) {
        return true;
    }
    if (source == NULL || target == NULL) {
        return false;
    }
    return BSL_SAL_StrcaseCmp(source, target) == 0;
}

static int32_t EncodeWithKeyChain(CRYPT_ENCODER_PoolCtx *poolCtx, BSL_Param **outParam)
{
    int32_t ret;
    CRYPT_ENCODER_Ctx *encoderCtx = NULL;
    CRYPT_ENCODER_Node *currNode = BSL_LIST_GET_FIRST(poolCtx->encoderPath);
    while (!BSL_LIST_EMPTY(poolCtx->encoderPath)) {
        if (IsStrMatch(currNode->inData.format, poolCtx->targetFormat) &&
            IsStrMatch(currNode->inData.type, poolCtx->targetType)) {
            *outParam = currNode->inData.data;
            return CRYPT_SUCCESS;
        }
        /* Get the usable encoder from the pool */
        encoderCtx = GetUsableEncoderFromPool(poolCtx, currNode);
        /* If the encoder is found, try to encode */
        if (encoderCtx != NULL) {
            currNode->encoderCtx = encoderCtx;
            ret = TryEncodeWithEncoder(poolCtx, currNode);
            if (ret == CRYPT_ENCODE_RETRY) {
                continue;
            }
        } else {
            ret = BackToLastLayerEncodeNode(poolCtx, currNode);
        }
        if (ret != CRYPT_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        CRYPT_ENCODER_Node **curNodePtr = (CRYPT_ENCODER_Node **)BSL_LIST_Curr(poolCtx->encoderPath);
        currNode = curNodePtr == NULL ? NULL : *curNodePtr;
    }

    BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_ERR_NO_USABLE_ENCODER);
    return CRYPT_ENCODE_ERR_NO_USABLE_ENCODER;
}

typedef int32_t (*CRYPT_ENCODE_ProviderProcessCb)(CRYPT_ENCODER_Ctx *encoderCtx, void *args);
typedef struct {
    CRYPT_ENCODE_ProviderProcessCb cb;
    void *args;
} CRYPT_ENCODE_ProviderProcessArgs;

static int32_t ProcessEachProviderEncoder(CRYPT_EAL_ProvMgrCtx *ctx, void *args)
{
    CRYPT_ENCODE_ProviderProcessArgs *processArgs = (CRYPT_ENCODE_ProviderProcessArgs *)args;
    CRYPT_ENCODER_Ctx *encoderCtx = NULL;
    CRYPT_EAL_AlgInfo *algInfos = NULL;
    int32_t ret;

    if (ctx == NULL || args == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }

    ret = CRYPT_EAL_ProviderQuery(ctx, CRYPT_EAL_OPERAID_ENCODER, &algInfos);
    if (ret == CRYPT_NOT_SUPPORT) {
        return CRYPT_SUCCESS;
    }
    if (ret != CRYPT_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }

    for (int32_t i = 0; algInfos != NULL && algInfos[i].algId != 0; i++) {
        encoderCtx = CRYPT_ENCODE_NewEncoderCtxByMethod(algInfos[i].implFunc, ctx, algInfos[i].attr);
        if (encoderCtx == NULL) {
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return CRYPT_MEM_ALLOC_FAIL;
        }
        ret = processArgs->cb(encoderCtx, processArgs->args);
        if (ret != CRYPT_SUCCESS) {
            CRYPT_ENCODE_Free(encoderCtx);
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
    }

    return CRYPT_SUCCESS;
}

int32_t CRYPT_ENCODE_ProviderProcessAll(CRYPT_EAL_LibCtx *ctx, CRYPT_ENCODE_ProviderProcessCb cb, void *args)
{
    if (cb == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    CRYPT_ENCODE_ProviderProcessArgs processArgs = {
        .cb = cb,
        .args = args
    };
    int32_t ret = CRYPT_EAL_ProviderProcessAll(ctx, ProcessEachProviderEncoder, &processArgs);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_ENCODE_PoolEncode(CRYPT_ENCODER_PoolCtx *poolCtx, const BSL_Param *inParam, BSL_Param **outParam)
{
    if (poolCtx == NULL || inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    if (*outParam != NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    int32_t ret = CRYPT_ENCODE_ProviderProcessAll(poolCtx->libCtx, CollectEncoder, poolCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    if (BSL_LIST_COUNT(poolCtx->encoders) == 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_ENCODE_ERR_NO_ENCODER);
        return CRYPT_ENCODE_ERR_NO_ENCODER;
    }
    CRYPT_ENCODER_Node *initialNode = CreateEncoderNode(poolCtx->inputFormat, poolCtx->inputType,
        poolCtx->targetFormat, poolCtx->targetType, inParam);
    if (initialNode == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = BSL_LIST_AddElement(poolCtx->encoderPath, initialNode, BSL_LIST_POS_END);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(initialNode);
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    return EncodeWithKeyChain(poolCtx, outParam);
}

#endif /* HITLS_CRYPTO_CODECS && HITLS_CRYPTO_PROVIDER */