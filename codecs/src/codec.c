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
#include "crypt_errno.h"
#include "crypt_eal_implprovider.h"
#include "crypt_eal_provider.h"
#include "crypt_eal_codecs_unified.h"
#include "codec_local.h"

const char *CRYPT_CODEC_GetOpTypeString(CRYPT_CODEC_OP_TYPE opType)
{
    switch (opType) {
        case CRYPT_CODEC_OP_DECODE:
            return "decode";
        case CRYPT_CODEC_OP_ENCODE:
            return "encode";
        default:
            return "unknown";
    }
}

int32_t CRYPT_CODEC_ValidateCtx(const CRYPT_CODEC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->method == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    
    return CRYPT_SUCCESS;
}

CRYPT_CODEC_Ctx *CRYPT_CODEC_NewCtx(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType, 
                                     int32_t keyType, const char *attrName)
{
    CRYPT_CODEC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_CODEC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    ctx->opType = opType;
    ctx->freeOutData = true; // Default to free output data
    
    if (attrName != NULL) {
        ctx->attrName = BSL_SAL_Strdup(attrName);
        if (ctx->attrName == NULL) {
            BSL_SAL_Free(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
    }
    
    // Get provider manager context
    ctx->providerMgrCtx = CRYPT_EAL_LibCtxGetProvMgrCtx(libCtx);
    if (ctx->providerMgrCtx == NULL) {
        BSL_SAL_Free(ctx->attrName);
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_FOUND);
        return NULL;
    }
    
    ctx->codecState = CRYPT_CODEC_STATE_UNTRIED;
    
    return ctx;
}

void CRYPT_CODEC_Free(CRYPT_CODEC_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    if (ctx->method != NULL && ctx->method->freeCtx != NULL && ctx->codecCtx != NULL) {
        ctx->method->freeCtx(ctx->codecCtx);
    }
    
    BSL_SAL_Free(ctx->attrName);
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_CODEC_SetParam(CRYPT_CODEC_Ctx *ctx, const BSL_Param *param)
{
    int32_t ret = CRYPT_CODEC_ValidateCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->method->setParam != NULL) {
        return ctx->method->setParam(ctx->codecCtx, param);
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CODEC_GetParam(CRYPT_CODEC_Ctx *ctx, BSL_Param *param)
{
    int32_t ret = CRYPT_CODEC_ValidateCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->method->getParam != NULL) {
        return ctx->method->getParam(ctx->codecCtx, param);
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CODEC_Process(CRYPT_CODEC_Ctx *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    int32_t ret = CRYPT_CODEC_ValidateCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    if (inParam == NULL || outParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->method->process == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_SUPPORT);
        return CRYPT_PROVIDER_NOT_SUPPORT;
    }
    
    ctx->codecState = CRYPT_CODEC_STATE_TRYING;
    ret = ctx->method->process(ctx->codecCtx, inParam, outParam);
    
    if (ret == CRYPT_SUCCESS) {
        ctx->codecState = CRYPT_CODEC_STATE_SUCCESS;
    } else {
        ctx->codecState = CRYPT_CODEC_STATE_TRIED;
    }
    
    return ret;
}

int32_t CRYPT_CODEC_SwitchOperation(CRYPT_CODEC_Ctx *ctx, CRYPT_CODEC_OP_TYPE newOpType)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->opType == newOpType) {
        return CRYPT_SUCCESS; // No change needed
    }
    
    ctx->opType = newOpType;
    ctx->codecState = CRYPT_CODEC_STATE_UNTRIED; // Reset state
    
    // If provider supports ctrl method, inform it about the operation change
    if (ctx->method != NULL && ctx->method->ctrl != NULL) {
        return ctx->method->ctrl(ctx->codecCtx, CRYPT_CODEC_CMD_SET_OPERATION_TYPE, 
                                &newOpType, sizeof(newOpType));
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CODEC_Ctrl(CRYPT_CODEC_Ctx *ctx, int32_t cmd, void *val, int32_t valLen)
{
    int32_t ret = CRYPT_CODEC_ValidateCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    switch (cmd) {
        case CRYPT_CODEC_CMD_SET_OPERATION_TYPE:
            if (val == NULL || valLen != sizeof(CRYPT_CODEC_OP_TYPE)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            return CRYPT_CODEC_SwitchOperation(ctx, *(CRYPT_CODEC_OP_TYPE*)val);
            
        case CRYPT_CODEC_CMD_SET_TARGET_FORMAT:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            ctx->outFormat = (const char*)val;
            break;
            
        case CRYPT_CODEC_CMD_SET_TARGET_TYPE:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            ctx->outType = (const char*)val;
            break;
            
        case CRYPT_CODEC_CMD_SET_FLAG_FREE_OUT_DATA:
            if (val == NULL || valLen != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->freeOutData = *(bool*)val;
            break;
            
        case CRYPT_CODEC_CMD_GET_OPERATION_TYPE:
            if (val == NULL || valLen != sizeof(CRYPT_CODEC_OP_TYPE)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(CRYPT_CODEC_OP_TYPE*)val = ctx->opType;
            break;
            
        case CRYPT_CODEC_CMD_GET_TARGET_FORMAT:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            *(const char**)val = ctx->outFormat;
            break;
            
        case CRYPT_CODEC_CMD_GET_TARGET_TYPE:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            *(const char**)val = ctx->outType;
            break;
            
        default:
            // Forward unknown commands to provider implementation
            if (ctx->method->ctrl != NULL) {
                return ctx->method->ctrl(ctx->codecCtx, cmd, val, valLen);
            }
            BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
            return CRYPT_INVALID_ARG;
    }
    
    return CRYPT_SUCCESS;
}

void CRYPT_CODEC_FreeOutData(CRYPT_CODEC_Ctx *ctx, BSL_Param *outData)
{
    if (ctx == NULL || outData == NULL) {
        return;
    }
    
    if (!ctx->freeOutData) {
        return; // Don't free if flag is set
    }
    
    if (ctx->method != NULL && ctx->method->freeOutData != NULL) {
        ctx->method->freeOutData(ctx->codecCtx, outData);
    } else {
        // Default cleanup
        BSL_SAL_Free(outData);
    }
}

int32_t CRYPT_CODEC_ParseAttr(const char *attrName, CODEC_AttrInfo *info)
{
    if (attrName == NULL || info == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Clear the structure
    (void)memset_s(info, sizeof(CODEC_AttrInfo), 0, sizeof(CODEC_AttrInfo));
    
    // Simple implementation - can be extended for complex attribute parsing
    info->attrName = BSL_SAL_Strdup(attrName);
    if (info->attrName == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    // Parse format from attribute name (e.g., "DER", "PEM", "RSA")
    // This is a simplified parser - real implementation would be more sophisticated
    if (strstr(attrName, "DER") != NULL) {
        info->inFormat = "DER";
        info->outFormat = "DER";
    } else if (strstr(attrName, "PEM") != NULL) {
        info->inFormat = "PEM";
        info->outFormat = "PEM";
    }
    
    if (strstr(attrName, "RSA") != NULL) {
        info->inType = "RSA";
        info->outType = "RSA";
    } else if (strstr(attrName, "ECC") != NULL || strstr(attrName, "EC") != NULL) {
        info->inType = "ECC";
        info->outType = "ECC";
    }
    
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_CODECS */