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
#include "crypt_eal_provider.h"
#include "crypt_eal_codec_unified.h"
#include "codec_unified_local.h"

/* === UTILITY FUNCTIONS === */

const char *CODEC_GetOpString(CRYPT_CODEC_OP_TYPE opType)
{
    return (opType == CRYPT_CODEC_OP_ENCODE) ? "encode" : "decode";
}

int32_t CODEC_ValidateCtx(const CRYPT_CODEC_Ctx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (ctx->method == NULL || ctx->implCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
        return CRYPT_INVALID_ARG;
    }
    
    return CRYPT_SUCCESS;
}

bool CODEC_IsFormatCompatible(const char *format1, const char *format2)
{
    if (format1 == NULL || format2 == NULL) {
        return false;
    }
    return (strcmp(format1, format2) == 0);
}

bool CODEC_IsTypeCompatible(const char *type1, const char *type2)
{
    if (type1 == NULL || type2 == NULL) {
        return false;
    }
    return (strcmp(type1, type2) == 0);
}

/* === CORE IMPLEMENTATION === */

CRYPT_CODEC_Ctx *CRYPT_CODEC_NewCtx(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType, 
                                     int32_t keyType, const char *attrName)
{
    if (libCtx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return NULL;
    }
    
    CRYPT_CODEC_Ctx *ctx = BSL_SAL_Calloc(1, sizeof(CRYPT_CODEC_Ctx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    ctx->opType = opType;
    ctx->state = CODEC_STATE_INIT;
    ctx->autoFreeOutput = true;
    ctx->reusable = true;
    
    // Get provider manager context
    ctx->provMgrCtx = CRYPT_EAL_LibCtxGetProvMgrCtx(libCtx);
    if (ctx->provMgrCtx == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_PROVIDER_NOT_FOUND);
        return NULL;
    }
    
    // Copy attribute name if provided
    if (attrName != NULL) {
        ctx->attrName = BSL_SAL_Calloc(1, strlen(attrName) + 1);
        if (ctx->attrName == NULL) {
            BSL_SAL_Free(ctx);
            BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
            return NULL;
        }
        strcpy_s(ctx->attrName, strlen(attrName) + 1, attrName);
    }
    
    ctx->state = CODEC_STATE_READY;
    return ctx;
}

void CRYPT_CODEC_Free(CRYPT_CODEC_Ctx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    // Free implementation context
    if (ctx->method != NULL && ctx->method->freeCtx != NULL && ctx->implCtx != NULL) {
        ctx->method->freeCtx(ctx->implCtx);
    }
    
    // Free allocated memory
    BSL_SAL_Free(ctx->attrName);
    BSL_SAL_Free(ctx);
}

int32_t CRYPT_CODEC_SetParam(CRYPT_CODEC_Ctx *ctx, const BSL_Param *param)
{
    int32_t ret = CODEC_ValidateCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Handle unified codec parameters
    for (const BSL_Param *p = param; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_CODEC_OPERATION_TYPE:
                if (p->value != NULL && p->valueLen == sizeof(CRYPT_CODEC_OP_TYPE)) {
                    ctx->opType = *(CRYPT_CODEC_OP_TYPE*)p->value;
                }
                break;
            case CRYPT_PARAM_CODEC_INPUT_FORMAT:
                ctx->inFormat = (const char*)p->value;
                break;
            case CRYPT_PARAM_CODEC_INPUT_TYPE:
                ctx->inType = (const char*)p->value;
                break;
            case CRYPT_PARAM_CODEC_OUTPUT_FORMAT:
                ctx->outFormat = (const char*)p->value;
                break;
            case CRYPT_PARAM_CODEC_OUTPUT_TYPE:
                ctx->outType = (const char*)p->value;
                break;
            case CRYPT_PARAM_CODEC_FREE_OUT_DATA:
                if (p->value != NULL && p->valueLen == sizeof(bool)) {
                    ctx->autoFreeOutput = *(bool*)p->value;
                }
                break;
            default:
                // Forward to implementation
                if (ctx->method != NULL && ctx->method->setParam != NULL) {
                    ret = ctx->method->setParam(ctx->implCtx, p);
                    if (ret != CRYPT_SUCCESS) {
                        return ret;
                    }
                }
                break;
        }
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CODEC_GetParam(CRYPT_CODEC_Ctx *ctx, BSL_Param *param)
{
    int32_t ret = CODEC_ValidateCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    // Handle unified codec parameters
    for (BSL_Param *p = param; p->key != 0; p++) {
        switch (p->key) {
            case CRYPT_PARAM_CODEC_OPERATION_TYPE:
                if (p->value != NULL && p->valueLen >= sizeof(CRYPT_CODEC_OP_TYPE)) {
                    *(CRYPT_CODEC_OP_TYPE*)p->value = ctx->opType;
                    p->useLen = sizeof(CRYPT_CODEC_OP_TYPE);
                }
                break;
            case CRYPT_PARAM_CODEC_INPUT_FORMAT:
                p->value = (void*)(uintptr_t)ctx->inFormat;
                break;
            case CRYPT_PARAM_CODEC_INPUT_TYPE:
                p->value = (void*)(uintptr_t)ctx->inType;
                break;
            case CRYPT_PARAM_CODEC_OUTPUT_FORMAT:
                p->value = (void*)(uintptr_t)ctx->outFormat;
                break;
            case CRYPT_PARAM_CODEC_OUTPUT_TYPE:
                p->value = (void*)(uintptr_t)ctx->outType;
                break;
            case CRYPT_PARAM_CODEC_FREE_OUT_DATA:
                if (p->value != NULL && p->valueLen >= sizeof(bool)) {
                    *(bool*)p->value = ctx->autoFreeOutput;
                    p->useLen = sizeof(bool);
                }
                break;
            default:
                // Forward to implementation
                if (ctx->method != NULL && ctx->method->getParam != NULL) {
                    ret = ctx->method->getParam(ctx->implCtx, p);
                    if (ret != CRYPT_SUCCESS) {
                        return ret;
                    }
                }
                break;
        }
    }
    
    return CRYPT_SUCCESS;
}

int32_t CRYPT_CODEC_Process(CRYPT_CODEC_Ctx *ctx, const BSL_Param *inParam, BSL_Param **outParam)
{
    int32_t ret = CODEC_ValidateCtx(ctx);
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
    
    ctx->state = CODEC_STATE_PROCESSING;
    
    // Add operation type to input parameters
    BSL_Param *extendedParam = BSL_SAL_Calloc(16, sizeof(BSL_Param)); // Reasonable buffer
    if (extendedParam == NULL) {
        ctx->state = CODEC_STATE_ERROR;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    // Copy original parameters
    int32_t paramCount = 0;
    for (const BSL_Param *p = inParam; p->key != 0 && paramCount < 14; p++, paramCount++) {
        extendedParam[paramCount] = *p;
    }
    
    // Add operation type
    extendedParam[paramCount].key = CRYPT_PARAM_CODEC_OPERATION_TYPE;
    extendedParam[paramCount].value = &ctx->opType;
    extendedParam[paramCount].valueLen = sizeof(CRYPT_CODEC_OP_TYPE);
    extendedParam[paramCount].useLen = sizeof(CRYPT_CODEC_OP_TYPE);
    paramCount++;
    
    // Terminate parameter list
    extendedParam[paramCount].key = 0;
    extendedParam[paramCount].value = NULL;
    extendedParam[paramCount].valueLen = 0;
    extendedParam[paramCount].useLen = 0;
    
    ret = ctx->method->process(ctx->implCtx, extendedParam, outParam);
    
    BSL_SAL_Free(extendedParam);
    
    if (ret == CRYPT_SUCCESS) {
        ctx->state = CODEC_STATE_DONE;
    } else {
        ctx->state = CODEC_STATE_ERROR;
    }
    
    return ret;
}

int32_t CRYPT_CODEC_Ctrl(CRYPT_CODEC_Ctx *ctx, int32_t cmd, void *val, int32_t valLen)
{
    int32_t ret = CODEC_ValidateCtx(ctx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    switch (cmd) {
        case CRYPT_CODEC_CMD_SET_OPERATION:
            if (val == NULL || valLen != sizeof(CRYPT_CODEC_OP_TYPE)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->opType = *(CRYPT_CODEC_OP_TYPE*)val;
            ctx->state = CODEC_STATE_READY; // Reset state when operation changes
            break;
            
        case CRYPT_CODEC_CMD_GET_OPERATION:
            if (val == NULL || valLen != sizeof(CRYPT_CODEC_OP_TYPE)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(CRYPT_CODEC_OP_TYPE*)val = ctx->opType;
            break;
            
        case CRYPT_CODEC_CMD_SET_FORMAT:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            ctx->outFormat = (const char*)val;
            break;
            
        case CRYPT_CODEC_CMD_GET_FORMAT:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            *(const char**)val = ctx->outFormat;
            break;
            
        case CRYPT_CODEC_CMD_SET_TYPE:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            ctx->outType = (const char*)val;
            break;
            
        case CRYPT_CODEC_CMD_GET_TYPE:
            if (val == NULL) {
                BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
                return CRYPT_NULL_INPUT;
            }
            *(const char**)val = ctx->outType;
            break;
            
        case CRYPT_CODEC_CMD_SET_FREE_FLAG:
            if (val == NULL || valLen != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            ctx->autoFreeOutput = *(bool*)val;
            break;
            
        case CRYPT_CODEC_CMD_GET_FREE_FLAG:
            if (val == NULL || valLen != sizeof(bool)) {
                BSL_ERR_PUSH_ERROR(CRYPT_INVALID_ARG);
                return CRYPT_INVALID_ARG;
            }
            *(bool*)val = ctx->autoFreeOutput;
            break;
            
        default:
            // Forward to implementation
            if (ctx->method != NULL && ctx->method->ctrl != NULL) {
                return ctx->method->ctrl(ctx->implCtx, cmd, val, valLen);
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
    
    if (!ctx->autoFreeOutput) {
        return; // Don't free if auto-free is disabled
    }
    
    if (ctx->method != NULL && ctx->method->freeOutData != NULL) {
        ctx->method->freeOutData(ctx->implCtx, outData);
    } else {
        // Default cleanup - free the parameter array
        BSL_SAL_Free(outData);
    }
}

#endif /* HITLS_CRYPTO_CODECS */