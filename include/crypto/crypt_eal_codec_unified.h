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

/**
 * @defgroup crypt_eal_codec_unified
 * @ingroup crypt
 * @brief Unified codec interface replacing both encode and decode
 */

#ifndef CRYPT_EAL_CODEC_UNIFIED_H
#define CRYPT_EAL_CODEC_UNIFIED_H

#include <stdint.h>
#include <stdbool.h>
#include "bsl_params.h"
#include "bsl_types.h"
#include "bsl_list.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"

#ifdef __cplusplus
extern "C" {
#endif

/* === UNIFIED OPERATION TYPES === */
typedef enum {
    CRYPT_CODEC_OP_DECODE = 0,
    CRYPT_CODEC_OP_ENCODE = 1,
} CRYPT_CODEC_OP_TYPE;

/* === UNIFIED CONTEXT TYPES === */
typedef struct CRYPT_CodecCtx CRYPT_CODEC_Ctx;
typedef struct CRYPT_CodecPoolCtx CRYPT_CODEC_PoolCtx;

/* === UNIFIED CONTROL COMMANDS === */
typedef enum {
    CRYPT_CODEC_CMD_SET_OPERATION = 1,
    CRYPT_CODEC_CMD_GET_OPERATION = 2,
    CRYPT_CODEC_CMD_SET_FORMAT = 3,
    CRYPT_CODEC_CMD_GET_FORMAT = 4,
    CRYPT_CODEC_CMD_SET_TYPE = 5,
    CRYPT_CODEC_CMD_GET_TYPE = 6,
    CRYPT_CODEC_CMD_SET_FREE_FLAG = 7,
    CRYPT_CODEC_CMD_GET_FREE_FLAG = 8,
} CRYPT_CODEC_CMD;

/* === UNIFIED CORE INTERFACE === */

/**
 * @brief Create unified codec context
 */
CRYPT_CODEC_Ctx *CRYPT_CODEC_NewCtx(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType, 
                                     int32_t keyType, const char *attrName);

/**
 * @brief Free codec context
 */
void CRYPT_CODEC_Free(CRYPT_CODEC_Ctx *ctx);

/**
 * @brief Set codec parameters
 */
int32_t CRYPT_CODEC_SetParam(CRYPT_CODEC_Ctx *ctx, const BSL_Param *param);

/**
 * @brief Get codec parameters
 */
int32_t CRYPT_CODEC_GetParam(CRYPT_CODEC_Ctx *ctx, BSL_Param *param);

/**
 * @brief Unified process function (encode/decode based on context)
 */
int32_t CRYPT_CODEC_Process(CRYPT_CODEC_Ctx *ctx, const BSL_Param *inParam, BSL_Param **outParam);

/**
 * @brief Control codec behavior
 */
int32_t CRYPT_CODEC_Ctrl(CRYPT_CODEC_Ctx *ctx, int32_t cmd, void *val, int32_t valLen);

/**
 * @brief Free output data
 */
void CRYPT_CODEC_FreeOutData(CRYPT_CODEC_Ctx *ctx, BSL_Param *outData);

/* === UNIFIED POOL INTERFACE === */

/**
 * @brief Create codec pool
 */
CRYPT_CODEC_PoolCtx *CRYPT_CODEC_PoolNew(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
    const char *attrName, int32_t keyType, const char *format, const char *type);

/**
 * @brief Free codec pool
 */
void CRYPT_CODEC_PoolFree(CRYPT_CODEC_PoolCtx *poolCtx);

/**
 * @brief Process through codec pool
 */
int32_t CRYPT_CODEC_PoolProcess(CRYPT_CODEC_PoolCtx *poolCtx, const BSL_Param *inParam, BSL_Param **outParam);

/**
 * @brief Control codec pool
 */
int32_t CRYPT_CODEC_PoolCtrl(CRYPT_CODEC_PoolCtx *poolCtx, int32_t cmd, void *val, int32_t valLen);

/* === UNIFIED HIGH-LEVEL FUNCTIONS === */

/**
 * @brief Unified buffer processing
 */
int32_t CRYPT_EAL_CodecBuff(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type, 
    const BSL_Buffer *input, const void *params, void **output);

/**
 * @brief Unified file processing  
 */
int32_t CRYPT_EAL_CodecFile(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type,
    const char *path, const void *params, void **output);

/* === BACKWARD COMPATIBILITY MACROS === */

/* Replace all decode functions with unified codec */
#define CRYPT_DECODE_ProviderNewCtx(libCtx, keyType, attrName) \
    CRYPT_CODEC_NewCtx(libCtx, CRYPT_CODEC_OP_DECODE, keyType, attrName)

#define CRYPT_DECODE_Free(ctx) \
    CRYPT_CODEC_Free(ctx)

#define CRYPT_DECODE_SetParam(ctx, param) \
    CRYPT_CODEC_SetParam(ctx, param)

#define CRYPT_DECODE_GetParam(ctx, param) \
    CRYPT_CODEC_GetParam(ctx, param)

#define CRYPT_DECODE_Decode(ctx, inParam, outParam) \
    CRYPT_CODEC_Process(ctx, inParam, outParam)

#define CRYPT_DECODE_FreeOutData(ctx, outData) \
    CRYPT_CODEC_FreeOutData(ctx, outData)

#define CRYPT_DECODE_PoolNewCtx(libCtx, attrName, keyType, format, type) \
    CRYPT_CODEC_PoolNew(libCtx, CRYPT_CODEC_OP_DECODE, attrName, keyType, format, type)

#define CRYPT_DECODE_PoolFreeCtx(poolCtx) \
    CRYPT_CODEC_PoolFree(poolCtx)

#define CRYPT_DECODE_PoolDecode(poolCtx, inParam, outParam) \
    CRYPT_CODEC_PoolProcess(poolCtx, inParam, outParam)

#define CRYPT_DECODE_PoolCtrl(poolCtx, cmd, val, valLen) \
    CRYPT_CODEC_PoolCtrl(poolCtx, cmd, val, valLen)

/* Replace all encode functions with unified codec */
#define CRYPT_ENCODE_ProviderNewCtx(libCtx, keyType, attrName) \
    CRYPT_CODEC_NewCtx(libCtx, CRYPT_CODEC_OP_ENCODE, keyType, attrName)

#define CRYPT_ENCODE_Free(ctx) \
    CRYPT_CODEC_Free(ctx)

#define CRYPT_ENCODE_SetParam(ctx, param) \
    CRYPT_CODEC_SetParam(ctx, param)

#define CRYPT_ENCODE_GetParam(ctx, param) \
    CRYPT_CODEC_GetParam(ctx, param)

#define CRYPT_ENCODE_Encode(ctx, inParam, outParam) \
    CRYPT_CODEC_Process(ctx, inParam, outParam)

#define CRYPT_ENCODE_FreeOutData(ctx, outData) \
    CRYPT_CODEC_FreeOutData(ctx, outData)

#define CRYPT_ENCODE_PoolNewCtx(libCtx, attrName, keyType, format, type) \
    CRYPT_CODEC_PoolNew(libCtx, CRYPT_CODEC_OP_ENCODE, attrName, keyType, format, type)

#define CRYPT_ENCODE_PoolFreeCtx(poolCtx) \
    CRYPT_CODEC_PoolFree(poolCtx)

#define CRYPT_ENCODE_PoolEncode(poolCtx, inParam, outParam) \
    CRYPT_CODEC_PoolProcess(poolCtx, inParam, outParam)

#define CRYPT_ENCODE_PoolCtrl(poolCtx, cmd, val, valLen) \
    CRYPT_CODEC_PoolCtrl(poolCtx, cmd, val, valLen)

/* High-level compatibility functions */
#define CRYPT_EAL_DecodeBuffKey(format, type, encode, pwd, pwdlen, ealPKey) \
    CRYPT_EAL_CodecBuff(NULL, CRYPT_CODEC_OP_DECODE, type, NULL, NULL, encode, pwd, (void**)ealPKey)

#define CRYPT_EAL_EncodeBuffKey(ealPKey, encodeParam, format, type, encode) \
    CRYPT_EAL_CodecBuff(NULL, CRYPT_CODEC_OP_ENCODE, type, NULL, NULL, (BSL_Buffer*)ealPKey, encodeParam, (void**)encode)

#define CRYPT_EAL_DecodeFileKey(format, type, path, pwd, pwdlen, ealPKey) \
    CRYPT_EAL_CodecFile(NULL, CRYPT_CODEC_OP_DECODE, type, NULL, NULL, path, pwd, (void**)ealPKey)

#define CRYPT_EAL_EncodeFileKey(ealPKey, encodeParam, format, type, path) \
    CRYPT_EAL_CodecFile(NULL, CRYPT_CODEC_OP_ENCODE, type, NULL, NULL, path, encodeParam, NULL)

#ifdef __cplusplus
}
#endif

#endif /* CRYPT_EAL_CODEC_UNIFIED_H */