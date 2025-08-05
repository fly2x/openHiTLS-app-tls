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
 * @defgroup crypt_eal_codecs_unified
 * @ingroup crypt
 * @brief Unified codec interface for encode/decode operations
 */

#ifndef CRYPT_EAL_CODECS_UNIFIED_H
#define CRYPT_EAL_CODECS_UNIFIED_H

#include <stdint.h>
#include "bsl_params.h"
#include "bsl_types.h"
#include "bsl_list.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_provider.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/**
 * @brief Codec operation types
 */
typedef enum {
    CRYPT_CODEC_OP_DECODE = 0,     /* Decode operation */
    CRYPT_CODEC_OP_ENCODE = 1,     /* Encode operation */
} CRYPT_CODEC_OP_TYPE;

/**
 * @brief Unified codec context
 */
typedef struct CRYPT_CodecCtx CRYPT_CODEC_Ctx;

/**
 * @brief Unified codec pool context
 */
typedef struct CRYPT_CodecPoolCtx CRYPT_CODEC_PoolCtx;

/**
 * @brief Command codes for CRYPT_CODEC_Ctrl function
 */
typedef enum {
    /** Set the operation type (encode/decode) */
    CRYPT_CODEC_CMD_SET_OPERATION_TYPE,
    /** Set the target format */
    CRYPT_CODEC_CMD_SET_TARGET_FORMAT,
    /** Set the target type */
    CRYPT_CODEC_CMD_SET_TARGET_TYPE,
    /** Set the flag for not freeing out data */
    CRYPT_CODEC_CMD_SET_FLAG_FREE_OUT_DATA,
    /** Get current operation type */
    CRYPT_CODEC_CMD_GET_OPERATION_TYPE,
    /** Get current target format */
    CRYPT_CODEC_CMD_GET_TARGET_FORMAT,
    /** Get current target type */
    CRYPT_CODEC_CMD_GET_TARGET_TYPE,
} CRYPT_CODEC_CMD;

/**
 * @brief Create a unified codec context for the specified format and type
 * 
 * @param libCtx EAL library context
 * @param opType Operation type (encode/decode)
 * @param keyType Target key type (e.g., CRYPT_ALG_ID_RSA, CRYPT_ALG_ID_EC)
 * @param attrName Attribute name for specific type processing (can be NULL)
 * @return CRYPT_CODEC_Ctx* Codec context, returns NULL on failure
 */
CRYPT_CODEC_Ctx *CRYPT_CODEC_NewCtx(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType, 
                                     int32_t keyType, const char *attrName);

/**
 * @brief Free the codec context
 * 
 * @param ctx Codec context
 */
void CRYPT_CODEC_Free(CRYPT_CODEC_Ctx *ctx);

/**
 * @brief Set codec parameters
 * 
 * @param ctx Codec context
 * @param param Parameter
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_SetParam(CRYPT_CODEC_Ctx *ctx, const BSL_Param *param);

/**
 * @brief Get codec parameters
 * 
 * @param ctx Codec context
 * @param param Parameter (output)
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_GetParam(CRYPT_CODEC_Ctx *ctx, BSL_Param *param);

/**
 * @brief Perform codec operation (encode or decode based on context setting)
 * 
 * @param ctx Codec context
 * @param inParam Input parameter
 * @param outParam Output parameter
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_Process(CRYPT_CODEC_Ctx *ctx, const BSL_Param *inParam, BSL_Param **outParam);

/**
 * @brief Control operation for codec context
 * 
 * @param ctx Codec context
 * @param cmd Control command
 * @param val The value of the control command
 * @param valLen The length of the value
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_Ctrl(CRYPT_CODEC_Ctx *ctx, int32_t cmd, void *val, int32_t valLen);

/**
 * @brief Free the output data
 * 
 * @param ctx Codec context
 * @param data Output data
 */
void CRYPT_CODEC_FreeOutData(CRYPT_CODEC_Ctx *ctx, BSL_Param *outData);

/**
 * @brief Create a unified codec pool context
 * 
 * @param libCtx EAL library context
 * @param opType Operation type (encode/decode)
 * @param attrName Provider attribute name, can be NULL
 * @param keyType Target key type
 * @param format Input data format (e.g., BSL_FORMAT_PEM, BSL_FORMAT_DER)
 * @param type Target type (e.g., CRYPT_ALG_ID_RSA, CRYPT_ALG_ID_EC)
 * @return CRYPT_CODEC_PoolCtx* Codec pool context on success, NULL on failure
 */
CRYPT_CODEC_PoolCtx *CRYPT_CODEC_PoolNewCtx(CRYPT_EAL_LibCtx *libCtx, CRYPT_CODEC_OP_TYPE opType,
    const char *attrName, int32_t keyType, const char *format, const char *type);

/**
 * @brief Free a codec pool context
 * 
 * @param poolCtx Codec pool context
 */
void CRYPT_CODEC_PoolFreeCtx(CRYPT_CODEC_PoolCtx *poolCtx);

/**
 * @brief Process the input data with the codec chain
 * 
 * @param poolCtx Codec pool context
 * @param inParam Input data
 * @param outParam Output Data
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_PoolProcess(CRYPT_CODEC_PoolCtx *poolCtx, const BSL_Param *inParam, BSL_Param **outParam);

/**
 * @brief Control operation for codec pool
 * 
 * @param poolCtx Codec pool context
 * @param cmd Control command
 * @param val The value of the control command
 * @param valLen The length of the value
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_PoolCtrl(CRYPT_CODEC_PoolCtx *poolCtx, int32_t cmd, void *val, int32_t valLen);

/**
 * @brief Unified buffer processing function for key codec operations
 *
 * @param libCtx EAL library context
 * @param attrName Provider attribute name, maybe NULL
 * @param opType Operation type (encode/decode)
 * @param keyType The type of pkey
 * @param format The buffer format
 * @param type The type string
 * @param inputBuf Input buffer
 * @param pwd Password buffer (for decode) or encode params (for encode)
 * @param outputBuf Output buffer (for encode) or pkey context (for decode)
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_EAL_CodecBuffKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type, const BSL_Buffer *inputBuf, 
    const void *auxParam, void **outputData);

/**
 * @brief Unified file processing function for key codec operations
 *
 * @param libCtx EAL library context
 * @param attrName Provider attribute name, maybe NULL
 * @param opType Operation type (encode/decode)
 * @param keyType The type of pkey
 * @param format The file format
 * @param type The type string
 * @param path The file path
 * @param auxParam Auxiliary parameter (password for decode, encode params for encode)
 * @param outputData Output data
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_EAL_CodecFileKey(CRYPT_EAL_LibCtx *libCtx, const char *attrName, CRYPT_CODEC_OP_TYPE opType,
    int32_t keyType, const char *format, const char *type, const char *path,
    const void *auxParam, void **outputData);

/* Backward compatibility macros */
#define CRYPT_DECODE_ProviderNewCtx(libCtx, keyType, attrName) \
    CRYPT_CODEC_NewCtx(libCtx, CRYPT_CODEC_OP_DECODE, keyType, attrName)

#define CRYPT_ENCODE_ProviderNewCtx(libCtx, keyType, attrName) \
    CRYPT_CODEC_NewCtx(libCtx, CRYPT_CODEC_OP_ENCODE, keyType, attrName)

#define CRYPT_DECODE_Free(ctx) CRYPT_CODEC_Free(ctx)
#define CRYPT_ENCODE_Free(ctx) CRYPT_CODEC_Free(ctx)

#define CRYPT_DECODE_SetParam(ctx, param) CRYPT_CODEC_SetParam(ctx, param)
#define CRYPT_ENCODE_SetParam(ctx, param) CRYPT_CODEC_SetParam(ctx, param)

#define CRYPT_DECODE_GetParam(ctx, param) CRYPT_CODEC_GetParam(ctx, param)
#define CRYPT_ENCODE_GetParam(ctx, param) CRYPT_CODEC_GetParam(ctx, param)

#define CRYPT_DECODE_Decode(ctx, inParam, outParam) CRYPT_CODEC_Process(ctx, inParam, outParam)
#define CRYPT_ENCODE_Encode(ctx, inParam, outParam) CRYPT_CODEC_Process(ctx, inParam, outParam)

#define CRYPT_DECODE_FreeOutData(ctx, outData) CRYPT_CODEC_FreeOutData(ctx, outData)
#define CRYPT_ENCODE_FreeOutData(ctx, outData) CRYPT_CODEC_FreeOutData(ctx, outData)

#ifdef __cplusplus
}
#endif // __cplusplus

#endif // CRYPT_EAL_CODECS_UNIFIED_H