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

#ifndef CODEC_LOCAL_H
#define CODEC_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECS
#include "crypt_eal_implprovider.h"
#include "crypt_eal_codecs_unified.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/* Codec states */
#define CRYPT_CODEC_STATE_UNTRIED 1
#define CRYPT_CODEC_STATE_TRYING 2
#define CRYPT_CODEC_STATE_TRIED 3
#define CRYPT_CODEC_STATE_SUCCESS 4

#define MAX_CRYPT_CODEC_FORMAT_TYPE_STR_LEN 64
#define MAX_CRYPT_CODEC_FORMAT_TYPE_SIZE 128

/**
 * @brief Unified codec method structure
 */
typedef struct CRYPT_CODEC_Method {
    CRYPT_CODEC_IMPL_NewCtx newCtx;               /* New context function */
    CRYPT_CODEC_IMPL_SetParam setParam;           /* Set parameter function */
    CRYPT_CODEC_IMPL_GetParam getParam;           /* Get parameter function */
    CRYPT_CODEC_IMPL_Process process;             /* Unified process function */
    CRYPT_CODEC_IMPL_Ctrl ctrl;                   /* Control function */
    CRYPT_CODEC_IMPL_FreeOutData freeOutData;     /* Free output data function */
    CRYPT_CODEC_IMPL_FreeCtx freeCtx;             /* Free context function */
} CRYPT_CODEC_Method;

/**
 * @brief Unified codec context structure
 */
struct CRYPT_CodecCtx {
    /* Provider manager context for queries */
    CRYPT_EAL_ProvMgrCtx *providerMgrCtx;     /* Provider manager context */
    char *attrName;                           /* Attribute name */
    CRYPT_CODEC_OP_TYPE opType;               /* Operation type (encode/decode) */
    const char *inFormat;                     /* Input data format */
    const char *inType;                       /* Input data type */
    const char *outFormat;                    /* Output data format */
    const char *outType;                      /* Output data type */
    void *codecCtx;                           /* Codec internal context */
    CRYPT_CODEC_Method *method;               /* Codec method */
    int32_t codecState;                       /* Codec state */
    bool freeOutData;                         /* Flag for freeing output data */
};

/**
 * @brief Data information structure
 */
typedef struct {
    const char *format;                    /* Data format */
    const char *type;                      /* Data type */
    BSL_Param *data;                       /* Data */
} CodecDataInfo;

/**
 * @brief Codec node structure for chaining
 */
typedef struct CRYPT_CODEC_Node {
    CodecDataInfo inData;                       /* Input data */
    CodecDataInfo outData;                      /* Output data */
    CRYPT_CODEC_Ctx *codecCtx;                  /* Codec context */
} CRYPT_CODEC_Node;

/**
 * @brief Unified codec pool context structure
 */
struct CRYPT_CodecPoolCtx {
    CRYPT_EAL_LibCtx *libCtx;               /* EAL library context */
    CRYPT_CODEC_OP_TYPE opType;             /* Operation type */
    const char *attrName;                   /* Attribute name */
    const char *inputFormat;                /* Input data format */
    const char *inputType;                  /* Input data type */
    int32_t inputKeyType;                   /* Input data key type */
    BSL_Param *input;                       /* Input data */
    const char *targetFormat;               /* Target format */
    const char *targetType;                 /* Target type */
    int32_t targetKeyType;                  /* Target data key type */
    BslList *codecs;                        /* The codecs pool of all provider, the entry is CRYPT_CODEC_Ctx */
    BslList *codecPath;                     /* The path of the codec, the entry is CRYPT_CODEC_Node */
    bool freeOutData;                       /* Flag for freeing output data */
};

/**
 * @brief Codec attribute information
 */
typedef struct {
    char *attrName;
    const char *inFormat;
    const char *inType;
    const char *outFormat;
    const char *outType;
} CODEC_AttrInfo;

/**
 * @brief Parse codec attribute string
 * 
 * @param attrName Attribute name string
 * @param info Output attribute information
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_ParseAttr(const char *attrName, CODEC_AttrInfo *info);

/**
 * @brief Create new codec context by method
 * 
 * @param funcs Provider functions
 * @param mgrCtx Provider manager context
 * @param opType Operation type
 * @param attrName Attribute name
 * @return CRYPT_CODEC_Ctx* Codec context on success, NULL on failure
 */
CRYPT_CODEC_Ctx *CRYPT_CODEC_NewCtxByMethod(const CRYPT_EAL_Func *funcs, CRYPT_EAL_ProvMgrCtx *mgrCtx,
    CRYPT_CODEC_OP_TYPE opType, const char *attrName);

/**
 * @brief Internal function to switch operation type
 * 
 * @param ctx Codec context
 * @param newOpType New operation type
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_CODEC_SwitchOperation(CRYPT_CODEC_Ctx *ctx, CRYPT_CODEC_OP_TYPE newOpType);

/**
 * @brief Get operation type string
 * 
 * @param opType Operation type
 * @return const char* Operation type string
 */
const char *CRYPT_CODEC_GetOpTypeString(CRYPT_CODEC_OP_TYPE opType);

/**
 * @brief Validate codec context
 * 
 * @param ctx Codec context
 * @return int32_t CRYPT_SUCCESS if valid, error code otherwise
 */
int32_t CRYPT_CODEC_ValidateCtx(const CRYPT_CODEC_Ctx *ctx);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HITLS_CRYPTO_CODECS */

#endif /* CODEC_LOCAL_H */