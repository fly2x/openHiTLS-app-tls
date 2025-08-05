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

#ifndef ENCODE_LOCAL_H
#define ENCODE_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECS
#include "crypt_eal_implprovider.h"
#include "crypt_eal_codecs.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define CRYPT_ENCODER_STATE_UNTRIED 1
#define CRYPT_ENCODER_STATE_TRING 2
#define CRYPT_ENCODER_STATE_TRIED 3
#define CRYPT_ENCODER_STATE_SUCCESS 4
#define MAX_CRYPT_ENCODER_FORMAT_TYPE_STR_LEN 64

/**
 * @brief Encoder context structure
 */
typedef struct CRYPT_ENCODER_Method {
    CRYPT_ENCODER_IMPL_NewCtx newCtx;               /* New context function */
    CRYPT_ENCODER_IMPL_SetParam setParam;           /* Set parameter function */
    CRYPT_ENCODER_IMPL_GetParam getParam;           /* Get parameter function */
    CRYPT_ENCODER_IMPL_Encode encode;               /* Encode function */
    CRYPT_ENCODER_IMPL_FreeOutData freeOutData;     /* Free output data function */
    CRYPT_ENCODER_IMPL_FreeCtx freeCtx;             /* Free context function */
} CRYPT_ENCODER_Method;

struct CRYPT_EncoderCtx {
    /* To get the provider manager context when query */
    CRYPT_EAL_ProvMgrCtx *providerMgrCtx;     /* Provider manager context */
    char *attrName;                     /* Attribute name */
    const char *inFormat;                     /* Input data format */
    const char *inType;                       /* Input data type */
    const char *outFormat;                    /* Output data format */
    const char *outType;                      /* Output data type */
    void *encoderCtx;                   /* Encoder internal context */
    CRYPT_ENCODER_Method *method;             /* Encoder method */
    int32_t encoderState;               /* Encoder state */
};

typedef struct {
    const char *format;                    /* Data format */
    const char *type;                      /* Data type */
    BSL_Param *data;                       /* Data */
} EncodeDataInfo;

typedef struct CRYPT_ENCODER_Node {
    EncodeDataInfo inData;                       /* Input data */
    EncodeDataInfo outData;                      /* Output data */
    CRYPT_ENCODER_Ctx *encoderCtx;         /* Encoder context */
} CRYPT_ENCODER_Node;

#define MAX_CRYPT_ENCODE_FORMAT_TYPE_SIZE 128
struct CRYPT_ENCODER_PoolCtx {
    CRYPT_EAL_LibCtx *libCtx;               /* EAL library context */
    const char *attrName;                   /* Attribute name */
    const char *inputFormat;                /* Input data format */
    const char *inputType;                  /* Input data type */
    int32_t inputKeyType;                   /* Input data key type */
    BSL_Param *input;                       /* Input data */
    const char *targetFormat;               /* Target format */
    const char *targetType;                 /* Target type */
    int32_t targetKeyType;                  /* Target data key type */
    BslList *encoders;                      /* The encoders pool of all provider, the entry is CRYPT_ENCODER_Ctx */
    BslList *encoderPath;                   /* The path of the encoder, the entry is CRYPT_ENCODER_Node */
};

typedef struct {
    char *attrName;
    const char *inFormat;
    const char *inType;
    const char *outFormat;
    const char *outType;
} ENCODER_AttrInfo;

int32_t CRYPT_ENCODE_ParseEncoderAttr(const char *attrName, ENCODER_AttrInfo *info);

CRYPT_ENCODER_Ctx *CRYPT_ENCODE_NewEncoderCtxByMethod(const CRYPT_EAL_Func *funcs, CRYPT_EAL_ProvMgrCtx *mgrCtx,
    const char *attrName);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif /* HITLS_CRYPTO_CODECS */

#endif /* ENCODE_LOCAL_H */