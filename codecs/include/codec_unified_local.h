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

#ifndef CODEC_UNIFIED_LOCAL_H
#define CODEC_UNIFIED_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECS
#include "crypt_eal_implprovider.h"
#include "crypt_eal_codec_unified.h"
#include "bsl_list.h"

#ifdef __cplusplus
extern "C" {
#endif

/* === UNIFIED STATES === */
#define CODEC_STATE_INIT       0
#define CODEC_STATE_READY      1
#define CODEC_STATE_PROCESSING 2
#define CODEC_STATE_DONE       3
#define CODEC_STATE_ERROR      4

/* === UNIFIED CONSTANTS === */
#define MAX_CODEC_ATTR_LEN   128
#define MAX_CODEC_FORMAT_LEN 64
#define MAX_CODEC_TYPE_LEN   64

/* === UNIFIED METHOD STRUCTURE (replaces both decoder and encoder methods) === */
typedef struct CRYPT_CODEC_Method {
    void *(*newCtx)(void *provCtx);                                    /* Create context */
    int32_t (*setParam)(void *ctx, const BSL_Param *param);           /* Set parameters */
    int32_t (*getParam)(void *ctx, BSL_Param *param);                 /* Get parameters */
    int32_t (*process)(void *ctx, const BSL_Param *inParam, BSL_Param **outParam); /* Unified process */
    int32_t (*ctrl)(void *ctx, int32_t cmd, void *val, int32_t valLen); /* Control */
    void (*freeOutData)(void *ctx, BSL_Param *outData);               /* Free output */
    void (*freeCtx)(void *ctx);                                       /* Free context */
} CRYPT_CODEC_Method;

/* === UNIFIED DATA INFO STRUCTURE (replaces DataInfo and EncodeDataInfo) === */
typedef struct CODEC_DataInfo {
    const char *format;    /* Data format (PEM, DER, etc.) */
    const char *type;      /* Data type (RSA, ECC, etc.) */
    BSL_Param *data;       /* Actual data */
    uint32_t dataLen;      /* Data length */
} CODEC_DataInfo;

/* === UNIFIED CONTEXT STRUCTURE (replaces both DecoderCtx and EncoderCtx) === */
struct CRYPT_CodecCtx {
    /* Core fields */
    CRYPT_EAL_ProvMgrCtx *provMgrCtx;        /* Provider manager */
    CRYPT_CODEC_OP_TYPE opType;              /* Operation type */
    int32_t state;                           /* Current state */
    
    /* Configuration */
    char *attrName;                          /* Attribute name */
    const char *inFormat;                    /* Input format */
    const char *inType;                      /* Input type */
    const char *outFormat;                   /* Output format */
    const char *outType;                     /* Output type */
    
    /* Implementation */
    void *implCtx;                           /* Implementation context */
    CRYPT_CODEC_Method *method;              /* Method table */
    
    /* Flags */
    bool autoFreeOutput;                     /* Auto free output flag */
    bool reusable;                           /* Context reusable flag */
};

/* === UNIFIED NODE STRUCTURE (replaces both decoder and encoder nodes) === */
typedef struct CODEC_Node {
    CODEC_DataInfo input;                    /* Input data info */
    CODEC_DataInfo output;                   /* Output data info */
    CRYPT_CODEC_Ctx *codecCtx;               /* Associated codec context */
    struct CODEC_Node *next;                 /* Next node in chain */
} CODEC_Node;

/* === UNIFIED POOL STRUCTURE (replaces both decoder and encoder pools) === */
struct CRYPT_CodecPoolCtx {
    /* Core fields */
    CRYPT_EAL_LibCtx *libCtx;                /* Library context */
    CRYPT_CODEC_OP_TYPE opType;              /* Operation type */
    int32_t keyType;                         /* Key type */
    
    /* Configuration */
    char *attrName;                          /* Attribute name */
    char *inputFormat;                       /* Input format */
    char *inputType;                         /* Input type */
    char *targetFormat;                      /* Target format */  
    char *targetType;                        /* Target type */
    
    /* Chain management */
    BslList *availableCodecs;                /* Available codec contexts */
    CODEC_Node *processingChain;             /* Active processing chain */
    
    /* Flags and options */
    bool autoFreeOutput;                     /* Auto free output */
    bool optimizeChain;                      /* Optimize processing chain */
    uint32_t maxChainDepth;                  /* Maximum chain depth */
};

/* === UNIFIED ATTRIBUTE INFO STRUCTURE === */
typedef struct CODEC_AttrInfo {
    char *name;                              /* Attribute name */
    const char *inFormat;                    /* Input format */
    const char *inType;                      /* Input type */
    const char *outFormat;                   /* Output format */
    const char *outType;                     /* Output type */
    CRYPT_CODEC_OP_TYPE defaultOp;           /* Default operation */
} CODEC_AttrInfo;

/* === INTERNAL HELPER FUNCTIONS === */

/**
 * @brief Parse codec attribute string into structured info
 */
int32_t CODEC_ParseAttr(const char *attrName, CODEC_AttrInfo *info);

/**
 * @brief Create codec context using method table
 */
CRYPT_CODEC_Ctx *CODEC_NewCtxByMethod(const CRYPT_EAL_Func *funcs, 
    CRYPT_EAL_ProvMgrCtx *mgrCtx, CRYPT_CODEC_OP_TYPE opType, const char *attrName);

/**
 * @brief Switch operation type for existing context
 */
int32_t CODEC_SwitchOperation(CRYPT_CODEC_Ctx *ctx, CRYPT_CODEC_OP_TYPE newOpType);

/**
 * @brief Validate codec context
 */
int32_t CODEC_ValidateCtx(const CRYPT_CODEC_Ctx *ctx);

/**
 * @brief Build optimal processing chain
 */
int32_t CODEC_BuildChain(CRYPT_CODEC_PoolCtx *poolCtx, const char *fromFormat, 
    const char *fromType, const char *toFormat, const char *toType);

/**
 * @brief Execute processing chain
 */
int32_t CODEC_ExecuteChain(CODEC_Node *chain, const BSL_Param *input, BSL_Param **output);

/**
 * @brief Free processing chain
 */
void CODEC_FreeChain(CODEC_Node *chain);

/**
 * @brief Get operation type string
 */
const char *CODEC_GetOpString(CRYPT_CODEC_OP_TYPE opType);

/**
 * @brief Copy data info structure
 */
int32_t CODEC_CopyDataInfo(const CODEC_DataInfo *src, CODEC_DataInfo *dst);

/**
 * @brief Free data info structure
 */
void CODEC_FreeDataInfo(CODEC_DataInfo *info);

/**
 * @brief Check format compatibility
 */
bool CODEC_IsFormatCompatible(const char *format1, const char *format2);

/**
 * @brief Check type compatibility
 */
bool CODEC_IsTypeCompatible(const char *type1, const char *type2);

/* === STATISTICS AND DEBUGGING === */
typedef struct CODEC_Stats {
    uint32_t totalProcessed;                 /* Total items processed */
    uint32_t encodeCount;                    /* Encode operations */
    uint32_t decodeCount;                    /* Decode operations */
    uint32_t chainOptimizations;             /* Chain optimizations performed */
    uint32_t errorCount;                     /* Error count */
} CODEC_Stats;

/**
 * @brief Get codec statistics
 */
int32_t CODEC_GetStats(CRYPT_CODEC_PoolCtx *poolCtx, CODEC_Stats *stats);

/**
 * @brief Reset codec statistics
 */
void CODEC_ResetStats(CRYPT_CODEC_PoolCtx *poolCtx);

#ifdef __cplusplus
}
#endif
#endif /* HITLS_CRYPTO_CODECS */

#endif /* CODEC_UNIFIED_LOCAL_H */