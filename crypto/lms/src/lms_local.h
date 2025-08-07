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

#ifndef LMS_LOCAL_H
#define LMS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS

#include <stdint.h>
#include "crypt_lms.h"
#include "crypt_types.h"
#include "bsl_sal.h"
#include "eal_md_local.h"

/* Constants from RFC 8554 */
#define LMS_M_VALUE 32  /* SHA-256 output size */
#define LMS_N_VALUE 32  /* SHA-256 output size for LMS */

/* LMS tree height values */
#define LMS_H5  5
#define LMS_H10 10
#define LMS_H15 15
#define LMS_H20 20
#define LMS_H25 25

/* LM-OTS Winternitz parameter values */
#define LMOTS_W1 1
#define LMOTS_W2 2
#define LMOTS_W4 4
#define LMOTS_W8 8

/* Type codes from RFC 8554 */
#define D_INTR  0x01
#define D_LEAF  0x02
#define D_MESG  0x81
#define D_PBLC  0x80

/* Key types */
#define LMS_PRVKEY 0x1
#define LMS_PUBKEY 0x10

/* Maximum values */
#define LMS_MAX_HEIGHT 25
#define LMS_MAX_P 265  /* For W=1 */
#define HSS_MAX_LEVELS 8

/**
 * @brief LM-OTS parameters structure
 */
typedef struct {
    uint32_t algId;      /* Algorithm ID */
    uint32_t n;          /* Hash output size in bytes */
    uint32_t w;          /* Winternitz parameter */
    uint32_t p;          /* Number of n-byte elements in signature */
    uint32_t ls;         /* Left shift for checksum */
    uint32_t sigLen;     /* Total signature length */
} LmotsParam;

/**
 * @brief LMS parameters structure
 */
typedef struct {
    uint32_t algId;      /* Algorithm ID */
    uint32_t m;          /* Hash output size in bytes */
    uint32_t h;          /* Tree height */
    uint32_t pubKeyLen;  /* Public key length */
    uint32_t sigLen;     /* Signature length (excluding message) */
} LmsParam;

/**
 * @brief LMS tree node structure
 */
typedef struct {
    uint8_t *value;      /* Node value (n bytes) */
    uint32_t index;      /* Node index in tree */
} LmsNode;

/**
 * @brief LM-OTS private key
 */
typedef struct {
    uint32_t algId;                          /* LM-OTS algorithm ID */
    uint8_t I[16];                           /* 16-byte identifier */
    uint32_t q;                              /* Leaf index */
    uint8_t seed[LMS_N_VALUE];               /* Random seed */
} LmotsPrivateKey;

/**
 * @brief LM-OTS public key
 */
typedef struct {
    uint32_t algId;                          /* LM-OTS algorithm ID */
    uint8_t I[16];                           /* 16-byte identifier */
    uint32_t q;                              /* Leaf index */
    uint8_t K[LMS_N_VALUE];                  /* Public key value */
} LmotsPublicKey;

/**
 * @brief LMS private key
 */
typedef struct {
    uint32_t algId;                          /* LMS algorithm ID */
    uint32_t otsAlgId;                       /* LM-OTS algorithm ID */
    uint8_t I[16];                           /* 16-byte identifier */
    uint8_t seed[LMS_M_VALUE];               /* Master seed */
    uint32_t q;                              /* Current leaf index */
    uint32_t maxQ;                           /* Maximum leaf index (2^h - 1) */
} LmsPrivateKey;

/**
 * @brief LMS public key
 */
typedef struct {
    uint32_t algId;                          /* LMS algorithm ID */
    uint32_t otsAlgId;                       /* LM-OTS algorithm ID */
    uint8_t I[16];                           /* 16-byte identifier */
    uint8_t T1[LMS_M_VALUE];                 /* Root node value */
} LmsPublicKey;

/**
 * @brief HSS private key
 */
typedef struct {
    uint32_t L;                              /* Number of levels */
    LmsPrivateKey *lmsKeys[HSS_MAX_LEVELS]; /* Array of LMS private keys */
    LmsPublicKey *lmsPubs[HSS_MAX_LEVELS];  /* Array of LMS public keys */
    uint8_t *sigList[HSS_MAX_LEVELS - 1];   /* Stored signatures */
} HssPrivateKey;

/**
 * @brief HSS public key
 */
typedef struct {
    uint32_t L;                              /* Number of levels */
    LmsPublicKey pubKey;                     /* Top-level public key */
} HssPublicKey;

/**
 * @brief LMS context structure
 */
struct CryptLmsCtx {
    void *libCtx;                            /* Library context */
    uint32_t keyType;                        /* Key type flags */
    
    /* Single LMS keys */
    LmsPrivateKey *lmsPrv;                   /* LMS private key */
    LmsPublicKey *lmsPub;                    /* LMS public key */
    
    /* HSS keys */
    HssPrivateKey *hssPrv;                   /* HSS private key */
    HssPublicKey *hssPub;                    /* HSS public key */
    
    /* Hash method */
    const EAL_MdMethod *mdMethod;            /* Hash function method */
    
    BSL_SAL_RefCount references;             /* Reference count */
};

/* Internal functions */

/* LM-OTS functions */
int32_t LmotsGeneratePrivateKey(LmotsPrivateKey *prv, const uint8_t *I, uint32_t q, 
                                const uint8_t *seed, uint32_t algId);
int32_t LmotsGeneratePublicKey(const LmotsPrivateKey *prv, LmotsPublicKey *pub);
int32_t LmotsSign(const LmotsPrivateKey *prv, const uint8_t *message, uint32_t msgLen,
                  uint8_t *signature, uint32_t *sigLen);
int32_t LmotsVerify(const LmotsPublicKey *pub, const uint8_t *message, uint32_t msgLen,
                   const uint8_t *signature, uint32_t sigLen);

/* LMS functions */
int32_t LmsGeneratePrivateKey(LmsPrivateKey *prv, uint32_t lmsAlgId, uint32_t otsAlgId);
int32_t LmsGeneratePublicKey(const LmsPrivateKey *prv, LmsPublicKey *pub);
int32_t LmsSign(LmsPrivateKey *prv, const uint8_t *message, uint32_t msgLen,
                uint8_t *signature, uint32_t *sigLen);
int32_t LmsVerify(const LmsPublicKey *pub, const uint8_t *message, uint32_t msgLen,
                  const uint8_t *signature, uint32_t sigLen);

/* HSS functions */
int32_t HssGeneratePrivateKey(HssPrivateKey *prv, uint32_t L, const uint32_t *lmsAlgIds,
                             const uint32_t *otsAlgIds);
int32_t HssGeneratePublicKey(const HssPrivateKey *prv, HssPublicKey *pub);
int32_t HssSign(HssPrivateKey *prv, const uint8_t *message, uint32_t msgLen,
                uint8_t *signature, uint32_t *sigLen);
int32_t HssVerify(const HssPublicKey *pub, const uint8_t *message, uint32_t msgLen,
                  const uint8_t *signature, uint32_t sigLen);

/* Helper functions */
const LmotsParam *GetLmotsParam(uint32_t algId);
const LmsParam *GetLmsParam(uint32_t algId);
int32_t LmsGenerateLeafNode(const LmsPrivateKey *prv, uint32_t leafIndex, uint8_t *node);
int32_t LmsComputeRoot(const LmsPrivateKey *prv, uint8_t *root);

/* Hash functions - can reuse from SLH-DSA/XMSS */
int32_t LmsHash(const EAL_MdMethod *md, const uint8_t *data, uint32_t dataLen, 
                uint8_t *out, uint32_t outLen);

#endif // HITLS_CRYPTO_LMS

#endif // LMS_LOCAL_H