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

#ifndef LMS_HSS_LOCAL_H
#define LMS_HSS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS_HSS

#include <stdint.h>
#include <stdbool.h>
#include "bsl_params.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_errno.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "sal_atomic.h"
#include "crypt_lms_hss.h"

/* Key type flags */
#define LMS_HSS_PUBKEY              0x10
#define LMS_HSS_PRVKEY              0x01
#define LMS_HSS_KEYPAIR             0x11

/* Constants from RFC 8554 */
#define LMS_HSS_HASH_LEN            32      /* SHA-256 output length */
#define LMS_HSS_IDENTIFIER_LEN      16      /* Identifier length */
#define LMS_HSS_SEED_LEN            32      /* Seed length */
#define LMS_HSS_MAX_LEVELS          8       /* Maximum HSS levels */
#define LMS_HSS_MAX_HEIGHT          25      /* Maximum LMS tree height */

/* LMS/HSS address types from RFC 8554 */
#define LMS_HSS_ADDR_TYPE_OTS   0
#define LMS_HSS_ADDR_TYPE_TREE  1

/* LMS/HSS parameter structure - independent implementation */
typedef struct {
    uint32_t algId;         /* Algorithm ID */
    uint32_t lmsType;       /* LMS algorithm type */
    uint32_t lmotsType;     /* LMOTS algorithm type */
    uint32_t levels;        /* HSS levels */
    uint32_t h;             /* Tree height */
    uint32_t n;             /* Hash length */
    uint32_t w;             /* Winternitz parameter */
    uint32_t p;             /* Number of chains */
    uint32_t ls;            /* Left shift count */
    uint32_t sigLen;        /* Signature length */
    uint32_t pubKeyLen;     /* Public key length */
    uint32_t prvKeyLen;     /* Private key length */
} LmsHssPara;

/* LMS/HSS address structure following RFC 8554 */
typedef struct {
    uint8_t type;           /* Address type (OTS or TREE) */
    uint32_t q;             /* Tree node index or OTS key index */
    uint16_t i;             /* Chain address (for LMOTS) or tree height */
    uint8_t j;              /* Hash address (for LMOTS) */
} LmsHssAdrs;

/* Hash function interface - adapted from SLH-DSA patterns */
typedef struct {
    int32_t (*h)(const struct CryptLmsHssCtx *ctx, const LmsHssAdrs *adrs, 
                 const uint8_t *msg, uint32_t msgLen, uint8_t *out);
    int32_t (*f)(const struct CryptLmsHssCtx *ctx, const LmsHssAdrs *adrs, 
                 const uint8_t *msg, uint32_t msgLen, uint8_t *out);
    int32_t (*prf)(const struct CryptLmsHssCtx *ctx, const LmsHssAdrs *adrs, 
                   const uint8_t *seed, uint8_t *out);
} LmsHssHashFuncs;

/* LMS public key structure */
typedef struct {
    uint32_t lmsType;
    uint32_t lmotsType;
    uint8_t identifier[LMS_HSS_IDENTIFIER_LEN];
    uint8_t root[LMS_HSS_HASH_LEN];
} LmsPubKey;

/* HSS public key structure */
typedef struct {
    uint32_t levels;
    LmsPubKey topLevelPubKey;
} HssPubKey;

/* LMS private key structure */
typedef struct {
    uint32_t lmsType;
    uint32_t lmotsType;
    uint8_t identifier[LMS_HSS_IDENTIFIER_LEN];
    uint32_t q;         /* next available signature index */
    uint8_t seed[LMS_HSS_SEED_LEN];
    LmsPubKey pubKey;
} LmsPrvKey;

/* HSS private key structure */
typedef struct {
    uint32_t levels;
    LmsPrvKey *prvKeys;     /* array of LMS private keys for each level */
    uint8_t **signatures;   /* array of signatures for each level */
} HssPrvKey;

/* LMOTS signature structure */
typedef struct {
    uint32_t lmotsType;
    uint8_t c[LMS_HSS_HASH_LEN];    /* random value */
    uint8_t *y;                     /* signature values (length p*n) */
} LmotsSignature;

/* LMS signature structure */
typedef struct {
    uint32_t q;                     /* signature index */
    LmotsSignature lmotsSignature;
    uint32_t lmsType;
    uint8_t *authPath;              /* authentication path (length h * LMS_HSS_HASH_LEN) */
} LmsSignature;

/* HSS signature structure */
typedef struct {
    uint32_t nspk;                  /* number of signed public keys */
    LmsSignature *lmsSignatures;    /* array of LMS signatures */
    LmsPubKey *pubKeys;             /* array of public keys */
} HssSignature;

/* Main LMS/HSS context structure */
struct CryptLmsHssCtx {
    LmsHssPara para;
    HssPubKey pubKey;
    HssPrvKey prvKey;
    LmsHssHashFuncs hashFuncs;
    uint8_t keyType;
    void *libCtx;
    BSL_SAL_RefCount references;
};

/* Internal function declarations */

/* Parameter functions */
int32_t LmsHss_InitPara(LmsHssPara *para, uint32_t lmsType, uint32_t lmotsType, uint32_t levels);
int32_t LmsHss_ValidatePara(const LmsHssPara *para);
uint32_t LmsHss_GetSignatureLength(const LmsHssPara *para);
uint32_t LmsHss_GetPublicKeyLength(const LmsHssPara *para);
uint32_t LmsHss_GetPrivateKeyLength(const LmsHssPara *para);

/* Hash function wrappers - using SLH-DSA infrastructure */
int32_t LmsHss_InitHashFuncs(CryptLmsHssCtx *ctx);

/* Deterministic key generation from seed */
int32_t LmsHss_GenerateFromSeed(CryptLmsHssCtx *ctx, const uint8_t *seed, uint32_t seedLen);

/* Merkle tree functions - adapted from SLH-DSA XmssNode */
int32_t LmsNode(uint8_t *node, uint32_t idx, uint32_t height, LmsHssAdrs *adrs, 
                const CryptLmsHssCtx *ctx, uint8_t *authPath, uint32_t leafIdx, uint32_t level);
int32_t LmsGeneratePublicKey(CryptLmsHssCtx *ctx, uint32_t level, uint8_t *pubKey);
int32_t LmsSign(CryptLmsHssCtx *ctx, uint32_t level, const uint8_t *msg, uint32_t msgLen,
                uint8_t *sig, uint32_t *sigLen);
int32_t LmsVerify(const CryptLmsHssCtx *ctx, uint32_t level, const uint8_t *msg, uint32_t msgLen,
                  const uint8_t *sig, uint32_t sigLen, const uint8_t *pubKey);

/* LMOTS functions */
int32_t LMOTS_Sign(CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                   const uint8_t *identifier, uint32_t q, const uint8_t *seed,
                   LmotsSignature *signature);
int32_t LMOTS_Verify(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                     const LmotsSignature *signature, const uint8_t *pubKey, uint32_t q);
int32_t LMOTS_ReconstructPublicKey(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                                   const LmotsSignature *signature, const uint8_t *identifier, uint32_t q, 
                                   uint8_t *reconstructedPubKey);
int32_t LMOTS_GenerateKeyPair(const CryptLmsHssCtx *ctx, const uint8_t *identifier,
                              uint32_t q, const uint8_t *seed);
int32_t LMOTS_GeneratePublicKey(const CryptLmsHssCtx *ctx, const uint8_t *identifier,
                               uint32_t q, const uint8_t *seed, uint8_t *pubKey);

/* Internal signature state management */
int32_t UpdateSignatureState(CryptLmsHssCtx *ctx, uint32_t level);

/* Backward compatibility hash functions */
int32_t LmsHss_Hash(const CryptLmsHssCtx *ctx, const uint8_t *data, uint32_t dataLen, uint8_t *hash);
int32_t LmsHss_PRF(const CryptLmsHssCtx *ctx, const uint8_t *key, const uint8_t *data, 
                   uint32_t dataLen, uint8_t *out);

/* Security and validation functions */
int32_t LmsHss_ValidateContext(const CryptLmsHssCtx *ctx);
int32_t LmsHss_ValidateSignatureParams(const CryptLmsHssCtx *ctx, const uint8_t *data, 
                                       uint32_t dataLen, uint8_t *sign, uint32_t *signLen);
int32_t LmsHss_ValidateVerifyParams(const CryptLmsHssCtx *ctx, const uint8_t *data, 
                                    uint32_t dataLen, const uint8_t *sign, uint32_t signLen);
int32_t LmsHss_CheckSignatureExhaustion(const CryptLmsHssCtx *ctx);
int32_t LmsHss_SecureMemcpy(void *dst, uint32_t dstSize, const void *src, uint32_t srcSize);
int32_t LmsHss_ConstantTimeCompare(const uint8_t *a, const uint8_t *b, uint32_t len);
int32_t LmsHss_ValidateKeyData(const uint8_t *keyData, uint32_t keyLen, uint32_t expectedMinLen);
int32_t LmsHss_SanitizeCtrlInput(int32_t opt, void *val, uint32_t len);
int32_t LmsHss_CheckRateLimit(void);
void LmsHss_SecureContextCleanup(CryptLmsHssCtx *ctx);
int32_t LmsHss_AntiTamperingCheck(const CryptLmsHssCtx *ctx, const uint8_t *criticalData, 
                                  uint32_t dataLen);
int32_t LmsHss_ValidateSignatureIndex(const CryptLmsHssCtx *ctx, uint32_t level, uint32_t index);

/* Error reporting */
void LmsHss_SetErrorInfo(uint32_t errorCode, const char *function, uint32_t line, 
                         const char *description);
int32_t LmsHss_GetLastErrorInfo(uint32_t *errorCode, const char **function, 
                                uint32_t *line, const char **description);

/* Key serialization functions */
int32_t LmsHss_SerializePublicKey(const CryptLmsHssCtx *ctx, uint8_t **data, uint32_t *dataLen);
int32_t LmsHss_DeserializePublicKey(CryptLmsHssCtx *ctx, const uint8_t *data, uint32_t dataLen);
int32_t LmsHss_SerializePrivateKey(const CryptLmsHssCtx *ctx, uint8_t **data, uint32_t *dataLen);
int32_t LmsHss_DeserializePrivateKey(CryptLmsHssCtx *ctx, const uint8_t *data, uint32_t dataLen);

/* LMOTS core functions */
int32_t LMOTS_GenerateKeyPair(const CryptLmsHssCtx *ctx, const uint8_t *identifier,
                              uint32_t q, const uint8_t *seed);
int32_t LMOTS_Sign(CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                   const uint8_t *identifier, uint32_t q, const uint8_t *seed,
                   LmotsSignature *signature);
int32_t LMOTS_Verify(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                     const LmotsSignature *signature, const uint8_t *pubKey, uint32_t q);

/* LMS core functions */
int32_t LMS_GenerateKeyPair(CryptLmsHssCtx *ctx, uint32_t level);
int32_t LMS_Sign(CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen, 
                 uint32_t level, LmsSignature *signature);
int32_t LMS_Verify(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                   const LmsSignature *signature, const LmsPubKey *pubKey);

/* HSS core functions */
int32_t HSS_GenerateKeyPair(CryptLmsHssCtx *ctx);
int32_t HSS_Sign(CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                 HssSignature *signature);
int32_t HSS_Verify(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                   const HssSignature *signature);

/* Utility functions */
int32_t LmsHss_ComputeAuthPath(CryptLmsHssCtx *ctx, uint32_t leafIndex, uint8_t **authPath);
int32_t LmsHss_ComputeRoot(const CryptLmsHssCtx *ctx, const uint8_t *leaf, uint32_t leafIndex, 
                           const uint8_t *authPath, uint8_t *root);

/* Memory management wrappers */
static inline void *LmsHss_Malloc(uint32_t size) {
    void *ptr = BSL_SAL_Malloc(size);
    return ptr;
}

static inline void *LmsHss_Calloc(uint32_t num, uint32_t size) {
    void *ptr = BSL_SAL_Calloc(num, size);
    return ptr;
}

static inline void LmsHss_Free(void *ptr) {
    BSL_SAL_Free(ptr);
}

static inline void LmsHss_SecureClear(void *ptr, uint32_t size) {
    if (ptr != NULL) {
        (void)memset_s(ptr, size, 0, size);
    }
}

#endif /* HITLS_CRYPTO_LMS_HSS */
#endif /* LMS_HSS_LOCAL_H */