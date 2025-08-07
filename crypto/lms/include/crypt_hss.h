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

#ifndef CRYPT_HSS_H
#define CRYPT_HSS_H

#include <stdint.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "crypt_lms.h"

#ifdef __cplusplus
extern "C" {
#endif

/* HSS (Hierarchical Signature System) - Multi-tree variant of LMS */
/* RFC 8554 compliant implementation */

/* Maximum HSS levels supported */
#define CRYPT_HSS_MAX_LEVELS 8

/* HSS Context - Opaque structure */
typedef struct CryptHssCtx CRYPT_HSS_Ctx;

/* HSS Parameter structure */
typedef struct {
    uint32_t levels;                              /* Number of HSS levels (1-8) */
    uint32_t lmsParam[CRYPT_HSS_MAX_LEVELS];     /* LMS parameter for each level */
    uint32_t lmotsParam[CRYPT_HSS_MAX_LEVELS];   /* LM-OTS parameter for each level */
} CRYPT_HSS_Param;

/**
 * @brief Create a new HSS context
 * @return Pointer to new HSS context, or NULL on failure
 */
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtx(void);

/**
 * @brief Create a new HSS context with library context
 * @param libCtx Library context
 * @return Pointer to new HSS context, or NULL on failure
 */
CRYPT_HSS_Ctx *CRYPT_HSS_NewCtxEx(void *libCtx);

/**
 * @brief Free an HSS context
 * @param ctx HSS context to free
 */
void CRYPT_HSS_FreeCtx(CRYPT_HSS_Ctx *ctx);

/**
 * @brief Duplicate an HSS context
 * @param ctx HSS context to duplicate
 * @return Pointer to duplicated context, or NULL on failure
 */
CRYPT_HSS_Ctx *CRYPT_HSS_DupCtx(const CRYPT_HSS_Ctx *ctx);

/**
 * @brief Generate HSS key pair
 * @param ctx HSS context
 * @param param HSS parameters
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_HSS_Gen(CRYPT_HSS_Ctx *ctx, const CRYPT_HSS_Param *param);

/**
 * @brief Sign a message using HSS
 * @param ctx HSS context with private key
 * @param mdId Message digest algorithm (ignored, HSS uses SHA-256)
 * @param data Message to sign
 * @param dataLen Message length
 * @param sign Output signature buffer
 * @param signLen Input: buffer size, Output: signature length
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_HSS_Sign(CRYPT_HSS_Ctx *ctx, CRYPT_MD_AlgId mdId, 
                       const uint8_t *data, uint32_t dataLen,
                       uint8_t *sign, uint32_t *signLen);

/**
 * @brief Verify an HSS signature
 * @param ctx HSS context with public key
 * @param mdId Message digest algorithm (ignored, HSS uses SHA-256)
 * @param data Message that was signed
 * @param dataLen Message length
 * @param sign Signature to verify
 * @param signLen Signature length
 * @return CRYPT_SUCCESS if signature is valid, error code otherwise
 */
int32_t CRYPT_HSS_Verify(CRYPT_HSS_Ctx *ctx, CRYPT_MD_AlgId mdId,
                         const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen);

/**
 * @brief Set HSS private key
 * @param ctx HSS context
 * @param prv Private key structure
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_HSS_SetPrvKey(CRYPT_HSS_Ctx *ctx, const CRYPT_HssPrv *prv);

/**
 * @brief Set HSS public key
 * @param ctx HSS context
 * @param pub Public key structure
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_HSS_SetPubKey(CRYPT_HSS_Ctx *ctx, const CRYPT_HssPub *pub);

/**
 * @brief Get HSS private key
 * @param ctx HSS context
 * @param prv Output private key structure
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_HSS_GetPrvKey(const CRYPT_HSS_Ctx *ctx, CRYPT_HssPrv *prv);

/**
 * @brief Get HSS public key
 * @param ctx HSS context
 * @param pub Output public key structure
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_HSS_GetPubKey(const CRYPT_HSS_Ctx *ctx, CRYPT_HssPub *pub);

/**
 * @brief Get HSS signature size for given parameters
 * @param param HSS parameters
 * @return Signature size in bytes, or 0 on error
 */
uint32_t CRYPT_HSS_GetSignatureSize(const CRYPT_HSS_Param *param);

/**
 * @brief Get HSS public key size for given parameters
 * @param param HSS parameters
 * @return Public key size in bytes, or 0 on error
 */
uint32_t CRYPT_HSS_GetPublicKeySize(const CRYPT_HSS_Param *param);

/**
 * @brief Control function for HSS context
 * @param ctx HSS context
 * @param cmd Control command
 * @param val Value for the command
 * @param len Length of value
 * @return CRYPT_SUCCESS on success, error code otherwise
 */
int32_t CRYPT_HSS_Ctrl(CRYPT_HSS_Ctx *ctx, int32_t cmd, void *val, uint32_t len);

#ifdef __cplusplus
}
#endif

#endif /* CRYPT_HSS_H */