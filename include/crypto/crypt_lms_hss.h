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
 * @defgroup crypt_lms_hss
 * @ingroup crypt
 * @brief LMS/HSS (Leighton-Micali Signature / Hierarchical Signature System) post-quantum signature algorithm
 */

#ifndef CRYPT_LMS_HSS_H
#define CRYPT_LMS_HSS_H

#include <stdint.h>
#include <stdbool.h>
#include "crypt_types.h"
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @ingroup crypt_lms_hss
 * LMS (Leighton-Micali Signature) algorithm types as defined in RFC 8554
 */
typedef enum {
    LMS_SHA256_M32_H5  = 0x00000005,  /**< LMS with SHA-256, tree height 5 (32 signatures) */
    LMS_SHA256_M32_H10 = 0x00000006,  /**< LMS with SHA-256, tree height 10 (1024 signatures) */
    LMS_SHA256_M32_H15 = 0x00000007,  /**< LMS with SHA-256, tree height 15 (32768 signatures) */
    LMS_SHA256_M32_H20 = 0x00000008,  /**< LMS with SHA-256, tree height 20 (1M+ signatures) */
    LMS_SHA256_M32_H25 = 0x00000009,  /**< LMS with SHA-256, tree height 25 (33M+ signatures) */
} LMS_AlgType;

/**
 * @ingroup crypt_lms_hss
 * LMOTS (LM One-Time Signature) algorithm types as defined in RFC 8554
 */
typedef enum {
    LMOTS_SHA256_N32_W1 = 0x00000001,  /**< LMOTS with SHA-256, Winternitz parameter 1 */
    LMOTS_SHA256_N32_W2 = 0x00000002,  /**< LMOTS with SHA-256, Winternitz parameter 2 */
    LMOTS_SHA256_N32_W4 = 0x00000003,  /**< LMOTS with SHA-256, Winternitz parameter 4 */
    LMOTS_SHA256_N32_W8 = 0x00000004,  /**< LMOTS with SHA-256, Winternitz parameter 8 */
} LMOTS_AlgType;

/**
 * @ingroup crypt_lms_hss
 * LMS/HSS control commands for CRYPT_LMS_HSS_Ctrl()
 */
typedef enum {
    CRYPT_CTRL_SET_LMS_TYPE = 1001,    /**< Set LMS algorithm type */
    CRYPT_CTRL_SET_LMOTS_TYPE,         /**< Set LMOTS algorithm type */
    CRYPT_CTRL_SET_HSS_LEVELS,         /**< Set HSS hierarchy levels */
    CRYPT_CTRL_GET_LMS_TYPE,           /**< Get LMS algorithm type */
    CRYPT_CTRL_GET_LMOTS_TYPE,         /**< Get LMOTS algorithm type */
    CRYPT_CTRL_GET_HSS_LEVELS,         /**< Get HSS hierarchy levels */
    CRYPT_CTRL_GET_SIGNATURE_LEN,      /**< Get signature length */
    CRYPT_CTRL_GET_LMS_HSS_PUBKEY_LEN, /**< Get public key length */
    CRYPT_CTRL_GET_LMS_HSS_PRVKEY_LEN, /**< Get private key length */
    CRYPT_CTRL_GET_REMAINING_SIGS,     /**< Get remaining signature count */
} CRYPT_LMS_HSS_CtrlCmd;

/**
 * @ingroup crypt_lms_hss
 * LMS/HSS public key structure
 */
typedef struct {
    uint8_t *data;  /**< Public key data */
    uint32_t len;   /**< Public key data length */
} CRYPT_LmsHssPub;

/**
 * @ingroup crypt_lms_hss
 * LMS/HSS private key structure
 */
typedef struct {
    uint8_t *data;  /**< Private key data */
    uint32_t len;   /**< Private key data length */
} CRYPT_LmsHssPrv;

/**
 * @ingroup crypt_lms_hss
 * LMS/HSS context structure (opaque)
 */
typedef struct CryptLmsHssCtx CryptLmsHssCtx;

/**
 * @ingroup crypt_lms_hss
 * LMS/HSS error codes base
 */
#define CRYPT_LMS_HSS_ERR_BASE                  0x11300000
#define CRYPT_LMS_HSS_INVALID_PARA              (CRYPT_LMS_HSS_ERR_BASE + 1)
#define CRYPT_LMS_HSS_INVALID_LMS_TYPE          (CRYPT_LMS_HSS_ERR_BASE + 2)
#define CRYPT_LMS_HSS_INVALID_LMOTS_TYPE        (CRYPT_LMS_HSS_ERR_BASE + 3)
#define CRYPT_LMS_HSS_INVALID_LEVEL             (CRYPT_LMS_HSS_ERR_BASE + 4)
#define CRYPT_LMS_HSS_INVALID_HASH_TYPE         (CRYPT_LMS_HSS_ERR_BASE + 5)
#define CRYPT_LMS_HSS_KEY_NOT_SET               (CRYPT_LMS_HSS_ERR_BASE + 6)
#define CRYPT_LMS_HSS_TREE_EXHAUSTED            (CRYPT_LMS_HSS_ERR_BASE + 7)
#define CRYPT_LMS_HSS_INVALID_SIGNATURE         (CRYPT_LMS_HSS_ERR_BASE + 8)
#define CRYPT_LMS_HSS_VERIFY_FAIL               (CRYPT_LMS_HSS_ERR_BASE + 9)
#define CRYPT_LMS_HSS_CTRL_ERROR                (CRYPT_LMS_HSS_ERR_BASE + 10)

/**
 * @ingroup crypt_lms_hss
 * LMS/HSS algorithm ID for CRYPT_EAL interface
 */
#define CRYPT_PKEY_LMS_HSS                      0x1300

/**
 * @ingroup crypt_lms_hss
 * BSL_Param parameter IDs for LMS/HSS
 */
#define CRYPT_PARAM_LMS_HSS_BASE                    2000
#define CRYPT_PARAM_LMS_HSS_PUBKEY_ID              (CRYPT_PARAM_LMS_HSS_BASE + 1)
#define CRYPT_PARAM_LMS_HSS_PRVKEY_ID              (CRYPT_PARAM_LMS_HSS_BASE + 2)

/**
 * @ingroup crypt_lms_hss
 * @brief Create a new LMS/HSS context
 *
 * @return CryptLmsHssCtx* New LMS/HSS context, NULL on failure
 */
CryptLmsHssCtx *CRYPT_LMS_HSS_NewCtx(void);

/**
 * @ingroup crypt_lms_hss
 * @brief Create a new LMS/HSS context with library context
 *
 * @param libCtx [IN] Library context
 * @return CryptLmsHssCtx* New LMS/HSS context, NULL on failure
 */
CryptLmsHssCtx *CRYPT_LMS_HSS_NewCtxEx(void *libCtx);

/**
 * @ingroup crypt_lms_hss
 * @brief Free LMS/HSS context
 *
 * @param ctx [IN] LMS/HSS context to free
 */
void CRYPT_LMS_HSS_FreeCtx(CryptLmsHssCtx *ctx);

/**
 * @ingroup crypt_lms_hss
 * @brief LMS/HSS control function
 *
 * @param ctx [IN] LMS/HSS context
 * @param opt [IN] Control option
 * @param val [IN/OUT] Value pointer
 * @param len [IN] Value length
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Ctrl(CryptLmsHssCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @ingroup crypt_lms_hss
 * @brief Generate LMS/HSS key pair
 *
 * @param ctx [IN] LMS/HSS context
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Gen(CryptLmsHssCtx *ctx);

/**
 * @ingroup crypt_lms_hss
 * @brief Set public key
 *
 * @param ctx [IN] LMS/HSS context
 * @param pub [IN] Public key structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPubKey(CryptLmsHssCtx *ctx, const CRYPT_LmsHssPub *pub);

/**
 * @ingroup crypt_lms_hss
 * @brief Set private key
 *
 * @param ctx [IN] LMS/HSS context
 * @param prv [IN] Private key structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPrvKey(CryptLmsHssCtx *ctx, const CRYPT_LmsHssPrv *prv);

/**
 * @ingroup crypt_lms_hss
 * @brief Get public key
 *
 * @param ctx [IN] LMS/HSS context
 * @param pub [OUT] Public key structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPubKey(const CryptLmsHssCtx *ctx, CRYPT_LmsHssPub *pub);

/**
 * @ingroup crypt_lms_hss
 * @brief Get private key
 *
 * @param ctx [IN] LMS/HSS context
 * @param prv [OUT] Private key structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPrvKey(const CryptLmsHssCtx *ctx, CRYPT_LmsHssPrv *prv);

/**
 * @ingroup crypt_lms_hss
 * @brief Sign a message
 *
 * @param ctx [IN] LMS/HSS context
 * @param algId [IN] Algorithm ID (should be CRYPT_PKEY_LMS_HSS)
 * @param data [IN] Message to sign
 * @param dataLen [IN] Message length
 * @param sign [OUT] Signature buffer
 * @param signLen [IN/OUT] Signature buffer length / actual signature length
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Sign(CryptLmsHssCtx *ctx, int32_t algId, const uint8_t *data, 
                           uint32_t dataLen, uint8_t *sign, uint32_t *signLen);

/**
 * @ingroup crypt_lms_hss
 * @brief Verify a signature
 *
 * @param ctx [IN] LMS/HSS context
 * @param algId [IN] Algorithm ID (should be CRYPT_PKEY_LMS_HSS)
 * @param data [IN] Original message
 * @param dataLen [IN] Message length
 * @param sign [IN] Signature to verify
 * @param signLen [IN] Signature length
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Verify(const CryptLmsHssCtx *ctx, int32_t algId, const uint8_t *data, 
                             uint32_t dataLen, const uint8_t *sign, uint32_t signLen);

#ifdef HITLS_BSL_PARAMS
/**
 * @ingroup crypt_lms_hss
 * @brief Set public key using BSL_Param
 *
 * @param ctx [IN] LMS/HSS context
 * @param para [IN] BSL_Param structure containing public key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPubKeyEx(CryptLmsHssCtx *ctx, const BSL_Param *para);

/**
 * @ingroup crypt_lms_hss
 * @brief Set private key using BSL_Param
 *
 * @param ctx [IN] LMS/HSS context
 * @param para [IN] BSL_Param structure containing private key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPrvKeyEx(CryptLmsHssCtx *ctx, const BSL_Param *para);

/**
 * @ingroup crypt_lms_hss
 * @brief Get public key using BSL_Param
 *
 * @param ctx [IN] LMS/HSS context
 * @param para [OUT] BSL_Param structure to receive public key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPubKeyEx(const CryptLmsHssCtx *ctx, BSL_Param *para);

/**
 * @ingroup crypt_lms_hss
 * @brief Get private key using BSL_Param
 *
 * @param ctx [IN] LMS/HSS context
 * @param para [OUT] BSL_Param structure to receive private key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPrvKeyEx(const CryptLmsHssCtx *ctx, BSL_Param *para);
#endif /* HITLS_BSL_PARAMS */

#ifdef __cplusplus
}
#endif

#endif /* CRYPT_LMS_HSS_H */