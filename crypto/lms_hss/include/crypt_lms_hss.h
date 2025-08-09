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

#ifndef CRYPT_LMS_HSS_H
#define CRYPT_LMS_HSS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS_HSS

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif

/* LMS/HSS algorithm context */
typedef struct LmsHssCtx CryptLmsHssCtx;

/* LMS/HSS public key structure */
typedef struct {
    uint8_t *data;
    uint32_t len;
} CRYPT_LmsHssPub;

/* LMS/HSS private key structure */
typedef struct {
    uint8_t *data;
    uint32_t len;
} CRYPT_LmsHssPrv;

/* LMS algorithm type definitions (RFC 8554) */
#define LMS_SHA256_M32_H5           0x00000005
#define LMS_SHA256_M32_H10          0x00000006
#define LMS_SHA256_M32_H15          0x00000007
#define LMS_SHA256_M32_H20          0x00000008
#define LMS_SHA256_M32_H25          0x00000009

/* LMOTS algorithm type definitions (RFC 8554) */
#define LMOTS_SHA256_N32_W1         0x00000001
#define LMOTS_SHA256_N32_W2         0x00000002
#define LMOTS_SHA256_N32_W4         0x00000003
#define LMOTS_SHA256_N32_W8         0x00000004

/* Control option definitions */
#define CRYPT_CTRL_SET_LMS_TYPE     0x1001
#define CRYPT_CTRL_SET_LMOTS_TYPE   0x1002
#define CRYPT_CTRL_SET_HSS_LEVELS   0x1003
#define CRYPT_CTRL_GET_LMS_TYPE     0x1004
#define CRYPT_CTRL_GET_LMOTS_TYPE   0x1005
#define CRYPT_CTRL_GET_HSS_LEVELS   0x1006
#define CRYPT_CTRL_GET_SIGNATURE_LEN 0x1007
#define CRYPT_LMS_HSS_CTRL_GET_PUBKEY_LEN   0x2008
#define CRYPT_LMS_HSS_CTRL_GET_PRVKEY_LEN   0x2009
#define CRYPT_CTRL_GET_REMAINING_SIGS 0x100A

/* BSL_Param key names for LMS/HSS */
#define CRYPT_PARAM_LMS_HSS_PUBKEY  "lms-hss-pubkey"
#define CRYPT_PARAM_LMS_HSS_PRVKEY  "lms-hss-prvkey"

/* BSL_Param key integers for LMS/HSS */
#define CRYPT_PARAM_LMS_HSS_PUBKEY_ID  0x3001
#define CRYPT_PARAM_LMS_HSS_PRVKEY_ID  0x3002
#define CRYPT_PARAM_LMS_TYPE_ID        0x3003
#define CRYPT_PARAM_LMOTS_TYPE_ID      0x3004
#define CRYPT_PARAM_HSS_LEVELS_ID      0x3005
#define CRYPT_PARAM_LMS_HSS_SEED_ID    0x3006

/**
 * @brief Create a new LMS/HSS context
 * 
 * @return CryptLmsHssCtx* Pointer to the new LMS/HSS context, NULL on error
 */
CryptLmsHssCtx *CRYPT_LMS_HSS_NewCtx(void);

/**
 * @brief Create a new LMS/HSS context with library context
 * 
 * @param libCtx Pointer to the library context
 * @return CryptLmsHssCtx* Pointer to the new LMS/HSS context, NULL on error
 */
CryptLmsHssCtx *CRYPT_LMS_HSS_NewCtxEx(void *libCtx);

/**
 * @brief Free an LMS/HSS context
 * 
 * @param ctx Pointer to the LMS/HSS context
 */
void CRYPT_LMS_HSS_FreeCtx(CryptLmsHssCtx *ctx);

/**
 * @brief Generate an LMS/HSS key pair
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Gen(CryptLmsHssCtx *ctx);

/**
 * @brief Set LMS/HSS public key
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param pub Pointer to the public key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPubKey(CryptLmsHssCtx *ctx, const CRYPT_LmsHssPub *pub);

/**
 * @brief Set LMS/HSS private key
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param prv Pointer to the private key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPrvKey(CryptLmsHssCtx *ctx, const CRYPT_LmsHssPrv *prv);

/**
 * @brief Get LMS/HSS public key
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param pub Pointer to store the public key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPubKey(const CryptLmsHssCtx *ctx, CRYPT_LmsHssPub *pub);

/**
 * @brief Get LMS/HSS private key
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param prv Pointer to store the private key
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPrvKey(const CryptLmsHssCtx *ctx, CRYPT_LmsHssPrv *prv);

/**
 * @brief Sign data using LMS/HSS
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param algId Algorithm ID
 * @param data Pointer to the data to sign
 * @param dataLen Length of the data
 * @param sign Pointer to store the signature
 * @param signLen Pointer to the signature length
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Sign(CryptLmsHssCtx *ctx, int32_t algId, const uint8_t *data, 
                           uint32_t dataLen, uint8_t *sign, uint32_t *signLen);

/**
 * @brief Verify signature using LMS/HSS
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param algId Algorithm ID
 * @param data Pointer to the data to verify
 * @param dataLen Length of the data
 * @param sign Pointer to the signature
 * @param signLen Length of the signature
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Verify(const CryptLmsHssCtx *ctx, int32_t algId, const uint8_t *data, 
                             uint32_t dataLen, const uint8_t *sign, uint32_t signLen);

/**
 * @brief Control function for LMS/HSS
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param opt Control option
 * @param val Value pointer
 * @param len Length of the value
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_Ctrl(CryptLmsHssCtx *ctx, int32_t opt, void *val, uint32_t len);

#ifdef HITLS_BSL_PARAMS
/**
 * @brief Set LMS/HSS public key using BSL_Param
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param para Pointer to the BSL_Param structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPubKeyEx(CryptLmsHssCtx *ctx, const BSL_Param *para);

/**
 * @brief Set LMS/HSS private key using BSL_Param
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param para Pointer to the BSL_Param structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_SetPrvKeyEx(CryptLmsHssCtx *ctx, const BSL_Param *para);

/**
 * @brief Get LMS/HSS public key using BSL_Param
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param para Pointer to the BSL_Param structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPubKeyEx(const CryptLmsHssCtx *ctx, BSL_Param *para);

/**
 * @brief Get LMS/HSS private key using BSL_Param
 * 
 * @param ctx Pointer to the LMS/HSS context
 * @param para Pointer to the BSL_Param structure
 * @return int32_t CRYPT_SUCCESS on success, error code on failure
 */
int32_t CRYPT_LMS_HSS_GetPrvKeyEx(const CryptLmsHssCtx *ctx, BSL_Param *para);
#endif

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_LMS_HSS */
#endif /* CRYPT_LMS_HSS_H */