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

#ifndef CRYPT_LMS_H
#define CRYPT_LMS_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS

#include <stdint.h>
#include "bsl_params.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct CryptLmsCtx CryptLmsCtx;

/**
 * @brief LMS algorithm IDs as per RFC 8554
 */
typedef enum {
    /* LM-OTS Parameters */
    CRYPT_LMOTS_SHA256_N32_W1 = 0x00000001,
    CRYPT_LMOTS_SHA256_N32_W2 = 0x00000002,
    CRYPT_LMOTS_SHA256_N32_W4 = 0x00000003,
    CRYPT_LMOTS_SHA256_N32_W8 = 0x00000004,
    /* LMS Parameters */
    CRYPT_LMS_SHA256_M32_H5  = 0x00000005,
    CRYPT_LMS_SHA256_M32_H10 = 0x00000006,
    CRYPT_LMS_SHA256_M32_H15 = 0x00000007,
    CRYPT_LMS_SHA256_M32_H20 = 0x00000008,
    CRYPT_LMS_SHA256_M32_H25 = 0x00000009,
} CRYPT_LMS_AlgId;

/**
 * @brief HSS (Hierarchical Signature System) levels
 */
typedef enum {
    CRYPT_HSS_LEVEL_1 = 1,
    CRYPT_HSS_LEVEL_2 = 2,
    CRYPT_HSS_LEVEL_3 = 3,
    CRYPT_HSS_LEVEL_4 = 4,
    CRYPT_HSS_LEVEL_5 = 5,
    CRYPT_HSS_LEVEL_6 = 6,
    CRYPT_HSS_LEVEL_7 = 7,
    CRYPT_HSS_LEVEL_8 = 8,
} CRYPT_HSS_Level;

/**
 * @brief Allocate LMS context memory space.
 *
 * @retval (CryptLmsCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptLmsCtx *CRYPT_LMS_NewCtx(void);

/**
 * @brief Allocate LMS context memory space with library context.
 * 
 * @param libCtx [IN] Library context
 *
 * @retval (CryptLmsCtx *) Pointer to the memory space of the allocated context
 * @retval NULL             Invalid null pointer.
 */
CryptLmsCtx *CRYPT_LMS_NewCtxEx(void *libCtx);

/**
 * @brief Release LMS key context structure
 *
 * @param ctx [IN] Pointer to the context structure to be released. The ctx is set NULL by the invoker.
 */
void CRYPT_LMS_FreeCtx(CryptLmsCtx *ctx);

/**
 * @brief Generate the LMS key pair.
 *
 * @param ctx [IN/OUT] LMS context structure
 *
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_SUCCESS            The key pair is successfully generated.
 */
int32_t CRYPT_LMS_Gen(CryptLmsCtx *ctx);

/**
 * @brief Sign data using LMS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param mdId [IN] Message digest algorithm ID (ignored, LMS uses SHA-256)
 * @param data [IN] Pointer to the data to sign
 * @param dataLen [IN] Length of the data
 * @param sign [OUT] Pointer to the signature
 * @param signLen [IN/OUT] Length of the signature
 */
int32_t CRYPT_LMS_Sign(CryptLmsCtx *ctx, CRYPT_MD_AlgId mdId, const uint8_t *data, uint32_t dataLen,
                       uint8_t *sign, uint32_t *signLen);

/**
 * @brief Verify data using LMS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param data [IN] Pointer to the data to verify
 * @param dataLen [IN] Length of the data
 * @param sign [IN] Pointer to the signature
 * @param signLen [IN] Length of the signature
 */
int32_t CRYPT_LMS_Verify(const CryptLmsCtx *ctx, const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen);

/**
 * @brief Control function for LMS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param opt [IN] Option
 * @param val [IN] Value
 * @param len [IN] Length of the value
 */
int32_t CRYPT_LMS_Ctrl(CryptLmsCtx *ctx, int32_t opt, void *val, uint32_t len);

/**
 * @brief Get the public key of LMS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param para [OUT] Pointer to the public key parameters
 */
int32_t CRYPT_LMS_GetPubKey(const CryptLmsCtx *ctx, BSL_Param *para);

/**
 * @brief Get the private key of LMS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param para [OUT] Pointer to the private key parameters
 */
int32_t CRYPT_LMS_GetPrvKey(const CryptLmsCtx *ctx, BSL_Param *para);

/**
 * @brief Set the public key of LMS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param para [IN] Pointer to the public key parameters
 */
int32_t CRYPT_LMS_SetPubKey(CryptLmsCtx *ctx, const BSL_Param *para);

/**
 * @brief Set the private key of LMS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param para [IN] Pointer to the private key parameters
 */
int32_t CRYPT_LMS_SetPrvKey(CryptLmsCtx *ctx, const BSL_Param *para);

/**
 * @brief Generate HSS (Hierarchical Signature System) key pair
 * 
 * @param ctx [IN/OUT] LMS context structure
 * @param level [IN] HSS hierarchy level (1-8)
 * @param lmsAlgIds [IN] Array of LMS algorithm IDs for each level
 * @param lmotsAlgIds [IN] Array of LM-OTS algorithm IDs for each level
 * 
 * @retval CRYPT_NULL_INPUT         Error null pointer input
 * @retval CRYPT_MEM_ALLOC_FAIL     Memory allocation failure
 * @retval CRYPT_SUCCESS            The key pair is successfully generated.
 */
int32_t CRYPT_HSS_Gen(CryptLmsCtx *ctx, uint32_t level, const int32_t *lmsAlgIds, const int32_t *lmotsAlgIds);

/**
 * @brief Sign data using HSS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param data [IN] Pointer to the data to sign
 * @param dataLen [IN] Length of the data
 * @param sign [OUT] Pointer to the signature
 * @param signLen [IN/OUT] Length of the signature
 */
int32_t CRYPT_HSS_Sign(CryptLmsCtx *ctx, const uint8_t *data, uint32_t dataLen, 
                       uint8_t *sign, uint32_t *signLen);

/**
 * @brief Verify data using HSS
 * 
 * @param ctx [IN] Pointer to the LMS context
 * @param data [IN] Pointer to the data to verify
 * @param dataLen [IN] Length of the data
 * @param sign [IN] Pointer to the signature
 * @param signLen [IN] Length of the signature
 */
int32_t CRYPT_HSS_Verify(const CryptLmsCtx *ctx, const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen);

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_LMS

#endif // CRYPT_LMS_H