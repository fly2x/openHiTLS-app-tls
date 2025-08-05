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

#ifndef CRYPT_ENCODE_KEY_IMPL_H
#define CRYPT_ENCODE_KEY_IMPL_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECSKEY

#include "bsl_types.h"
#include "bsl_asn1.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_implprovider.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cpluscplus */

#ifdef HITLS_CRYPTO_KEY_ENCODE

/* RSA Encoder */
#ifdef HITLS_CRYPTO_RSA
void *CRYPT_ENCODE_RSA_NewCtx(void *provCtx);
int32_t CRYPT_ENCODE_RSA_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_ENCODE_RSA_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_ENCODE_RSA_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void CRYPT_ENCODE_RSA_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_ENCODE_RSA_FreeCtx(void *ctx);
#endif

/* ECC Encoder */
#ifdef HITLS_CRYPTO_ECC
void *CRYPT_ENCODE_ECC_NewCtx(void *provCtx);
int32_t CRYPT_ENCODE_ECC_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_ENCODE_ECC_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_ENCODE_ECC_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void CRYPT_ENCODE_ECC_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_ENCODE_ECC_FreeCtx(void *ctx);
#endif

/* SM2 Encoder */
#ifdef HITLS_CRYPTO_SM2
void *CRYPT_ENCODE_SM2_NewCtx(void *provCtx);
int32_t CRYPT_ENCODE_SM2_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_ENCODE_SM2_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_ENCODE_SM2_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void CRYPT_ENCODE_SM2_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_ENCODE_SM2_FreeCtx(void *ctx);
#endif

/* DSA Encoder */
#ifdef HITLS_CRYPTO_DSA
void *CRYPT_ENCODE_DSA_NewCtx(void *provCtx);
int32_t CRYPT_ENCODE_DSA_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_ENCODE_DSA_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_ENCODE_DSA_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void CRYPT_ENCODE_DSA_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_ENCODE_DSA_FreeCtx(void *ctx);
#endif

/* DH Encoder */
#ifdef HITLS_CRYPTO_DH
void *CRYPT_ENCODE_DH_NewCtx(void *provCtx);
int32_t CRYPT_ENCODE_DH_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_ENCODE_DH_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_ENCODE_DH_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void CRYPT_ENCODE_DH_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_ENCODE_DH_FreeCtx(void *ctx);
#endif

/* Generic Key-to-DER Encoder */
void *CRYPT_ENCODE_KEY2DER_NewCtx(void *provCtx);
int32_t CRYPT_ENCODE_KEY2DER_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_ENCODE_KEY2DER_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_ENCODE_KEY2DER_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void CRYPT_ENCODE_KEY2DER_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_ENCODE_KEY2DER_FreeCtx(void *ctx);

/* Generic DER-to-PEM Encoder */
void *CRYPT_ENCODE_DER2PEM_NewCtx(void *provCtx);
int32_t CRYPT_ENCODE_DER2PEM_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_ENCODE_DER2PEM_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_ENCODE_DER2PEM_Encode(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
void CRYPT_ENCODE_DER2PEM_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_ENCODE_DER2PEM_FreeCtx(void *ctx);

#endif // HITLS_CRYPTO_KEY_ENCODE

#ifdef __cplusplus
}
#endif

#endif // HITLS_CRYPTO_CODECSKEY

#endif // CRYPT_ENCODE_KEY_IMPL_H