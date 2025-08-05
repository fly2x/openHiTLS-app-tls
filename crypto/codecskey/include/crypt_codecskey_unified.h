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

#ifndef CRYPT_CODECSKEY_UNIFIED_H
#define CRYPT_CODECSKEY_UNIFIED_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CODECSKEY

#include "bsl_types.h"
#include "bsl_asn1.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_codec_unified.h"

#ifdef __cplusplus
extern "C" {
#endif

/* === UNIFIED KEY CODEC INTERFACE === */

/**
 * @brief Unified RSA key codec context
 * Replaces separate CRYPT_ENCODE_RSA_* and DECODER_RSA_* functions
 */
void *CRYPT_CODECSKEY_RSA_NewCtx(void *provCtx);
int32_t CRYPT_CODECSKEY_RSA_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_CODECSKEY_RSA_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_CODECSKEY_RSA_Process(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t CRYPT_CODECSKEY_RSA_Ctrl(void *ctx, int32_t cmd, void *val, int32_t valLen);
void CRYPT_CODECSKEY_RSA_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_CODECSKEY_RSA_FreeCtx(void *ctx);

/**
 * @brief Unified ECC key codec context
 * Replaces separate CRYPT_ENCODE_ECC_* and DECODER_ECC_* functions
 */
void *CRYPT_CODECSKEY_ECC_NewCtx(void *provCtx);
int32_t CRYPT_CODECSKEY_ECC_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_CODECSKEY_ECC_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_CODECSKEY_ECC_Process(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t CRYPT_CODECSKEY_ECC_Ctrl(void *ctx, int32_t cmd, void *val, int32_t valLen);
void CRYPT_CODECSKEY_ECC_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_CODECSKEY_ECC_FreeCtx(void *ctx);

/**
 * @brief Unified format conversion context
 * Replaces separate PEM2DER and DER2PEM functions
 */
void *CRYPT_CODECSKEY_FORMAT_NewCtx(void *provCtx);
int32_t CRYPT_CODECSKEY_FORMAT_SetParam(void *ctx, const BSL_Param *param);
int32_t CRYPT_CODECSKEY_FORMAT_GetParam(void *ctx, BSL_Param *param);
int32_t CRYPT_CODECSKEY_FORMAT_Process(void *ctx, const BSL_Param *inParam, BSL_Param **outParam);
int32_t CRYPT_CODECSKEY_FORMAT_Ctrl(void *ctx, int32_t cmd, void *val, int32_t valLen);
void CRYPT_CODECSKEY_FORMAT_FreeOutData(void *ctx, BSL_Param *outData);
void CRYPT_CODECSKEY_FORMAT_FreeCtx(void *ctx);

/* === BACKWARD COMPATIBILITY === */
/* Map old interfaces to unified ones for smooth transition */

#define CRYPT_ENCODE_RSA_NewCtx(provCtx) \
    CRYPT_CODECSKEY_RSA_NewCtx(provCtx)
#define CRYPT_ENCODE_RSA_SetParam(ctx, param) \
    CRYPT_CODECSKEY_RSA_SetParam(ctx, param) 
#define CRYPT_ENCODE_RSA_GetParam(ctx, param) \
    CRYPT_CODECSKEY_RSA_GetParam(ctx, param)
#define CRYPT_ENCODE_RSA_Encode(ctx, inParam, outParam) \
    CRYPT_CODECSKEY_RSA_Process(ctx, inParam, outParam)
#define CRYPT_ENCODE_RSA_FreeOutData(ctx, outData) \
    CRYPT_CODECSKEY_RSA_FreeOutData(ctx, outData)
#define CRYPT_ENCODE_RSA_FreeCtx(ctx) \
    CRYPT_CODECSKEY_RSA_FreeCtx(ctx)

#define DECODER_RsaDer2KeyNewCtx(provCtx) \
    CRYPT_CODECSKEY_RSA_NewCtx(provCtx)
#define DECODER_RsaPrvKeyDer2KeyDecode(ctx, inParam, outParam) \
    CRYPT_CODECSKEY_RSA_Process(ctx, inParam, outParam)

/* Similar mappings for ECC and other key types... */

#ifdef __cplusplus
}
#endif

#endif /* HITLS_CRYPTO_CODECSKEY */
#endif /* CRYPT_CODECSKEY_UNIFIED_H */