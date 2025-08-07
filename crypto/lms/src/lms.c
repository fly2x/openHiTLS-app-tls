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

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS

#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_lms.h"
#include "lms_local.h"
#include "crypt_util_rand.h"
#include "crypt_sha256.h"
#include "eal_md_local.h"

/* LM-OTS parameter table based on RFC 8554 */
static const LmotsParam g_lmotsParamTable[] = {
    { CRYPT_LMOTS_SHA256_N32_W1, 32, 1, 265, 7, 8516 },  /* p = 265, ls = 7 */
    { CRYPT_LMOTS_SHA256_N32_W2, 32, 2, 133, 6, 4292 },  /* p = 133, ls = 6 */
    { CRYPT_LMOTS_SHA256_N32_W4, 32, 4, 67,  4, 2180 },  /* p = 67,  ls = 4 */
    { CRYPT_LMOTS_SHA256_N32_W8, 32, 8, 34,  0, 1124 },  /* p = 34,  ls = 0 */
};

/* LMS parameter table based on RFC 8554 */
static const LmsParam g_lmsParamTable[] = {
    { CRYPT_LMS_SHA256_M32_H5,  32, 5,  64, 2804 },
    { CRYPT_LMS_SHA256_M32_H10, 32, 10, 64, 2804 },
    { CRYPT_LMS_SHA256_M32_H15, 32, 15, 64, 2804 },
    { CRYPT_LMS_SHA256_M32_H20, 32, 20, 64, 2804 },
    { CRYPT_LMS_SHA256_M32_H25, 32, 25, 64, 2804 },
};

/* Get LM-OTS parameters by algorithm ID */
const LmotsParam *GetLmotsParam(uint32_t algId)
{
    for (size_t i = 0; i < sizeof(g_lmotsParamTable) / sizeof(g_lmotsParamTable[0]); i++) {
        if (g_lmotsParamTable[i].algId == algId) {
            return &g_lmotsParamTable[i];
        }
    }
    return NULL;
}

/* Get LMS parameters by algorithm ID */
const LmsParam *GetLmsParam(uint32_t algId)
{
    for (size_t i = 0; i < sizeof(g_lmsParamTable) / sizeof(g_lmsParamTable[0]); i++) {
        if (g_lmsParamTable[i].algId == algId) {
            return &g_lmsParamTable[i];
        }
    }
    return NULL;
}

/* Create new LMS context */
CryptLmsCtx *CRYPT_LMS_NewCtx(void)
{
    return CRYPT_LMS_NewCtxEx(NULL);
}

/* Create new LMS context with library context */
CryptLmsCtx *CRYPT_LMS_NewCtxEx(void *libCtx)
{
    CryptLmsCtx *ctx = BSL_SAL_Calloc(1, sizeof(CryptLmsCtx));
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return NULL;
    }
    
    ctx->libCtx = libCtx;
    BSL_SAL_ReferencesInit(&ctx->references);
    
    /* Initialize SHA-256 method */
    ctx->mdMethod = EAL_MdFindMethod(CRYPT_MD_SHA256);
    if (ctx->mdMethod == NULL) {
        BSL_SAL_Free(ctx);
        BSL_ERR_PUSH_ERROR(CRYPT_EAL_ALG_NOT_SUPPORT);
        return NULL;
    }
    
    return ctx;
}

/* Free LMS private key */
static void FreeLmsPrivateKey(LmsPrivateKey *prv)
{
    if (prv != NULL) {
        CRYPT_Memset(prv, 0, sizeof(LmsPrivateKey));
        BSL_SAL_Free(prv);
    }
}

/* Free LMS public key */
static void FreeLmsPublicKey(LmsPublicKey *pub)
{
    if (pub != NULL) {
        BSL_SAL_Free(pub);
    }
}

/* Free HSS private key */
static void FreeHssPrivateKey(HssPrivateKey *prv)
{
    if (prv != NULL) {
        for (uint32_t i = 0; i < prv->L; i++) {
            if (prv->lmsKeys[i] != NULL) {
                FreeLmsPrivateKey(prv->lmsKeys[i]);
            }
            if (prv->lmsPubs[i] != NULL) {
                FreeLmsPublicKey(prv->lmsPubs[i]);
            }
            if (i < prv->L - 1 && prv->sigList[i] != NULL) {
                BSL_SAL_Free(prv->sigList[i]);
            }
        }
        CRYPT_Memset(prv, 0, sizeof(HssPrivateKey));
        BSL_SAL_Free(prv);
    }
}

/* Free HSS public key */
static void FreeHssPublicKey(HssPublicKey *pub)
{
    if (pub != NULL) {
        BSL_SAL_Free(pub);
    }
}

/* Free LMS context */
void CRYPT_LMS_FreeCtx(CryptLmsCtx *ctx)
{
    if (ctx == NULL) {
        return;
    }
    
    int val = 0;
    BSL_SAL_AtomicDownReferences(&ctx->references, &val);
    if (val > 0) {
        return;
    }
    
    if (ctx->lmsPrv != NULL) {
        FreeLmsPrivateKey(ctx->lmsPrv);
    }
    if (ctx->lmsPub != NULL) {
        FreeLmsPublicKey(ctx->lmsPub);
    }
    if (ctx->hssPrv != NULL) {
        FreeHssPrivateKey(ctx->hssPrv);
    }
    if (ctx->hssPub != NULL) {
        FreeHssPublicKey(ctx->hssPub);
    }
    
    BSL_SAL_Free(ctx);
}

/* Generate LMS key pair */
int32_t CRYPT_LMS_Gen(CryptLmsCtx *ctx)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* Default to LMS_SHA256_M32_H10 with LMOTS_SHA256_N32_W8 */
    uint32_t lmsAlgId = CRYPT_LMS_SHA256_M32_H10;
    uint32_t lmotsAlgId = CRYPT_LMOTS_SHA256_N32_W8;
    
    /* Free existing keys */
    if (ctx->lmsPrv != NULL) {
        FreeLmsPrivateKey(ctx->lmsPrv);
        ctx->lmsPrv = NULL;
    }
    if (ctx->lmsPub != NULL) {
        FreeLmsPublicKey(ctx->lmsPub);
        ctx->lmsPub = NULL;
    }
    
    /* Allocate private key */
    ctx->lmsPrv = BSL_SAL_Calloc(1, sizeof(LmsPrivateKey));
    if (ctx->lmsPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Generate private key */
    int32_t ret = LmsGeneratePrivateKey(ctx->lmsPrv, lmsAlgId, lmotsAlgId);
    if (ret != CRYPT_SUCCESS) {
        FreeLmsPrivateKey(ctx->lmsPrv);
        ctx->lmsPrv = NULL;
        return ret;
    }
    
    /* Allocate public key */
    ctx->lmsPub = BSL_SAL_Calloc(1, sizeof(LmsPublicKey));
    if (ctx->lmsPub == NULL) {
        FreeLmsPrivateKey(ctx->lmsPrv);
        ctx->lmsPrv = NULL;
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Generate public key */
    ret = LmsGeneratePublicKey(ctx->lmsPrv, ctx->lmsPub);
    if (ret != CRYPT_SUCCESS) {
        FreeLmsPrivateKey(ctx->lmsPrv);
        FreeLmsPublicKey(ctx->lmsPub);
        ctx->lmsPrv = NULL;
        ctx->lmsPub = NULL;
        return ret;
    }
    
    ctx->keyType = LMS_PRVKEY | LMS_PUBKEY;
    return CRYPT_SUCCESS;
}

/* Control function */
int32_t CRYPT_LMS_Ctrl(CryptLmsCtx *ctx, int32_t opt, void *val, uint32_t len)
{
    if (ctx == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    (void)opt;
    (void)val;
    (void)len;
    
    /* TODO: Implement control options */
    return CRYPT_SUCCESS;
}

/* Get public key */
int32_t CRYPT_LMS_GetPubKey(const CryptLmsCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if ((ctx->keyType & LMS_PUBKEY) == 0 || ctx->lmsPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    /* TODO: Implement parameter packing */
    return CRYPT_SUCCESS;
}

/* Get private key */
int32_t CRYPT_LMS_GetPrvKey(const CryptLmsCtx *ctx, BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if ((ctx->keyType & LMS_PRVKEY) == 0 || ctx->lmsPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    /* TODO: Implement parameter packing */
    return CRYPT_SUCCESS;
}

/* Set public key */
int32_t CRYPT_LMS_SetPubKey(CryptLmsCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* TODO: Implement parameter unpacking */
    return CRYPT_SUCCESS;
}

/* Set private key */
int32_t CRYPT_LMS_SetPrvKey(CryptLmsCtx *ctx, const BSL_Param *para)
{
    if (ctx == NULL || para == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    /* TODO: Implement parameter unpacking */
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_LMS