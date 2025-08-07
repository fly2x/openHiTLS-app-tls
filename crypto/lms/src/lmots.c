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
#include "crypt_utils.h"

/* Compute checksum for LM-OTS */
static uint16_t ComputeChecksum(const uint8_t *Q, uint32_t n, uint32_t w, uint32_t ls)
{
    uint32_t sum = 0;
    uint32_t max = (1u << w) - 1;
    uint32_t u = 8 / w;  /* Number of w-bit values per byte */
    
    for (uint32_t i = 0; i < n * u; i++) {
        uint32_t byteIndex = i / u;
        uint32_t bitOffset = (u - 1 - (i % u)) * w;
        uint32_t coef = (Q[byteIndex] >> bitOffset) & max;
        sum += max - coef;
    }
    
    return (uint16_t)(sum << ls);
}

/* Coef function: extract i-th w-bit value from S */
static uint8_t Coef(const uint8_t *S, uint32_t i, uint32_t w)
{
    uint32_t u = 8 / w;  /* Number of w-bit values per byte */
    uint32_t byteIndex = i / u;
    uint32_t bitOffset = (u - 1 - (i % u)) * w;
    uint32_t mask = (1u << w) - 1;
    
    return (S[byteIndex] >> bitOffset) & mask;
}

/* Chain function for LM-OTS */
static int32_t Chain(const uint8_t *X, uint32_t start, uint32_t steps, 
                    const uint8_t *I, uint32_t q, uint16_t i,
                    uint8_t *out, uint32_t n)
{
    if (steps == 0) {
        (void)memcpy_s(out, n, X, n);
        return CRYPT_SUCCESS;
    }
    
    uint8_t tmp[LMS_N_VALUE];
    (void)memcpy_s(tmp, sizeof(tmp), X, n);
    
    for (uint32_t j = start; j < start + steps; j++) {
        /* Build hash input: I || q || i || j || tmp */
        uint8_t hashInput[16 + 4 + 2 + 1 + LMS_N_VALUE];
        size_t offset = 0;
        
        (void)memcpy_s(hashInput + offset, sizeof(hashInput) - offset, I, 16);
        offset += 16;
        
        CRYPT_PutBE32(hashInput + offset, q);
        offset += 4;
        
        CRYPT_PutBE16(hashInput + offset, i);
        offset += 2;
        
        hashInput[offset] = (uint8_t)j;
        offset += 1;
        
        (void)memcpy_s(hashInput + offset, sizeof(hashInput) - offset, tmp, n);
        offset += n;
        
        /* Hash to get next value */
        CRYPT_SHA256_Ctx ctx;
        CRYPT_SHA256_Init(&ctx);
        CRYPT_SHA256_Update(&ctx, hashInput, offset);
        CRYPT_SHA256_Final(&ctx, tmp);
        CRYPT_SHA256_Deinit(&ctx);
    }
    
    (void)memcpy_s(out, n, tmp, n);
    return CRYPT_SUCCESS;
}

/* Generate LM-OTS public key from private key */
int32_t LmotsGeneratePublicKey(const LmotsPrivateKey *prv, LmotsPublicKey *pub)
{
    if (prv == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    const LmotsParam *param = GetLmotsParam(prv->algId);
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    pub->algId = prv->algId;
    (void)memcpy_s(pub->I, sizeof(pub->I), prv->I, sizeof(prv->I));
    pub->q = prv->q;
    
    /* Allocate temporary storage for hash values */
    uint8_t *y = BSL_SAL_Malloc(param->p * param->n);
    if (y == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Generate all hash chains */
    for (uint32_t i = 0; i < param->p; i++) {
        /* Generate random value x[i] */
        uint8_t x[LMS_N_VALUE];
        uint8_t seedData[16 + 4 + 2 + 1 + LMS_N_VALUE];
        size_t offset = 0;
        
        (void)memcpy_s(seedData + offset, sizeof(seedData) - offset, prv->I, 16);
        offset += 16;
        
        CRYPT_PutBE32(seedData + offset, prv->q);
        offset += 4;
        
        CRYPT_PutBE16(seedData + offset, (uint16_t)i);
        offset += 2;
        
        seedData[offset] = 0xFF;  /* Marker for private key generation */
        offset += 1;
        
        (void)memcpy_s(seedData + offset, sizeof(seedData) - offset, prv->seed, param->n);
        offset += param->n;
        
        CRYPT_SHA256_Ctx ctx;
        CRYPT_SHA256_Init(&ctx);
        CRYPT_SHA256_Update(&ctx, seedData, offset);
        CRYPT_SHA256_Final(&ctx, x);
        CRYPT_SHA256_Deinit(&ctx);
        
        /* Compute y[i] = chain(x[i], 0, 2^w - 1) */
        uint32_t maxSteps = (1u << param->w) - 1;
        int32_t ret = Chain(x, 0, maxSteps, prv->I, prv->q, (uint16_t)i, 
                           y + i * param->n, param->n);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(y);
            return ret;
        }
    }
    
    /* Compute public key K = H(I || q || D_PBLC || y) */
    uint8_t *hashInput = BSL_SAL_Malloc(16 + 4 + 2 + param->p * param->n);
    if (hashInput == NULL) {
        BSL_SAL_Free(y);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    size_t offset = 0;
    (void)memcpy_s(hashInput + offset, 16 + 4 + 2 + param->p * param->n - offset, prv->I, 16);
    offset += 16;
    
    CRYPT_PutBE32(hashInput + offset, prv->q);
    offset += 4;
    
    CRYPT_PutBE16(hashInput + offset, D_PBLC);
    offset += 2;
    
    (void)memcpy_s(hashInput + offset, 16 + 4 + 2 + param->p * param->n - offset, y, param->p * param->n);
    offset += param->p * param->n;
    
    CRYPT_SHA256_Ctx ctx;
    CRYPT_SHA256_Init(&ctx);
    CRYPT_SHA256_Update(&ctx, hashInput, offset);
    CRYPT_SHA256_Final(&ctx, pub->K);
    CRYPT_SHA256_Deinit(&ctx);
    
    BSL_SAL_Free(y);
    BSL_SAL_Free(hashInput);
    
    return CRYPT_SUCCESS;
}

/* LM-OTS sign */
int32_t LmotsSign(const LmotsPrivateKey *prv, const uint8_t *message, uint32_t msgLen,
                  uint8_t *signature, uint32_t *sigLen)
{
    if (prv == NULL || message == NULL || signature == NULL || sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    const LmotsParam *param = GetLmotsParam(prv->algId);
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    if (*sigLen < param->sigLen) {
        *sigLen = param->sigLen;
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    uint32_t offset = 0;
    
    /* Write algorithm ID */
    CRYPT_PutBE32(signature + offset, prv->algId);
    offset += 4;
    
    /* Generate random C */
    uint8_t C[param->n];
    int32_t ret = CRYPT_Rand(C, param->n);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    (void)memcpy_s(signature + offset, *sigLen - offset, C, param->n);
    offset += param->n;
    
    /* Compute Q = H(I || q || D_MESG || C || message) */
    size_t hashInputLen = 16 + 4 + 2 + param->n + msgLen;
    uint8_t *hashInput = BSL_SAL_Malloc(hashInputLen);
    if (hashInput == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    size_t hashOffset = 0;
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, prv->I, 16);
    hashOffset += 16;
    
    CRYPT_PutBE32(hashInput + hashOffset, prv->q);
    hashOffset += 4;
    
    CRYPT_PutBE16(hashInput + hashOffset, D_MESG);
    hashOffset += 2;
    
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, C, param->n);
    hashOffset += param->n;
    
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, message, msgLen);
    hashOffset += msgLen;
    
    uint8_t Q[LMS_N_VALUE];
    CRYPT_SHA256_Ctx ctx;
    CRYPT_SHA256_Init(&ctx);
    CRYPT_SHA256_Update(&ctx, hashInput, hashOffset);
    CRYPT_SHA256_Final(&ctx, Q);
    CRYPT_SHA256_Deinit(&ctx);
    
    BSL_SAL_Free(hashInput);
    
    /* Compute checksum */
    uint16_t checksum = ComputeChecksum(Q, param->n, param->w, param->ls);
    uint8_t Qc[LMS_N_VALUE + 2];
    (void)memcpy_s(Qc, sizeof(Qc), Q, param->n);
    CRYPT_PutBE16(Qc + param->n, checksum);
    
    /* Generate signature values */
    uint8_t *y = signature + offset;
    
    for (uint32_t i = 0; i < param->p; i++) {
        /* Generate x[i] */
        uint8_t x[LMS_N_VALUE];
        uint8_t seedData[16 + 4 + 2 + 1 + LMS_N_VALUE];
        size_t seedOffset = 0;
        
        (void)memcpy_s(seedData + seedOffset, sizeof(seedData) - seedOffset, prv->I, 16);
        seedOffset += 16;
        
        CRYPT_PutBE32(seedData + seedOffset, prv->q);
        seedOffset += 4;
        
        CRYPT_PutBE16(seedData + seedOffset, (uint16_t)i);
        seedOffset += 2;
        
        seedData[seedOffset] = 0xFF;
        seedOffset += 1;
        
        (void)memcpy_s(seedData + seedOffset, sizeof(seedData) - seedOffset, prv->seed, param->n);
        seedOffset += param->n;
        
        CRYPT_SHA256_Init(&ctx);
        CRYPT_SHA256_Update(&ctx, seedData, seedOffset);
        CRYPT_SHA256_Final(&ctx, x);
        CRYPT_SHA256_Deinit(&ctx);
        
        /* Compute y[i] = chain(x[i], 0, a) where a = coef(Qc, i) */
        uint8_t a = Coef(Qc, i, param->w);
        ret = Chain(x, 0, a, prv->I, prv->q, (uint16_t)i, y + i * param->n, param->n);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
    }
    
    *sigLen = param->sigLen;
    return CRYPT_SUCCESS;
}

/* LM-OTS verify - reconstruct public key K from signature */
int32_t LmotsVerify(const LmotsPublicKey *pub, const uint8_t *message, uint32_t msgLen,
                   const uint8_t *signature, uint32_t sigLen)
{
    if (pub == NULL || message == NULL || signature == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (sigLen < 4) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    /* Read algorithm ID */
    uint32_t algId = CRYPT_GetBE32(signature);
    if (algId != pub->algId) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    const LmotsParam *param = GetLmotsParam(algId);
    if (param == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    if (sigLen != param->sigLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    uint32_t offset = 4;
    
    /* Read C */
    const uint8_t *C = signature + offset;
    offset += param->n;
    
    /* Compute Q = H(I || q || D_MESG || C || message) */
    size_t hashInputLen = 16 + 4 + 2 + param->n + msgLen;
    uint8_t *hashInput = BSL_SAL_Malloc(hashInputLen);
    if (hashInput == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    size_t hashOffset = 0;
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, pub->I, 16);
    hashOffset += 16;
    
    CRYPT_PutBE32(hashInput + hashOffset, pub->q);
    hashOffset += 4;
    
    CRYPT_PutBE16(hashInput + hashOffset, D_MESG);
    hashOffset += 2;
    
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, C, param->n);
    hashOffset += param->n;
    
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, message, msgLen);
    hashOffset += msgLen;
    
    uint8_t Q[LMS_N_VALUE];
    CRYPT_SHA256_Ctx ctx;
    CRYPT_SHA256_Init(&ctx);
    CRYPT_SHA256_Update(&ctx, hashInput, hashOffset);
    CRYPT_SHA256_Final(&ctx, Q);
    CRYPT_SHA256_Deinit(&ctx);
    
    BSL_SAL_Free(hashInput);
    
    /* Compute checksum */
    uint16_t checksum = ComputeChecksum(Q, param->n, param->w, param->ls);
    uint8_t Qc[LMS_N_VALUE + 2];
    (void)memcpy_s(Qc, sizeof(Qc), Q, param->n);
    CRYPT_PutBE16(Qc + param->n, checksum);
    
    /* Allocate temporary storage for z values */
    uint8_t *z = BSL_SAL_Malloc(param->p * param->n);
    if (z == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Compute z values from signature */
    const uint8_t *y = signature + offset;
    uint32_t maxVal = (1u << param->w) - 1;
    
    for (uint32_t i = 0; i < param->p; i++) {
        uint8_t a = Coef(Qc, i, param->w);
        int32_t ret = Chain(y + i * param->n, a, maxVal - a, pub->I, pub->q, 
                           (uint16_t)i, z + i * param->n, param->n);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(z);
            return ret;
        }
    }
    
    /* Compute Kc = H(I || q || D_PBLC || z) */
    hashInputLen = 16 + 4 + 2 + param->p * param->n;
    hashInput = BSL_SAL_Malloc(hashInputLen);
    if (hashInput == NULL) {
        BSL_SAL_Free(z);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    hashOffset = 0;
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, pub->I, 16);
    hashOffset += 16;
    
    CRYPT_PutBE32(hashInput + hashOffset, pub->q);
    hashOffset += 4;
    
    CRYPT_PutBE16(hashInput + hashOffset, D_PBLC);
    hashOffset += 2;
    
    (void)memcpy_s(hashInput + hashOffset, hashInputLen - hashOffset, z, param->p * param->n);
    hashOffset += param->p * param->n;
    
    uint8_t Kc[LMS_N_VALUE];
    CRYPT_SHA256_Init(&ctx);
    CRYPT_SHA256_Update(&ctx, hashInput, hashOffset);
    CRYPT_SHA256_Final(&ctx, Kc);
    CRYPT_SHA256_Deinit(&ctx);
    
    BSL_SAL_Free(z);
    BSL_SAL_Free(hashInput);
    
    /* Store reconstructed public key in the provided structure */
    (void)memcpy_s((void *)pub->K, sizeof(pub->K), Kc, param->n);
    
    return CRYPT_SUCCESS;
}

#endif // HITLS_CRYPTO_LMS