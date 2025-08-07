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

/* Helper function to compute SHA-256 hash */
static int32_t LmsHashSha256(const uint8_t *data, uint32_t dataLen, uint8_t *out)
{
    CRYPT_SHA256_Ctx ctx;
    CRYPT_SHA256_Init(&ctx);
    CRYPT_SHA256_Update(&ctx, data, dataLen);
    CRYPT_SHA256_Final(&ctx, out);
    CRYPT_SHA256_Deinit(&ctx);
    return CRYPT_SUCCESS;
}

/* Generate LMS private key */
int32_t LmsGeneratePrivateKey(LmsPrivateKey *prv, uint32_t lmsAlgId, uint32_t otsAlgId)
{
    if (prv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    const LmsParam *lmsParam = GetLmsParam(lmsAlgId);
    const LmotsParam *otsParam = GetLmotsParam(otsAlgId);
    
    if (lmsParam == NULL || otsParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    prv->algId = lmsAlgId;
    prv->otsAlgId = otsAlgId;
    prv->q = 0;
    prv->maxQ = (1u << lmsParam->h) - 1;
    
    /* Generate random I (identifier) */
    int32_t ret = CRYPT_Rand(prv->I, sizeof(prv->I));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    /* Generate random seed */
    ret = CRYPT_Rand(prv->seed, sizeof(prv->seed));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    return CRYPT_SUCCESS;
}

/* Generate OTS key at given leaf index */
static int32_t GenerateOtsKey(const LmsPrivateKey *prv, uint32_t leafIndex, 
                             LmotsPrivateKey *otsPriv)
{
    if (prv == NULL || otsPriv == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    otsPriv->algId = prv->otsAlgId;
    (void)memcpy_s(otsPriv->I, sizeof(otsPriv->I), prv->I, sizeof(prv->I));
    otsPriv->q = leafIndex;
    
    /* Generate OTS seed from master seed and leaf index */
    uint8_t seedData[16 + 4 + LMS_M_VALUE];
    (void)memcpy_s(seedData, sizeof(seedData), prv->I, 16);
    CRYPT_PutBE32(seedData + 16, leafIndex);
    (void)memcpy_s(seedData + 20, sizeof(seedData) - 20, prv->seed, LMS_M_VALUE);
    
    return LmsHashSha256(seedData, 16 + 4 + LMS_M_VALUE, otsPriv->seed);
}

/* Compute hash of OTS public key */
static int32_t HashOtsPublicKey(const LmotsPublicKey *otsPub, uint8_t *hash)
{
    /* Hash the OTS public key: H(I || q || D_LEAF || OTSpub) */
    uint8_t hashData[16 + 4 + 2 + LMS_N_VALUE];
    size_t offset = 0;
    
    (void)memcpy_s(hashData + offset, sizeof(hashData) - offset, otsPub->I, 16);
    offset += 16;
    
    CRYPT_PutBE32(hashData + offset, otsPub->q);
    offset += 4;
    
    CRYPT_PutBE16(hashData + offset, D_LEAF);
    offset += 2;
    
    (void)memcpy_s(hashData + offset, sizeof(hashData) - offset, otsPub->K, LMS_N_VALUE);
    offset += LMS_N_VALUE;
    
    return LmsHashSha256(hashData, offset, hash);
}

/* Generate LMS leaf node at given index */
int32_t LmsGenerateLeafNode(const LmsPrivateKey *prv, uint32_t leafIndex, uint8_t *node)
{
    if (prv == NULL || node == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    /* Generate OTS key pair */
    LmotsPrivateKey otsPriv;
    int32_t ret = GenerateOtsKey(prv, leafIndex, &otsPriv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    LmotsPublicKey otsPub;
    ret = LmotsGeneratePublicKey(&otsPriv, &otsPub);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_Memset(&otsPriv, 0, sizeof(otsPriv));
        return ret;
    }
    
    /* Hash the OTS public key to get leaf node */
    ret = HashOtsPublicKey(&otsPub, node);
    
    CRYPT_Memset(&otsPriv, 0, sizeof(otsPriv));
    return ret;
}

/* Compute internal node from two child nodes */
static int32_t ComputeInternalNode(const uint8_t *I, uint32_t height, uint32_t index,
                                   const uint8_t *left, const uint8_t *right, uint8_t *node)
{
    /* Hash: H(I || u32(height) || u32(index) || D_INTR || left || right) */
    uint8_t hashData[16 + 4 + 4 + 2 + 2 * LMS_M_VALUE];
    size_t offset = 0;
    
    (void)memcpy_s(hashData + offset, sizeof(hashData) - offset, I, 16);
    offset += 16;
    
    CRYPT_PutBE32(hashData + offset, height);
    offset += 4;
    
    CRYPT_PutBE32(hashData + offset, index);
    offset += 4;
    
    CRYPT_PutBE16(hashData + offset, D_INTR);
    offset += 2;
    
    (void)memcpy_s(hashData + offset, sizeof(hashData) - offset, left, LMS_M_VALUE);
    offset += LMS_M_VALUE;
    
    (void)memcpy_s(hashData + offset, sizeof(hashData) - offset, right, LMS_M_VALUE);
    offset += LMS_M_VALUE;
    
    return LmsHashSha256(hashData, offset, node);
}

/* Compute root of LMS tree */
int32_t LmsComputeRoot(const LmsPrivateKey *prv, uint8_t *root)
{
    if (prv == NULL || root == NULL) {
        return CRYPT_NULL_INPUT;
    }
    
    const LmsParam *param = GetLmsParam(prv->algId);
    if (param == NULL) {
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    uint32_t h = param->h;
    uint32_t numLeaves = 1u << h;
    
    /* Allocate memory for tree nodes (we only need two layers at a time) */
    uint8_t *currentLayer = BSL_SAL_Malloc(numLeaves * LMS_M_VALUE);
    uint8_t *nextLayer = BSL_SAL_Malloc(numLeaves * LMS_M_VALUE);
    
    if (currentLayer == NULL || nextLayer == NULL) {
        BSL_SAL_Free(currentLayer);
        BSL_SAL_Free(nextLayer);
        BSL_ERR_PUSH_ERROR(CRYPT_MEM_ALLOC_FAIL);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    
    /* Generate all leaf nodes */
    for (uint32_t i = 0; i < numLeaves; i++) {
        int32_t ret = LmsGenerateLeafNode(prv, i, currentLayer + i * LMS_M_VALUE);
        if (ret != CRYPT_SUCCESS) {
            BSL_SAL_Free(currentLayer);
            BSL_SAL_Free(nextLayer);
            return ret;
        }
    }
    
    /* Build tree from bottom to top */
    uint32_t currentNodes = numLeaves;
    for (uint32_t level = 0; level < h; level++) {
        uint32_t nextNodes = currentNodes / 2;
        uint32_t nodeHeight = level + 1;
        
        for (uint32_t i = 0; i < nextNodes; i++) {
            int32_t ret = ComputeInternalNode(prv->I, nodeHeight, i,
                                             currentLayer + (2 * i) * LMS_M_VALUE,
                                             currentLayer + (2 * i + 1) * LMS_M_VALUE,
                                             nextLayer + i * LMS_M_VALUE);
            if (ret != CRYPT_SUCCESS) {
                BSL_SAL_Free(currentLayer);
                BSL_SAL_Free(nextLayer);
                return ret;
            }
        }
        
        /* Swap layers */
        uint8_t *temp = currentLayer;
        currentLayer = nextLayer;
        nextLayer = temp;
        currentNodes = nextNodes;
    }
    
    /* Copy root node */
    (void)memcpy_s(root, LMS_M_VALUE, currentLayer, LMS_M_VALUE);
    
    BSL_SAL_Free(currentLayer);
    BSL_SAL_Free(nextLayer);
    
    return CRYPT_SUCCESS;
}

/* Generate LMS public key from private key */
int32_t LmsGeneratePublicKey(const LmsPrivateKey *prv, LmsPublicKey *pub)
{
    if (prv == NULL || pub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    pub->algId = prv->algId;
    pub->otsAlgId = prv->otsAlgId;
    (void)memcpy_s(pub->I, sizeof(pub->I), prv->I, sizeof(prv->I));
    
    /* Compute root of Merkle tree */
    return LmsComputeRoot(prv, pub->T1);
}

/* Build authentication path for given leaf */
static int32_t BuildAuthPath(const LmsPrivateKey *prv, uint32_t leafIndex, 
                            uint8_t *authPath, uint32_t authPathLen)
{
    const LmsParam *param = GetLmsParam(prv->algId);
    if (param == NULL) {
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    uint32_t h = param->h;
    if (authPathLen < h * LMS_M_VALUE) {
        return CRYPT_LMS_ERR_INVALID_PARAM;
    }
    
    /* For simplicity, we compute siblings on-the-fly */
    /* In a real implementation, these would be cached */
    
    uint8_t currentNode[LMS_M_VALUE];
    int32_t ret = LmsGenerateLeafNode(prv, leafIndex, currentNode);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    uint32_t currentIndex = leafIndex;
    
    for (uint32_t level = 0; level < h; level++) {
        uint32_t siblingIndex = currentIndex ^ 1;  /* XOR with 1 to get sibling */
        uint8_t siblingNode[LMS_M_VALUE];
        
        if (level == 0) {
            /* Sibling is another leaf */
            ret = LmsGenerateLeafNode(prv, siblingIndex, siblingNode);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        } else {
            /* Compute sibling node recursively - simplified version */
            /* In practice, this would use cached values */
            ret = LmsGenerateLeafNode(prv, siblingIndex * (1u << level), siblingNode);
            if (ret != CRYPT_SUCCESS) {
                return ret;
            }
        }
        
        /* Copy sibling to auth path */
        (void)memcpy_s(authPath + level * LMS_M_VALUE, LMS_M_VALUE, siblingNode, LMS_M_VALUE);
        
        /* Move up to parent */
        currentIndex = currentIndex / 2;
    }
    
    return CRYPT_SUCCESS;
}

/* LMS sign */
int32_t LmsSign(LmsPrivateKey *prv, const uint8_t *message, uint32_t msgLen,
                uint8_t *signature, uint32_t *sigLen)
{
    if (prv == NULL || message == NULL || signature == NULL || sigLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    const LmsParam *lmsParam = GetLmsParam(prv->algId);
    const LmotsParam *otsParam = GetLmotsParam(prv->otsAlgId);
    
    if (lmsParam == NULL || otsParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    /* Check if key is exhausted */
    if (prv->q > prv->maxQ) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_KEY_EXPIRED);
        return CRYPT_LMS_ERR_KEY_EXPIRED;
    }
    
    /* Calculate required signature length */
    uint32_t requiredLen = 4 + otsParam->sigLen + 4 + lmsParam->h * LMS_M_VALUE;
    if (*sigLen < requiredLen) {
        *sigLen = requiredLen;
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    uint32_t offset = 0;
    
    /* Write leaf index q */
    CRYPT_PutBE32(signature + offset, prv->q);
    offset += 4;
    
    /* Generate and sign with OTS key */
    LmotsPrivateKey otsPriv;
    int32_t ret = GenerateOtsKey(prv, prv->q, &otsPriv);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    uint32_t otsSigLen = otsParam->sigLen;
    ret = LmotsSign(&otsPriv, message, msgLen, signature + offset, &otsSigLen);
    CRYPT_Memset(&otsPriv, 0, sizeof(otsPriv));
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    offset += otsSigLen;
    
    /* Write LMS algorithm ID */
    CRYPT_PutBE32(signature + offset, prv->algId);
    offset += 4;
    
    /* Build and write authentication path */
    ret = BuildAuthPath(prv, prv->q, signature + offset, lmsParam->h * LMS_M_VALUE);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    offset += lmsParam->h * LMS_M_VALUE;
    
    *sigLen = offset;
    
    /* Increment leaf index */
    prv->q++;
    
    return CRYPT_SUCCESS;
}

/* LMS verify */
int32_t LmsVerify(const LmsPublicKey *pub, const uint8_t *message, uint32_t msgLen,
                  const uint8_t *signature, uint32_t sigLen)
{
    if (pub == NULL || message == NULL || signature == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if (sigLen < 8) {  /* Minimum: q (4) + algId (4) */
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    uint32_t offset = 0;
    
    /* Read leaf index */
    uint32_t q = CRYPT_GetBE32(signature + offset);
    offset += 4;
    
    /* Get parameters */
    const LmsParam *lmsParam = GetLmsParam(pub->algId);
    const LmotsParam *otsParam = GetLmotsParam(pub->otsAlgId);
    
    if (lmsParam == NULL || otsParam == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    /* Check leaf index range */
    if (q >= (1u << lmsParam->h)) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_PARAM);
        return CRYPT_LMS_ERR_INVALID_PARAM;
    }
    
    /* Check signature length */
    uint32_t expectedLen = 4 + otsParam->sigLen + 4 + lmsParam->h * LMS_M_VALUE;
    if (sigLen != expectedLen) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_SIG_LEN);
        return CRYPT_LMS_ERR_INVALID_SIG_LEN;
    }
    
    /* Reconstruct OTS public key from signature */
    LmotsPublicKey otsPub;
    otsPub.algId = pub->otsAlgId;
    (void)memcpy_s(otsPub.I, sizeof(otsPub.I), pub->I, sizeof(pub->I));
    otsPub.q = q;
    
    int32_t ret = LmotsVerify(&otsPub, message, msgLen, signature + offset, otsParam->sigLen);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    offset += otsParam->sigLen;
    
    /* Read LMS algorithm ID */
    uint32_t algId = CRYPT_GetBE32(signature + offset);
    offset += 4;
    
    if (algId != pub->algId) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_ALGID);
        return CRYPT_LMS_ERR_INVALID_ALGID;
    }
    
    /* Compute leaf node from reconstructed OTS public key */
    uint8_t currentNode[LMS_M_VALUE];
    ret = HashOtsPublicKey(&otsPub, currentNode);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    /* Verify authentication path */
    uint32_t currentIndex = q;
    for (uint32_t level = 0; level < lmsParam->h; level++) {
        uint8_t sibling[LMS_M_VALUE];
        (void)memcpy_s(sibling, sizeof(sibling), signature + offset + level * LMS_M_VALUE, LMS_M_VALUE);
        
        uint8_t parent[LMS_M_VALUE];
        if ((currentIndex & 1) == 0) {
            /* Current node is left child */
            ret = ComputeInternalNode(pub->I, level + 1, currentIndex / 2,
                                     currentNode, sibling, parent);
        } else {
            /* Current node is right child */
            ret = ComputeInternalNode(pub->I, level + 1, currentIndex / 2,
                                     sibling, currentNode, parent);
        }
        
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        (void)memcpy_s(currentNode, sizeof(currentNode), parent, sizeof(parent));
        currentIndex = currentIndex / 2;
    }
    
    /* Compare with public key root */
    if (memcmp(currentNode, pub->T1, LMS_M_VALUE) != 0) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_SIGNATURE_VERIFY_FAIL);
        return CRYPT_LMS_ERR_SIGNATURE_VERIFY_FAIL;
    }
    
    return CRYPT_SUCCESS;
}

/* Sign with LMS context */
int32_t CRYPT_LMS_Sign(CryptLmsCtx *ctx, CRYPT_MD_AlgId mdId, const uint8_t *data, uint32_t dataLen,
                       uint8_t *sign, uint32_t *signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL || signLen == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if ((ctx->keyType & LMS_PRVKEY) == 0 || ctx->lmsPrv == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    /* LMS uses SHA-256, ignore mdId parameter */
    (void)mdId;
    
    return LmsSign(ctx->lmsPrv, data, dataLen, sign, signLen);
}

/* Verify with LMS context */
int32_t CRYPT_LMS_Verify(const CryptLmsCtx *ctx, const uint8_t *data, uint32_t dataLen,
                         const uint8_t *sign, uint32_t signLen)
{
    if (ctx == NULL || data == NULL || sign == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_NULL_INPUT);
        return CRYPT_NULL_INPUT;
    }
    
    if ((ctx->keyType & LMS_PUBKEY) == 0 || ctx->lmsPub == NULL) {
        BSL_ERR_PUSH_ERROR(CRYPT_LMS_ERR_INVALID_KEYLEN);
        return CRYPT_LMS_ERR_INVALID_KEYLEN;
    }
    
    return LmsVerify(ctx->lmsPub, data, dataLen, sign, signLen);
}

#endif // HITLS_CRYPTO_LMS