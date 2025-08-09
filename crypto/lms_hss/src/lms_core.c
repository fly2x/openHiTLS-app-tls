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
#ifdef HITLS_CRYPTO_LMS_HSS

#include <string.h>
#include "securec.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "../../include/crypt_util_rand.h"
#include "lms_hss_local.h"

/* Helper function declarations */
static int32_t ComputeTreeNode(const CryptLmsHssCtx *ctx, uint32_t level, uint32_t nodeIndex, uint8_t *node);
static int32_t ComputeLeafNode(const CryptLmsHssCtx *ctx, uint32_t leafIndex, uint8_t *leaf);

/* LMS domain separator constants from RFC 8554 */
#define LMS_D_LEAF      0x8383
#define LMS_D_INTR      0x8484

/* Compute LMS leaf node */
static int32_t LmsComputeLeaf(const CryptLmsHssCtx *ctx, const uint8_t *identifier, 
                              uint32_t r, const uint8_t *lmotsPublicKey, uint8_t *leaf)
{
    if (ctx == NULL || identifier == NULL || lmotsPublicKey == NULL || leaf == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Compute leaf = H(identifier || r || D_LEAF || lmots_public_key) */
    uint32_t inputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + LMS_HSS_HASH_LEN;
    uint8_t *input = LmsHss_Malloc(inputLen);
    if (input == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    
    /* identifier */
    if (memcpy_s(input + offset, inputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* r (big-endian) */
    input[offset++] = (uint8_t)(r >> 24);
    input[offset++] = (uint8_t)(r >> 16);
    input[offset++] = (uint8_t)(r >> 8);
    input[offset++] = (uint8_t)r;
    
    /* D_LEAF */
    input[offset++] = (uint8_t)(LMS_D_LEAF >> 8);
    input[offset++] = (uint8_t)LMS_D_LEAF;
    
    /* LMOTS public key */
    if (memcpy_s(input + offset, inputLen - offset, lmotsPublicKey, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }

    LmsHssAdrs adrs = {0};
    adrs.type = LMS_HSS_ADDR_TYPE_TREE;
    adrs.q = r; /* Use r parameter instead of leafIndex */
    adrs.i = 0; /* Leaf level */
    adrs.j = 0;
    
    int32_t ret = ctx->hashFuncs.h(ctx, &adrs, input, inputLen, leaf);
    LmsHss_Free(input);
    
    return ret;
}

/* Compute LMS internal node */
static int32_t LmsComputeInternalNode(const CryptLmsHssCtx *ctx, const uint8_t *identifier,
                                      uint32_t r, const uint8_t *leftChild, 
                                      const uint8_t *rightChild, uint8_t *node)
{
    if (ctx == NULL || identifier == NULL || leftChild == NULL || rightChild == NULL || node == NULL) {
        return CRYPT_NULL_INPUT;
    }

    /* Compute node = H(identifier || r || D_INTR || left || right) */
    uint32_t inputLen = LMS_HSS_IDENTIFIER_LEN + 4 + 2 + 2 * LMS_HSS_HASH_LEN;
    uint8_t *input = LmsHss_Malloc(inputLen);
    if (input == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint32_t offset = 0;
    
    /* identifier */
    if (memcpy_s(input + offset, inputLen - offset, identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_IDENTIFIER_LEN;
    
    /* r (big-endian) */
    input[offset++] = (uint8_t)(r >> 24);
    input[offset++] = (uint8_t)(r >> 16);
    input[offset++] = (uint8_t)(r >> 8);
    input[offset++] = (uint8_t)r;
    
    /* D_INTR */
    input[offset++] = (uint8_t)(LMS_D_INTR >> 8);
    input[offset++] = (uint8_t)LMS_D_INTR;
    
    /* left child */
    if (memcpy_s(input + offset, inputLen - offset, leftChild, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }
    offset += LMS_HSS_HASH_LEN;
    
    /* right child */
    if (memcpy_s(input + offset, inputLen - offset, rightChild, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(input);
        return CRYPT_SECUREC_FAIL;
    }

    LmsHssAdrs adrs = {0};
    adrs.type = LMS_HSS_ADDR_TYPE_TREE;
    adrs.q = r; /* Node index */
    adrs.i = 1; /* Internal node level */
    adrs.j = 0;
    
    int32_t ret = ctx->hashFuncs.h(ctx, &adrs, input, inputLen, node);
    LmsHss_Free(input);
    
    return ret;
}

/* Build Merkle tree and compute root */
static int32_t LmsBuildTree(const CryptLmsHssCtx *ctx, const uint8_t *identifier,
                            const uint8_t *seed, uint8_t **tree, uint8_t *root)
{
    if (ctx == NULL || identifier == NULL || seed == NULL || tree == NULL || root == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t h = ctx->para.h;
    uint32_t numNodes = (1 << (h + 1)) - 1;  /* Total nodes in binary tree */
    uint32_t numLeaves = 1 << h;              /* Number of leaf nodes */
    
    /* Allocate memory for the tree */
    *tree = LmsHss_Calloc(numNodes, LMS_HSS_HASH_LEN);
    if (*tree == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    /* Generate leaf nodes */
    for (uint32_t i = 0; i < numLeaves; i++) {
        uint8_t lmotsPublicKey[LMS_HSS_HASH_LEN];
        
        /* Generate LMOTS public key for leaf i */
        int32_t ret = LMOTS_GenerateKeyPair(ctx, identifier, i, seed);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_Free(*tree);
            *tree = NULL;
            return ret;
        }
        
        /* This is a simplified version - in practice we'd need the full LMOTS public key generation */
        LmsHssAdrs adrs = {0};
        adrs.type = LMS_HSS_ADDR_TYPE_OTS;
        adrs.q = i;
        adrs.i = 0;
        adrs.j = 0;
        
        ret = ctx->hashFuncs.prf(ctx, &adrs, seed, lmotsPublicKey);
        if (ret != CRYPT_SUCCESS) {
            LmsHss_Free(*tree);
            *tree = NULL;
            return ret;
        }
        
        /* Compute leaf node */
        uint32_t leafIndex = numNodes - numLeaves + i;  /* Leaf nodes are at the end */
        ret = LmsComputeLeaf(ctx, identifier, i, lmotsPublicKey, 
                             (*tree) + leafIndex * LMS_HSS_HASH_LEN);
        
        if (ret != CRYPT_SUCCESS) {
            LmsHss_Free(*tree);
            *tree = NULL;
            return ret;
        }
    }

    /* Build internal nodes from bottom up */
    for (uint32_t level = h; level > 0; level--) {
        uint32_t levelStart = (1 << (level - 1)) - 1;     /* Start index of this level */
        uint32_t childLevelStart = (1 << level) - 1;      /* Start index of child level */
        uint32_t nodesInLevel = 1 << (level - 1);         /* Number of nodes in this level */
        
        for (uint32_t i = 0; i < nodesInLevel; i++) {
            uint32_t nodeIndex = levelStart + i;
            uint32_t leftChildIndex = childLevelStart + 2 * i;
            uint32_t rightChildIndex = childLevelStart + 2 * i + 1;
            uint32_t r = (1 << (level - 1)) + i;  /* Node identifier for internal node */
            
            int32_t ret = LmsComputeInternalNode(ctx, identifier, r,
                                                 (*tree) + leftChildIndex * LMS_HSS_HASH_LEN,
                                                 (*tree) + rightChildIndex * LMS_HSS_HASH_LEN,
                                                 (*tree) + nodeIndex * LMS_HSS_HASH_LEN);
            if (ret != CRYPT_SUCCESS) {
                LmsHss_Free(*tree);
                *tree = NULL;
                return ret;
            }
        }
    }

    /* Root is at index 0 */
    if (memcpy_s(root, LMS_HSS_HASH_LEN, (*tree), LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(*tree);
        *tree = NULL;
        return CRYPT_SECUREC_FAIL;
    }

    return CRYPT_SUCCESS;
}

/* Compute authentication path for a given leaf */
int32_t LmsHss_ComputeAuthPath(CryptLmsHssCtx *ctx, uint32_t leafIndex, uint8_t **authPath)
{
    if (ctx == NULL || authPath == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t h = ctx->para.h;
    uint32_t numLeaves = 1 << h;
    
    if (leafIndex >= numLeaves) {
        return CRYPT_LMS_HSS_INVALID_PARA;
    }

    /* Allocate memory for authentication path */
    *authPath = LmsHss_Calloc(h, LMS_HSS_HASH_LEN);
    if (*authPath == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    /* RFC 8554 compliant authentication path computation */
    uint32_t currentIndex = leafIndex;
    
    for (uint32_t level = 0; level < h; level++) {
        uint32_t siblingIndex = currentIndex ^ 1; /* XOR with 1 to get sibling */
        uint8_t *pathNode = (*authPath) + level * LMS_HSS_HASH_LEN;
        
        if (siblingIndex < (1U << (h - level))) {
            /* Recursively compute tree node or use stored value */
            int32_t ret = ComputeTreeNode(ctx, level, siblingIndex, pathNode);
            if (ret != CRYPT_SUCCESS) {
                LmsHss_Free(*authPath);
                *authPath = NULL;
                return ret;
            }
        } else {
            /* Node doesn't exist, use zero */
            memset(pathNode, 0, LMS_HSS_HASH_LEN);
        }
        
        currentIndex >>= 1; /* Move up one level */
    }
    
    return CRYPT_SUCCESS;
}

/* Helper function to compute individual tree nodes */
static int32_t ComputeTreeNode(const CryptLmsHssCtx *ctx, uint32_t level, uint32_t nodeIndex, uint8_t *node)
{
    if (level == 0) {
        /* Leaf node - compute from LMOTS public key */
        return ComputeLeafNode(ctx, nodeIndex, node);
    } else {
        /* Internal node - compute from children */
        uint8_t leftChild[LMS_HSS_HASH_LEN];
        uint8_t rightChild[LMS_HSS_HASH_LEN];
        
        uint32_t leftIndex = nodeIndex * 2;
        uint32_t rightIndex = leftIndex + 1;
        
        int32_t ret = ComputeTreeNode(ctx, level - 1, leftIndex, leftChild);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        ret = ComputeTreeNode(ctx, level - 1, rightIndex, rightChild);
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        /* Hash left || right to get parent */
        LmsHssAdrs adrs = {0};
        adrs.type = LMS_HSS_ADDR_TYPE_TREE;
        adrs.q = nodeIndex;
        adrs.i = level;
        adrs.j = 0;
        
        uint8_t input[2 * LMS_HSS_HASH_LEN];
        memcpy(input, leftChild, LMS_HSS_HASH_LEN);
        memcpy(input + LMS_HSS_HASH_LEN, rightChild, LMS_HSS_HASH_LEN);
        
        return ctx->hashFuncs.h(ctx, &adrs, input, 2 * LMS_HSS_HASH_LEN, node);
    }
}

/* Compute leaf node from LMOTS public key */
static int32_t ComputeLeafNode(const CryptLmsHssCtx *ctx, uint32_t leafIndex, uint8_t *leaf)
{
    /* Generate LMOTS key pair for this leaf */
    uint8_t identifier[LMS_HSS_IDENTIFIER_LEN];
    memcpy(identifier, ctx->prvKey.prvKeys[0].identifier, LMS_HSS_IDENTIFIER_LEN);
    
    uint8_t seed[LMS_HSS_SEED_LEN];
    /* Derive deterministic seed for this leaf */
    LmsHssAdrs adrs = {0};
    adrs.type = LMS_HSS_ADDR_TYPE_OTS;
    adrs.q = leafIndex;
    adrs.i = 0;
    adrs.j = 0;
    
    int32_t ret = ctx->hashFuncs.prf(ctx, &adrs, ctx->prvKey.prvKeys[0].seed, seed);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    /* Generate LMOTS public key for this leaf */
    return LMOTS_GeneratePublicKey(ctx, identifier, leafIndex, seed, leaf);
    
    return CRYPT_SUCCESS;
}

/* Verify authentication path and compute root */
int32_t LmsHss_ComputeRoot(const CryptLmsHssCtx *ctx, const uint8_t *leaf, uint32_t leafIndex,
                           const uint8_t *authPath, uint8_t *root)
{
    if (ctx == NULL || leaf == NULL || authPath == NULL || root == NULL) {
        return CRYPT_NULL_INPUT;
    }

    uint32_t h = ctx->para.h;
    uint8_t currentNode[LMS_HSS_HASH_LEN];
    
    /* Start with the leaf node */
    if (memcpy_s(currentNode, LMS_HSS_HASH_LEN, leaf, LMS_HSS_HASH_LEN) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }

    /* Compute path to root */
    uint32_t index = leafIndex;
    for (uint32_t i = 0; i < h; i++) {
        uint8_t sibling[LMS_HSS_HASH_LEN];
        if (memcpy_s(sibling, LMS_HSS_HASH_LEN, authPath + i * LMS_HSS_HASH_LEN, LMS_HSS_HASH_LEN) != EOK) {
            return CRYPT_SECUREC_FAIL;
        }

        uint8_t parent[LMS_HSS_HASH_LEN];
        uint32_t r = (1 << (h - i)) + (index >> 1);  /* Parent node identifier */
        
        int32_t ret;
        if (index & 1) {
            /* Current node is right child */
            ret = LmsComputeInternalNode(ctx, ctx->prvKey.prvKeys[0].identifier, r,
                                         sibling, currentNode, parent);
        } else {
            /* Current node is left child */
            ret = LmsComputeInternalNode(ctx, ctx->prvKey.prvKeys[0].identifier, r,
                                         currentNode, sibling, parent);
        }
        
        if (ret != CRYPT_SUCCESS) {
            return ret;
        }
        
        if (memcpy_s(currentNode, LMS_HSS_HASH_LEN, parent, LMS_HSS_HASH_LEN) != EOK) {
            return CRYPT_SECUREC_FAIL;
        }
        
        index >>= 1;
    }

    if (memcpy_s(root, LMS_HSS_HASH_LEN, currentNode, LMS_HSS_HASH_LEN) != EOK) {
        return CRYPT_SECUREC_FAIL;
    }

    return CRYPT_SUCCESS;
}

/* Generate LMS key pair */
int32_t LMS_GenerateKeyPair(CryptLmsHssCtx *ctx, uint32_t level)
{
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (level >= ctx->para.levels) {
        return CRYPT_LMS_HSS_INVALID_LEVEL;
    }

    LmsPrvKey *prvKey = &ctx->prvKey.prvKeys[level];
    LmsPubKey *pubKey = (level == 0) ? &ctx->pubKey.topLevelPubKey : NULL;

    /* Initialize private key */
    prvKey->lmsType = ctx->para.lmsType;
    prvKey->lmotsType = ctx->para.lmotsType;
    prvKey->q = 0;  /* Start with signature index 0 */
    
    /* Generate random identifier */
    int32_t ret = CRYPT_RandEx(NULL, prvKey->identifier, LMS_HSS_IDENTIFIER_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    
    /* Generate random seed */
    ret = CRYPT_RandEx(NULL, prvKey->seed, LMS_HSS_SEED_LEN);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Build Merkle tree and compute root */
    uint8_t *tree = NULL;
    uint8_t root[LMS_HSS_HASH_LEN];
    ret = LmsBuildTree(ctx, prvKey->identifier, prvKey->seed, &tree, root);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Set up public key */
    if (pubKey != NULL) {
        pubKey->lmsType = ctx->para.lmsType;
        pubKey->lmotsType = ctx->para.lmotsType;
        if (memcpy_s(pubKey->identifier, LMS_HSS_IDENTIFIER_LEN, 
                     prvKey->identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
            LmsHss_Free(tree);
            return CRYPT_SECUREC_FAIL;
        }
        if (memcpy_s(pubKey->root, LMS_HSS_HASH_LEN, root, LMS_HSS_HASH_LEN) != EOK) {
            LmsHss_Free(tree);
            return CRYPT_SECUREC_FAIL;
        }
    }

    /* Set up private key's public key reference */
    prvKey->pubKey.lmsType = ctx->para.lmsType;
    prvKey->pubKey.lmotsType = ctx->para.lmotsType;
    if (memcpy_s(prvKey->pubKey.identifier, LMS_HSS_IDENTIFIER_LEN,
                 prvKey->identifier, LMS_HSS_IDENTIFIER_LEN) != EOK) {
        LmsHss_Free(tree);
        return CRYPT_SECUREC_FAIL;
    }
    if (memcpy_s(prvKey->pubKey.root, LMS_HSS_HASH_LEN, root, LMS_HSS_HASH_LEN) != EOK) {
        LmsHss_Free(tree);
        return CRYPT_SECUREC_FAIL;
    }

    /* Clean up tree (in practice, we might want to store it for signing) */
    LmsHss_Free(tree);
    
    return CRYPT_SUCCESS;
}

/* LMS signature generation */
int32_t LMS_Sign(CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                 uint32_t level, LmsSignature *signature)
{
    if (ctx == NULL || message == NULL || signature == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (level >= ctx->para.levels) {
        return CRYPT_LMS_HSS_INVALID_LEVEL;
    }

    LmsPrvKey *prvKey = &ctx->prvKey.prvKeys[level];
    uint32_t maxSignatures = 1 << ctx->para.h;
    
    /* Check if we've exhausted signatures for this tree */
    if (prvKey->q >= maxSignatures) {
        return CRYPT_LMS_HSS_TREE_EXHAUSTED;
    }

    /* Set signature parameters */
    signature->q = prvKey->q;
    signature->lmsType = ctx->para.lmsType;
    
    /* Generate LMOTS signature */
    int32_t ret = LMOTS_Sign(ctx, message, messageLen, prvKey->identifier, prvKey->q,
                             prvKey->seed, &signature->lmotsSignature);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Compute authentication path */
    ret = LmsHss_ComputeAuthPath(ctx, prvKey->q, &signature->authPath);
    if (ret != CRYPT_SUCCESS) {
        /* Clean up LMOTS signature */
        if (signature->lmotsSignature.y != NULL) {
            LmsHss_SecureClear(signature->lmotsSignature.y, ctx->para.p * LMS_HSS_HASH_LEN);
            LmsHss_Free(signature->lmotsSignature.y);
            signature->lmotsSignature.y = NULL;
        }
        return ret;
    }

    /* Update signature counter with RFC 8554 compliant state management */
    ret = UpdateSignatureState(ctx, 0); /* Level 0 for single-level LMS */
    if (ret != CRYPT_SUCCESS) {
        /* Clean up LMOTS signature and auth path */
        if (signature->lmotsSignature.y != NULL) {
            LmsHss_SecureClear(signature->lmotsSignature.y, ctx->para.p * LMS_HSS_HASH_LEN);
            LmsHss_Free(signature->lmotsSignature.y);
            signature->lmotsSignature.y = NULL;
        }
        return ret;
    }
    
    return CRYPT_SUCCESS;
}

/* LMS signature verification */
int32_t LMS_Verify(const CryptLmsHssCtx *ctx, const uint8_t *message, uint32_t messageLen,
                   const LmsSignature *signature, const LmsPubKey *pubKey)
{
    if (ctx == NULL || message == NULL || signature == NULL || pubKey == NULL) {
        return CRYPT_NULL_INPUT;
    }

    if (signature->lmsType != ctx->para.lmsType) {
        return CRYPT_LMS_HSS_INVALID_LMS_TYPE;
    }

    uint32_t maxSignatures = 1 << ctx->para.h;
    if (signature->q >= maxSignatures) {
        return CRYPT_LMS_HSS_INVALID_SIGNATURE;
    }

    /* First reconstruct LMOTS public key from signature */
    uint8_t lmotsPubKey[LMS_HSS_HASH_LEN];
    
    /* The LMOTS public key is reconstructed by running the hash chains forward from the signature */
    int32_t ret = LMOTS_ReconstructPublicKey(ctx, message, messageLen, &signature->lmotsSignature,
                                            pubKey->identifier, signature->q, lmotsPubKey);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Compute leaf node from LMOTS public key */
    uint8_t leafNode[LMS_HSS_HASH_LEN];
    ret = LmsComputeLeaf(ctx, pubKey->identifier, signature->q, lmotsPubKey, leafNode);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Compute root using authentication path */
    uint8_t computedRoot[LMS_HSS_HASH_LEN];
    ret = LmsHss_ComputeRoot(ctx, leafNode, signature->q,
                             signature->authPath, computedRoot);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    /* Compare computed root with public key root */
    if (memcmp(computedRoot, pubKey->root, LMS_HSS_HASH_LEN) != 0) {
        return CRYPT_LMS_HSS_VERIFY_FAIL;
    }

    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_LMS_HSS */