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

/* 
 * LMS/HSS Post-Quantum Signature Demo
 * 
 * This demo shows how to use LMS/HSS (Leighton-Micali Signature / Hierarchical Signature System)
 * post-quantum signature algorithm for secure digital signatures.
 * 
 * LMS/HSS provides quantum-resistant signatures suitable for long-term security applications
 * such as firmware signing, code signing, and other scenarios where post-quantum security is required.
 */

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_LMS_HSS

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "securec.h"
#include "crypt_errno.h"
#include "crypt_lms_hss.h"
#include "bsl_sal.h"

/* Print binary data as hex string */
static void PrintHex(const char *label, const uint8_t *data, uint32_t len)
{
    printf("%s (%u bytes): ", label, len);
    for (uint32_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
        if (i > 0 && (i + 1) % 16 == 0) {
            printf("\n");
            if (i + 1 < len) {
                printf("%*s", (int)strlen(label) + 12, ""); /* Indent for next line */
            }
        } else if (i + 1 < len) {
            printf(" ");
        }
    }
    printf("\n\n");
}

/* Basic LMS/HSS usage example */
static int32_t BasicLmsHssExample(void)
{
    printf("=== Basic LMS/HSS Usage Example ===\n\n");

    /* Step 1: Create LMS/HSS context */
    CryptLmsHssCtx *ctx = CRYPT_LMS_HSS_NewCtx();
    if (ctx == NULL) {
        printf("ERROR: Failed to create LMS/HSS context\n");
        return CRYPT_LMS_HSS_ERR_BASE;
    }
    printf("✓ Created LMS/HSS context\n");

    /* Step 2: Configure algorithm parameters */
    uint32_t lmsType = LMS_SHA256_M32_H10;      /* LMS with SHA-256, tree height 10 (1024 signatures) */
    uint32_t lmotsType = LMOTS_SHA256_N32_W4;   /* LMOTS with SHA-256, Winternitz parameter 4 */
    uint32_t levels = 1;                        /* Single-level LMS (not hierarchical) */

    int32_t ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_LMS_TYPE, &lmsType, sizeof(lmsType));
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to set LMS type: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_LMOTS_TYPE, &lmotsType, sizeof(lmotsType));
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to set LMOTS type: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_HSS_LEVELS, &levels, sizeof(levels));
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to set HSS levels: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }
    printf("✓ Configured parameters: LMS-SHA256-M32-H10, LMOTS-SHA256-N32-W4, 1 level\n");

    /* Step 3: Generate key pair */
    ret = CRYPT_LMS_HSS_Gen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to generate key pair: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }
    printf("✓ Generated LMS/HSS key pair\n");

    /* Step 4: Get and display key information */
    uint32_t signatureLen = 0;
    ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_GET_SIGNATURE_LEN, &signatureLen, sizeof(signatureLen));
    if (ret == CRYPT_SUCCESS) {
        printf("  - Expected signature length: %u bytes\n", signatureLen);
    }

    uint32_t remainingSigs = 0;
    ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_GET_REMAINING_SIGS, &remainingSigs, sizeof(remainingSigs));
    if (ret == CRYPT_SUCCESS) {
        printf("  - Remaining signatures: %u\n", remainingSigs);
    }

    /* Step 5: Sign a message */
    const char *message = "This is a test message for LMS/HSS post-quantum signature.";
    uint32_t messageLen = strlen(message);
    
    uint8_t signature[8192];  /* Large buffer for signature */
    uint32_t actualSigLen = sizeof(signature);

    ret = CRYPT_LMS_HSS_Sign(ctx, CRYPT_PKEY_LMS_HSS, (const uint8_t *)message, 
                            messageLen, signature, &actualSigLen);
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to sign message: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }
    
    printf("✓ Successfully signed message\n");
    printf("  - Message: \"%s\"\n", message);
    printf("  - Message length: %u bytes\n", messageLen);
    printf("  - Actual signature length: %u bytes\n", actualSigLen);

    /* Step 6: Verify the signature */
    ret = CRYPT_LMS_HSS_Verify(ctx, CRYPT_PKEY_LMS_HSS, (const uint8_t *)message, 
                              messageLen, signature, actualSigLen);
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to verify signature: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }
    
    printf("✓ Signature verification successful\n");

    /* Step 7: Test signature with modified message (should fail) */
    const char *modifiedMessage = "This is a MODIFIED message for LMS/HSS post-quantum signature.";
    uint32_t modifiedLen = strlen(modifiedMessage);
    
    ret = CRYPT_LMS_HSS_Verify(ctx, CRYPT_PKEY_LMS_HSS, (const uint8_t *)modifiedMessage, 
                              modifiedLen, signature, actualSigLen);
    if (ret == CRYPT_SUCCESS) {
        printf("ERROR: Signature should have failed verification with modified message\n");
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return CRYPT_LMS_HSS_ERR_BASE;
    }
    
    printf("✓ Correctly rejected signature for modified message\n");

    /* Step 8: Clean up */
    CRYPT_LMS_HSS_FreeCtx(ctx);
    printf("✓ Cleaned up resources\n");

    printf("\n=== Basic example completed successfully ===\n\n");
    return CRYPT_SUCCESS;
}

/* Hierarchical Signature System (HSS) example */
static int32_t HssMultiLevelExample(void)
{
    printf("=== Hierarchical Signature System (HSS) Example ===\n\n");

    /* Create HSS context with multiple levels */
    CryptLmsHssCtx *ctx = CRYPT_LMS_HSS_NewCtx();
    if (ctx == NULL) {
        printf("ERROR: Failed to create HSS context\n");
        return CRYPT_LMS_HSS_ERR_BASE;
    }

    /* Configure HSS with 3 levels for more signatures */
    uint32_t lmsType = LMS_SHA256_M32_H5;       /* Tree height 5 (32 signatures per tree) */
    uint32_t lmotsType = LMOTS_SHA256_N32_W2;   /* Winternitz parameter 2 */
    uint32_t levels = 3;                        /* 3-level hierarchy */

    int32_t ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_LMS_TYPE, &lmsType, sizeof(lmsType));
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to set LMS type: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_LMOTS_TYPE, &lmotsType, sizeof(lmotsType));
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to set LMOTS type: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }

    ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_HSS_LEVELS, &levels, sizeof(levels));
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to set HSS levels: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }

    printf("✓ Configured HSS with 3 levels (tree height 5 each)\n");
    printf("  - Total possible signatures: 32^3 = 32,768 signatures\n");

    /* Generate HSS key pair */
    ret = CRYPT_LMS_HSS_Gen(ctx);
    if (ret != CRYPT_SUCCESS) {
        printf("ERROR: Failed to generate HSS key pair: %d\n", ret);
        CRYPT_LMS_HSS_FreeCtx(ctx);
        return ret;
    }
    printf("✓ Generated HSS multi-level key pair\n");

    /* Perform multiple signatures to demonstrate HSS capability */
    const char *messages[] = {
        "Document 1: Firmware version 1.0",
        "Document 2: Firmware version 1.1", 
        "Document 3: Firmware version 1.2",
        "Document 4: Critical security update",
        "Document 5: Emergency patch release"
    };
    
    uint32_t numMessages = sizeof(messages) / sizeof(messages[0]);
    
    for (uint32_t i = 0; i < numMessages; i++) {
        uint8_t signature[8192];
        uint32_t sigLen = sizeof(signature);
        
        ret = CRYPT_LMS_HSS_Sign(ctx, CRYPT_PKEY_LMS_HSS, (const uint8_t *)messages[i], 
                                strlen(messages[i]), signature, &sigLen);
        if (ret != CRYPT_SUCCESS) {
            printf("ERROR: Failed to sign message %u: %d\n", i + 1, ret);
            CRYPT_LMS_HSS_FreeCtx(ctx);
            return ret;
        }
        
        ret = CRYPT_LMS_HSS_Verify(ctx, CRYPT_PKEY_LMS_HSS, (const uint8_t *)messages[i], 
                                  strlen(messages[i]), signature, sigLen);
        if (ret != CRYPT_SUCCESS) {
            printf("ERROR: Failed to verify signature %u: %d\n", i + 1, ret);
            CRYPT_LMS_HSS_FreeCtx(ctx);
            return ret;
        }
        
        printf("✓ Message %u: Signed and verified (%u bytes signature)\n", i + 1, sigLen);
        
        /* Check remaining signatures */
        uint32_t remaining = 0;
        ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_GET_REMAINING_SIGS, &remaining, sizeof(remaining));
        if (ret == CRYPT_SUCCESS) {
            printf("  - Remaining signatures: %u\n", remaining);
        }
    }

    CRYPT_LMS_HSS_FreeCtx(ctx);
    printf("\n=== HSS multi-level example completed successfully ===\n\n");
    return CRYPT_SUCCESS;
}

/* Parameter comparison example */
static int32_t ParameterComparisonExample(void)
{
    printf("=== LMS/HSS Parameter Comparison Example ===\n\n");
    
    printf("This example demonstrates different LMS/HSS parameter sets and their trade-offs:\n\n");
    
    struct ParameterSet {
        uint32_t lmsType;
        uint32_t lmotsType;
        const char *name;
        const char *description;
    } paramSets[] = {
        {LMS_SHA256_M32_H5,  LMOTS_SHA256_N32_W1, "H5-W1", "Small tree, small signatures (slow)"},
        {LMS_SHA256_M32_H5,  LMOTS_SHA256_N32_W8, "H5-W8", "Small tree, larger signatures (fast)"},
        {LMS_SHA256_M32_H10, LMOTS_SHA256_N32_W2, "H10-W2", "Medium tree, balanced"},
        {LMS_SHA256_M32_H15, LMOTS_SHA256_N32_W4, "H15-W4", "Large tree, many signatures"},
        {LMS_SHA256_M32_H20, LMOTS_SHA256_N32_W8, "H20-W8", "Very large tree, maximum signatures"}
    };
    
    uint32_t numSets = sizeof(paramSets) / sizeof(paramSets[0]);
    
    printf("Parameter Set | Signatures | Signature Size | Description\n");
    printf("------------- | ---------- | -------------- | -----------\n");
    
    for (uint32_t i = 0; i < numSets; i++) {
        CryptLmsHssCtx *ctx = CRYPT_LMS_HSS_NewCtx();
        if (ctx == NULL) {
            continue;
        }
        
        uint32_t levels = 1;
        int32_t ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_LMS_TYPE, 
                                        &paramSets[i].lmsType, sizeof(paramSets[i].lmsType));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_LMS_HSS_FreeCtx(ctx);
            continue;
        }
        
        ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_LMOTS_TYPE, 
                                &paramSets[i].lmotsType, sizeof(paramSets[i].lmotsType));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_LMS_HSS_FreeCtx(ctx);
            continue;
        }
        
        ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_SET_HSS_LEVELS, &levels, sizeof(levels));
        if (ret != CRYPT_SUCCESS) {
            CRYPT_LMS_HSS_FreeCtx(ctx);
            continue;
        }
        
        uint32_t sigLen = 0;
        ret = CRYPT_LMS_HSS_Ctrl(ctx, CRYPT_CTRL_GET_SIGNATURE_LEN, &sigLen, sizeof(sigLen));
        
        uint32_t h = (paramSets[i].lmsType == LMS_SHA256_M32_H5) ? 5 :
                     (paramSets[i].lmsType == LMS_SHA256_M32_H10) ? 10 :
                     (paramSets[i].lmsType == LMS_SHA256_M32_H15) ? 15 :
                     (paramSets[i].lmsType == LMS_SHA256_M32_H20) ? 20 : 25;
        
        uint32_t maxSigs = 1U << h;  /* 2^h signatures */
        
        printf("%-13s | %10u | %14u | %s\n", 
               paramSets[i].name, maxSigs, sigLen, paramSets[i].description);
        
        CRYPT_LMS_HSS_FreeCtx(ctx);
    }
    
    printf("\nNotes:\n");
    printf("- Larger trees (higher H values) provide more signatures but require more storage\n");
    printf("- Larger Winternitz parameters (W) create larger signatures but verify faster\n");
    printf("- HSS levels multiply the number of available signatures\n");
    printf("- All parameter sets provide post-quantum security\n");
    
    printf("\n=== Parameter comparison completed ===\n\n");
    return CRYPT_SUCCESS;
}

/* Main demo function */
int main(void)
{
    printf("LMS/HSS Post-Quantum Signature Algorithm Demo\n");
    printf("==============================================\n\n");
    
    int32_t ret = CRYPT_SUCCESS;
    
    /* Run basic example */
    ret = BasicLmsHssExample();
    if (ret != CRYPT_SUCCESS) {
        printf("Basic example failed with error: %d\n", ret);
        return ret;
    }
    
    /* Run HSS multi-level example */
    ret = HssMultiLevelExample();
    if (ret != CRYPT_SUCCESS) {
        printf("HSS multi-level example failed with error: %d\n", ret);
        return ret;
    }
    
    /* Run parameter comparison */
    ret = ParameterComparisonExample();
    if (ret != CRYPT_SUCCESS) {
        printf("Parameter comparison failed with error: %d\n", ret);
        return ret;
    }
    
    printf("=== All LMS/HSS demos completed successfully! ===\n");
    printf("\nFor production use:\n");
    printf("1. Choose appropriate parameters based on your signature count requirements\n");
    printf("2. Securely manage private keys and track signature counters\n");
    printf("3. Never reuse LMS/HSS private keys after exhaustion\n");
    printf("4. Consider HSS for applications requiring many signatures\n");
    printf("5. Integrate proper random number generation for key generation\n\n");
    
    return CRYPT_SUCCESS;
}

#else
int main(void)
{
    printf("LMS/HSS support is not enabled in this build.\n");
    printf("Please enable HITLS_CRYPTO_LMS_HSS to run this demo.\n");
    return 1;
}
#endif /* HITLS_CRYPTO_LMS_HSS */