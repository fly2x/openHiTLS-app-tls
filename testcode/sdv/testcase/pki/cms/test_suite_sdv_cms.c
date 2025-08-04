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

/* BEGIN_HEADER */

#include "bsl_sal.h"
#include "securec.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "crypt_encode_decode_key.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_rand.h"
#include "crypt_errno.h"
#include "hitls_cms_local.h"
#include "hitls_pki_errno.h"

/* END_HEADER */

/**
 * For test parse p7-encryptData of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_ENCRYPTEDDATA_TC001(Hex *buff)
{
    BSL_Buffer output = {0};
    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);

    int32_t ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    BSL_SAL_Free(output.data);
    output.data = NULL;

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, NULL, (const uint8_t *)pwd, pwdlen, &output);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, NULL, pwdlen, &output);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, 8192, &output);
    ASSERT_EQ(ret, CRYPT_INVALID_ARG);

    char *pwd1 = "123456@123";
    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd1, strlen(pwd1),
        &output);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    char *pwd2 = "";
    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd2, strlen(pwd2),
        &output);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);

    (void)memset_s(buff->x + buff->len - 20, 16, 0, 16); // modify the ciphertext, 16 and 20 are random number.
    ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen,
        &output);
    ASSERT_EQ(ret, CRYPT_EAL_CIPHER_DATA_ERROR);
EXIT:
    return;
}
/* END_CASE */

/**
 * For test parse p7-encryptData of right conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_ENCRYPTEDDATA_TC002(Hex *buff)
{
    BSL_Buffer output = {0};
    char *pwd = "123456";
    uint32_t pwdlen = strlen(pwd);
    int32_t ret =  CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, (BSL_Buffer *)buff, (const uint8_t *)pwd, pwdlen,
        &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
EXIT:
    BSL_SAL_Free(output.data);
    return;
}
/* END_CASE */

/**
 * For test parse p7-DigestInfo of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_DIGESTINFO_TC001(Hex *buff, int alg, Hex *digest)
{
    BSL_Buffer output = {0};
    BslCid cid = BSL_CID_UNKNOWN;
    int32_t ret = HITLS_CMS_ParseDigestInfo(NULL, &cid, &output);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);

    ret = HITLS_CMS_ParseDigestInfo((BSL_Buffer *)buff, &cid, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);

    ret = HITLS_CMS_ParseDigestInfo((BSL_Buffer *)buff, &cid, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);

    ASSERT_EQ(alg, cid);
    ASSERT_EQ(memcmp(output.data, digest->x, digest->len), 0);
EXIT:
    BSL_SAL_Free(output.data);
    return;
}
/* END_CASE */

/**
 * For test parse p7-DigestInfo of right conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_DIGESTINFO_TC002(Hex *buff, int alg, Hex *digest)
{
    BSL_Buffer output = {0};
    BslCid cid = BSL_CID_UNKNOWN;
    int32_t ret =  HITLS_CMS_ParseDigestInfo((BSL_Buffer *)buff, &cid, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(alg, cid);
    ASSERT_EQ(memcmp(output.data, digest->x, digest->len), 0);
EXIT:
    BSL_SAL_Free(output.data);
    return;
}
/* END_CASE */

/**
 * For test encode p7-encryptData.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_ENCRYPTEDDATA_TC001(Hex *buff)
{
    BSL_Buffer data = {buff->x, buff->len};
    BSL_Buffer output = {0};
    BSL_Buffer verify = {0};
    char *pwd = "123456";
    CRYPT_Pbkdf2Param param = {0};
    param.pbesId = BSL_CID_PBES2;
    param.pbkdfId = BSL_CID_PBKDF2;
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    param.symId = CRYPT_CIPHER_AES256_CBC;
    param.pwd = (uint8_t *)pwd;
    param.pwdLen = strlen(pwd);
    param.saltLen = 16;
    param.itCnt = 2048;
    CRYPT_EncodeParam paramEx = {CRYPT_DERIVE_PBKDF2, &param};

    ASSERT_EQ(TestRandInit(), HITLS_PKI_SUCCESS);
    int32_t ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, NULL, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, NULL, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);
    ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, &paramEx, NULL);
    ASSERT_EQ(ret, CRYPT_NULL_INPUT);

    param.hmacId = CRYPT_MAC_MAX;
    ret =  CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, &paramEx, &output);
    ASSERT_EQ(ret, CRYPT_ERR_ALGID);
    param.hmacId = CRYPT_MAC_HMAC_SHA256;
    ret = CRYPT_EAL_EncodePKCS7EncryptDataBuff(NULL, NULL, &data, &paramEx, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = CRYPT_EAL_ParseAsn1PKCS7EncryptedData(NULL, NULL, &output, (const uint8_t *)pwd, strlen(pwd), &verify);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_COMPARE("encode p7-encryptData", data.data, data.dataLen, verify.data, verify.dataLen);
EXIT:
    TestRandDeInit();
    BSL_SAL_FREE(verify.data);
    BSL_SAL_FREE(output.data);
    return;
}
/* END_CASE */

/**
 * For test encode p7-DigestInfo.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_DIGESTINFO_TC001()
{
    BSL_Buffer input = {0};
    BSL_Buffer output = {0};
    BslCid cid = 0;
    BSL_Buffer digest = {0};
    int32_t ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, NULL, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    input.dataLen = 1;
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, &output);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    input.dataLen = 0;
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_ParseDigestInfo(&output, &cid, &digest);
    ASSERT_EQ(ret, HITLS_CMS_ERR_INVALID_DATA);
    BSL_SAL_FREE(output.data);
    input.data = (uint8_t *)"123456";
    input.dataLen = 6;
    ret = HITLS_CMS_EncodeDigestInfoBuff(BSL_CID_MD5, &input, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_ParseDigestInfo(&output, &cid, &digest);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(cid, BSL_CID_MD5);
EXIT:
    BSL_SAL_FREE(digest.data);
    BSL_SAL_FREE(output.data);
    return;
}
/* END_CASE */

/**
 * For test encode p7-DigestInfo vector.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_DIGESTINFO_TC002(int algid, Hex *in)
{
    BSL_Buffer input = {in->x, in->len};
    BSL_Buffer output = {0};
    BslCid cid = 0;
    BSL_Buffer digest = {0};
    int32_t ret = HITLS_CMS_EncodeDigestInfoBuff(algid, &input, &output);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ret = HITLS_CMS_ParseDigestInfo(&output, &cid, &digest);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(cid, algid);
EXIT:
    BSL_SAL_FREE(digest.data);
    BSL_SAL_FREE(output.data);
    return;
}
/* END_CASE */

/**
 * For test parse SignedData of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_SIGNEDDATA_TC001()
{
    HITLS_CMS_SignedData signedData = {0};
    BSL_Buffer encode = {0};
    
    int32_t ret = HITLS_CMS_ParseSignedData(NULL, &signedData);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
    ret = HITLS_CMS_ParseSignedData(&encode, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
EXIT:
    HITLS_CMS_FreeSignedData(&signedData);
    return;
}
/* END_CASE */

/**
 * For test encode SignedData of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_SIGNEDDATA_TC001()
{
    HITLS_CMS_SignedData signedData = {0};
    BSL_Buffer encode = {0};
    
    int32_t ret = HITLS_CMS_EncodeSignedData(NULL, &encode);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
    ret = HITLS_CMS_EncodeSignedData(&signedData, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
    encode.data = (uint8_t *)"test";
    ret = HITLS_CMS_EncodeSignedData(&signedData, &encode);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
EXIT:
    encode.data = NULL;
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_FreeSignedData(&signedData);
    return;
}
/* END_CASE */

/**
 * For test encode and parse SignedData round trip.
*/
/* BEGIN_CASE */
void SDV_CMS_SIGNEDDATA_ROUNDTRIP_TC001()
{
    HITLS_CMS_SignedData originalData = {0};
    HITLS_CMS_SignedData parsedData = {0};
    BSL_Buffer encode = {0};
    
    originalData.version = 1;
    
    uint8_t digestAlgs[] = {0x31, 0x00};
    originalData.digestAlgorithms.data = BSL_SAL_Dump(digestAlgs, sizeof(digestAlgs));
    originalData.digestAlgorithms.dataLen = sizeof(digestAlgs);
    ASSERT_NE(originalData.digestAlgorithms.data, NULL);
    
    uint8_t signerInfos[] = {0x31, 0x00};
    originalData.signerInfos.data = BSL_SAL_Dump(signerInfos, sizeof(signerInfos));
    originalData.signerInfos.dataLen = sizeof(signerInfos);
    ASSERT_NE(originalData.signerInfos.data, NULL);
    
    int32_t ret = HITLS_CMS_EncodeSignedData(&originalData, &encode);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(encode.data, NULL);
    ASSERT_GT(encode.dataLen, 0);
    
    ret = HITLS_CMS_ParseSignedData(&encode, &parsedData);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedData.version, originalData.version);
    
EXIT:
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_FreeSignedData(&originalData);
    HITLS_CMS_FreeSignedData(&parsedData);
    return;
}
/* END_CASE */

/**
 * For test parse EnvelopedData of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_PARSE_ENVELOPEDDATA_TC001()
{
    HITLS_CMS_EnvelopedData envelopedData = {0};
    BSL_Buffer encode = {0};
    
    int32_t ret = HITLS_CMS_ParseEnvelopedData(NULL, &envelopedData);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
    ret = HITLS_CMS_ParseEnvelopedData(&encode, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
EXIT:
    HITLS_CMS_FreeEnvelopedData(&envelopedData);
    return;
}
/* END_CASE */

/**
 * For test encode EnvelopedData of wrong conditions.
*/
/* BEGIN_CASE */
void SDV_CMS_ENCODE_ENVELOPEDDATA_TC001()
{
    HITLS_CMS_EnvelopedData envelopedData = {0};
    BSL_Buffer encode = {0};
    
    int32_t ret = HITLS_CMS_EncodeEnvelopedData(NULL, &encode);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
    ret = HITLS_CMS_EncodeEnvelopedData(&envelopedData, NULL);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
    encode.data = (uint8_t *)"test";
    ret = HITLS_CMS_EncodeEnvelopedData(&envelopedData, &encode);
    ASSERT_EQ(ret, HITLS_CMS_ERR_NULL_POINTER);
    
    encode.data = NULL;
    envelopedData.contentEncryptionAlg = BSL_CID_UNKNOWN;
    ret = HITLS_CMS_EncodeEnvelopedData(&envelopedData, &encode);
    ASSERT_EQ(ret, HITLS_CMS_ERR_INVALID_ALGO);
    
EXIT:
    encode.data = NULL;
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_FreeEnvelopedData(&envelopedData);
    return;
}
/* END_CASE */

/**
 * For test encode and parse EnvelopedData round trip.
*/
/* BEGIN_CASE */
void SDV_CMS_ENVELOPEDDATA_ROUNDTRIP_TC001()
{
    HITLS_CMS_EnvelopedData originalData = {0};
    HITLS_CMS_EnvelopedData parsedData = {0};
    BSL_Buffer encode = {0};
    
    originalData.version = 2;
    originalData.contentEncryptionAlg = BSL_CID_AES256_CBC;
    
    uint8_t recipientInfos[] = {0x31, 0x00};
    originalData.recipientInfos.data = BSL_SAL_Dump(recipientInfos, sizeof(recipientInfos));
    originalData.recipientInfos.dataLen = sizeof(recipientInfos);
    ASSERT_NE(originalData.recipientInfos.data, NULL);
    
    uint8_t encryptedContent[] = {0x01, 0x02, 0x03, 0x04};
    originalData.encryptedContent.data = BSL_SAL_Dump(encryptedContent, sizeof(encryptedContent));
    originalData.encryptedContent.dataLen = sizeof(encryptedContent);
    ASSERT_NE(originalData.encryptedContent.data, NULL);
    
    int32_t ret = HITLS_CMS_EncodeEnvelopedData(&originalData, &encode);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_NE(encode.data, NULL);
    ASSERT_GT(encode.dataLen, 0);
    
    ret = HITLS_CMS_ParseEnvelopedData(&encode, &parsedData);
    ASSERT_EQ(ret, HITLS_PKI_SUCCESS);
    ASSERT_EQ(parsedData.version, originalData.version);
    ASSERT_EQ(parsedData.contentEncryptionAlg, originalData.contentEncryptionAlg);
    
EXIT:
    BSL_SAL_FREE(encode.data);
    HITLS_CMS_FreeEnvelopedData(&originalData);
    HITLS_CMS_FreeEnvelopedData(&parsedData);
    return;
}
/* END_CASE */

/**
 * For test SignedData free function.
*/
/* BEGIN_CASE */
void SDV_CMS_FREE_SIGNEDDATA_TC001()
{
    HITLS_CMS_SignedData signedData = {0};
    
    uint8_t testData[] = {0x01, 0x02, 0x03};
    signedData.digestAlgorithms.data = BSL_SAL_Dump(testData, sizeof(testData));
    signedData.digestAlgorithms.dataLen = sizeof(testData);
    signedData.contentType.data = BSL_SAL_Dump(testData, sizeof(testData));
    signedData.contentType.dataLen = sizeof(testData);
    signedData.content.data = BSL_SAL_Dump(testData, sizeof(testData));
    signedData.content.dataLen = sizeof(testData);
    signedData.signerInfos.data = BSL_SAL_Dump(testData, sizeof(testData));
    signedData.signerInfos.dataLen = sizeof(testData);
    
    HITLS_CMS_FreeSignedData(&signedData);
    
    ASSERT_EQ(signedData.digestAlgorithms.data, NULL);
    ASSERT_EQ(signedData.digestAlgorithms.dataLen, 0);
    ASSERT_EQ(signedData.contentType.data, NULL);
    ASSERT_EQ(signedData.contentType.dataLen, 0);
    ASSERT_EQ(signedData.content.data, NULL);
    ASSERT_EQ(signedData.content.dataLen, 0);
    ASSERT_EQ(signedData.signerInfos.data, NULL);
    ASSERT_EQ(signedData.signerInfos.dataLen, 0);
    
    HITLS_CMS_FreeSignedData(NULL);
    
EXIT:
    return;
}
/* END_CASE */

/**
 * For test EnvelopedData free function.
*/
/* BEGIN_CASE */
void SDV_CMS_FREE_ENVELOPEDDATA_TC001()
{
    HITLS_CMS_EnvelopedData envelopedData = {0};
    
    uint8_t testData[] = {0x01, 0x02, 0x03};
    envelopedData.originatorInfo.data = BSL_SAL_Dump(testData, sizeof(testData));
    envelopedData.originatorInfo.dataLen = sizeof(testData);
    envelopedData.recipientInfos.data = BSL_SAL_Dump(testData, sizeof(testData));
    envelopedData.recipientInfos.dataLen = sizeof(testData);
    envelopedData.contentType.data = BSL_SAL_Dump(testData, sizeof(testData));
    envelopedData.contentType.dataLen = sizeof(testData);
    envelopedData.contentEncryptionParams.data = BSL_SAL_Dump(testData, sizeof(testData));
    envelopedData.contentEncryptionParams.dataLen = sizeof(testData);
    envelopedData.encryptedContent.data = BSL_SAL_Dump(testData, sizeof(testData));
    envelopedData.encryptedContent.dataLen = sizeof(testData);
    
    HITLS_CMS_FreeEnvelopedData(&envelopedData);
    
    ASSERT_EQ(envelopedData.originatorInfo.data, NULL);
    ASSERT_EQ(envelopedData.originatorInfo.dataLen, 0);
    ASSERT_EQ(envelopedData.recipientInfos.data, NULL);
    ASSERT_EQ(envelopedData.recipientInfos.dataLen, 0);
    ASSERT_EQ(envelopedData.contentType.data, NULL);
    ASSERT_EQ(envelopedData.contentType.dataLen, 0);
    ASSERT_EQ(envelopedData.contentEncryptionParams.data, NULL);
    ASSERT_EQ(envelopedData.contentEncryptionParams.dataLen, 0);
    ASSERT_EQ(envelopedData.encryptedContent.data, NULL);
    ASSERT_EQ(envelopedData.encryptedContent.dataLen, 0);
    
    HITLS_CMS_FreeEnvelopedData(NULL);
    
EXIT:
    return;
}
/* END_CASE */
