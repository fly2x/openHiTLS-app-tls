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

#ifndef HITLS_CMS_LOCAL_H
#define HITLS_CMS_LOCAL_H

#include "hitls_build.h"
#ifdef HITLS_PKI_PKCS12
#include "bsl_types.h"
#include "bsl_obj.h"

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

typedef struct {
    int32_t version;
    BSL_Buffer digestAlgorithms;
    BSL_Buffer contentType;
    BSL_Buffer content;
    BSL_Buffer certificates;
    BSL_Buffer crls;
    BSL_Buffer signerInfos;
} HITLS_CMS_SignedData;

typedef struct {
    int32_t version;
    BSL_Buffer originatorInfo;
    BSL_Buffer recipientInfos;
    BSL_Buffer contentType;
    BslCid contentEncryptionAlg;
    BSL_Buffer contentEncryptionParams;
    BSL_Buffer encryptedContent;
    BSL_Buffer unprotectedAttrs;
} HITLS_CMS_EnvelopedData;

#ifdef HITLS_PKI_PKCS12_PARSE
// parse PKCS7-Data
int32_t HITLS_CMS_ParseAsn1Data(BSL_Buffer *encode, BSL_Buffer *dataValue);

// parse PKCS7-SignedData
int32_t HITLS_CMS_ParseSignedData(BSL_Buffer *encode, HITLS_CMS_SignedData *signedData);

// parse PKCS7-EnvelopedData
int32_t HITLS_CMS_ParseEnvelopedData(BSL_Buffer *encode, HITLS_CMS_EnvelopedData *envelopedData);
#endif

// parse PKCS7-DigestInfo：only support hash.
int32_t HITLS_CMS_ParseDigestInfo(BSL_Buffer *encode, BslCid *cid, BSL_Buffer *digest);

#ifdef HITLS_PKI_PKCS12_GEN
// encode PKCS7-DigestInfo：only support hash.
int32_t HITLS_CMS_EncodeDigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer *encode);

// encode PKCS7-SignedData
int32_t HITLS_CMS_EncodeSignedData(HITLS_CMS_SignedData *signedData, BSL_Buffer *encode);

// encode PKCS7-EnvelopedData
int32_t HITLS_CMS_EncodeEnvelopedData(HITLS_CMS_EnvelopedData *envelopedData, BSL_Buffer *encode);
#endif

// free HITLS_CMS_SignedData
void HITLS_CMS_FreeSignedData(HITLS_CMS_SignedData *signedData);

// free HITLS_CMS_EnvelopedData
void HITLS_CMS_FreeEnvelopedData(HITLS_CMS_EnvelopedData *envelopedData);

#ifdef __cplusplus
}
#endif

#endif // HITLS_PKI_PKCS12

#endif // HITLS_CMS_LOCAL_H
