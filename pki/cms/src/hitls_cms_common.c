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
#ifdef HITLS_PKI_PKCS12
#include "securec.h"
#include "bsl_err_internal.h"
#include "bsl_asn1.h"
#include "bsl_obj_internal.h"
#include "crypt_eal_codecs.h"
#include "crypt_eal_md.h"
#include "crypt_encode_decode_key.h"
#include "hitls_pki_errno.h"

#ifdef HITLS_PKI_PKCS12_PARSE
/**
 * Data Content Type
 * Data ::= OCTET STRING
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#section-4
 */
int32_t HITLS_CMS_ParseAsn1Data(BSL_Buffer *encode, BSL_Buffer *dataValue)
{
    if (encode == NULL || dataValue == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    uint8_t *temp = encode->data;
    uint32_t tempLen = encode->dataLen;
    uint32_t decodeLen = 0;
    uint8_t *data = NULL;
    int32_t ret = BSL_ASN1_DecodeTagLen(BSL_ASN1_TAG_OCTETSTRING, &temp, &tempLen, &decodeLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    if (decodeLen == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    data = BSL_SAL_Dump(temp, decodeLen);
    if (data == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    dataValue->data = data;
    dataValue->dataLen = decodeLen;
    return HITLS_PKI_SUCCESS;
}
#endif

/**
 * DigestInfo ::= SEQUENCE {
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      digest Digest
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc2315#section-9.4
 */

static BSL_ASN1_TemplateItem g_digestInfoTempl[] = {
    /* digestAlgorithm */
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_NULL, 0, 1},
    /* digest */
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
};

typedef enum {
    HITLS_P7_DIGESTINFO_OID_IDX,
    HITLS_P7_DIGESTINFO_ALGPARAM_IDX,
    HITLS_P7_DIGESTINFO_OCTSTRING_IDX,
    HITLS_P7_DIGESTINFO_MAX_IDX,
} HITLS_P7_DIGESTINFO_IDX;

int32_t HITLS_CMS_ParseDigestInfo(BSL_Buffer *encode, BslCid *cid, BSL_Buffer *digest)
{
    if (encode == NULL || encode->data == NULL || digest == NULL || cid == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    if (encode->dataLen == 0 || digest->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_X509_ERR_INVALID_PARAM);
        return HITLS_X509_ERR_INVALID_PARAM;
    }
    uint8_t *temp = encode->data;
    uint32_t  tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_P7_DIGESTINFO_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_digestInfoTempl, sizeof(g_digestInfoTempl) / sizeof(g_digestInfoTempl[0])};
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_P7_DIGESTINFO_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    BslOidString oidStr = {asn1[HITLS_P7_DIGESTINFO_OID_IDX].len, (char *)asn1[HITLS_P7_DIGESTINFO_OID_IDX].buff, 0};
    BslCid parseCid = BSL_OBJ_GetCID(&oidStr);
    if (parseCid == BSL_CID_UNKNOWN) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
        return HITLS_CMS_ERR_PARSE_TYPE;
    }
    if (asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len == 0) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_DATA);
        return HITLS_CMS_ERR_INVALID_DATA;
    }
    uint8_t *output = BSL_SAL_Dump(asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].buff,
        asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len);
    if (output == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
        return BSL_DUMP_FAIL;
    }
    digest->data = output;
    digest->dataLen = asn1[HITLS_P7_DIGESTINFO_OCTSTRING_IDX].len;
    *cid = parseCid;
    return HITLS_PKI_SUCCESS;
}

#ifdef HITLS_PKI_PKCS12_GEN
int32_t HITLS_CMS_EncodeDigestInfoBuff(BslCid cid, BSL_Buffer *in, BSL_Buffer *encode)
{
    if (in == NULL || encode == NULL || encode->data != NULL || (in->data == NULL && in->dataLen != 0)) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }

    BslOidString *oidstr = BSL_OBJ_GetOID(cid);
    if (oidstr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    BSL_ASN1_Buffer asn1[HITLS_P7_DIGESTINFO_MAX_IDX] = {
        {BSL_ASN1_TAG_OBJECT_ID, oidstr->octetLen, (uint8_t *)oidstr->octs},
        {BSL_ASN1_TAG_NULL, 0, NULL},
        {BSL_ASN1_TAG_OCTETSTRING, in->dataLen, in->data},
    };
    BSL_Buffer tmp = {0};
    BSL_ASN1_Template templ = {g_digestInfoTempl, sizeof(g_digestInfoTempl) / sizeof(g_digestInfoTempl[0])};
    int32_t ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_P7_DIGESTINFO_MAX_IDX, &tmp.data, &tmp.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    encode->data = tmp.data;
    encode->dataLen = tmp.dataLen;
    return HITLS_PKI_SUCCESS;
}
#endif
/**
 * SignerInfo ::= SEQUENCE {
 *      version CMSVersion,
 *      sid SignerIdentifier,
 *      digestAlgorithm DigestAlgorithmIdentifier,
 *      signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
 *      signatureAlgorithm SignatureAlgorithmIdentifier,
 *      signature SignatureValue,
 *      unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#section-5.3
 */

static BSL_ASN1_TemplateItem g_signerInfoTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_NULL, 0, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_NULL, 0, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 0, BSL_ASN1_FLAG_OPTIONAL, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_NULL, 0, 1},
    {BSL_ASN1_TAG_OCTETSTRING, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 1, BSL_ASN1_FLAG_OPTIONAL, 0},
};

typedef enum {
    HITLS_CMS_SIGNERINFO_VERSION_IDX,
    HITLS_CMS_SIGNERINFO_SID_IDX,
    HITLS_CMS_SIGNERINFO_DIGESTALG_OID_IDX,
    HITLS_CMS_SIGNERINFO_DIGESTALG_PARAM_IDX,
    HITLS_CMS_SIGNERINFO_SIGNALG_IDX,
    HITLS_CMS_SIGNERINFO_SIGNALG_OID_IDX,
    HITLS_CMS_SIGNERINFO_SIGNALG_PARAM_IDX,
    HITLS_CMS_SIGNERINFO_SIGNEDATTRS_IDX,
    HITLS_CMS_SIGNERINFO_SIGNATURE_IDX,
    HITLS_CMS_SIGNERINFO_UNSIGNEDATTRS_IDX,
    HITLS_CMS_SIGNERINFO_MAX_IDX,
} HITLS_CMS_SIGNERINFO_IDX;

/**
 * SignedData ::= SEQUENCE {
 *      version CMSVersion,
 *      digestAlgorithms DigestAlgorithmIdentifiers,
 *      encapContentInfo EncapsulatedContentInfo,
 *      certificates [0] IMPLICIT CertificateSet OPTIONAL,
 *      crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
 *      signerInfos SignerInfos
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#section-5.1
 */

static BSL_ASN1_TemplateItem g_signedDataTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 0, BSL_ASN1_FLAG_EXPLICIT, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 0, BSL_ASN1_FLAG_OPTIONAL, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 1, BSL_ASN1_FLAG_OPTIONAL, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0},
};

typedef enum {
    HITLS_CMS_SIGNEDDATA_VERSION_IDX,
    HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX,
    HITLS_CMS_SIGNEDDATA_ENCAPCONTENTINFO_IDX,
    HITLS_CMS_SIGNEDDATA_CONTENTTYPE_IDX,
    HITLS_CMS_SIGNEDDATA_CONTENT_IDX,
    HITLS_CMS_SIGNEDDATA_CERTS_IDX,
    HITLS_CMS_SIGNEDDATA_CRLS_IDX,
    HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX,
    HITLS_CMS_SIGNEDDATA_MAX_IDX,
} HITLS_CMS_SIGNEDDATA_IDX;

typedef struct {
    int32_t version;
    BSL_Buffer digestAlgorithms;
    BSL_Buffer contentType;
    BSL_Buffer content;
    BSL_Buffer certificates;
    BSL_Buffer crls;
    BSL_Buffer signerInfos;
} HITLS_CMS_SignedData;

#ifdef HITLS_PKI_PKCS12_PARSE
int32_t HITLS_CMS_ParseSignedData(BSL_Buffer *encode, HITLS_CMS_SignedData *signedData)
{
    if (encode == NULL || signedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    
    uint8_t *temp = encode->data;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_CMS_SIGNEDDATA_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_signedDataTempl, sizeof(g_signedDataTempl) / sizeof(g_signedDataTempl[0])};
    
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_CMS_SIGNEDDATA_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    if (asn1[HITLS_CMS_SIGNEDDATA_VERSION_IDX].len > 0) {
        uint32_t version = 0;
        ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_CMS_SIGNEDDATA_VERSION_IDX], &version);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        signedData->version = version;
    }
    
    if (asn1[HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX].len > 0) {
        signedData->digestAlgorithms.data = BSL_SAL_Dump(asn1[HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX].buff,
            asn1[HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX].len);
        if (signedData->digestAlgorithms.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        signedData->digestAlgorithms.dataLen = asn1[HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX].len;
    }
    
    if (asn1[HITLS_CMS_SIGNEDDATA_CONTENTTYPE_IDX].len > 0) {
        signedData->contentType.data = BSL_SAL_Dump(asn1[HITLS_CMS_SIGNEDDATA_CONTENTTYPE_IDX].buff,
            asn1[HITLS_CMS_SIGNEDDATA_CONTENTTYPE_IDX].len);
        if (signedData->contentType.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        signedData->contentType.dataLen = asn1[HITLS_CMS_SIGNEDDATA_CONTENTTYPE_IDX].len;
    }
    
    if (asn1[HITLS_CMS_SIGNEDDATA_CONTENT_IDX].len > 0) {
        signedData->content.data = BSL_SAL_Dump(asn1[HITLS_CMS_SIGNEDDATA_CONTENT_IDX].buff,
            asn1[HITLS_CMS_SIGNEDDATA_CONTENT_IDX].len);
        if (signedData->content.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        signedData->content.dataLen = asn1[HITLS_CMS_SIGNEDDATA_CONTENT_IDX].len;
    }
    
    if (asn1[HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX].len > 0) {
        signedData->signerInfos.data = BSL_SAL_Dump(asn1[HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX].buff,
            asn1[HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX].len);
        if (signedData->signerInfos.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        signedData->signerInfos.dataLen = asn1[HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX].len;
    }
    
    return HITLS_PKI_SUCCESS;
}
#endif

#ifdef HITLS_PKI_PKCS12_GEN
int32_t HITLS_CMS_EncodeSignedData(HITLS_CMS_SignedData *signedData, BSL_Buffer *encode)
{
    if (signedData == NULL || encode == NULL || encode->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    
    BSL_ASN1_Buffer asn1[HITLS_CMS_SIGNEDDATA_MAX_IDX] = {0};
    
    uint8_t version[4] = {0};
    uint32_t versionLen = 0;
    int32_t ret = BSL_ASN1_EncodePrimitiveItem(BSL_ASN1_TAG_INTEGER, &signedData->version, version, sizeof(version),
        &versionLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn1[HITLS_CMS_SIGNEDDATA_VERSION_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_INTEGER, versionLen, version};
    
    asn1[HITLS_CMS_SIGNEDDATA_DIGESTALGS_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        signedData->digestAlgorithms.dataLen, signedData->digestAlgorithms.data};
    
    if (signedData->contentType.dataLen > 0) {
        asn1[HITLS_CMS_SIGNEDDATA_CONTENTTYPE_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_OBJECT_ID,
            signedData->contentType.dataLen, signedData->contentType.data};
    }
    
    if (signedData->content.dataLen > 0) {
        asn1[HITLS_CMS_SIGNEDDATA_CONTENT_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 0,
            signedData->content.dataLen, signedData->content.data};
    }
    
    asn1[HITLS_CMS_SIGNEDDATA_SIGNERINFOS_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        signedData->signerInfos.dataLen, signedData->signerInfos.data};
    
    BSL_Buffer tmp = {0};
    BSL_ASN1_Template templ = {g_signedDataTempl, sizeof(g_signedDataTempl) / sizeof(g_signedDataTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_CMS_SIGNEDDATA_MAX_IDX, &tmp.data, &tmp.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    encode->data = tmp.data;
    encode->dataLen = tmp.dataLen;
    return HITLS_PKI_SUCCESS;
}
#endif

/**
 * EnvelopedData ::= SEQUENCE {
 *      version CMSVersion,
 *      originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
 *      recipientInfos RecipientInfos,
 *      encryptedContentInfo EncryptedContentInfo,
 *      unprotectedAttrs [1] IMPLICIT UnprotectedAttributes OPTIONAL
 * }
 *
 * https://datatracker.ietf.org/doc/html/rfc5652#section-6.1
 */

static BSL_ASN1_TemplateItem g_envelopedDataTempl[] = {
    {BSL_ASN1_TAG_INTEGER, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 0, BSL_ASN1_FLAG_OPTIONAL, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET, 0, 0},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 0},
        {BSL_ASN1_TAG_OBJECT_ID, 0, 1},
        {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SEQUENCE, 0, 1},
            {BSL_ASN1_TAG_OBJECT_ID, 0, 2},
            {BSL_ASN1_TAG_OCTETSTRING, 0, 2},
        {BSL_ASN1_TAG_CONTEXT_SPECIFIC | 0, BSL_ASN1_FLAG_OPTIONAL, 1},
    {BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_CONTEXT_SPECIFIC | 1, BSL_ASN1_FLAG_OPTIONAL, 0},
};

typedef enum {
    HITLS_CMS_ENVELOPEDDATA_VERSION_IDX,
    HITLS_CMS_ENVELOPEDDATA_ORIGINATORINFO_IDX,
    HITLS_CMS_ENVELOPEDDATA_RECIPIENTINFOS_IDX,
    HITLS_CMS_ENVELOPEDDATA_ENCRYPTEDCONTENTINFO_IDX,
    HITLS_CMS_ENVELOPEDDATA_CONTENTTYPE_IDX,
    HITLS_CMS_ENVELOPEDDATA_CONTENTALG_IDX,
    HITLS_CMS_ENVELOPEDDATA_CONTENTALG_OID_IDX,
    HITLS_CMS_ENVELOPEDDATA_CONTENTALG_PARAM_IDX,
    HITLS_CMS_ENVELOPEDDATA_ENCRYPTEDCONTENT_IDX,
    HITLS_CMS_ENVELOPEDDATA_UNPROTECTEDATTRS_IDX,
    HITLS_CMS_ENVELOPEDDATA_MAX_IDX,
} HITLS_CMS_ENVELOPEDDATA_IDX;

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
int32_t HITLS_CMS_ParseEnvelopedData(BSL_Buffer *encode, HITLS_CMS_EnvelopedData *envelopedData)
{
    if (encode == NULL || envelopedData == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    
    uint8_t *temp = encode->data;
    uint32_t tempLen = encode->dataLen;
    BSL_ASN1_Buffer asn1[HITLS_CMS_ENVELOPEDDATA_MAX_IDX] = {0};
    BSL_ASN1_Template templ = {g_envelopedDataTempl, sizeof(g_envelopedDataTempl) / sizeof(g_envelopedDataTempl[0])};
    
    int32_t ret = BSL_ASN1_DecodeTemplate(&templ, NULL, &temp, &tempLen, asn1, HITLS_CMS_ENVELOPEDDATA_MAX_IDX);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    if (asn1[HITLS_CMS_ENVELOPEDDATA_VERSION_IDX].len > 0) {
        uint32_t version = 0;
        ret = BSL_ASN1_DecodePrimitiveItem(&asn1[HITLS_CMS_ENVELOPEDDATA_VERSION_IDX], &version);
        if (ret != BSL_SUCCESS) {
            BSL_ERR_PUSH_ERROR(ret);
            return ret;
        }
        envelopedData->version = version;
    }
    
    if (asn1[HITLS_CMS_ENVELOPEDDATA_RECIPIENTINFOS_IDX].len > 0) {
        envelopedData->recipientInfos.data = BSL_SAL_Dump(asn1[HITLS_CMS_ENVELOPEDDATA_RECIPIENTINFOS_IDX].buff,
            asn1[HITLS_CMS_ENVELOPEDDATA_RECIPIENTINFOS_IDX].len);
        if (envelopedData->recipientInfos.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        envelopedData->recipientInfos.dataLen = asn1[HITLS_CMS_ENVELOPEDDATA_RECIPIENTINFOS_IDX].len;
    }
    
    if (asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTTYPE_IDX].len > 0) {
        envelopedData->contentType.data = BSL_SAL_Dump(asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTTYPE_IDX].buff,
            asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTTYPE_IDX].len);
        if (envelopedData->contentType.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        envelopedData->contentType.dataLen = asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTTYPE_IDX].len;
    }
    
    if (asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_OID_IDX].len > 0) {
        BslOidString oidStr = {asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_OID_IDX].len,
            (char *)asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_OID_IDX].buff, 0};
        envelopedData->contentEncryptionAlg = BSL_OBJ_GetCID(&oidStr);
        if (envelopedData->contentEncryptionAlg == BSL_CID_UNKNOWN) {
            BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_PARSE_TYPE);
            return HITLS_CMS_ERR_PARSE_TYPE;
        }
    }
    
    if (asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_PARAM_IDX].len > 0) {
        envelopedData->contentEncryptionParams.data = BSL_SAL_Dump(asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_PARAM_IDX].buff,
            asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_PARAM_IDX].len);
        if (envelopedData->contentEncryptionParams.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        envelopedData->contentEncryptionParams.dataLen = asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_PARAM_IDX].len;
    }
    
    if (asn1[HITLS_CMS_ENVELOPEDDATA_ENCRYPTEDCONTENT_IDX].len > 0) {
        envelopedData->encryptedContent.data = BSL_SAL_Dump(asn1[HITLS_CMS_ENVELOPEDDATA_ENCRYPTEDCONTENT_IDX].buff,
            asn1[HITLS_CMS_ENVELOPEDDATA_ENCRYPTEDCONTENT_IDX].len);
        if (envelopedData->encryptedContent.data == NULL) {
            BSL_ERR_PUSH_ERROR(BSL_DUMP_FAIL);
            return BSL_DUMP_FAIL;
        }
        envelopedData->encryptedContent.dataLen = asn1[HITLS_CMS_ENVELOPEDDATA_ENCRYPTEDCONTENT_IDX].len;
    }
    
    return HITLS_PKI_SUCCESS;
}
#endif

#ifdef HITLS_PKI_PKCS12_GEN
int32_t HITLS_CMS_EncodeEnvelopedData(HITLS_CMS_EnvelopedData *envelopedData, BSL_Buffer *encode)
{
    if (envelopedData == NULL || encode == NULL || encode->data != NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_NULL_POINTER);
        return HITLS_CMS_ERR_NULL_POINTER;
    }
    
    BslOidString *oidstr = BSL_OBJ_GetOID(envelopedData->contentEncryptionAlg);
    if (oidstr == NULL) {
        BSL_ERR_PUSH_ERROR(HITLS_CMS_ERR_INVALID_ALGO);
        return HITLS_CMS_ERR_INVALID_ALGO;
    }
    
    BSL_ASN1_Buffer asn1[HITLS_CMS_ENVELOPEDDATA_MAX_IDX] = {0};
    
    uint8_t version[4] = {0};
    uint32_t versionLen = 0;
    int32_t ret = BSL_ASN1_EncodePrimitiveItem(BSL_ASN1_TAG_INTEGER, &envelopedData->version, version, sizeof(version),
        &versionLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    asn1[HITLS_CMS_ENVELOPEDDATA_VERSION_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_INTEGER, versionLen, version};
    
    asn1[HITLS_CMS_ENVELOPEDDATA_RECIPIENTINFOS_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_CONSTRUCTED | BSL_ASN1_TAG_SET,
        envelopedData->recipientInfos.dataLen, envelopedData->recipientInfos.data};
    
    if (envelopedData->contentType.dataLen > 0) {
        asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTTYPE_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_OBJECT_ID,
            envelopedData->contentType.dataLen, envelopedData->contentType.data};
    }
    
    asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_OID_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_OBJECT_ID,
        oidstr->octetLen, (uint8_t *)oidstr->octs};
    
    if (envelopedData->contentEncryptionParams.dataLen > 0) {
        asn1[HITLS_CMS_ENVELOPEDDATA_CONTENTALG_PARAM_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_OCTETSTRING,
            envelopedData->contentEncryptionParams.dataLen, envelopedData->contentEncryptionParams.data};
    }
    
    if (envelopedData->encryptedContent.dataLen > 0) {
        asn1[HITLS_CMS_ENVELOPEDDATA_ENCRYPTEDCONTENT_IDX] = (BSL_ASN1_Buffer){BSL_ASN1_TAG_CONTEXT_SPECIFIC | 0,
            envelopedData->encryptedContent.dataLen, envelopedData->encryptedContent.data};
    }
    
    BSL_Buffer tmp = {0};
    BSL_ASN1_Template templ = {g_envelopedDataTempl, sizeof(g_envelopedDataTempl) / sizeof(g_envelopedDataTempl[0])};
    ret = BSL_ASN1_EncodeTemplate(&templ, asn1, HITLS_CMS_ENVELOPEDDATA_MAX_IDX, &tmp.data, &tmp.dataLen);
    if (ret != BSL_SUCCESS) {
        BSL_ERR_PUSH_ERROR(ret);
        return ret;
    }
    
    encode->data = tmp.data;
    encode->dataLen = tmp.dataLen;
    return HITLS_PKI_SUCCESS;
}
#endif

void HITLS_CMS_FreeSignedData(HITLS_CMS_SignedData *signedData)
{
    if (signedData == NULL) {
        return;
    }
    
    BSL_SAL_FREE(signedData->digestAlgorithms.data);
    BSL_SAL_FREE(signedData->contentType.data);
    BSL_SAL_FREE(signedData->content.data);
    BSL_SAL_FREE(signedData->certificates.data);
    BSL_SAL_FREE(signedData->crls.data);
    BSL_SAL_FREE(signedData->signerInfos.data);
    (void)memset_s(signedData, sizeof(HITLS_CMS_SignedData), 0, sizeof(HITLS_CMS_SignedData));
}

void HITLS_CMS_FreeEnvelopedData(HITLS_CMS_EnvelopedData *envelopedData)
{
    if (envelopedData == NULL) {
        return;
    }
    
    BSL_SAL_FREE(envelopedData->originatorInfo.data);
    BSL_SAL_FREE(envelopedData->recipientInfos.data);
    BSL_SAL_FREE(envelopedData->contentType.data);
    BSL_SAL_FREE(envelopedData->contentEncryptionParams.data);
    BSL_SAL_FREE(envelopedData->encryptedContent.data);
    BSL_SAL_FREE(envelopedData->unprotectedAttrs.data);
    (void)memset_s(envelopedData, sizeof(HITLS_CMS_EnvelopedData), 0, sizeof(HITLS_CMS_EnvelopedData));
}

#endif // HITLS_PKI_PKCS12
