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
#include "hitls_pki_pkcs12.h"
#include "hitls_pki_errno.h"
#include "bsl_types.h"
#include "bsl_log.h"
#include "sal_file.h"
#include "bsl_init.h"
#include "hitls_pkcs12_local.h"
#include "hitls_crl_local.h"
#include "hitls_cert_type.h"
#include "hitls_cert_local.h"
#include "bsl_types.h"
#include "crypt_errno.h"
#include "stub_replace.h"
#include "bsl_list_internal.h"
/* END_HEADER */

static int32_t SetCertBag(HITLS_PKCS12 *p12, HITLS_X509_Cert *cert)
{
    HITLS_PKCS12_Bag *certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, cert); // new a cert Bag
    ASSERT_NE(certBag, NULL);
    char *name = "I am a x509CertBag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_CERTBAG, certBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(certBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t SetEntityCertBag(HITLS_PKCS12 *p12, HITLS_X509_Cert *cert)
{
    HITLS_PKCS12_Bag *certBag = HITLS_PKCS12_BagNew(BSL_CID_CERTBAG, BSL_CID_X509CERTIFICATE, cert); // new a cert Bag
    ASSERT_NE(certBag, NULL);
    char *name = "I am a entity cert bag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(certBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_CERTBAG, certBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(certBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t SetEntityKeyBag(HITLS_PKCS12 *p12, CRYPT_EAL_PkeyCtx *cert)
{
    HITLS_PKCS12_Bag *pkeyBag = HITLS_PKCS12_BagNew(BSL_CID_PKCS8SHROUDEDKEYBAG, 0, cert); // new a cert Bag
    ASSERT_NE(pkeyBag, NULL);
    char *name = "I am a p8 encrypted bag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(pkeyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_SET_ENTITY_KEYBAG, pkeyBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(pkeyBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t NewAndSetKeyBag(HITLS_PKCS12 *p12, int algId)
{
    CRYPT_EAL_PkeyCtx *key = CRYPT_EAL_PkeyNewCtx(algId);
    ASSERT_NE(key, NULL);
    if (algId == BSL_CID_RSA) {
        CRYPT_EAL_PkeyPara para = {.id = CRYPT_PKEY_RSA};
        uint8_t e[] = {1, 0, 1};
        para.para.rsaPara.e = e;
        para.para.rsaPara.eLen = 3;
        para.para.rsaPara.bits = 1024;
        ASSERT_TRUE(CRYPT_EAL_PkeySetPara(key, &para) == CRYPT_SUCCESS);
    }
    ASSERT_EQ(CRYPT_EAL_PkeyGen(key), 0);
    HITLS_PKCS12_Bag *keyBag = HITLS_PKCS12_BagNew(BSL_CID_KEYBAG, 0, key); // new a key Bag
    ASSERT_NE(keyBag, NULL);
    char *name = "I am a keyBag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)name;
    buffer.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(keyBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_KEYBAG, keyBag, 0), 0);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(key);
    HITLS_PKCS12_BagFree(keyBag);
    return HITLS_PKI_SUCCESS;
}

static int32_t NewAndSetSecretBag(HITLS_PKCS12 *p12)
{
    char *secret = "this is the secret.";
    BSL_Buffer buffer = {0};
    buffer.data = (uint8_t *)secret;
    buffer.dataLen = strlen(secret);
    HITLS_PKCS12_Bag *secretBag = HITLS_PKCS12_BagNew(BSL_CID_SECRETBAG, BSL_CID_PKCS7_SIMPLEDATA, &buffer); // new a secret Bag
    ASSERT_NE(secretBag, NULL);
    char *name = "I am an attribute of secretBag";
    uint32_t nameLen = strlen(name);
    BSL_Buffer buffer2 = {0};
    buffer2.data = (uint8_t *)name;
    buffer2.dataLen = nameLen;
    ASSERT_EQ(HITLS_PKCS12_BagCtrl(secretBag, HITLS_PKCS12_BAG_ADD_ATTR, &buffer2, BSL_CID_FRIENDLYNAME), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_ADD_SECRETBAG, secretBag, 0), 0);
EXIT:
    HITLS_PKCS12_BagFree(secretBag);
    return HITLS_PKI_SUCCESS;
}

/**
 * For test generating a .p12 inlcuding keyBag, certBag, p8KeyBag and secretBag.
*/
/* BEGIN_CASE */
void SDV_PKCS12_GEN_KEYBAGS_TC001(char *pkeyPath, char *enCertPath, char *ca1CertPath, char *otherCertPath)
{
#ifndef HITLS_PKI_PKCS12_GEN
    (void)pkeyPath;
    (void)enCertPath;
    (void)ca1CertPath;
    (void)otherCertPath;
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA256, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
#ifdef HITLS_PKI_PKCS12_PARSE
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
#endif
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    HITLS_X509_Cert *enCert = NULL;
    HITLS_X509_Cert *ca1Cert = NULL;
    HITLS_X509_Cert *otherCert = NULL;
    int32_t mdId = CRYPT_MD_SHA1;
    BSL_Buffer output = {0};
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    HITLS_PKCS12 *p12_1 = NULL;
    BSL_ASN1_List *certList = NULL;
    BSL_ASN1_List *keyList = NULL;
    BSL_ASN1_List *secretBags = NULL;
    ASSERT_EQ(CRYPT_EAL_DecodeFileKey(BSL_FORMAT_ASN1, CRYPT_PRIKEY_PKCS8_UNENCRYPT, pkeyPath, NULL, 0, &pkey), 0);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, enCertPath, &enCert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, ca1CertPath, &ca1Cert), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_X509_CertParseFile(BSL_FORMAT_ASN1, otherCertPath, &otherCert), HITLS_PKI_SUCCESS);

    // Add the entity cert to p12.
    ASSERT_EQ(SetEntityCertBag(p12, enCert), HITLS_PKI_SUCCESS);
    // Add the entity key to p12.
    ASSERT_EQ(SetEntityKeyBag(p12, pkey), HITLS_PKI_SUCCESS);
    // Add the ca cert to p12.
    ASSERT_EQ(SetCertBag(p12, ca1Cert), HITLS_PKI_SUCCESS);
    // Add the other cert to p12.
    ASSERT_EQ(SetCertBag(p12, otherCert), HITLS_PKI_SUCCESS);
    // Gen and add key bag to p12.
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_RSA), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_ED25519), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetSecretBag(p12), HITLS_PKI_SUCCESS);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12, HITLS_PKCS12_GEN_LOCALKEYID, &mdId, sizeof(CRYPT_MD_AlgId)), 0);
    // Gen a p12.
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), 0);
    
#ifdef HITLS_PKI_PKCS12_PARSE
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, true), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_CERTBAGS, &certList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_KEYBAGS, &keyList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0), 0);
    ASSERT_EQ(BSL_LIST_COUNT(certList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(keyList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(secretBags), 1);
    ASSERT_NE(p12_1->entityCert, NULL);
    ASSERT_NE(p12_1->key, NULL);
#endif
    certList = NULL;
    keyList = NULL;
    secretBags = NULL;
    BSL_SAL_FREE(output.data);
    output.dataLen = 0;
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, false, &output), 0);
    HITLS_PKCS12_Free(p12_1);
    p12_1 = NULL;
#ifdef HITLS_PKI_PKCS12_PARSE
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, false), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_CERTBAGS, &certList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_KEYBAGS, &keyList, 0), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_SECRETBAGS, &secretBags, 0), 0);
    ASSERT_EQ(BSL_LIST_COUNT(certList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(keyList), 2);
    ASSERT_EQ(BSL_LIST_COUNT(secretBags), 1);
    ASSERT_NE(p12_1->entityCert, NULL);
    ASSERT_NE(p12_1->key, NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    HITLS_X509_CertFree(enCert);
    HITLS_X509_CertFree(ca1Cert);
    HITLS_X509_CertFree(otherCert);
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
#endif
}
/* END_CASE */

/**
 * For test ctrl of get key bags from p12.
*/
/* BEGIN_CASE */
void SDV_PKCS12_CTRL_GET_KEYBAGS_TC001(void)
{
#ifndef HITLS_PKI_PKCS12_GEN
    SKIP_TEST();
#else
    TestMemInit();
    ASSERT_EQ(TestRandInit(), 0);
    char *pwd = "123456";
    CRYPT_Pbkdf2Param pbParam = {BSL_CID_PBES2, BSL_CID_PBKDF2, CRYPT_MAC_HMAC_SHA256, CRYPT_CIPHER_AES256_CBC,
        16, (uint8_t *)pwd, strlen(pwd), 2048};
    CRYPT_EncodeParam encParam = {CRYPT_DERIVE_PBKDF2, &pbParam};
    HITLS_PKCS12_KdfParam macParam = {8, 2048, BSL_CID_SHA256, (uint8_t *)pwd, strlen(pwd)};
    HITLS_PKCS12_MacParam paramTest = {.para = &macParam, .algId = BSL_CID_PKCS12KDF};
    HITLS_PKCS12_EncodeParam encodeParam = {encParam, paramTest};
#ifdef HITLS_PKI_PKCS12_PARSE
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
#endif
    BSL_ASN1_List *keyList = NULL;
    BSL_Buffer output = {0};
    HITLS_PKCS12 *p12 = HITLS_PKCS12_New();
    ASSERT_NE(p12, NULL);
    HITLS_PKCS12 *p12_1 = NULL;
    HITLS_PKCS12_Bag *bag = NULL;
    uint8_t bufferValue[20] = {0}; // 20 bytes is enough for the attr value.
    uint32_t bufferValueLen = 20;
    int32_t id = 0;
    BSL_Buffer buffer = {.data = bufferValue, .dataLen = bufferValueLen};
    char *attrName = "I am a keyBag";
    CRYPT_EAL_PkeyCtx *key = NULL;
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_RSA), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetKeyBag(p12, BSL_CID_ED25519), HITLS_PKI_SUCCESS);
    ASSERT_EQ(NewAndSetSecretBag(p12), HITLS_PKI_SUCCESS);
    // Gen a p12.
    ASSERT_EQ(HITLS_PKCS12_GenBuff(BSL_FORMAT_ASN1, p12, &encodeParam, true, &output), 0);

#ifdef HITLS_PKI_PKCS12_PARSE
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &output, &pwdParam, &p12_1, true), 0);
    ASSERT_EQ(HITLS_PKCS12_Ctrl(p12_1, HITLS_PKCS12_GET_KEYBAGS, &keyList, 0), 0);
    ASSERT_EQ(BSL_LIST_COUNT(keyList), 2);
    ASSERT_NE(keyList, NULL);
    bag = BSL_LIST_GET_FIRST(keyList);
    while (bag != NULL) {
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_VALUE, &key, 0), 0);
        ASSERT_NE(key, NULL);
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_ID, &id, sizeof(int32_t)), 0);
        ASSERT_EQ(id, BSL_CID_KEYBAG);
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_ATTR, &buffer, BSL_CID_FRIENDLYNAME), 0);
        ASSERT_COMPARE("compare key bag attr", buffer.data, buffer.dataLen, attrName, strlen(attrName));
        ASSERT_EQ(HITLS_PKCS12_BagCtrl(bag, HITLS_PKCS12_BAG_GET_ATTR, &buffer, BSL_CID_LOCALKEYID),
            HITLS_PKCS12_ERR_NO_SAFEBAG_ATTRIBUTES);
        bag = BSL_LIST_GET_NEXT(keyList);
        CRYPT_EAL_PkeyFreeCtx(key);
        key = NULL;
    }
#endif
EXIT:
    HITLS_PKCS12_Free(p12);
    HITLS_PKCS12_Free(p12_1);
    BSL_SAL_Free(output.data);
#endif
}
/* END_CASE */

/**
 * For test parse multi bags in p12, including certBag, keyBag, secretBag, p8ShroudedKeyBag.
*/
/* BEGIN_CASE */
void SDV_PKCS12_PARSE_MULBAG_TC001(Hex *mulBag, int hasMac)
{
#ifndef HITLS_PKI_PKCS12_PARSE
    (void)mulBag;
    (void)hasMac;
    SKIP_TEST();
#else
    char *pwd = "123456";
    BSL_Buffer encPwd = {.data = (uint8_t *)pwd, .dataLen = strlen(pwd)};
    HITLS_PKCS12_PwdParam pwdParam = {.encPwd = &encPwd, .macPwd = &encPwd};
    HITLS_PKCS12 *p12 = NULL;
    BSL_Buffer buffer = {.data = (uint8_t *)mulBag->x, .dataLen = mulBag->len};
    ASSERT_EQ(HITLS_PKCS12_ParseBuff(BSL_FORMAT_ASN1, &buffer, &pwdParam, &p12, hasMac == 1), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->certList), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->keyList), 0);
    ASSERT_NE(BSL_LIST_COUNT(p12->secretBags), 0);
    ASSERT_NE(p12->key, NULL);
EXIT:
    HITLS_PKCS12_Free(p12);
#endif
}
/* END_CASE */
