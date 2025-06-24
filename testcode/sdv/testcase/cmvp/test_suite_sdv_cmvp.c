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

#ifdef HITLS_CRYPTO_CMVP

/* BEGIN_HEADER */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <sys/stat.h>
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "cmvp_common.h"
#include "crypt_cmvp.h"
#include "stub_replace.h"
#include "cmvp_iso19790.h"
#include "iso19790.h"
#include "cmvp_gmt.h"
#include "crypt_util_rand.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_md.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_entropy.h"
#include "securec.h"
#include "bsl_errno.h"
#include "crypt_params_key.h"
#include "crypt_hmac.h"

/* END_HEADER */

#define GOTO_EXIT_IF(condition) \
    do {                        \
        if (condition) {        \
            goto EXIT;          \
        }                       \
    } while (0)

#define MAX_OUTPUT 200

extern bool CMVP_Pct(CRYPT_EAL_PkeyCtx *pkey);
extern void CMVP_SetSelfTestFin(CRYPT_ALGO_TYPE type, int id, bool ret);
extern void CMVP_StatusSet(int32_t status);
extern void CMVP_DefaultEntryPoint(void);
extern void CMVP_DefaultExitPoint(void);
extern const char *GetIntegrityKey(void);

static void *StdMalloc(uint32_t len)
{
    return malloc((size_t)len);
}

static void RegNormalMem(void)
{
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC, StdMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE, free);
}

static void *STUB_Malloc(uint32_t size)
{
    (void)size;
    return NULL;
}

static char *Bin2Hex(const uint8_t *input, int length)
{
    const int perHexLen = 2;
    int rLen = length * perHexLen + 1;
    char *result = malloc(rLen);
    if (result == NULL) {
        return NULL;
    }
    (void)memset_s(result, rLen, 0, rLen);
    for (int i = 0; i < length; i++) {
        if (sprintf_s(result + perHexLen * i, rLen, "%02x", input[i]) <= 0) {
            free(result);
            return NULL;
        }
    }
    result[rLen - 1] = 0;
    return result;
}

#define HMAC_SHA256_SIZE 32

static int32_t CmvpHmacTest(const char *key, uint32_t id, uint8_t *buf, uint32_t bufLen, uint8_t *mac, uint32_t *macLen)
{
    CRYPT_HMAC_Ctx *hmacCtx = CRYPT_HMAC_NewCtx(id);
    if (hmacCtx == NULL) {
        return -1;
    }
    int32_t ret = CRYPT_HMAC_Init(hmacCtx, (uint8_t *)(uintptr_t)key, strlen(key), NULL);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_HMAC_FreeCtx(hmacCtx);
        return ret;
    }
    ret = CRYPT_HMAC_Update(hmacCtx, buf, bufLen);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_HMAC_FreeCtx(hmacCtx);
        return ret;
    }
    ret = CRYPT_HMAC_Final(hmacCtx, mac, macLen);
    CRYPT_HMAC_FreeCtx(hmacCtx);
    return ret;
}

static void CreatIntegrityFile(void)
{
    uint32_t bufLen;
    char *out = NULL;
    FILE *fp = NULL;
    uint8_t *buf = (uint8_t *)CMVP_ReadFile("test_suite_sdv_cmvp", "rb", &bufLen);
    ASSERT_TRUE(buf != NULL);
    uint32_t id;
    uint8_t mac[HMAC_SHA256_SIZE];
    uint32_t macLen = sizeof(mac);
#if (HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM)
    id = CRYPT_MAC_HMAC_SM3;
#else
    id = CRYPT_MAC_HMAC_SHA256;
#endif
    ASSERT_TRUE(CmvpHmacTest(GetIntegrityKey(), id, buf, bufLen, mac, &macLen) == CRYPT_SUCCESS);
    out = Bin2Hex(mac, HMAC_SHA256_SIZE);
    ASSERT_TRUE(out != NULL);
    fp = fopen("test_suite_sdv_cmvp.hmac", "w");
    ASSERT_TRUE(fp != NULL);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(fprintf(fp, "%s%s\n", "HMAC-SM3(test_suite_sdv_cmvp)= ", out) > 0);
#else
    ASSERT_TRUE(fprintf(fp, "%s%s\n", "HMAC-SHA256(test_suite_sdv_cmvp)= ", out) > 0);
#endif
    (void)fclose(fp);
EXIT:
    free(buf);
    free(out);
}

static int CreateFakeIntegrityFile(const char *key, uint32_t id)
{
    int ret = 1;
    uint32_t bufLen;
    char *out = NULL;
    FILE *fp = NULL;
    uint8_t *buf = (uint8_t *)CMVP_ReadFile("test_suite_sdv_cmvp", "rb", &bufLen);
    ASSERT_TRUE(buf != NULL);
    uint8_t mac[HMAC_SHA256_SIZE];
    uint32_t macLen = sizeof(mac);
    ASSERT_TRUE(CmvpHmacTest(key, id, buf, bufLen, mac, &macLen) == CRYPT_SUCCESS);
    out = Bin2Hex(mac, HMAC_SHA256_SIZE);
    ASSERT_TRUE(out != NULL);
    fp = fopen("test_suite_sdv_cmvp.hmac", "w");
    ASSERT_TRUE(fp != NULL);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(fprintf(fp, "%s%s\n", "HMAC-SM3(test_suite_sdv_cmvp)= ", out) > 0);
#else
    ASSERT_TRUE(fprintf(fp, "%s%s\n", "HMAC-SHA256(test_suite_sdv_cmvp)= ", out) > 0);
#endif
    (void)fclose(fp);
    ret = CRYPT_SUCCESS;
EXIT:
    free(buf);
    free(out);
    return ret;
}

static int FalsifyFile(const char *path)
{
    FILE *fp;
    char ch;
    int ret = 1;
    fp = fopen(path, "r+");
    ASSERT_TRUE(fp != NULL);
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fread(&ch, 1, 1, fp) != 0);
    ch++;
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fwrite(&ch, 1, 1, fp) != 0);  // 将文件最后一个字节修改
    (void)fclose(fp);
    ret = CRYPT_SUCCESS;
EXIT:
    return ret;
}

static int RecoverFile(const char *path)
{
    FILE *fp;
    char ch;
    int ret = 1;
    fp = fopen(path, "r+");
    ASSERT_TRUE(fp != NULL);
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fread(&ch, 1, 1, fp) != 0);
    ch--;
    ASSERT_TRUE(fseek(fp, -2, SEEK_END) == 0);
    ASSERT_TRUE(fwrite(&ch, 1, 1, fp) != 0);  // 将文件最后一个字节修改
    (void)fclose(fp);
    ret = CRYPT_SUCCESS;
EXIT:
    return ret;
}

static int CopyFile(const char *src_path)
{
    FILE *src_file, *dst_file;
    int ret = 1;
    char *dst_path="copy";
    char buffer[1024];
    size_t bytes_read;
    src_file = fopen(src_path, "rb");
    if (src_file == NULL) {
        return ret;
    }
    dst_file = fopen(dst_path, "wb");
    if (dst_file == NULL) {
        fclose(src_file);
        return ret;
    }
    while ((bytes_read = fread(buffer, 1, sizeof(buffer), src_file)) > 0) {
        fwrite(buffer, 1, bytes_read, dst_file);
    }
    fclose(src_file);
    fclose(dst_file);
    ret = CRYPT_SUCCESS;
    return ret;
}

static uint32_t g_randId[] = {
    CRYPT_RAND_SHA1,
    CRYPT_RAND_SHA224,
    CRYPT_RAND_SHA256,
    CRYPT_RAND_SHA384,
    CRYPT_RAND_SHA512,
    CRYPT_RAND_HMAC_SHA1,
    CRYPT_RAND_HMAC_SHA224,
    CRYPT_RAND_HMAC_SHA256,
    CRYPT_RAND_HMAC_SHA384,
    CRYPT_RAND_HMAC_SHA512,
    CRYPT_RAND_AES128_CTR,
    CRYPT_RAND_AES192_CTR,
    CRYPT_RAND_AES256_CTR,
    CRYPT_RAND_AES128_CTR_DF,
    CRYPT_RAND_AES192_CTR_DF,
    CRYPT_RAND_AES256_CTR_DF,
};

static uint32_t g_mdId[] = {
    CRYPT_MD_MD5,
    CRYPT_MD_SHA1,
    CRYPT_MD_SHA224,
    CRYPT_MD_SHA256,
    CRYPT_MD_SHA384,
    CRYPT_MD_SHA512,
    CRYPT_MD_SHA3_224,
    CRYPT_MD_SHA3_256,
    CRYPT_MD_SHA3_384,
    CRYPT_MD_SHA3_512,
    CRYPT_MD_SHAKE128,
    CRYPT_MD_SHAKE256,
    CRYPT_MD_SM3,
};

static uint32_t g_macId[] = {
    CRYPT_MAC_HMAC_MD5,
    CRYPT_MAC_HMAC_SHA1,
    CRYPT_MAC_HMAC_SHA224,
    CRYPT_MAC_HMAC_SHA256,
    CRYPT_MAC_HMAC_SHA384,
    CRYPT_MAC_HMAC_SHA512,
    CRYPT_MAC_HMAC_SM3,
    CRYPT_MAC_CMAC_AES128,
    CRYPT_MAC_CMAC_AES192,
    CRYPT_MAC_CMAC_AES256,
    CRYPT_MAC_GMAC_AES128,
    CRYPT_MAC_GMAC_AES192,
    CRYPT_MAC_GMAC_AES256,
};

static uint32_t g_pkeyId[] = {
    CRYPT_PKEY_DSA,
    CRYPT_PKEY_ED25519,
    CRYPT_PKEY_X25519,
    CRYPT_PKEY_RSA,
    CRYPT_PKEY_DH,
    CRYPT_PKEY_ECDSA,
    CRYPT_PKEY_ECDH,
    CRYPT_PKEY_SM2,
};
static uint32_t g_cipherId[] = {
    CRYPT_CIPHER_AES128_CBC,
    CRYPT_CIPHER_AES192_CBC,
    CRYPT_CIPHER_AES256_CBC,

    CRYPT_CIPHER_AES128_CTR,
    CRYPT_CIPHER_AES192_CTR,
    CRYPT_CIPHER_AES256_CTR,

    CRYPT_CIPHER_AES128_ECB,
    CRYPT_CIPHER_AES192_ECB,
    CRYPT_CIPHER_AES256_ECB,

    CRYPT_CIPHER_AES128_XTS,
    CRYPT_CIPHER_AES256_XTS,

    CRYPT_CIPHER_AES128_CCM,
    CRYPT_CIPHER_AES192_CCM,
    CRYPT_CIPHER_AES256_CCM,

    CRYPT_CIPHER_AES128_GCM,
    CRYPT_CIPHER_AES192_GCM,
    CRYPT_CIPHER_AES256_GCM,

    CRYPT_CIPHER_CHACHA20_POLY1305,

    CRYPT_CIPHER_SM4_XTS,
    CRYPT_CIPHER_SM4_CBC,
    CRYPT_CIPHER_SM4_ECB,
    CRYPT_CIPHER_SM4_CTR,
    CRYPT_CIPHER_SM4_GCM,
    CRYPT_CIPHER_SM4_CFB,
    CRYPT_CIPHER_SM4_OFB,

    CRYPT_CIPHER_AES128_CFB,
    CRYPT_CIPHER_AES192_CFB,
    CRYPT_CIPHER_AES256_CFB,
    CRYPT_CIPHER_AES128_OFB,
    CRYPT_CIPHER_AES192_OFB,
    CRYPT_CIPHER_AES256_OFB,
};
static uint32_t g_kdfId[] = {
    CRYPT_KDF_SCRYPT,
    CRYPT_KDF_PBKDF2,
    CRYPT_KDF_KDFTLS12,
    CRYPT_KDF_HKDF,
};

static void ResetStatus(void)
{
    CreatIntegrityFile(); // Generating an Integrity Verification File
    // Reset various states
    CMVP_ModeSet(CRYPT_CMVP_MODE_NONAPPROVED);
    CMVP_StatusSet(CRYPT_SUCCESS);
    CMVP_CspFlagSet(false);
    CRYPT_EAL_RegPct(NULL);
    CRYPT_EAL_RegEventReport(NULL);
    uint32_t i;
    for (i = 0; i < sizeof(g_cipherId) / sizeof(g_cipherId[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_CIPHER, (int32_t)g_cipherId[i], false);
    }
    for (i = 0; i < sizeof(g_pkeyId) / sizeof(g_pkeyId[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_PKEY, (int32_t)g_pkeyId[i], false);
    }
    for (i = 0; i < sizeof(g_mdId) / sizeof(g_mdId[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_MD, (int32_t)g_mdId[i], false);
    }
    for (i = 0; i < sizeof(g_macId) / sizeof(g_macId[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_MAC, (int32_t)g_macId[i], false);
    }
    for (i = 0; i < sizeof(g_kdfId) / sizeof(g_kdfId[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_KDF, (int32_t)g_kdfId[i], false);
    }
    for (i = 0; i < sizeof(g_randId) / sizeof(g_randId[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_RAND, (int32_t)g_randId[i], false);
    }
}

static void StartTest(void)
{
    CMVP_DefaultEntryPoint(); // Invoke the default interface.
    RegNormalMem();
    CRYPT_CMVP_MultiThreadEnable();
}

static void ResetStatusAndStartTest(void)
{
    ResetStatus();
    StartTest();
}

static void EndTest(void)
{
    CMVP_DefaultExitPoint();
}

static int GenPkey(CRYPT_EAL_PkeyCtx *pkey, int expRet)
{
    int i, ret;
    for (i = 0; i < 20; i++) { // 20 attempts to generate
        ret = CRYPT_EAL_PkeyGen(pkey);
        if (ret == expRet) {
            break;
        }
    }
    return ret;
}

static int SetParaAndGenPkey(CRYPT_EAL_PkeyCtx *pkey, CRYPT_EAL_PkeyPara *para, int expRet)
{
    int ret = CRYPT_EAL_PkeySetPara(pkey, para);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    return GenPkey(pkey, expRet);
}

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
static int CreatSm2Key(int expRet, Hex *e, int bits)
{
    (void)e;
    (void)bits;
    int ret; 
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    ret = GenPkey(pkey, expRet);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}
#endif

static int CreatRsaKey(int expRet, Hex *e, int bits)
{
    int ret;
    CRYPT_EAL_PkeyPara para;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = bits;
    para.para.rsaPara.e = e->x;
    para.para.rsaPara.eLen = e->len;
    ret = SetParaAndGenPkey(pkey, &para, expRet);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

static int STUB_PkeyVerify(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *data, uint32_t dataLen,
    const uint8_t *sign, uint32_t signLen)
{
    (void)pkey;
    (void)id;
    (void)data;
    (void)dataLen;
    (void)sign;
    (void)signLen;
    return CRYPT_NULL_INPUT;
}

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC002
* @spec  -
* @title  Integrity verification file error_Integrity verification file missing
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC002(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ResetStatus();
    ASSERT_TRUE(remove("test_suite_sdv_cmvp.hmac") == 0);
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    CMVP_ModeSet(CRYPT_CMVP_MODE_GM);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey == NULL);
#else
    CMVP_ModeSet(CRYPT_CMVP_MODE_ISO19790);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey == NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC003
* @spec  -
* @title  Integrity verification file error_Integrity verification file is falsified.
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC003(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ResetStatus();
    ASSERT_TRUE(FalsifyFile("test_suite_sdv_cmvp.hmac") == 0);
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    CMVP_ModeSet(CRYPT_CMVP_MODE_GM);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey == NULL);
#else
    CMVP_ModeSet(CRYPT_CMVP_MODE_ISO19790);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey == NULL);
#endif
EXIT:
    RecoverFile("test_suite_sdv_cmvp.hmac");
    CRYPT_EAL_PkeyFreeCtx(pkey);
    EndTest();
}

/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC004
* @spec  -
* @title  Integrity verification file error_Integrity verification file is generated with incorrect Mac key
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC004(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    const char fake_key[] = "a8fc4931453af3285f0f";
    ResetStatus();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CreateFakeIntegrityFile(fake_key, CRYPT_MAC_HMAC_SM3) == 0);
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
    CMVP_ModeSet(CRYPT_CMVP_MODE_GM);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey == NULL);
#else
    ASSERT_TRUE(CreateFakeIntegrityFile(fake_key, CRYPT_MAC_HMAC_SHA256) == 0);
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
    CMVP_ModeSet(CRYPT_CMVP_MODE_ISO19790);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey == NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC005
* @spec  -
* @title  Integrity verification file error_Integrity verification file is generated using an incorrect algorithm
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC005(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    const char key[] = "b8fc4931453af3285f0f";
    ResetStatus();
    ASSERT_TRUE(CreateFakeIntegrityFile(key, CRYPT_MAC_HMAC_SHA256) == 0);
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    CMVP_ModeSet(CRYPT_CMVP_MODE_GM);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey == NULL);
#else
    CMVP_ModeSet(CRYPT_CMVP_MODE_ISO19790);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey == NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC006
* @spec  -
* @title  Integrity verification file error_"test_suite_sdv_cmvp" file missing
* @precon  Prepare the test environment.
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_CMVP_ERR_INTEGRITY
2.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC006(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ResetStatus();
    ASSERT_TRUE(CopyFile("test_suite_sdv_cmvp") == 0);
    ASSERT_TRUE(remove("test_suite_sdv_cmvp") == 0);
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    CMVP_ModeSet(CRYPT_CMVP_MODE_GM);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey == NULL);
#else
    CMVP_ModeSet(CRYPT_CMVP_MODE_ISO19790);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey == NULL);
#endif
EXIT:
    ASSERT_TRUE(rename("copy", "test_suite_sdv_cmvp") == 0);
    ASSERT_TRUE(chmod("test_suite_sdv_cmvp", S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH) == 0);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_STATUS_TC001
* @spec  -
* @title  Key Pairing Test Failure Event Occurs_20220523170436207
* @precon  nan
* @brief
1.Register the default failed key pairing test callback. Expected result 1 is obtained.
2.Use CRYPT_EAL_PkeyNewCtx to create a context. Expected result 2 is obtained.
3.Run the CRYPT_EAL_PkeySetPara command to set parameters. Expected result 3 is obtained.
4.Use CRYPT_EAL_PkeyGen to generate a key pair. Expected result 4 is obtained.
5.Obtain the current status. Expected result 5 is obtained.
6.Create an asymmetric context. Expected result 6 is obtained.
* @expect
1.none
2.not NULL
3.return CRYPT_SUCCESS
4.return CRYPT_EAL_ERR_PAIRWISETEST
5.return CRYPT_EAL_ERR_PAIRWISETEST
6.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_STATUS_TC001(int mode, Hex *e, int bits)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CMVP_MODE_GM) {
        goto EXIT;
    }
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SM4_CTR_DF, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(CreatSm2Key(CRYPT_SUCCESS, e, bits) == CRYPT_SUCCESS);

    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify);
    ASSERT_TRUE(CreatSm2Key(CRYPT_CMVP_ERR_PAIRWISETEST, e, bits) == CRYPT_CMVP_ERR_PAIRWISETEST);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_PAIRWISETEST);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey == NULL);
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CreatRsaKey(CRYPT_SUCCESS, e, bits) == CRYPT_SUCCESS);

    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify);
    ASSERT_TRUE(CreatRsaKey(CRYPT_CMVP_ERR_PAIRWISETEST, e, bits) == CRYPT_CMVP_ERR_PAIRWISETEST);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_PAIRWISETEST);

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey == NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int STUB_MdInit(CRYPT_EAL_MdCTX *ctx)
{
    (void)ctx;
    return CRYPT_NULL_INPUT;
}

/* @
* @test  SDV_CRYPTO_CMVP_INTEGRITY_TC001
* @spec  -
* @title  Integrity verification file is correct_Integrity verification file
* @precon  nan
* @brief
1.CRYPT_CMVP_StatusGet Obtain the error code. Expected result 1 is obtained.
2.Create an asymmetric context. Expected result 2 is obtained.
* @expect
1.return CRYPT_SUCCESS
2.return no NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_INTEGRITY_TC001(void)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_SUCCESS);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey != NULL);
#else
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_STATUS_TC002
* @spec  -
* @title  Algorithm self-check failure event, whether key errors occur
* @precon  nan
* @brief
1.Use CRYPT_EAL_MdNewCtx to create a CRYPT_MD_SHA256 context and stub the EAL hash interface to make it fail.
  Expected result 1 is obtained.
2.Obtain the current status. Expected result 2 is obtained.
3.Create an asymmetric context. Expected result 3 is obtained.
* @expect
1.return NULL
2.return CRYPT_CMVP_ERR_ALGO_SELFTEST
3.return NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_STATUS_TC002(int mode)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if(mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

    STUB_Replace(&tmpStubInfo, CRYPT_EAL_MdInit, STUB_MdInit);
    ASSERT_TRUE(CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3) == NULL);
    STUB_Reset(&tmpStubInfo);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_ALGO_SELFTEST);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey == NULL);
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

    STUB_Replace(&tmpStubInfo, CRYPT_EAL_MdInit, STUB_MdInit);
    ASSERT_TRUE(CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256) == NULL);
    STUB_Reset(&tmpStubInfo);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_ALGO_SELFTEST);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey == NULL);
#endif
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_STATUS_TC003
* @spec  -
* @title  An integrity verification failure event has occurred, whether a critical error has occurred
* @precon  nan
* @brief
1.Modify the integrity verification file and start the module. Expected result 1 is obtained.
2.Obtain the current status. Expected result 2 is obtained.
* @expect
1.none
2.reurn CRYPT_CMVP_ERR_INTEGRITY
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_STATUS_TC003(void)
{
    ResetStatus();
    ASSERT_TRUE(remove("test_suite_sdv_cmvp.hmac") == 0);
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_STATUS_TC004
* @spec  -
* @title  No Critical Error Occurs
* @precon  nan
* @brief
1.Obtain the current status. Expected result 1 is obtained.
* @expect
1.return CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_STATUS_TC004(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_SUCCESS);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC001
* @spec  -
* @title  MAC Algorithm self-check, Algorithm id
* @precon  nan
* @brief
1.Register Memory Management
2.Transfer CRYPT_MAC_HMAC_SHA1 to perform algorithm self-check. Expected result 2 is obtained.
3.Transfer CRYPT_MAC_HMAC_SHA224 to perform algorithm self-check. Expected result 3 is obtained.
4.Transfer CRYPT_MAC_HMAC_SHA256 to perform algorithm self-check. Expected result 4 is obtained.
5.Transfer CRYPT_MAC_HMAC_SHA384 to perform algorithm self-check. Expected result 5 is obtained.
6.Transfer CRYPT_MAC_HMAC_SHA512 to perform algorithm self-check. Expected result 6 is obtained.
7.Transfer CRYPT_MAC_MAX to perform algorithm self-check. Expected result 7 is obtained.
8.Transfer -1 to perform algorithm self-check. Expected result 8 is obtained.
* @expect
1.none 2.return true 3.return true
4.return true 5.return true 6.return true
7.return true 8.return true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC001(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES192) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES192) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC010
* @spec  -
* @title  MD Algorithm self-check. Indicates whether the ID is valid.
* @precon  nan
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
3.Transfer CRYPT_MD_MD5 to perform algorithm self-check. Expected result 2 is obtained.
3.Transfer CRYPT_MD_SHA1 to perform algorithm self-check. Expected result 3 is obtained.
4.Transfer CRYPT_MD_SHA224 to perform algorithm self-check. Expected result 4 is obtained.
5.Transfer CRYPT_MD_SHA256 to perform algorithm self-check. Expected result 5 is obtained.
6.Transfer CRYPT_MD_SHA384 to perform algorithm self-check. Expected result 6 is obtained.
7.Transfer CRYPT_MD_SHA512 to perform algorithm self-check. Expected result 7 is obtained.
8.Transfer CRYPT_MD_SHA3_224 to perform algorithm self-check. Expected result 8 is obtained.
9.Transfer CRYPT_MD_SHA3_256 to perform algorithm self-check. Expected result 9 is obtained.
10.Transfer CRYPT_MD_SHA3_384 to perform algorithm self-check. Expected result 10 is obtained.
11.Transfer CRYPT_MD_SHA3_512 to perform algorithm self-check. Expected result 111 is obtained.
12.Transfer CRYPT_MD_SM3 to perform algorithm self-check. Expected result 12 is obtained.
13.Transfer CRYPT_MD_MAX to perform algorithm self-check. Expected result 13 is obtained.
14.Transfer -1 to perform algorithm self-check. Expected result 14 is obtained.
* @expect
1.none 2.return false 3.return true
4.return true 5.return true 6.return true
7.return true 8.return true 9.return true
10.return true 11.return true 12.return false
13.return false 14.return false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC010(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_MD5) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA3_512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHAKE128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHAKE256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC019
* @spec  -
* @title  DRBG Algorithm self-check. Indicates whether the ID is valid.
* @precon  Prepare the test environment.
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
2.Transfer CRYPT_RAND_AES128_CTR_DF to perform algorithm self-check. Expected result 2 is obtained.
3.Transfer CRYPT_RAND_AES192_CTR_DF to perform algorithm self-check. Expected result 3 is obtained.
4.Transfer CRYPT_RAND_AES256_CTR_DF to perform algorithm self-check. Expected result 4 is obtained.
5.Transfer CRYPT_RAND_AES128_CTR to perform algorithm self-check. Expected result 5 is obtained.
6.Transfer CRYPT_RAND_AES192_CTR to perform algorithm self-check. Expected result 6 is obtained.
7.Transfer CRYPT_RAND_AES256_CTR to perform algorithm self-check. Expected result 7 is obtained.
8.Transfer CRYPT_RAND_HMAC_SHA1 to perform algorithm self-check. Expected result 8 is obtained.
9.Transfer CRYPT_RAND_HMAC_SHA224 to perform algorithm self-check. Expected result 9 is obtained.
10.Transfer CRYPT_RAND_HMAC_SHA256 to perform algorithm self-check. Expected result 10 is obtained.
11.Transfer CRYPT_RAND_HMAC_SHA384 to perform algorithm self-check. Expected result 11 is obtained.
12.Transfer CRYPT_RAND_HMAC_SHA512 to perform algorithm self-check. Expected result 12 is obtained.
13.Transfer CRYPT_RAND_SHA1 to perform algorithm self-check. Expected result 13 is obtained.
14.Transfer CRYPT_RAND_SHA224 to perform algorithm self-check. Expected result 14 is obtained.
15.Transfer CRYPT_RAND_SHA256 to perform algorithm self-check. Expected result 15 is obtained.
16.Transfer CRYPT_RAND_SHA384 to perform algorithm self-check. Expected result 16 is obtained.
17.Transfer CRYPT_RAND_SHA512 to perform algorithm self-check. Expected result 17 is obtained.
18.Transfer CRYPT_RAND_ALGID_MAX to perform algorithm self-check. Expected result 18 is obtained.
19.Transfer -1 to perform algorithm self-check. Expected result 19 is obtained.
* @expect  
1.none
2.return true 3.return true 4.return true 5.return true
6.return true 7.return true 8.return true 9.return true
10.return true 11.return true 12.return true 13.return true
14.return true 15.return true 16.return true 17.return true
18.return false 19.return false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC019(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES128_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES192_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM4_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES128_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES192_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_ALGID_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */


/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC035
* @spec  -
* @title  SM2 Algorithm self-check.
* @precon  nan
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
2.Perform SM2 algorithm self-check. Expected result 2 is obtained.
* @expect
1.none
2.return true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC035(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestSM2() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC036
* @spec  -
* @title  RSA Algorithm self-check.
* @precon  nan
* @brief
1.Register the memory management callback function. Expected result 1 is obtained.
2.Perform RSA algorithm self-check. Expected result 2 is obtained.
* @expect
1.none
2.return true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC036(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestRsa() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC037
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171150526
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC037(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_OFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_CHACHA20_POLY1305) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_MAX) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(-1) == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC038
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171311299
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC038(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestChacha20poly1305() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC039
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171322795
* @precon  准备好测试环境
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC039(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDh() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC040
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171331230
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC040(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDsa() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC041
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171347201
* @precon  准备好测试环境
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC041(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestEd25519() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC042
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171421887
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
* 2.执行Hkdf算法自检,有预期结果2
* 3.执行Pbkdf2算法自检,有预期结果3
* 4.执行Scrypt算法自检,有预期结果4
* @expect  1.返回BSL_SUCCESS
2.返回true 3.返回true 4.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC042(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestHkdf() == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestScrypt() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC043
* @spec  -
* @title  内存管理已注册_内存管理是否注册_20220523171421887
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
* 2.执行KdfTls12算法自检,有预期结果2
* @expect  1.无
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC043(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestKdfTls12() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC045
* @spec  -
* @title  X25519算法自检
* @precon  nan
* @brief  1.注册内存管理回调,有预期结果1
2.执行算法自检,有预期结果2
* @expect  1.返回BSL_SUCCESS
2.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC045(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestX25519() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC046
* @spec  -
* @title  内存管理未注册_内存是否注册_20220523171100467
* @precon  nan
* @brief  1.传入CRYPT_RAND_AES256_CTR_DF执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC046(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR_DF) == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC047
* @spec  -
* @title  内存管理未注册_内存管理回调是否注册_20220523171144681
* @precon  准备好测试环境
* @brief  1.传入CRYPT_MD_SHA256执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC047(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA256) == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC048
* @spec  -
* @title  内存管理未注册_内存管理是否已注册_20220523171355210
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC048(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestRsa() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC049
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171153018
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC049(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC050
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171318396
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC050(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestChacha20poly1305() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC051
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171325201
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC051(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDh() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC052
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171333044
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC052(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDsa() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC053
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171349655
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC053(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestEd25519() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC054
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171358066
* @precon  准备好测试环境
* @brief  1.执行Hkdf算法自检,有预期结果1
* 2.执行Pbkdf2算法自检,有预期结果2
* 3.执行Scrypt算法自检,有预期结果3
* @expect  1.返回false 2.返回false 3.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC054(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestHkdf() == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SHA1) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestScrypt() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC057
* @spec  -
* @title  内存管理未注册_内存管理是否注册_20220523171435826
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC057(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestX25519() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC058(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA256) == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC059
* @spec  -
* @title  ECDSA算法自检
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回true
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC059(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestEcdsa() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC060
* @spec  -
* @title  ECDH算法自检
* @precon  nan
* @brief  1.执行算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC060(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestEcdh() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC062
* @spec  -
* @title  内存管理未注册_内存管理是否注册
* @precon  nan
* @brief  1.执行TDES算法自检,有预期结果1
* @expect  1.返回false
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC062(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Init();
    FuncStubInfo tmpStubInfo = {0};
    STUB_Replace(&tmpStubInfo, BSL_SAL_Malloc, STUB_Malloc);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC063
* @spec  -
* @title  CMVP test for MLDSA
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC063(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMldsaSignVerify() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC064
* @spec  -
* @title  CMVP test for MLKEM
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC064(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMlkemEncapsDecaps() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_SELFTEST_TC065
* @spec  -
* @title  CMVP test for SLHDSA
* @precon  nan
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_SELFTEST_TC065(void)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestSlhdsaSignVerify() == true);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PCT_TC001
* @spec  -
* @title  EAL生成非对称密钥对_密钥配对一致性测试回调_20220523165551567
* @precon  准备好测试环境
* @brief  1.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果1
2.使用CRYPT_EAL_PkeySetPara接口设置密钥参数,有预期结果2
3.使用CRYPT_EAL_PkeyGen接口生成非对称密钥对,有预期结果3
4.释放上下文,有预期结果4
* @expect  1.创建ctx成功，函数返回值不为NULL
2.参数设置成功，函数返回CRYPT_SUCCESS
3.生成非对称密钥对成功，函数返回CRYPT_SUCCESS
4.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PCT_TC001(Hex *e, int bits)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    CRYPT_EAL_RegPct(NULL);
    ASSERT_TRUE(CreatRsaKey(CRYPT_SUCCESS, e, bits) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_RegPct(CMVP_Pct);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PCT_TC002
* @spec  -
* @title  ISO19790模式，异常执行_密钥配对一致性测试回调_20220523165540030
* @precon  nan
* @brief  1.切换到ISO19790模式,有预期结果1
2.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果2
3.使用CRYPT_EAL_PkeySetPara接口设置密钥参数,有预期结果3
4.对EAL验签函数进行打桩，直接返回失败,有预期结果4
5.使用CRYPT_EAL_PkeyGen接口生成非对称密钥对,有预期结果5
6.获取当前状态,有预期结果6
7.撤销EAL验签函数打桩,有预期结果7
8.使用CRYPT_EAL_PkeyGen接口生成非对称密钥对,有预期结果8
9.释放上下文,有预期结果9
* @expect  1.返回成功
2.创建ctx成功，函数返回值不为NULL
3.参数设置成功，函数返回CRYPT_SUCCESS
4.无5.返回失败
6.错误状态，错误为密钥配对测试失败
7.无8.返回失败
9.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PCT_TC002(int mode, Hex *e, int bits)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CreatRsaKey(CRYPT_SUCCESS, e, bits) == CRYPT_SUCCESS);

    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify);
    CRYPT_EAL_PkeyPara para;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = bits;
    para.para.rsaPara.e = e->x;
    para.para.rsaPara.eLen = e->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_CMVP_ERR_PAIRWISETEST);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_PAIRWISETEST);
    STUB_Reset(&tmpStubInfo);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_CMVP_NOT_APPROVED);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PCT_TC003
* @spec  -
* @title  ISO19790模式，正常执行_密钥配对一致性测试回调_20220523165537232
* @precon  准备好测试环境
* @brief  1.切换到ISO19790模式,有预期结果1
2.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果2
3.使用CRYPT_EAL_PkeySetPara接口设置密钥参数,有预期结果3
4.使用CRYPT_EAL_PkeyGen接口生成非对称密钥对,有预期结果4
5.释放上下文,有预期结果5
* @expect  1.返回成功
2.创建ctx成功，函数返回值不为NULL
3.参数设置成功，函数返回CRYPT_SUCCESS
4.生成非对称密钥对成功，函数返回CRYPT_SUCCESS
5.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PCT_TC003(int mode, Hex *e, int bits)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CreatRsaKey(CRYPT_SUCCESS, e, bits) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

#define PTHREAD_TIMES 5
#define PTHREAD_EXP_FAIL_TIMES 3
int g_failTimes = 0;
static BSL_SAL_ThreadLockHandle g_failTimesLock = NULL;
int g_succTimes = 0;
static BSL_SAL_ThreadLockHandle g_succTimesLock = NULL;

typedef struct {
    uint8_t *e;
    uint32_t eLen;
    int bits;
} ThreadParameter;

static int ThreadCreatRsaKey(void *arg)
{
    ThreadParameter *threadParameter = (ThreadParameter *)arg;
    int ret;
    CRYPT_EAL_PkeyPara para;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = threadParameter->bits;
    para.para.rsaPara.e = threadParameter->e;
    para.para.rsaPara.eLen = threadParameter->eLen;
    ret = SetParaAndGenPkey(pkey, &para, CRYPT_SUCCESS);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_ThreadWriteLock(g_failTimesLock);
        g_failTimes++;
        BSL_SAL_ThreadUnlock(g_failTimesLock);
    } else {
        BSL_SAL_ThreadWriteLock(g_succTimesLock);
        g_succTimes++;
        BSL_SAL_ThreadUnlock(g_succTimesLock);
    }
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

static int STUB_PthreadPkeyVerify(const CRYPT_EAL_PkeyCtx *pkey, CRYPT_MD_AlgId id, const uint8_t *data,
    uint32_t dataLen, const uint8_t *sign, uint32_t signLen)
{
    (void)pkey;
    (void)id;
    (void)data;
    (void)dataLen;
    (void)sign;
    (void)signLen;
    int ret = CRYPT_SUCCESS;
    BSL_SAL_ThreadReadLock(g_succTimesLock);
    if (g_succTimes == (PTHREAD_TIMES - PTHREAD_EXP_FAIL_TIMES)) {
        ret = CRYPT_NULL_INPUT;
    }
    BSL_SAL_ThreadUnlock(g_succTimesLock);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PCT_TC004
* @spec  -
* @title  多线程生成密钥对_密钥配对一致性测试回调_20220523165547135
* @precon  nan
* @brief  1.打桩EAL验签的接口，计数，前面几次成功,有预期结果1
2.多线程生成密钥,有预期结果2
3.获取当前状态,有预期结果3
4.比较多线程生成密钥失败次数与打桩函数返回失败次数,有预期结果4
* @expect  1.无
2.
3.错误状态，错误为密钥配对测试失败
4.次数一致
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PCT_TC004(int mode, Hex *e, int bits)
{
    uint32_t i;
    int ret;
    ThreadParameter arg[PTHREAD_TIMES];
    pthread_t thrd[PTHREAD_TIMES];
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(BSL_SAL_ThreadLockNew(&g_failTimesLock) == CRYPT_SUCCESS);
    ASSERT_TRUE(BSL_SAL_ThreadLockNew(&g_succTimesLock) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CreatRsaKey(CRYPT_SUCCESS, e, bits) == CRYPT_SUCCESS);

    g_failTimes = 0;
    g_succTimes = 0;
    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PthreadPkeyVerify);
    for (i = 0; i < PTHREAD_TIMES; i++) {
        arg[i].e = e->x;
        arg[i].eLen = e->len;
        arg[i].bits = bits;
    }
    for (uint32_t i = 0; i < PTHREAD_TIMES; i++) {
        ret = pthread_create(&thrd[i], NULL, (void *)ThreadCreatRsaKey, &arg[i]);
        ASSERT_TRUE(ret == 0);
    }
    for (uint32_t i = 0; i < PTHREAD_TIMES; i++) {
        pthread_join(thrd[i], NULL);
    }
    ASSERT_TRUE(g_failTimes == PTHREAD_EXP_FAIL_TIMES);
EXIT:
    BSL_SAL_ThreadLockFree(g_failTimesLock);
    BSL_SAL_ThreadLockFree(g_succTimesLock);
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PCT_TC005
* @spec  -
* @title  非核准模式，正常执行_密钥配对一致性测试回调_20220523165615122
* @precon  nan
* @brief  1.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果1
2.使用CRYPT_EAL_PkeySetPara接口设置密钥参数,有预期结果2
3.使用CRYPT_EAL_PkeyGen接口生成非对称密钥对,有预期结果3
4.注册默认失败的回调,有预期结果4
5.使用EAL接口生成密钥对,有预期结果5
6.释放上下文,有预期结果6
* @expect  1.创建ctx成功，函数返回值不为NULL
2.参数设置成功，函数返回CRYPT_SUCCESS
3.生成非对称密钥对失败，函数返回CRYPT_SUCCESS
4.无5.返回成功
6.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PCT_TC005(Hex *e, int bits)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify);
    ASSERT_TRUE(CreatRsaKey(CRYPT_SUCCESS, e, bits) == CRYPT_MEM_ALLOC_FAIL);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC001
* @spec  -
* @title  使用CMVP实现的回调_合规判断回调_20220523171445918
* @precon  准备好测试环境
* @brief  1.切换模式到指定模式,有预期结果1
2.CRYPT_CIPHER_AES128_CBC算法创建上下文,有预期结果2
3.释放上下文,有预期结果34.CRYPT_CIPHER_AES192_CBC算法创建上下文,有预期结果4
5.释放上下文,有预期结果56.CRYPT_CIPHER_AES256_CBC算法创建上下文,有预期结果6
7.释放上下文,有预期结果78.CRYPT_CIPHER_AES128_CTR算法创建上下文,有预期结果8
9.释放上下文,有预期结果910.CRYPT_CIPHER_AES192_CTR算法创建上下文,有预期结果10
11.释放上下文,有预期结果1112.CRYPT_CIPHER_AES256_CTR算法创建上下文,有预期结果12
13.释放上下文,有预期结果1314.CRYPT_CIPHER_AES128_ECB算法创建上下文,有预期结果14
15.释放上下文,有预期结果1516.CRYPT_CIPHER_AES192_ECB算法创建上下文,有预期结果16
17.释放上下文,有预期结果1718.CRYPT_CIPHER_AES256_ECB算法创建上下文,有预期结果18
19.释放上下文,有预期结果1920.CRYPT_CIPHER_AES128_XTS算法创建上下文,有预期结果20
21.释放上下文,有预期结果2122.CRYPT_CIPHER_AES256_XTS算法创建上下文,有预期结果22
23.释放上下文,有预期结果23
* @expect  1.返回CRYPT_SUCCESS
2.返回非NULL
3.无4.返回非NULL
5.无6.返回非NULL
7.无8.返回非NULL
9.无10.返回非NULL
11.无12.返回非NULL
13.无14.返回非NULL
15.无16.返回非NULL
17.无18.返回非NULL
19.无20.返回非NULL
21.无22.返回非NULL
23.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC001(int mode)
{
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_CFB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_SM4_OFB) == true);
#else
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CBC) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_ECB) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_XTS) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_CCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES192_GCM) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES256_GCM) == true);
#endif
    ASSERT_TRUE(CRYPT_CMVP_SelftestChacha20poly1305() == false);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC002
* @spec  -
* @title  使用CMVP实现的回调_合规判断回调_20220523171457053
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.计算scrypt派生密钥,有预期结果2
3.计算pbkdf2派生密钥,有预期结果3
4.计算hkdf派生密钥,有预期结果4
5.计算kdf tls1.2派生密钥,有预期结果5
* @expect  1.返回CRYPT_SUCCESS2.返回CRYPT_SUCCESS3.返回CRYPT_SUCCESS4.返回CRYPT_SUCCESS5.返回CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC002(int mode)
{
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SM3) == true);
#else
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestScrypt() == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestHkdf() == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestKdfTls12() == true);
#endif
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC003
* @spec  -
* @title  使用CMVP实现的回调_合规判断回调_20220523171500256
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.CRYPT_MAC_HMAC_SHA1算法创建上下文,有预期结果2
3.释放上下文,有预期结果34.CRYPT_MAC_HMAC_SHA224算法创建上下文,有预期结果4
5.释放上下文,有预期结果56.CRYPT_MAC_HMAC_SHA256算法创建上下文,有预期结果6
7.释放上下文,有预期结果78.CRYPT_MAC_HMAC_SHA384算法创建上下文,有预期结果8
9.释放上下文,有预期结果910.CRYPT_MAC_HMAC_SHA512算法创建上下文,有预期结果10
17.释放上下文,有预期结果17
* @expect  1.返回CRYPT_SUCCESS
2.返回非NULL
3.无4.返回非NULL
5.无6.返回非NULL
7.无8.返回非NULL
9.无10.返回非NULL
11.无12.返回非NULL
13.无14.返回非NULL
15.无16.返回非NULL
17.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC003(int mode)
{
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA1) == false);
#else
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES192) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_CMAC_AES256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES128) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES192) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_GMAC_AES256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SM3) == false);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_MD5) == false);
#endif
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC004
* @spec  -
* @title  使用CMVP实现的回调_合规判断回调_20220523171503060
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.CRYPT_MD_SHA224算法创建上下文,有预期结果2
3.释放上下文,有预期结果3
4.CRYPT_MD_SHA256算法创建上下文,有预期结果4
5.释放上下文,有预期结果5
6.CRYPT_MD_SHA384算法创建上下文,有预期结果6
7.释放上下文,有预期结果7
8.CRYPT_MD_SHA512算法创建上下文,有预期结果8
9.释放上下文,有预期结果9
10.CRYPT_MD_MD4算法创建上下文,有预期结果10
11.CRYPT_MD_MD5算法创建上下文,有预期结果11
12.CRYPT_MD_SHA1算法创建上下文,有预期结果12
13.CRYPT_MD_SM3算法创建上下文,有预期结果13
14.CRYPT_MD_MAX算法创建上下文,有预期结果14
* @expect  1.返回CRYPT_SUCCESS
2.返回非NULL
3.无
4.返回非NULL
5.无
6.返回非NULL
7.无
8.返回非NULL
9.无
10.返回NULL11.返回NULL12.返回非NULL13.返回NULL14.返回NULL
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC004(int mode)
{
    CRYPT_EAL_MdCTX *ctx = NULL;
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SM3) == true);
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA1);
    ASSERT_TRUE(ctx == NULL);
#else
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA512) == true);
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_MD5);
    ASSERT_TRUE(ctx == NULL);
    ctx = CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3);
    ASSERT_TRUE(ctx == NULL);
#endif
EXIT:
    CRYPT_EAL_MdFreeCtx(ctx);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int DsaSignAndVerify(Hex *p, Hex *q, Hex *g, CRYPT_MD_AlgId mdId)
{
    int ret;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen;
    const uint8_t msg[] = { 0x01, 0x02, 0x03, 0x04 };
    CRYPT_EAL_PkeyPara para;
    para.id = CRYPT_PKEY_DSA;
    para.para.dsaPara.p = p->x;
    para.para.dsaPara.pLen = p->len;
    para.para.dsaPara.q = q->x;
    para.para.dsaPara.qLen = q->len;
    para.para.dsaPara.g = g->x;
    para.para.dsaPara.gLen = g->len;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DSA);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = SetParaAndGenPkey(pkey, &para, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(signLen);
    if (sign == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySign(pkey, mdId, msg, sizeof(msg), sign, &signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, msg, sizeof(msg), sign, signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_FREE(sign);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC005
* @spec  -
* @title  使用CMVP实现的回调_合规判断回调_20220523171510190
* @precon  准备好测试环境
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.使用p=1024，q=160长度的dsa参数进行生成密钥，使用SHA256进行签名验签，有预期结果3
4.使用p=2048，q=224长度的dsa参数进行生成密钥，使用SHA256进行签名验签，有预期结果4
5.使用p=2048，q=256长度的dsa参数进行生成密钥，使用MD4进行签名验签，有预期结果5
6.使用p=2048，q=256长度的dsa参数进行生成密钥，使用MD5进行签名验签，有预期结果6
7.使用p=2048，q=256长度的dsa参数进行生成密钥，使用SHA1进行签名验签，有预期结果7
8.使用p=2048，q=256长度的dsa参数进行生成密钥，使用SHA224进行签名验签，有预期结果8
9.使用p=2048，q=256长度的dsa参数进行生成密钥，使用SHA256进行签名验签，有预期结果9
10.使用p=2048，q=256长度的dsa参数进行生成密钥，使用SHA384进行签名验签，有预期结果10
11.使用p=2048，q=256长度的dsa参数进行生成密钥，使用SHA512进行签名验签，有预期结果11
12.使用p=2048，q=256长度的dsa参数进行生成密钥，使用SM3进行签名验签，有预期结果12

* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_CMVP_NOT_APPROVED
4.返回CRYPT_SUCCESS
5.返回CRYPT_CMVP_NOT_APPROVED
6.返回CRYPT_CMVP_NOT_APPROVED
7.返回CRYPT_CMVP_NOT_APPROVED
8.返回CRYPT_SUCCESS
9.返回CRYPT_SUCCESS
10.返回CRYPT_SUCCESS
11.返回CRYPT_SUCCESS
12.返回CRYPT_CMVP_NOT_APPROVED
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC005(int mode, int ret, int mdId, Hex *p, Hex *q, Hex *g)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(DsaSignAndVerify(p, q, g, mdId) == ret);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int RsaSignAndVerify(CRYPT_MD_AlgId mdId, Hex *e, int bits)
{
    int ret;
    uint8_t *sign = NULL;
    uint32_t signLen;
    const uint8_t msg[] = { 0x01, 0x02, 0x03, 0x04 };
    CRYPT_EAL_PkeyPara para;
    CRYPT_EAL_PkeyCtx *pkey = NULL;

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = bits;
    para.para.rsaPara.e = e->x;
    para.para.rsaPara.eLen = e->len;
    ret = SetParaAndGenPkey(pkey, &para, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId, sizeof(mdId));
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(sizeof(uint32_t) * signLen);
    if (sign == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySign(pkey, mdId, msg, sizeof(msg), sign, &signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, msg, sizeof(msg), sign, signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
EXIT:
    BSL_SAL_FREE(sign);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC006
* @spec  -
* @title  使用CMVP实现的回调_合规判断回调_20220523171513977
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.生成密钥长度为1024的rsa密钥，使用SHA256进行签名验签，有预期结果3
4.生成密钥长度为1536的rsa密钥，使用SHA256进行签名验签，有预期结果4
5.生成密钥长度为2048的rsa密钥，使用SHA256进行签名验签，有预期结果5
6.生成密钥长度为3072的rsa密钥，使用SHA256进行签名验签，有预期结果6
7.生成密钥长度为4096的rsa密钥，使用SHA256进行签名验签，有预期结果7
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_CMVP_NOT_APPROVED
4.返回CRYPT_CMVP_NOT_APPROVED
5.返回CRYPT_SUCCESS
6.返回CRYPT_SUCCESS
7.返回CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC006(int mode, int ret, int mdId, Hex *e, int bits)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(RsaSignAndVerify(mdId, e, bits) == ret);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int DhComputeShareKeyByPQG(Hex *p, Hex *q, Hex *g)
{
    int ret;
    uint8_t share1[256];
    uint32_t share1Len = 256;

    CRYPT_EAL_PkeyPara para;
    para.id = CRYPT_PKEY_DH;
    para.para.dhPara.p = p->x;
    para.para.dhPara.pLen = p->len;
    para.para.dhPara.q = q->x;
    para.para.dhPara.qLen = q->len;
    para.para.dhPara.g = g->x;
    para.para.dhPara.gLen = g->len;

    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
    if (pkey1 == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
    if (pkey1 == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey1);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = SetParaAndGenPkey(pkey1, &para, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = SetParaAndGenPkey(pkey2, &para, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC007
* @spec  -
* @title  特定模式下测试DH参数
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.设置p=1024、q=160长度的dh参数生成密钥并计算共享密钥，有预期结果3
4.设置p=2048、q=224长度的dh参数生成密钥并计算共享密钥，有预期结果4
5.设置p=2048、q=256长度的dh参数生成密钥并计算共享密钥，有预期结果5
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_CMVP_NOT_APPROVED
4.返回CRYPT_SUCCESS
5.返回CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC007(int mode, int ret, Hex *p, Hex *q, Hex *g)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(DhComputeShareKeyByPQG(p, q, g) == ret);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int DhComputeShareKeyById(CRYPT_PKEY_ParaId id)
{
    int ret;
    uint8_t share1[1030];
    uint32_t share1Len = sizeof(share1);

    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
    if (pkey1 == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_DH);
    if (pkey1 == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey1);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySetParaById(pkey1, id);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySetParaById(pkey2, id);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = GenPkey(pkey1, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = GenPkey(pkey2, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC008
* @spec  -
* @title  特定模式下测试DH算法参数ID合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.生成CRYPT_DH_RFC2409_768密钥并计算共享密钥，有预期结果3
4.生成CRYPT_DH_RFC2409_1024密钥并计算共享密钥，有预期结果4
5.生成CRYPT_DH_RFC3526_1536密钥并计算共享密钥，有预期结果5
6.生成CRYPT_DH_RFC3526_2048密钥并计算共享密钥，有预期结果6
7.生成CRYPT_DH_RFC3526_3072密钥并计算共享密钥，有预期结果7
8.生成CRYPT_DH_RFC3526_4096密钥并计算共享密钥，有预期结果8
9.生成CRYPT_DH_RFC3526_6144密钥并计算共享密钥，有预期结果9
10.生成CRYPT_DH_RFC3526_8192密钥并计算共享密钥，有预期结果10
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_CMVP_NOT_APPROVED
4.返回CRYPT_CMVP_NOT_APPROVED
5.返回CRYPT_CMVP_NOT_APPROVED
6.返回CRYPT_CMVP_NOT_APPROVED
7.返回CRYPT_CMVP_NOT_APPROVED
8.返回CRYPT_CMVP_NOT_APPROVED
9.返回CRYPT_CMVP_NOT_APPROVED
10.返回CRYPT_CMVP_NOT_APPROVED
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC008(int mode, int ret, int id)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(DhComputeShareKeyById(id) == ret);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int Ed25519SignAndVerify(void)
{
    int ret;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ED25519);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }

    uint8_t msg[100] = {0};
    uint32_t msgLen = sizeof(msg);
    uint8_t sign[100];
    uint32_t signLen = sizeof(sign);
    ret = GenPkey(pkey, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SHA512, msg, msgLen, sign, &signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SHA512, msg, msgLen, sign, signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC009
* @spec  -
* @title  特定模式下测试ED25519算法合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.生成ed25519密钥,有预期结果3
4.使用ed25519进行签名,有预期结果4
5.使用ed25519进行验签,有预期结果5
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_SUCCESS
4.返回CRYPT_SUCCESS
5.返回CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC009(int mode, int ret)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(Ed25519SignAndVerify() == ret);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int X25519ComputeShareKey(void)
{
    int ret;
    uint8_t share1[32];
    uint32_t share1Len = 32;

    CRYPT_EAL_PkeyCtx *pkey1 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    if (pkey1 == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    CRYPT_EAL_PkeyCtx *pkey2 = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    if (pkey1 == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey1);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = GenPkey(pkey1, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = GenPkey(pkey2, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyComputeShareKey(pkey1, pkey2, share1, &share1Len);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey1);
    CRYPT_EAL_PkeyFreeCtx(pkey2);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC010
* @spec  -
* @title  特定模式下测试X25519算法合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.生成X25519密钥,有预期结果3
4.使用X25519计算共享密钥,有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_SUCCESS
4.返回CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC010(int mode, int ret)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(X25519ComputeShareKey() == ret);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC011
* @spec  -
* @title  特定模式下测试DRBG算法合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.使用CRYPT_RAND_SHA1算法，分别进行实例化、重新播种和生成随机数，有预期结果3
4.使用CRYPT_RAND_SHA224算法，分别进行实例化、重新播种和生成随机数，有预期结果4
5.使用CRYPT_RAND_SHA256算法，分别进行实例化、重新播种和生成随机数，有预期结果5
6.使用CRYPT_RAND_SHA384算法，分别进行实例化、重新播种和生成随机数，有预期结果6
7.使用CRYPT_RAND_SHA512算法，分别进行实例化、重新播种和生成随机数，有预期结果7
8.使用CRYPT_RAND_HMAC_SHA1算法，分别进行实例化、重新播种和生成随机数，有预期结果8
9.使用CRYPT_RAND_HMAC_SHA224算法，分别进行实例化、重新播种和生成随机数，有预期结果9
10.使用CRYPT_RAND_HMAC_SHA256算法，分别进行实例化、重新播种和生成随机数，有预期结果10
11.使用CRYPT_RAND_HMAC_SHA384算法，分别进行实例化、重新播种和生成随机数，有预期结果11
12.使用CRYPT_RAND_HMAC_SHA512算法，分别进行实例化、重新播种和生成随机数，有预期结果12
13.使用CRYPT_RAND_AES128_CTR算法，分别进行实例化、重新播种和生成随机数，有预期结果13
14.使用CRYPT_RAND_AES192_CTR算法，分别进行实例化、重新播种和生成随机数，有预期结果14
15.使用CRYPT_RAND_AES256_CTR算法，分别进行实例化、重新播种和生成随机数，有预期结果15
16.使用CRYPT_RAND_AES128_CTR_DF算法，分别进行实例化、重新播种和生成随机数，有预期结果16
17.使用CRYPT_RAND_AES192_CTR_DF算法，分别进行实例化、重新播种和生成随机数，有预期结果17
18.使用CRYPT_RAND_AES256_CTR_DF算法，分别进行实例化、重新播种和生成随机数，有预期结果18
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回成功
4.返回成功
5.返回成功
6.返回成功
7.返回成功
8.返回成功
9.返回成功
10.返回成功
11.返回成功
15.返回成功
16.返回成功
17.返回成功
18.返回成功
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC011(int mode)
{
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM3) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM4_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA256) == false);
#else
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA1) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA224) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA256) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA384) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_HMAC_SHA512) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES128_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES192_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES128_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES192_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AES256_CTR_DF) == true);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SM4_CTR_DF) == false);
#endif
EXIT:
    EndTest();
}
/* END_CASE */

static int EcdsaSignAndVerify(int32_t curveId, int32_t mdId)
{
    int ret;
    uint8_t *sign = NULL;
    CRYPT_EAL_PkeyCtx *pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_ECDSA);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySetParaById(pkey, curveId);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);

    uint8_t msg[4] = {0};
    uint32_t msgLen = sizeof(msg);
    uint32_t signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    GOTO_EXIT_IF(signLen == 0);
    sign = (uint8_t *)malloc(signLen);
    GOTO_EXIT_IF(sign == NULL);
    ret = GenPkey(pkey, CRYPT_SUCCESS);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeySign(pkey, mdId, msg, msgLen, sign, &signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(pkey, mdId, msg, msgLen, sign, signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    free(sign);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC012
* @spec  -
* @title  特定模式下测试ECDSA算法合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.生成密钥,有预期结果3
4.使用ECDSA进行签名验签,有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_SUCCESS
4.返回CRYPT_SUCCESS
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC012(int mode, int curveId, int mdId, int ret)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

    ASSERT_TRUE(EcdsaSignAndVerify(curveId, mdId) == ret);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

static int32_t HmacCalculate(int id, Hex *key)
{
    uint32_t ret;
    CRYPT_EAL_MacCtx *ctx = NULL;
    ctx = CRYPT_EAL_MacNewCtx(id);
    if (ctx == NULL) {
        return CRYPT_NULL_INPUT;
    }

    ret = CRYPT_EAL_MacInit(ctx, key->x, key->len);
    CRYPT_EAL_MacDeinit(ctx);
    CRYPT_EAL_MacFreeCtx(ctx);
    return ret;
}

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC013
* @spec  -
* @title  特定模式下测试HMAC算法的合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.初始化HMAC,有预期结果3
4.释放上下文,有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回结果与预期一致
4.释放成功
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC013(int mode, int id, Hex *key, int expectRet)
{
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

    ASSERT_TRUE(HmacCalculate(id, key) == expectRet);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC014
* @spec  -
* @title  特定模式下测试HKDF算法的合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.调用HKDF计算接口,有预期结果3
4.释放上下文,有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回结果与预期一致
4.释放成功
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC014(int mode, int id, Hex *key, Hex *salt, Hex *info, int expectRet)
{
    unsigned char output[MAX_OUTPUT];
    uint32_t outLen = MAX_OUTPUT;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_HKDF);
    ASSERT_TRUE(ctx != NULL);
    CRYPT_HKDF_MODE hmode = CRYPT_KDF_HKDF_MODE_FULL;
    BSL_Param param[6] = {
        {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id), 0},
        {CRYPT_PARAM_KDF_MODE, BSL_PARAM_TYPE_UINT32, &hmode, sizeof(hmode), 0},
        {CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, key->x, key->len, 0},
        {CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt->x, salt->len, 0},
        {CRYPT_PARAM_KDF_INFO, BSL_PARAM_TYPE_OCTETS, info->x, info->len, 0},
        BSL_PARAM_END
    };
    if (id == CRYPT_MAC_HMAC_SM3) {
        ASSERT_TRUE(CRYPT_EAL_KdfSetParam(ctx, param) != CRYPT_SUCCESS);
    } else {
        ASSERT_TRUE(CRYPT_EAL_KdfSetParam(ctx, param) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_KdfDerive(ctx, output, outLen) == expectRet);
    }
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC015
* @spec  -
* @title  特定模式下测试PBKDF算法的合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.调用PBKDF计算接口,有预期结果3
4.释放上下文,有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回结果与预期一致
4.释放成功
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC015(int mode, Hex *key, Hex *salt, int it, int dkLen, int expectRet)
{
    unsigned char output[MAX_OUTPUT];
    uint32_t outLen = MAX_OUTPUT;
    CRYPT_EAL_KdfCTX *ctx = NULL;
    uint32_t id = CRYPT_MAC_HMAC_SHA1;
    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(dkLen < MAX_OUTPUT);

    outLen = dkLen;
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_PBKDF2);
    ASSERT_TRUE(ctx != NULL);
    BSL_Param param[5] = {
        {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id), 0},
        {CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, key->x, key->len, 0},
        {CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt->x, salt->len, 0},
        {CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32, &it, sizeof(uint32_t), 0},
        BSL_PARAM_END
    };
    GOTO_EXIT_IF(CRYPT_EAL_KdfSetParam(ctx, param) == CRYPT_SUCCESS);
    GOTO_EXIT_IF(CRYPT_EAL_KdfDerive(ctx, output, outLen) == expectRet);
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PARA_TC016
* @spec  -
* @title  特定模式下测试KDF-TLS12算法的合法性
* @precon  nan
* @brief  1.切换模式到指定模式,有预期结果1
2.获取当前的模式，有预期结果2
3.调用KDF-TLS12计算接口,有预期结果3
4.释放上下文,有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回结果与预期一致
4.释放成功
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC016(int mode, int id, Hex *key, Hex *label, Hex *seed, int expectRet)
{
    unsigned char output[MAX_OUTPUT];
    uint32_t outLen = MAX_OUTPUT;
    CRYPT_EAL_KdfCTX *ctx = NULL;

    ResetStatusAndStartTest();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ctx = CRYPT_EAL_KdfNewCtx(CRYPT_KDF_KDFTLS12);
    ASSERT_TRUE(ctx != NULL);
    BSL_Param param[5] = {
        {CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32, &id, sizeof(id), 0},
        {CRYPT_PARAM_KDF_KEY, BSL_PARAM_TYPE_OCTETS, key->x, key->len, 0},
        {CRYPT_PARAM_KDF_LABEL, BSL_PARAM_TYPE_OCTETS, label->x, label->len, 0},
        {CRYPT_PARAM_KDF_SEED, BSL_PARAM_TYPE_OCTETS, seed->x, seed->len, 0},
        BSL_PARAM_END
    };
    if (id != CRYPT_MAC_HMAC_SHA256 && id != CRYPT_MAC_HMAC_SHA384 && id != CRYPT_MAC_HMAC_SHA512) {
        GOTO_EXIT_IF(CRYPT_EAL_KdfSetParam(ctx, param) == expectRet);
    } else {
        ASSERT_TRUE(CRYPT_EAL_KdfSetParam(ctx, param) == CRYPT_SUCCESS);
        ASSERT_TRUE(CRYPT_EAL_KdfDerive(ctx, output, outLen) == expectRet);
    }
EXIT:
    CRYPT_EAL_KdfFreeCtx(ctx);
    EndTest();
}
/* END_CASE */

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
static int Sm2SignAndVerify()
{
    int32_t ret;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    uint8_t *sign = NULL;
    uint32_t signLen;
    const uint8_t msg[] = { 0x01, 0x02, 0x03, 0x04 };

    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    if (pkey == NULL) {
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeyGen(pkey);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(signLen);
    if (sign == NULL) {
        CRYPT_EAL_PkeyFreeCtx(pkey);
        return CRYPT_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_PkeySign(pkey, CRYPT_MD_SM3, msg, sizeof(msg), sign, &signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
    ret = CRYPT_EAL_PkeyVerify(pkey, CRYPT_MD_SM3, msg, sizeof(msg), sign, signLen);
    GOTO_EXIT_IF(ret != CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    BSL_SAL_FREE(sign);
    return ret;
}
#endif

/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PARA_TC017()
{
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ResetStatusAndStartTest();
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_GM) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_GM);
    CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0);
    ASSERT_TRUE(Sm2SignAndVerify() == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_RandDeinit();
    EndTest();
#endif
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_MODE_TC001
* @spec  -
* @title  非法入参_模式id_20220523170400720
* @precon  nan
* @brief  1.执行CRYPT_CMVP_ModeGet接口,有预期结果12.传入CRYPT_CMVP_MODE_MAX执行模式切换,有预期结果2
3.传入CRYPT_CMVP_MODE_NONAPPROVED使用CRYPT_CMVP_ModeSet切换模式,有预期结果3
4.执行CRYPT_CMVP_ModeGet接口,有预期结果45.传入CRYPT_CMVP_MODE_ISO19790使用CRYPT_CMVP_ModeSet切换模式,有预期结果5
6.执行CRYPT_CMVP_ModeGet接口,有预期结果67.传入CRYPT_CMVP_MODE_ISO19790使用CRYPT_CMVP_ModeSet切换模式,有预期结果7
8.执行CRYPT_CMVP_ModeGet接口,有预期结果8
* @expect  1.返回CRYPT_CMVP_MODE_NONAPPROVED
2.返回失败
3.返回失败
4.返回CRYPT_CMVP_MODE_NONAPPROVED
5.返回CRYPT_SUCCESS
6.返回CRYPT_CMVP_MODE_ISO19790.返回失败
8.返回CRYPT_CMVP_MODE_ISO19790
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_MODE_TC001(int mode)
{
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_MAX) == CRYPT_CMVP_INVALID_INPUT);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_NONAPPROVED) == CRYPT_CMVP_ALREADY_IN_MODE);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_CMVP_ALREADY_IN_MODE);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_MODE_TC002
* @spec  -
* @title  密钥配对测试失败进入错误状态下切换失败_模块状态_20220523170403543
* @precon  准备好测试环境
* @brief  1.设置模块处于错误状态，错误原因是密钥配对测试失败,有预期结果1
2.获取当前状态,有预期结果2
3.获取当前的模式,有预期结果3
4.请求切换到ISO19790模式,有预期结果4
5.获取当前模式,有预期结果5
* @expect  1.无
2.错误状态，错误原因为密钥配对测试失败
3.非核准模式4.返回失败
5.非核准模式
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_MODE_TC002(int mode, Hex *e, int bits)
{
    CRYPT_EAL_PkeyPara para;
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    STUB_Init();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    (void)e;
    (void)bits;
    CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0);
    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify);
    ASSERT_TRUE(CreatSm2Key(CRYPT_CMVP_ERR_PAIRWISETEST, e, bits) == CRYPT_CMVP_ERR_PAIRWISETEST);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_PAIRWISETEST);
#else
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = bits;
    para.para.rsaPara.e = e->x;
    para.para.rsaPara.eLen = e->len;

    ASSERT_TRUE(STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify) == 0);
    ASSERT_TRUE(SetParaAndGenPkey(pkey, &para, CRYPT_CMVP_ERR_PAIRWISETEST) == CRYPT_CMVP_ERR_PAIRWISETEST);
#endif
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_PAIRWISETEST);
    STUB_Reset(&tmpStubInfo);

    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_NONAPPROVED) == CRYPT_CMVP_ERR_STATUS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_MODE_TC003
* @spec  -
* @title  内存中存在CSP后从核准切换到非核准_内存中有无CSP_20220523170353790
* @precon  nan
* @brief  1.执行CRYPT_CMVP_ModeGet接口,有预期结果1
2.切换到ISO19790模式,有预期结果2
3.获取当前模式,有预期结果3
4.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果4
5.释放上下文,有预期结果56.切换到非核准模式,有预期结果6
7.执行CRYPT_CMVP_ModeGet接口,有预期结果7
8.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果8
9.释放上下文,有预期结果9
* @expect  1.返回CRYPT_CMVP_MODE_NONAPPROVED
2.返回成功
3.返回ISO19790模式
4.返回值不为NULL
5.无6.返回失败
7.返回ISO19790模式
8.返回值不为NULL
9.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_MODE_TC003(int mode)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey != NULL);
    CRYPT_EAL_PkeyFreeCtx(pkey);
#else
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    ASSERT_TRUE(pkey != NULL);
    CRYPT_EAL_PkeyFreeCtx(pkey);
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_NONAPPROVED) == CRYPT_CMVP_ERR_CSP_EXIST);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
    ASSERT_TRUE(pkey != NULL);
#else
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
    ASSERT_TRUE(pkey != NULL);
#endif
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_MODE_TC004
* @spec  -
* @title  内存中存在CSP后从非核准切换到核准_内存中有无CSP_20220523170347451
* @precon  nan
* @brief  1.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果1
2.执行CRYPT_CMVP_ModeGet接口,有预期结果2
3.传入正确的身份验证凭证和CRYPT_CMVP_MODE_ISO19790使用CRYPT_CMVP_ModeSet切换模式,有预期结果3
4.执行CRYPT_CMVP_ModeGet接口,有预期结果4
5.使用CRYPT_EAL_PkeyFreeCtx释放ctx,有预期结果5
* @expect  1.返回值不为NULL
2.返回CRYPT_CMVP_MODE_NONAPPROVED
3.返回CRYPT_CMVP_ERR_CSP_EXIST
4.返回CRYPT_CMVP_MODE_NONAPPROVED
5.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_MODE_TC004(int mode)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
#else
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
#endif
    ASSERT_TRUE(pkey != NULL);
    CRYPT_EAL_PkeyFreeCtx(pkey);

    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_CMVP_ERR_CSP_EXIST);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);

#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_SM2);
#else
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_X25519);
#endif
    ASSERT_TRUE(pkey != NULL);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_MODE_TC005
* @spec  -
* @title  算法自检失败失败进入错误状态下切换失败_模块状态_20220523170407988
* @precon  nan
* @brief  1.设置模块处于错误状态，错误原因是算法自检失败,有预期结果1
2.获取当前状态,有预期结果2
3.获取当前的模式,有预期结果3
4.请求切换到ISO19790模式,有预期结果4
5.获取当前模式,有预期结果5
* @expect  1.无
2.错误状态，错误原因为算法自检失败
3.非核准模式4.返回失败
5.非核准模式
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_MODE_TC005(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);

    STUB_Replace(&tmpStubInfo, CRYPT_EAL_MdInit, STUB_MdInit);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    ASSERT_TRUE(CRYPT_EAL_MdNewCtx(CRYPT_MD_SM3) == NULL);
#else
    ASSERT_TRUE(CRYPT_EAL_MdNewCtx(CRYPT_MD_SHA256) == NULL);
#endif
    STUB_Reset(&tmpStubInfo);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_NONAPPROVED) == CRYPT_CMVP_ERR_STATUS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
EXIT:
    STUB_Reset(&tmpStubInfo);
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_MODE_TC006
* @spec  -
* @title  完整性验证失败进入错误状态下切换失败_模块状态_20220523170405892
* @precon  nan
* @brief  1.设置模块处于错误状态，错误原因是完整性验证失败,有预期结果1
2.获取当前状态,有预期结果2
3.获取当前的模式,有预期结果3
4.请求切换到ISO19790模式,有预期结果4
5.获取当前模式,有预期结果5
* @expect  1.无
2.错误状态，错误原因为完整性验证失败
3.非核准模式4.返回失败
5.非核准模式
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_MODE_TC006(int mode)
{
    ResetStatus();
    ASSERT_TRUE(remove("test_suite_sdv_cmvp.hmac") == 0);
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    StartTest();
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_CMVP_ERR_INTEGRITY);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_CMVP_ERR_STATUS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
EXIT:
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_MODE_TC007
* @spec  -
* @title  正常切换模式_模式id_20220523170358386
* @precon  nan
* @brief  1.传入CRYPT_CMVP_MODE_ISO19790使用CRYPT_CMVP_ModeSet切换模式,有预期结果1
2.执行CRYPT_CMVP_ModeGet接口,有预期结果23.传入CRYPT_CMVP_MODE_NONAPPROVED使用CRYPT_CMVP_ModeSet切换模式,有预期结果3
4.执行CRYPT_CMVP_ModeGet接口,有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.返回CRYPT_SUCCESS
4.返回CRYPT_CMVP_MODE_NONAPPROVED
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_MODE_TC007(int mode)
{
    ResetStatusAndStartTest();
#if HITLS_CRYPTO_CMVP_MODE == CMVP_MODE_GM
    if (mode != CRYPT_CMVP_MODE_GM) {
        goto EXIT;
    }
#else
    if(mode != CRYPT_CMVP_MODE_ISO19790 && mode != CRYPT_CMVP_MODE_FIPS) {
        goto EXIT;
    }
#endif
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_NONAPPROVED) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NONAPPROVED);
EXIT:
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC001(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    ASSERT_TRUE(type == CRYPT_ALGO_CIPHER);
    ASSERT_TRUE(id == CRYPT_CIPHER_AES128_CBC);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    ASSERT_TRUE(oper == CRYPT_EVENT_ZERO || oper == CRYPT_EVENT_ENC ||
        oper == CRYPT_EVENT_DEC || oper == CRYPT_EVENT_SETSSP);
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC001
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523165849237
* @precon  nan
* @brief  1.CRYPT_CIPHER_AES128_CBC算法，使用CRYPT_EAL_CipherNewCtx接口创建ctx,有预期结果1
2.使用CRYPT_EAL_CipherCtrl接口设置iv,有预期结果2
3.使用CRYPT_EAL_CipherSetPadding设置CRYPT_PADDING_NONE填充,有预期结果3
4.使用CRYPT_EAL_CipherInit初始化加密句柄,有预期结果4
5.使用CRYPT_EAL_CipherUpdate输入数据,有预期结果5
6.使用CRYPT_EAL_CipherFinal完成加密,有预期结果6
7.手动查看系统syslog日志,有预期结果78.使用CRYPT_EAL_CipherDeinit反初始化,有预期结果8
9.手动查看系统syslog日志,有预期结果910.使用CRYPT_EAL_CipherFreeCtx释放句柄,有预期结果10
11.手动查看系统syslog日志,有预期结果11
* @expect  1.创建ctx成功，函数返回值不为NULL
2.返回CRYPT_SUCCESS
3.返回CRYPT_SUCCESS
4.返回CRYPT_SUCCESS
5.返回CRYPT_SUCCESS
6.返回CRYPT_SUCCESS
7.日志内显示以下事件，包括事件发生的日期和时间1.执行过对称加密服务，算法为CRYPT_CIPHER_AES128_CBC
8.无
9.日志内显示以下事件，包括事件发生的日期和时间1.执行过置零服务，算法为CRYPT_CIPHER_AES128_CBC10.无
11.日志内显示以下事件，包括事件发生的日期和时间1.执行过置零服务，算法为CRYPT_CIPHER_AES128_CBC
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC001(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC001);
    ASSERT_TRUE(CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AES128_CBC) == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC002(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    ASSERT_TRUE(type == CRYPT_ALGO_PKEY || type == CRYPT_ALGO_RAND);
    ASSERT_TRUE(id == CRYPT_PKEY_DSA || id == CRYPT_RAND_SHA256);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    ASSERT_TRUE(oper == CRYPT_EVENT_RANDGEN || oper == CRYPT_EVENT_SIGN || oper == CRYPT_EVENT_VERIFY ||
        oper == CRYPT_EVENT_GEN || oper == CRYPT_EVENT_ZERO);
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC002
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170000841
* @precon  准备好测试环境
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用DSA算法执行密钥生成、签名、验签服务，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过签名、验签、生成密钥对、签名、验签、置零服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC002(int mode, int ret, int mdId, Hex *p, Hex *q, Hex *g)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(DsaSignAndVerify(p, q, g, mdId) == ret);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC002);
    ASSERT_TRUE(DsaSignAndVerify(p, q, g, mdId) == ret);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC003(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    static int step = 0;
    step++;
    ASSERT_TRUE(type == CRYPT_ALGO_MD);
    ASSERT_TRUE(id == CRYPT_MD_SHA256);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    switch (step) {
        case 1:
            ASSERT_TRUE(oper == CRYPT_EVENT_MD);
            return;
        case 2:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        case 3:
            ASSERT_TRUE(oper == CRYPT_EVENT_MD);
            return;
        case 4:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        default:
            RecordFailure("STUB_EventProcess_TC003 defalut", __FILE__);
            return;
    }
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC003
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170112025
* @precon  nan
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用SHA256算法执行哈希服务，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过哈希、置零服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC003(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA256) == true);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC003);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMd(CRYPT_MD_SHA256) == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC004(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    static int step = 0;
    step++;
    ASSERT_TRUE(type == CRYPT_ALGO_MAC);
    ASSERT_TRUE(id == CRYPT_MAC_HMAC_SHA256);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    switch (step) {
        case 1:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 2:
            ASSERT_TRUE(oper == CRYPT_EVENT_MAC);
            return;
        case 3:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        case 4:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 5:
            ASSERT_TRUE(oper == CRYPT_EVENT_MAC);
            return;
        case 6:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        default:
            RecordFailure("STUB_EventProcess_TC004 defalut", __FILE__);
            return;
    }
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC004
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170131319
* @precon  准备好测试环境
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用HMAC_SHA256算法执行MAC服务，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过MAC、置零服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC004(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA256) == true);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC004);
    ASSERT_TRUE(CRYPT_CMVP_SelftestMac(CRYPT_MAC_HMAC_SHA256) == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC005(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    static int step = 0;
    step++;
    ASSERT_TRUE(type == CRYPT_ALGO_PKEY);
    ASSERT_TRUE(id == CRYPT_PKEY_DH);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    switch (step) {
        case 1:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 2:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 3:
            ASSERT_TRUE(oper == CRYPT_EVENT_KEYAGGREMENT);
            return;
        case 4:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 5:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 6:
            ASSERT_TRUE(oper == CRYPT_EVENT_KEYAGGREMENT);
            return;
        case 7:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        case 8:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        case 9:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 10:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 11:
            ASSERT_TRUE(oper == CRYPT_EVENT_KEYAGGREMENT);
            return;
        case 12:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 13:
            ASSERT_TRUE(oper == CRYPT_EVENT_SETSSP);
            return;
        case 14:
            ASSERT_TRUE(oper == CRYPT_EVENT_KEYAGGREMENT);
            return;
        case 15:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        case 16:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        default:
            RecordFailure("STUB_EventProcess_TC005 defalut", __FILE__);
            return;
    }
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC005
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170153725
* @precon  nan
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用DH算法计算共享密钥，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过计算共享密钥、置零服务。
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC005(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDh() == true);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC005);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDh() == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC006(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    ASSERT_TRUE(type == CRYPT_ALGO_KDF);
    ASSERT_TRUE(id == CRYPT_KDF_HKDF);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    ASSERT_TRUE(oper == CRYPT_EVENT_KDF || oper == CRYPT_EVENT_ZERO);
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC006
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170213350
* @precon  准备好测试环境
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用HKDF算法计算派生密钥，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过密钥派生、置零服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC006(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestHkdf() == true);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC006);
    ASSERT_TRUE(CRYPT_CMVP_SelftestHkdf() == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC007(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    ASSERT_TRUE(type == CRYPT_ALGO_KDF);
    ASSERT_TRUE(id == BSL_CID_SCRYPT);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC007
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170217883
* @precon  nan
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用scrypt算法计算派生密钥，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.没有执行过scrypt服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC007(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC007);
    ASSERT_TRUE(CRYPT_CMVP_SelftestScrypt() == false);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC008(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    ASSERT_TRUE(type == CRYPT_ALGO_KDF);
    ASSERT_TRUE(id == CRYPT_KDF_KDFTLS12);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    ASSERT_TRUE(oper == CRYPT_EVENT_KDF || oper == CRYPT_EVENT_ZERO);
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC008
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170221231
* @precon  nan
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用tls1.2 kdf算法计算派生密钥，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过密钥派生、置零服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC008(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestKdfTls12() == true);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC008);
    ASSERT_TRUE(CRYPT_CMVP_SelftestKdfTls12() == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC009(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    ASSERT_TRUE(type == CRYPT_ALGO_KDF);
    ASSERT_TRUE(id == CRYPT_KDF_PBKDF2);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    ASSERT_TRUE(oper == CRYPT_EVENT_KDF || oper == CRYPT_EVENT_ZERO);
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC009
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170224934
* @precon  nan
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用pbkdf2算法计算派生密钥，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过密钥派生、置零服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC009(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SHA1) == true);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC009);
    ASSERT_TRUE(CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_HMAC_SHA1) == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

void STUB_EventProcess_TC010(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int id, int err)
{
    static int step = 0;
    step++;
    ASSERT_TRUE(type == CRYPT_ALGO_RAND);
    ASSERT_TRUE(id == CRYPT_RAND_SHA256);
    ASSERT_TRUE(err == CRYPT_SUCCESS);
    switch (step) {
        case 1:
            ASSERT_TRUE(oper == CRYPT_EVENT_RANDGEN);
            return;
        case 2:
            ASSERT_TRUE(oper == CRYPT_EVENT_RANDGEN);
            return;
        case 3:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        case 4:
            ASSERT_TRUE(oper == CRYPT_EVENT_RANDGEN);
            return;
        case 5:
            ASSERT_TRUE(oper == CRYPT_EVENT_RANDGEN);
            return;
        case 6:
            ASSERT_TRUE(oper == CRYPT_EVENT_ZERO);
            return;
        default:
            RecordFailure("STUB_EventProcess_TC010 defalut", __FILE__);
            return;
    }
EXIT:
    return;
}

/* @
* @test  SDV_CRYPTO_CMVP_EVENT_REPORT_TC010
* @spec  -
* @title  注册CMVP实现的回调_事件上报回调_20220523170228018
* @precon  nan
* @brief  1.切换至ISO19790模式，有预期结果1
2.获取当前模式，有预期结果2
3.打桩事件上报函数，有预期结果3
4.使用CRYPT_RAND_SHA256算法生成随机数，在打桩函数内判断是否执行过相应的服务，有预期结果4
* @expect  1.返回CRYPT_SUCCESS
2.返回CRYPT_CMVP_MODE_ISO19790
3.无
4.先后执行过随机数生成、置零服务
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_EVENT_REPORT_TC010(int mode)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(mode == CRYPT_CMVP_MODE_ISO19790 || mode == CRYPT_CMVP_MODE_FIPS);
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(mode) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == (uint32_t)mode);
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA256) == true);
    STUB_Replace(&tmpStubInfo, ISO19790_EventProcess, STUB_EventProcess_TC010);
    ASSERT_TRUE(CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_SHA256) == true);
EXIT:
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_PCT_TC006
* @spec  -
* @title  NDCPP模式，异常执行_密钥配对一致性测试回调
* @precon  nan
* @brief  1.切换到NDCPP模式,有预期结果1
2.使用CRYPT_EAL_PkeyNewCtx接口创建ctx,有预期结果2
3.使用CRYPT_EAL_PkeySetPara接口设置密钥参数,有预期结果3
4.对EAL验签函数进行打桩，直接返回失败,有预期结果4
5.使用CRYPT_EAL_PkeyGen接口生成非对称密钥对,有预期结果5
6.获取当前状态,有预期结果6
7.撤销EAL验签函数打桩,有预期结果7
8.使用CRYPT_EAL_PkeyGen接口生成非对称密钥对,有预期结果8
9.释放上下文,有预期结果9
* @expect  1.返回成功
2.创建ctx成功，函数返回值不为NULL
3.参数设置成功，函数返回CRYPT_SUCCESS
4.无5.返回CRYPT_CMVP_ERR_PAIRWISETEST
6.返回CRYPT_SUCCESS
7.无8.返回CRYPT_SUCCESS
9.无
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_PCT_TC006(Hex *e, int bits)
{
    CRYPT_EAL_PkeyCtx *pkey = NULL;
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();

    // 设置ndcpp模式
    ASSERT_TRUE(CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_NDCPP) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_ModeGet() == CRYPT_CMVP_MODE_NDCPP);

    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SHA256, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CreatRsaKey(CRYPT_SUCCESS, e, bits) == CRYPT_SUCCESS);

    STUB_Init();
    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify);
    CRYPT_EAL_PkeyPara para;
    pkey = CRYPT_EAL_PkeyNewCtx(CRYPT_PKEY_RSA);
    ASSERT_TRUE(pkey != NULL);
    para.id = CRYPT_PKEY_RSA;
    para.para.rsaPara.bits = bits;
    para.para.rsaPara.e = e->x;
    para.para.rsaPara.eLen = e->len;
    ASSERT_TRUE(CRYPT_EAL_PkeySetPara(pkey, &para) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_CMVP_ERR_PAIRWISETEST);
    ASSERT_TRUE(CRYPT_CMVP_StatusGet() == CRYPT_SUCCESS);   // NDCPP模式下密钥配对失败不进入错误状态
    STUB_Reset(&tmpStubInfo);

    ASSERT_TRUE(CRYPT_EAL_PkeyGen(pkey) == CRYPT_SUCCESS);
EXIT:
    CRYPT_EAL_PkeyFreeCtx(pkey);
    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */

/* @
* @test  SDV_CRYPTO_CMVP_GM_SELFTEST_TC001
* @spec  -
* @title  国密算法测试
* @precon  nan
* @brief  1.初始化随机数接口
2.调用国密自检接口,有预期结果1
3.对EAL验签函数进行打桩，直接返回失败,有预期结果1
4.调用国密自检接口, 有预期结果2
5.对EAL MD函数进行打桩，直接返回失败,有预期结果1
6.调用国密自检接口, 有预期结果3
* @expect  1.返回成功
2.MD SM3算法自检失败
3.SM3 和 SM2 算法自检失败。
* @prior  Level 1
* @auto  TRUE
@ */
/* BEGIN_CASE */
void SDV_CRYPTO_CMVP_GM_SELFTEST_TC001(void)
{
    FuncStubInfo tmpStubInfo = {0};
    ResetStatusAndStartTest();
    STUB_Init();
    ASSERT_TRUE(CRYPT_EAL_RandInit(CRYPT_RAND_SM3, NULL, NULL, NULL, 0) == CRYPT_SUCCESS);
    ASSERT_TRUE(CRYPT_CMVP_SelftestGM() == 0);
    STUB_Replace(&tmpStubInfo, CRYPT_EAL_PkeyVerify, STUB_PkeyVerify);
    ASSERT_TRUE(CRYPT_CMVP_SelftestGM() == CRYPT_CMVP_GM_SM2);
    STUB_Replace(&tmpStubInfo, CRYPT_EAL_MdInit, STUB_MdInit);
    ASSERT_TRUE(CRYPT_CMVP_SelftestGM() == CRYPT_CMVP_GM_SM3 || CRYPT_CMVP_GM_SM2);
EXIT:

    STUB_Reset(&tmpStubInfo);
    CRYPT_EAL_RandDeinit();
    EndTest();
}
/* END_CASE */
#endif
