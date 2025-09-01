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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include "app_enc.h"
#include "app_keymgmt.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_mac.h"
#include "bsl_ui.h"
#include "bsl_uio.h"
#include "securec.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_cmvp.h"
#include "eal_cipher_local.h"
#include "stub_replace.h"
/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_enc.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c ${HITLS_ROOT_PATH}/apps/src/app_utils.c */
/* END_HEADER */

#ifdef HITLS_APP_SM_MODE
#define WORK_PATH "./keymgmt_workpath"

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

#define SUFFIX ".p12"

#define SYNC_DATA_FILE "./keymgmt_workpath/sync_data.bin"

#ifdef HITLS_CRYPTO_CMVP_SM_PURE_C
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/C/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_ARMV8_LE
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/armv8_le/lib"
#endif

#ifdef HITLS_CRYPTO_CMVP_SM_X86_64
#define HITLS_SM_PROVIDER_PATH "../../output/CMVP/x86_64/lib"
#endif

#define HITLS_SM_LIB_NAME "libhitls_sm.so"
#define HITLS_SM_PROVIDER_ATTR "provider=sm"

#define SM_PARAM \
    "-sm", "-workpath", WORK_PATH, \
    "-provider", HITLS_SM_LIB_NAME, \
    "-provider-path", HITLS_SM_PROVIDER_PATH, \
    "-provider-attr", HITLS_SM_PROVIDER_ATTR

static AppProvider g_appProvider = {HITLS_SM_LIB_NAME, HITLS_SM_PROVIDER_PATH, HITLS_SM_PROVIDER_ATTR};

static int32_t AppTestInit(void)
{
    system("rm -rf " WORK_PATH);
    system("mkdir -p " WORK_PATH);
    int32_t ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    if (APP_GetCurrent_LibCtx() == NULL) {
        if (APP_Create_LibCtx() == NULL) {
            AppPrintError("Create g_libCtx failed\n");
            return HITLS_APP_INVALID_ARG;
        }
    }
    return HITLS_APP_SUCCESS;
}

static void AppTestUninit(void)
{
    HITLS_APP_FreeLibCtx();
    AppPrintErrorUioUnInit();
    system("rm -rf " WORK_PATH);
}

static int32_t STUB_BSL_UI_ReadPwdUtil(BSL_UI_ReadPwdParam *param, char *buff, uint32_t *buffLen, const BSL_UI_CheckDataCallBack checkDataCallBack, void *callBackData)
{
    (void)param;
    (void)checkDataCallBack;
    (void)callBackData;
    char result[] = "12345678";
    (void)strcpy_s(buff, *buffLen, result);
    *buffLen = (uint32_t)strlen(buff) + 1;
    return BSL_SUCCESS;
}

static int32_t STUB_HITLS_APP_SM_IntegrityCheck(void)
{
    return HITLS_APP_SUCCESS;
}

static int has_suffix(const char *filename, const char *suffix)
{
    size_t len_filename = strlen(filename);
    size_t len_suffix = strlen(suffix);
    if (len_filename >= len_suffix) {
        return strcmp(filename + len_filename - len_suffix, suffix) == 0;
    }
    return 0;
}

static char *GetUuidFromP12(const char *directory)
{
    struct dirent *entry;
    DIR *dp = opendir(directory);
    if (dp == NULL) {
        return NULL;
    }
    bool found = false;
    while ((entry = readdir(dp))) {
        if (entry->d_type == DT_REG && has_suffix(entry->d_name, SUFFIX)) {
            found = true;
            break;
        }
    }
    if (!found) {
        closedir(dp);
        return NULL;
    }
    uint32_t len = strlen(entry->d_name) - strlen(SUFFIX) + 1;
    char *uuid = BSL_SAL_Malloc(len);
    if (uuid == NULL) {
        closedir(dp);
        return NULL;
    }
    (void)memcpy_s(uuid, len, entry->d_name, len - 1);
    uuid[len - 1] = '\0';
    closedir(dp);
    return uuid;
}

// 获取目录中所有UUID的列表
static int32_t GetAllUuidsFromDirectory(const char *directory, char **uuidList, int maxCount)
{
    struct dirent *entry;
    DIR *dp = opendir(directory);
    if (dp == NULL) {
        return 0;
    }
    
    int count = 0;
    while ((entry = readdir(dp)) && count < maxCount) {
        if (entry->d_type == DT_REG && has_suffix(entry->d_name, SUFFIX)) {
            uint32_t len = strlen(entry->d_name) - strlen(SUFFIX) + 1;
            uuidList[count] = BSL_SAL_Malloc(len);
            if (uuidList[count] == NULL) {
                // 内存分配失败，清理已分配的内存
                for (int i = 0; i < count; i++) {
                    BSL_SAL_FREE(uuidList[i]);
                }
                closedir(dp);
                return -1;
            }
            (void)memcpy_s(uuidList[count], len, entry->d_name, len - 1);
            uuidList[count][len - 1] = '\0';
            count++;
        }
    }
    closedir(dp);
    return count;
}

static int32_t TEST_APP_SM_Init(AppProvider *provider, HITLS_APP_SM_Param *smParam)
{
    int32_t ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM4_CTR_DF, HITLS_SM_PROVIDER_ATTR,
        NULL, 0, NULL);
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    ret = HITLS_APP_SM_Init(provider, smParam->workPath, (char **)&smParam->password, &smParam->status);
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    if (ret != HITLS_APP_SUCCESS) {
        return ret;
    }
    smParam->passwordLen = strlen((char *)smParam->password);
    return HITLS_APP_SUCCESS;
}

typedef struct {
    int fd;
} TLCP_Context;

static int32_t TLCP_Send_Init(void *ctx)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    (void)memset_s(tlcpCtx, sizeof(TLCP_Context), 0, sizeof(TLCP_Context));
    int fd = open(SYNC_DATA_FILE, O_WRONLY | O_CREAT, 0644);
    if (fd == -1) {
        AppPrintError("open %s failed, ret: 0x%08x\n", SYNC_DATA_FILE, fd);
        return HITLS_APP_ERROR;
    }
    tlcpCtx->fd = fd;
    return HITLS_APP_SUCCESS;
}

static int32_t TLCP_Receive_Init(void *ctx)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    (void)memset_s(tlcpCtx, sizeof(TLCP_Context), 0, sizeof(TLCP_Context));
    int fd = open(SYNC_DATA_FILE, O_RDONLY);
    if (fd == -1) {
        AppPrintError("open %s failed, ret: 0x%08x\n", SYNC_DATA_FILE, fd);
        return HITLS_APP_ERROR;
    }
    tlcpCtx->fd = fd;
    return HITLS_APP_SUCCESS;
}

// transport stubs (to be replaced by TLCP integration)
static int32_t TLCP_Send(void *ctx, const void *data, uint32_t len)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    int ret = write(tlcpCtx->fd, data, len);
    if (ret < 0 || (uint32_t)ret != len) {
        AppPrintError("write %s failed, ret: %d\n", SYNC_DATA_FILE, ret);
        return HITLS_APP_ERROR;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t TLCP_Receive(void *ctx, void *data, uint32_t len)
{
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    int ret = read(tlcpCtx->fd, data, len);
    if (ret < 0 || (uint32_t)ret != len) {
        AppPrintError("read %s failed, ret: %d\n", SYNC_DATA_FILE, ret);
        return HITLS_APP_ERROR;
    }
    return HITLS_APP_SUCCESS;
}

static void TLCP_Deinit(void *ctx)
{
    if (ctx == NULL) {
        return;
    }
    TLCP_Context *tlcpCtx = (TLCP_Context *)ctx;
    close(tlcpCtx->fd);
    (void)memset_s(tlcpCtx, sizeof(TLCP_Context), 0, sizeof(TLCP_Context));
}

static int32_t CreateFile(const char *file)
{
    FILE *fp = fopen(file, "w");
    if (fp == NULL) {
        return HITLS_APP_ERROR;
    }
    fprintf(fp, "01234567890123456789");
    fclose(fp);
    return HITLS_APP_SUCCESS;
}

static int32_t CompareFile(const char *file1, const char *file2)
{
    FILE *fp1 = fopen(file1, "rb");
    FILE *fp2 = fopen(file2, "rb");
    if (fp1 == NULL || fp2 == NULL) {
        if (fp1 != NULL) fclose(fp1);
        if (fp2 != NULL) fclose(fp2);
        return HITLS_APP_ERROR;
    }
    int result = HITLS_APP_SUCCESS;
    char buf1[1024];
    char buf2[1024];
    size_t bytesRead1, bytesRead2;
    do {
        bytesRead1 = fread(buf1, 1, sizeof(buf1), fp1);
        bytesRead2 = fread(buf2, 1, sizeof(buf2), fp2);
        if (bytesRead1 != bytesRead2 || memcmp(buf1, buf2, bytesRead1) != 0) {
            result = HITLS_APP_ERROR;
            break;
        }
    } while (bytesRead1 > 0 && bytesRead2 > 0);
    fclose(fp1);
    fclose(fp2);
    return result;
}

static int32_t EncryptAndDecrypt(char *uuid, char *cipher)
{
    char *inFile = WORK_PATH "/test.txt";
    char *outFile = WORK_PATH "/test.txt.cipher";
    char *outFile2 = WORK_PATH "/test.txt.out";

    char *argv[][20] = {
        {"enc", "-enc", "-cipher", cipher, "-uuid", uuid, "-in", inFile, "-out", outFile, SM_PARAM},
        {"enc", "-dec", "-cipher", cipher, "-uuid", uuid, "-in", outFile, "-out", outFile2, SM_PARAM},
    };

    int ret = CreateFile(inFile);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_EncMain(sizeof(argv[0]) / sizeof(argv[0][0]) - 1, argv[0]);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_EncMain(sizeof(argv[1]) / sizeof(argv[1][0]) - 1, argv[1]);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CompareFile(inFile, outFile2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    system("rm -f " WORK_PATH "/test.txt");
    system("rm -f " WORK_PATH "/test.txt.cipher");
    system("rm -f " WORK_PATH "/test.txt.out");

EXIT:
    return ret;
}

static int32_t CalculateMac(char *uuid, char *algId)
{
    char *inFile = WORK_PATH "/test.txt";
    char *outFile = WORK_PATH "/test.txt.mac";

    char *argv[][19] = {
        {"mac", "-name", algId, "-uuid", uuid, SM_PARAM, "-in", inFile, "-out", outFile},
    };

    int ret = CreateFile(inFile);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_MacMain(sizeof(argv[0]) / sizeof(argv[0][0]) - 1, argv[0]);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    system("rm -f " WORK_PATH "/test.txt");
    system("rm -f " WORK_PATH "/test.txt.mac");

EXIT:
    return ret;
}

static void DeleteKey(char *uuid)
{
    if (uuid == NULL) {
        return;
    }
    char *argv[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuid, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    return;
}
#endif

/**
 * @test UT_HITLS_APP_KEYMGMT_TC001
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 创建、查找sm4密钥场景
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC001(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *uuid = NULL;
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    ret = EncryptAndDecrypt(uuid, "sm4_cbc");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_ecb");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_ctr");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_cfb");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_ofb");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = EncryptAndDecrypt(uuid, "sm4_gcm");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC002
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 创建、查找sm4_xts密钥场景
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC002(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *uuid = NULL;
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4_xts", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    ret = EncryptAndDecrypt(uuid, "sm4_xts");
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

#ifdef HITLS_APP_SM_MODE
static int32_t AsymSignAndVerify(CRYPT_EAL_PkeyCtx *pkeyCtx)
{
    uint8_t data[4] = {0, 1, 2, 3};
    uint32_t dataLen = sizeof(data);
    uint8_t sign[1024] = {0};
    uint32_t signLen = sizeof(sign);

    int32_t ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM3, HITLS_SM_PROVIDER_ATTR, NULL, 0, NULL);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeySign(pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, &signLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, signLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    return ret;
}
#endif

/**
 * @test UT_HITLS_APP_KEYMGMT_TC003
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 创建、查找sm2密钥场景
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC003(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};
    HITLS_APP_KeyInfo keyInfo = {0};

    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = AsymSignAndVerify(keyInfo.pkeyCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_KEYMGMT_TC004
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 创建密钥时传入不支持的算法id, 返回失败
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC004(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *argv[] = {"keymgmt", "-create", "-algid", "aes128_cbc", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);
EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC005
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 参数异常场景，返回失败
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC005(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // 测试1: 缺少操作参数(-create 或 -delete)
    char *argv1[] = {"keymgmt", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv1) / sizeof(argv1[0]) - 1, argv1);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // 测试2: 缺少-sm参数
    char *argv2[] = {"keymgmt", "-create", "-algid", "sm2", "-workpath", WORK_PATH, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // 测试3: 缺少-workpath参数
    char *argv3[] = {"keymgmt", "-create", "-algid", "sm2", "-sm", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv3) / sizeof(argv3[0]) - 1, argv3);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // 测试4: 缺少-algid参数(创建密钥时)
    char *argv4[] = {"keymgmt", "-create", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv4) / sizeof(argv4[0]) - 1, argv4);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // 测试5: 缺少-uuid参数(删除密钥时)
    char *argv5[] = {"keymgmt", "-delete", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv5) / sizeof(argv5[0]) - 1, argv5);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // 测试6: 同时指定-create和-delete(冲突操作)
    char *argv6[] = {"keymgmt", "-create", "-delete", "-algid", "sm2", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv6) / sizeof(argv6[0]) - 1, argv6);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    // 测试7: 空参数列表
    char *argv7[] = {"keymgmt", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv7) / sizeof(argv7[0]) - 1, argv7);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC006
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 传入的派生参数不符合要求，返回失败
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC006(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // 测试1: 传入的派生参数不符合要求
    char *argv1[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-iter", "1023", NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv1) / sizeof(argv1[0]) - 1, argv1);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    char *argv2[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-iter", "-1024", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_OPT_UNKOWN);

    // 测试2: 传入的盐值长度不符合要求
    char *argv3[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-saltlen", "7", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv3) / sizeof(argv3[0]) - 1, argv3);
    ASSERT_EQ(ret, HITLS_APP_OPT_VALUE_INVALID);

    char *argv4[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, "-saltlen", "-8", NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv4) / sizeof(argv4[0]) - 1, argv4);
    ASSERT_EQ(ret, HITLS_APP_OPT_UNKOWN);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC007
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试删除密钥，传入单个uuid，正常删除
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC007(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *uuid = NULL;
    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // 首先创建一个密钥
    char *argv_create[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_create) / sizeof(argv_create[0]) - 1, argv_create);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 获取创建的密钥UUID
    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    // 验证密钥文件存在
    char keyPath[256];
    snprintf(keyPath, sizeof(keyPath), "%s/%s.p12", WORK_PATH, uuid);
    FILE *fp = fopen(keyPath, "r");
    ASSERT_TRUE(fp != NULL);
    fclose(fp);

    // 测试删除密钥 - 传入单个UUID
    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuid, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 验证密钥文件已被删除
    fp = fopen(keyPath, "r");
    ASSERT_TRUE(fp == NULL);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_KEYMGMT_TC008
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试删除密钥，传入单个uuid，uuid对应密钥不存在，返回失败
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC008(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // 测试删除不存在的密钥 - 传入一个随机生成的UUID
    char fakeUuid[] = "1234567890abcdef1234567890abcdef";
    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", fakeUuid, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);
    
    // 应该返回失败，因为密钥不存在
    ASSERT_NE(ret, HITLS_APP_SUCCESS);

    // 验证工作目录中确实没有对应的密钥文件
    char keyPath[256];
    snprintf(keyPath, sizeof(keyPath), "%s/%s.p12", WORK_PATH, fakeUuid);
    FILE *fp = fopen(keyPath, "r");
    ASSERT_TRUE(fp == NULL);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC009
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试删除密钥，传入多个uuid，正常删除
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC009(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);
    char *uuid1 = NULL;
    char *uuidArray[10] = {NULL};
    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // 创建第一个密钥
    char *argv_create1[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_create1) / sizeof(argv_create1[0]) - 1, argv_create1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 创建第二个密钥
    char *argv_create2[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_create2) / sizeof(argv_create2[0]) - 1, argv_create2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 获取创建的密钥UUID列表
    uuid1 = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid1 != NULL);
    
    // 获取目录中所有UUID的列表
    int uuidCount = GetAllUuidsFromDirectory(WORK_PATH, uuidArray, 10);
    ASSERT_EQ(uuidCount, 2); // 应该有两个密钥
    
    // 找到与uuid1不同的UUID
    char *uuid2 = NULL;
    for (int i = 0; i < uuidCount; i++) {
        if (strcmp(uuidArray[i], uuid1) != 0) {
            uuid2 = uuidArray[i];
            break;
        }
    }
    ASSERT_TRUE(uuid2 != NULL);

    // 验证两个密钥文件都存在
    char keyPath1[256], keyPath2[256];
    snprintf(keyPath1, sizeof(keyPath1), "%s/%s.p12", WORK_PATH, uuid1);
    snprintf(keyPath2, sizeof(keyPath2), "%s/%s.p12", WORK_PATH, uuid2);
    
    FILE *fp1 = fopen(keyPath1, "r");
    ASSERT_TRUE(fp1 != NULL);
    fclose(fp1);
    FILE *fp2 = fopen(keyPath2, "r");
    ASSERT_TRUE(fp2 != NULL);
    fclose(fp2);

    // 测试删除多个密钥 - 传入多个UUID（用逗号分隔）
    char uuidList[256];
    snprintf(uuidList, sizeof(uuidList), "%s,%s", uuid1, uuid2);
    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuidList, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 验证两个密钥文件都已被删除
    fp1 = fopen(keyPath1, "r");
    fp2 = fopen(keyPath2, "r");
    ASSERT_TRUE(fp1 == NULL);
    ASSERT_TRUE(fp2 == NULL);

EXIT:
    BSL_SAL_FREE(uuid1);
    // 释放uuidArray中分配的内存
    for (int i = 0; i < 10; i++) {
        if (uuidArray[i] != NULL) {
            BSL_SAL_FREE(uuidArray[i]);
        }
    }
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC010
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试删除密钥，传入多个uuid，部分uuid对应密钥不存在，返回失败，按顺序会删除部分密钥
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC010(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    // 创建第一个密钥
    char *argv_create1[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};
    int ret = HITLS_KeyMgmtMain(sizeof(argv_create1) / sizeof(argv_create1[0]) - 1, argv_create1);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 获取创建的密钥UUID
    char *uuid1 = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid1 != NULL);

    // 验证密钥文件存在
    char keyPath1[256];
    snprintf(keyPath1, sizeof(keyPath1), "%s/%s.p12", WORK_PATH, uuid1);
    FILE *fp1 = fopen(keyPath1, "r");
    ASSERT_TRUE(fp1 != NULL);
    fclose(fp1);

    // 构造一个包含存在和不存在的UUID列表
    char fakeUuid[] = "1234567890abcdef1234567890abcdef";
    char uuidList[256];
    // 注意：将存在的UUID放在前面，不存在的放在后面，这样测试可以验证按顺序删除的逻辑
    snprintf(uuidList, sizeof(uuidList), "%s,%s", uuid1, fakeUuid);

    char *argv_delete[] = {"keymgmt", "-delete", SM_PARAM, "-uuid", uuidList, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv_delete) / sizeof(argv_delete[0]) - 1, argv_delete);

    // 应该返回失败，因为部分UUID对应的密钥不存在
    ASSERT_NE(ret, HITLS_APP_SUCCESS);

    // 验证存在的密钥文件已被删除（因为它在列表前面，会先被处理）
    fp1 = fopen(keyPath1, "r");
    ASSERT_TRUE(fp1 == NULL);

    // 验证不存在的密钥文件确实不存在
    char keyPath2[256];
    snprintf(keyPath2, sizeof(keyPath2), "%s/%s.p12", WORK_PATH, fakeUuid);
    FILE *fp2 = fopen(keyPath2, "r");
    ASSERT_TRUE(fp2 == NULL);

EXIT:
    BSL_SAL_FREE(uuid1);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */


/**
 * @test UT_HITLS_APP_KEYMGMT_TC011
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试查找密钥接口，传入uuid，查找sm4-ofb算法密钥，返回成功，keyLen等于16，传入sm4_xts算法，
 * 返回失败
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC011(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // 创建sm4密钥而不是sm2密钥
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 查找sm4-ofb密钥
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_OFB, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 验证密钥信息
    ASSERT_TRUE(keyInfo.key != NULL);
    ASSERT_EQ(keyInfo.keyLen, 16); // sm4密钥长度应该是16字节

    // 查找sm4_xts密钥，返回失败
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_XTS, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_KEY_NOT_SUPPORTED);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC012
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试查找密钥接口，传入uuid，查找sm4_xts算法密钥，返回成功，keyLen等于16，传入sm4-ofb算法，
 * 返回失败
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC012(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // 创建sm4密钥而不是sm2密钥
    char *argv[] = {"keymgmt", "-create", "-algid", "sm4_xts", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 查找sm4_xts密钥
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_XTS, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 验证密钥信息
    ASSERT_TRUE(keyInfo.key != NULL);
    ASSERT_EQ(keyInfo.keyLen, 32); // sm4_xts密钥长度应该是32字节

    // 查找sm4-ofb密钥，返回失败
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_CIPHER_SM4_OFB, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_KEY_NOT_SUPPORTED);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC013
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试创建mac密钥，调用mac命令行计算mac，返回成功
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC013(char *macAlgId)
{
#ifndef HITLS_APP_SM_MODE
    (void)macAlgId;
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *uuid = NULL;
    char *argv[] = {"keymgmt", "-create", "-algid", macAlgId, SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(uuid != NULL);

    ret = CalculateMac(uuid, macAlgId);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    BSL_SAL_FREE(uuid);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC014
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试查找密钥接口，传入uuid，查找mac算法密钥，返回成功, keyLen等于对应算法keyLen
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC014(int algId, char *macAlgId, int keyLen)
{
#ifndef HITLS_APP_SM_MODE
    (void)algId;
    (void)macAlgId;
    (void)keyLen;
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // 创建mac密钥
    char *argv[] = {"keymgmt", "-create", "-algid", macAlgId, SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 查找mac密钥
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, algId, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 验证密钥信息
    ASSERT_TRUE(keyInfo.key != NULL);
    ASSERT_EQ(keyInfo.keyLen, keyLen);
    ASSERT_EQ(keyInfo.attr.algId, algId);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC015
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试查找密钥接口，传入uuid，查找sm2算法密钥，返回成功, pkeyCtx不为空
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC015(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    HITLS_APP_KeyInfo keyInfo = {0};
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // 创建sm2密钥
    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 查找sm2密钥
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 验证密钥信息
    ASSERT_TRUE(keyInfo.pkeyCtx != NULL); // 关键验证：pkeyCtx不为空
    ASSERT_EQ(keyInfo.attr.algId, CRYPT_PKEY_SM2);

    // 测试SM2密钥的签名和验证功能
    ret = AsymSignAndVerify(keyInfo.pkeyCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC016
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试查找密钥接口，传入uuid，查找sm2算法密钥，传入错误的口令，pkcs12解密失败
 */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC016(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};

    // 创建sm2密钥
    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    HITLS_APP_KeyInfo keyInfo = {0};
    
    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    // 使用错误的口令尝试解密PKCS12：将已获取的正确口令改写成错误口令
    smParam.password[0] = ~smParam.password[0];

    // 查找sm2密钥应失败（PKCS12解密失败）
    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_CRYPTO_FAIL);

EXIT:
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC017(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    uint8_t data[4] = {0, 1, 2, 3};
    uint32_t dataLen = sizeof(data);
    uint8_t sign[1024] = {0};
    uint32_t signLen = sizeof(sign);
    HITLS_APP_SM_Param smParam = {NULL, 0, WORK_PATH, NULL, 0, HITLS_APP_SM_STATUS_CLOSE};
    HITLS_APP_KeyInfo keyInfo = {0};
    char *argv[] = {"keymgmt", "-create", "-algid", "sm2", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    smParam.uuid = GetUuidFromP12(WORK_PATH);
    ASSERT_TRUE(smParam.uuid != NULL);

    ret = TEST_APP_SM_Init(&g_appProvider, &smParam);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM3, "provider=sm", NULL, 0, NULL);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeySign(keyInfo.pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, &signLen);
    CRYPT_EAL_RandDeinitEx(APP_GetCurrent_LibCtx());
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    (void)memset_s(&keyInfo, sizeof(keyInfo), 0, sizeof(keyInfo));

    TLCP_Context tlcpCtx = {0};
    ret = TLCP_Send_Init(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);
    ret = HITLS_APP_SendKey(&g_appProvider, &smParam, TLCP_Send, &tlcpCtx);
    TLCP_Deinit(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    DeleteKey(smParam.uuid);

    ret = TLCP_Receive_Init(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_ProviderRandInitCtx(NULL, CRYPT_RAND_SM3, "provider=default", NULL, 0, NULL);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_ReceiveKey(&g_appProvider, &smParam, -1, -1, TLCP_Receive, &tlcpCtx);
    TLCP_Deinit(&tlcpCtx);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_APP_FindKey(&g_appProvider, &smParam, CRYPT_PKEY_SM2, &keyInfo);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = CRYPT_EAL_PkeyVerify(keyInfo.pkeyCtx, CRYPT_MD_SM3, data, dataLen, sign, signLen);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    CRYPT_EAL_PkeyFreeCtx(keyInfo.pkeyCtx);
    CRYPT_EAL_RandDeinitEx(NULL);
    BSL_SAL_FREE(smParam.uuid);
    BSL_SAL_FREE(smParam.password);
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC018
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试删除全量密钥接口，返回成功
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC018(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *argv[] = {"keymgmt", "-create", "-algid", "sm4", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

    char *argv2[] = {"keymgmt", "-erasekey", SM_PARAM, NULL};
    ret = HITLS_KeyMgmtMain(sizeof(argv2) / sizeof(argv2[0]) - 1, argv2);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC019
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试获取状态接口，返回成功
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC019(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *argv[] = {"keymgmt", "-getstatus", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC020
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试获取版本号接口，返回成功
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC020(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *argv[] = {"keymgmt", "-getversion", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_KEYMGMT_TC021
 * @spec  -
 * @title  测试命令行二级命令keymgmt, 测试自检接口，返回成功
 */
/* BEGIN_CASE */
void UT_HITLS_APP_KEYMGMT_TC021(void)
{
#ifndef HITLS_APP_SM_MODE
    SKIP_TEST();
#else
    STUB_Init();
    FuncStubInfo stubInfo[2] = {0};
    STUB_Replace(&stubInfo[0], BSL_UI_ReadPwdUtil, STUB_BSL_UI_ReadPwdUtil);
    STUB_Replace(&stubInfo[1], HITLS_APP_SM_IntegrityCheck, STUB_HITLS_APP_SM_IntegrityCheck);

    char *argv[] = {"keymgmt", "-selftest", SM_PARAM, NULL};

    ASSERT_EQ(AppTestInit(), HITLS_APP_SUCCESS);

    int ret = HITLS_KeyMgmtMain(sizeof(argv) / sizeof(argv[0]) - 1, argv);
    ASSERT_EQ(ret, HITLS_APP_SUCCESS);

EXIT:
    AppTestUninit();
    STUB_Reset(&stubInfo[0]);
    STUB_Reset(&stubInfo[1]);
#endif
}
/* END_CASE */
