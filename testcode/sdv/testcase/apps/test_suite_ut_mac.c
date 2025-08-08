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
#include "string.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_mac.h"
#include "app_print.h"
#include "app_provider.h"
#include "crypt_eal_mac.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "stub_replace.h"
/* END_HEADER */

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_mac.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */
#define IN_FILE_PATH "test.txt"
#define OUT_FILE_PATH "out_mac.bin"

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/**
 * @test UT_HITLS_APP_mac_TC001
 * @spec  -
 * @title   测试UT_HITLS_APP_mac_TC001函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_mac_TC001(void)
{
    system("echo 123456 > test.txt");
    char *argv[][20] = {
        {"mac", "-name", "hmac-sha256", "-key", "123456", "-out", OUT_FILE_PATH, "-in", IN_FILE_PATH},
        {"mac", "-name", "hmac-sha256", "-key", "123456", "-out", OUT_FILE_PATH, "-in", IN_FILE_PATH, "-binary"},
        {"mac", "-name", "hmac-md5", "-hexkey", "0x4a656665", "-in", IN_FILE_PATH},
    };
    OptTestData testData[] = {
        {9, argv[0], HITLS_APP_SUCCESS},
        {10, argv[1], HITLS_APP_SUCCESS},
        {7, argv[2], HITLS_APP_SUCCESS},
    };
    if (APP_GetCurrent_LibCtx() == NULL) {
        if (APP_Create_LibCtx() == NULL) {
            (void)AppPrintError("Create g_libCtx failed\n");
        }
    }
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_MacMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_mac_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_mac_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_mac_TC002(void)
{
    char *argv[][10] = {
        {"mac", "-help"},
    };
    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_MacMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_mac_TC003
 * @spec  -
 * @title   MAC命令异常参数测试
 */
/* BEGIN_CASE */
void UT_HITLS_APP_mac_TC003(void)
{
    char *argv[][20] = {
        {"mac", "-name", "hmac-sha256", "-out", OUT_FILE_PATH, "-in", IN_FILE_PATH}, // 无key
        {"mac", "-name", "hmac-md5", "-hexkey", "123456", "-in", IN_FILE_PATH}, // hexkey格式错误
        {"mac", "-name", "hmac-sha256", "-key", "-out", OUT_FILE_PATH, "-in", IN_FILE_PATH}, // key为空
        {"mac", "-name", "hmac-sha256", "-key", "123456", "-out", OUT_FILE_PATH, "-in", "not_exist.txt"}, // 输入文件不存在
        {"mac", "-name", "hmac-sha256", "-key", "123456", "-hexkey", "0x123456", "-out",
            OUT_FILE_PATH, "-in", IN_FILE_PATH}, // key,hexkey同在
    };
    OptTestData testData[] = {
        {7, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {7, argv[1], HITLS_APP_CRYPTO_FAIL},
        {8, argv[2], HITLS_APP_OPT_UNKOWN},
        {9, argv[3], HITLS_APP_UIO_FAIL},
        {11, argv[4], HITLS_APP_OPT_VALUE_INVALID},
    };
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_MacMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */
