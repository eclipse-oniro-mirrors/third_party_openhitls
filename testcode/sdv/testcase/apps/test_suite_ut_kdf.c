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
#include "app_kdf.h"
#include "app_print.h"
#include "app_provider.h"
#include "crypt_eal_kdf.h"
#include "bsl_sal.h"
#include "securec.h"
#include "bsl_errno.h"
#include "crypt_errno.h"
#include "stub_replace.h"
/* END_HEADER */

/* INCLUDE_SOURCE  ${HITLS_ROOT_PATH}/apps/src/app_print.c ${HITLS_ROOT_PATH}/apps/src/app_kdf.c ${HITLS_ROOT_PATH}/apps/src/app_opt.c */

#define OUT_FILE_PATH "out_kdf.bin"

typedef struct {
    int argc;
    char **argv;
    int expect;
} OptTestData;

/**
 * @test UT_HITLS_APP_kdf_TC001
 * @spec  -
 * @title  kdf命令行正常命令测试
 */
/* BEGIN_CASE */
void UT_HITLS_APP_kdf_TC001(void)
{
    char *argv[][20] = {
        // hmac-sha256 普通参数
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-keylen", "32",
            "-iter", "1000", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-keylen", "32",
            "-iter", "1000", "-out", OUT_FILE_PATH, "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-keylen", "32",
            "-iter", "1000", "-binary", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-keylen", "32",
            "-iter", "1000", "-binary", "-out", OUT_FILE_PATH, "pbkdf2"},
        // hmac-sha1 + hexpass + hexsalt
        {"kdf", "-mac", "hmac-sha1", "-hexpass", "0x70617373776f7264", "-hexsalt", "0x73616c74",
            "-keylen", "20", "-iter", "1", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha1", "-hexpass", "0x70617373776f7264", "-hexsalt", "0x73616c74",
            "-keylen", "20", "-iter", "1", "-out", OUT_FILE_PATH, "pbkdf2"},
        {"kdf", "-mac", "hmac-sha1", "-pass", "0x70617373776f7264", "-hexsalt", "0x73616c74",
            "-keylen", "20", "-iter", "1", "-binary", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha1", "-hexpass", "0x70617373776f7264", "-salt", "0x73616c74",
            "-keylen", "20", "-iter", "1", "-binary", "-out", OUT_FILE_PATH, "pbkdf2"},
        // hmac-sha512 + hexpass + hexsalt
        {"kdf", "-mac", "hmac-sha512", "-hexpass", "0x70617373776f7264", "-hexsalt", "0x73616c74",
            "-keylen", "64", "-iter", "2", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha512", "-hexpass", "0x70617373776f7264", "-hexsalt", "0x73616c74",
            "-keylen", "64", "-iter", "2", "-out", OUT_FILE_PATH, "pbkdf2"},
        {"kdf", "-mac", "hmac-sha512", "-hexpass", "0x70617373776f7264", "-hexsalt", "0x73616c74",
            "-keylen", "64", "-iter", "2", "-binary", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha512", "-hexpass", "0x70617373776f7264", "-hexsalt", "0x73616c74",
            "-keylen", "64", "-iter", "2", "-binary", "-out", OUT_FILE_PATH, "pbkdf2"},
    };
    OptTestData testData[] = {
        {12, argv[0], HITLS_APP_SUCCESS},
        {14, argv[1], HITLS_APP_SUCCESS},
        {13, argv[2], HITLS_APP_SUCCESS},
        {15, argv[3], HITLS_APP_SUCCESS},
        {12, argv[4], HITLS_APP_SUCCESS},
        {14, argv[5], HITLS_APP_SUCCESS},
        {13, argv[6], HITLS_APP_SUCCESS},
        {15, argv[7], HITLS_APP_SUCCESS},
        {12, argv[8], HITLS_APP_SUCCESS},
        {14, argv[9], HITLS_APP_SUCCESS},
        {13, argv[10], HITLS_APP_SUCCESS},
        {15, argv[11], HITLS_APP_SUCCESS},
    };
    if (APP_GetCurrent_LibCtx() == NULL) {
        if (APP_Create_LibCtx() == NULL) {
            (void)AppPrintError("Create g_libCtx failed\n");
        }
    }
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_KdfMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_kdf_TC002
 * @spec  -
 * @title   测试UT_HITLS_APP_kdf_TC002函数
 */
/* BEGIN_CASE */
void UT_HITLS_APP_kdf_TC002(void)
{
    char *argv[][2] = {
        {"kdf", "-help"},
    };
    OptTestData testData[] = {
        {2, argv[0], HITLS_APP_HELP},
    };
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_KdfMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */

/**
 * @test UT_HITLS_APP_kdf_TC003
 * @spec  -
 * @title   KDF异常参数测试
 */
/* BEGIN_CASE */
void UT_HITLS_APP_kdf_TC003(void)
{
    char *argv[][20] = {
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-keylen", "32",
            "-iter", "1000"},
        {"kdf", "unknownalg", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef",
            "-keylen", "32", "-iter", "1000"},
        {"kdf", "-mac", "unknownmac", "-pass", "123456", "-salt", "abcdef", "-keylen", "32",
            "-iter", "1000", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-hexpass", "70617373776f7264", "-salt", "abcdef",
            "-keylen", "32", "-iter", "1000", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-hexsalt", "73616c74", "-keylen", "32",
            "-iter", "1000", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-hexpass", "0x1234", "-salt", "abcdef",
            "-keylen", "32", "-iter", "1000", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-hexsalt", "0x1234",
            "-keylen", "32", "-iter", "1000", "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-iter", "1000",
            "pbkdf2"},
        {"kdf", "-mac", "hmac-sha256", "-pass", "123456", "-salt", "abcdef", "-keylen", "32",
            "-iter", "1000", "-keylen", "32", "pbkdf2"}
    };
    OptTestData testData[] = {
        {11, argv[0], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[1], HITLS_APP_OPT_UNKOWN},
        {12, argv[2], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[3], HITLS_APP_OPT_VALUE_INVALID},
        {12, argv[4], HITLS_APP_OPT_VALUE_INVALID},
        {14, argv[5], HITLS_APP_OPT_VALUE_INVALID},
        {14, argv[6], HITLS_APP_OPT_VALUE_INVALID},
        {10, argv[7], HITLS_APP_OPT_VALUE_INVALID},
        {15, argv[8], HITLS_APP_OPT_UNKOWN}
    };
    ASSERT_EQ(AppPrintErrorUioInit(stderr), HITLS_APP_SUCCESS);
    for (int i = 0; i < (int)(sizeof(testData) / sizeof(OptTestData)); ++i) {
        int ret = HITLS_KdfMain(testData[i].argc, testData[i].argv);
        ASSERT_EQ(ret, testData[i].expect);
    }
EXIT:
    AppPrintErrorUioUnInit();
    return;
}
/* END_CASE */