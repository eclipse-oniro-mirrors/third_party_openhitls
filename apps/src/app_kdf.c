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

#include "app_kdf.h"
#include <linux/limits.h>
#include "string.h"
#include "securec.h"
#include "bsl_sal.h"
#include "crypt_errno.h"
#include "crypt_eal_kdf.h"
#include "crypt_params_key.h"
#include "bsl_errno.h"
#include "bsl_params.h"
#include "app_opt.h"
#include "app_function.h"
#include "app_list.h"
#include "app_errno.h"
#include "app_help.h"
#include "app_print.h"
#include "app_provider.h"
#include "app_utils.h"

typedef enum OptionChoice {
    HITLS_APP_OPT_KDF_ERR = -1,
    HITLS_APP_OPT_KDF_EOF = 0,
    HITLS_APP_OPT_KDF_ALG = HITLS_APP_OPT_KDF_EOF,
    HITLS_APP_OPT_KDF_HELP = 1,  // The value of the help type of each opt option is 1. The following can be customized.
    HITLS_APP_OPT_KDF_KEYLEN,
    HITLS_APP_OPT_KDF_MAC_ALG,
    HITLS_APP_OPT_KDF_OUT,
    HITLS_APP_OPT_KDF_PASS,
    HITLS_APP_OPT_KDF_HEXPASS,
    HITLS_APP_OPT_KDF_SALT,
    HITLS_APP_OPT_KDF_HEXSALT,
    HITLS_APP_OPT_KDF_ITER,
    HITLS_APP_OPT_KDF_BINARY,
    HITLS_APP_PROV_ENUM
} HITLSOptType;

const HITLS_CmdOption g_kdfOpts[] = {
    {"help", HITLS_APP_OPT_KDF_HELP, HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Show usage information for KDF command."},
    {"mac", HITLS_APP_OPT_KDF_MAC_ALG, HITLS_APP_OPT_VALUETYPE_STRING,
        "Specify MAC algorithm used in KDF (e.g.: hmac-sha256)."},
    {"out", HITLS_APP_OPT_KDF_OUT, HITLS_APP_OPT_VALUETYPE_OUT_FILE,
        "Set output file for derived key (default: stdout, hex format)."},
    {"binary", HITLS_APP_OPT_KDF_BINARY, HITLS_APP_OPT_VALUETYPE_NO_VALUE,
        "Output derived key in binary format."},
    {"keylen", HITLS_APP_OPT_KDF_KEYLEN, HITLS_APP_OPT_VALUETYPE_UINT, "Length of derived key in bytes."},
    {"pass", HITLS_APP_OPT_KDF_PASS, HITLS_APP_OPT_VALUETYPE_STRING, "Input password as a string."},
    {"hexpass", HITLS_APP_OPT_KDF_HEXPASS, HITLS_APP_OPT_VALUETYPE_STRING,
        "Input password in hexadecimal format (e.g.: 0x1234ABCD)."},
    {"salt", HITLS_APP_OPT_KDF_SALT, HITLS_APP_OPT_VALUETYPE_STRING, "Input salt as a string."},
    {"hexsalt", HITLS_APP_OPT_KDF_HEXSALT, HITLS_APP_OPT_VALUETYPE_STRING,
        "Input salt in hexadecimal format (e.g.: 0xAABBCCDD)."},
    {"iter", HITLS_APP_OPT_KDF_ITER, HITLS_APP_OPT_VALUETYPE_UINT, "Number of iterations for KDF computation."},
    HITLS_APP_PROV_OPTIONS,
    {"kdfalg...", HITLS_APP_OPT_KDF_ALG, HITLS_APP_OPT_VALUETYPE_STRING, "Specify KDF algorithm (e.g.: pbkdf2)."},
    {NULL}};

typedef struct {
    int32_t macId;
    char *kdfName;
    int32_t kdfId;
    uint32_t keyLen;
    char *outFile;
    char *pass;
    char *hexPass;
    char *salt;
    char *hexSalt;
    uint32_t iter;
    AppProvider *provider;
    uint32_t isBinary;
} KdfOpt;

typedef int32_t (*KdfOptHandleFunc)(KdfOpt *);

typedef struct {
    int optType;
    KdfOptHandleFunc func;
} KdfOptHandleFuncMap;

static int32_t HandleKdfErr(KdfOpt *kdfOpt)
{
    (void)kdfOpt;
    AppPrintError("kdf: Use -help for summary.\n");
    return HITLS_APP_OPT_UNKOWN;
}

static int32_t HandleKdfHelp(KdfOpt *kdfOpt)
{
    (void)kdfOpt;
    HITLS_APP_OptHelpPrint(g_kdfOpts);
    return HITLS_APP_HELP;
}

static int32_t HandleKdfOut(KdfOpt *kdfOpt)
{
    kdfOpt->outFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int32_t HandleKdfPass(KdfOpt *kdfOpt)
{
    kdfOpt->pass = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfHexPass(KdfOpt *kdfOpt)
{
    kdfOpt->hexPass = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfSalt(KdfOpt *kdfOpt)
{
    kdfOpt->salt = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfHexSalt(KdfOpt *kdfOpt)
{
    kdfOpt->hexSalt = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfIter(KdfOpt *kdfOpt)
{
    int32_t ret = HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), &(kdfOpt->iter));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("kdf: Invalid iter value.\n");
    }
    return ret;
}

static int32_t HandleKdfKeyLen(KdfOpt *kdfOpt)
{
    int32_t ret = HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), &(kdfOpt->keyLen));
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("kdf: Invalid keylen value.\n");
    }
    return ret;
}

static int32_t HandleKdfBinary(KdfOpt *kdfOpt)
{
    kdfOpt->isBinary = 1;
    return HITLS_APP_SUCCESS;
}

static int32_t HandleKdfMacAlg(KdfOpt *kdfOpt)
{
    char *macName = HITLS_APP_OptGetValueStr();
    if (macName == NULL) {
        AppPrintError("kdf: MAC algorithm is NULL.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    kdfOpt->macId = HITLS_APP_GetCidByName(macName, HITLS_APP_LIST_OPT_MAC_ALG);
    if (kdfOpt->macId == BSL_CID_UNKNOWN) {
        AppPrintError("kdf: Unsupported MAC algorithm: %s\n", macName);
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    return HITLS_APP_SUCCESS;
}

static const KdfOptHandleFuncMap g_kdfOptHandleFuncMap[] = {
    {HITLS_APP_OPT_KDF_ERR, HandleKdfErr},
    {HITLS_APP_OPT_KDF_HELP, HandleKdfHelp},
    {HITLS_APP_OPT_KDF_OUT, HandleKdfOut},
    {HITLS_APP_OPT_KDF_PASS, HandleKdfPass},
    {HITLS_APP_OPT_KDF_HEXPASS, HandleKdfHexPass},
    {HITLS_APP_OPT_KDF_SALT, HandleKdfSalt},
    {HITLS_APP_OPT_KDF_HEXSALT, HandleKdfHexSalt},
    {HITLS_APP_OPT_KDF_ITER, HandleKdfIter},
    {HITLS_APP_OPT_KDF_KEYLEN, HandleKdfKeyLen},
    {HITLS_APP_OPT_KDF_MAC_ALG, HandleKdfMacAlg},
    {HITLS_APP_OPT_KDF_BINARY, HandleKdfBinary},
};

static int32_t ParseKdfOpt(KdfOpt *kdfOpt)
{
    int ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_KDF_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_KDF_EOF)) {
        for (size_t i = 0; i < (sizeof(g_kdfOptHandleFuncMap) / sizeof(g_kdfOptHandleFuncMap[0])); ++i) {
            if (optType == g_kdfOptHandleFuncMap[i].optType) {
                ret = g_kdfOptHandleFuncMap[i].func(kdfOpt);
                break;
            }
        }
        HITLS_APP_PROV_CASES(optType, kdfOpt->provider)
        if (ret != HITLS_APP_SUCCESS) {
            return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t GetKdfAlg(KdfOpt *kdfOpt)
{
    int32_t argc = HITLS_APP_GetRestOptNum();
    char **argv = HITLS_APP_GetRestOpt();
    if (argc == 0) {
        AppPrintError("Please input KDF algorithm.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    kdfOpt->kdfName = argv[0];
    kdfOpt->kdfId = HITLS_APP_GetCidByName(kdfOpt->kdfName, HITLS_APP_LIST_OPT_KDF_ALG);
    if (kdfOpt->macId == BSL_CID_UNKNOWN) {
        AppPrintError("No support KDF algorithm.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (argc - 1 != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("mac: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

static int32_t CheckParam(KdfOpt *kdfOpt)
{
    if (kdfOpt->kdfId == CRYPT_KDF_PBKDF2) {
        if (kdfOpt->pass == NULL && kdfOpt->hexPass == NULL) {
            AppPrintError("kdf: No pass entered.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (kdfOpt->pass != NULL && kdfOpt->hexPass != NULL) {
            AppPrintError("kdf: Cannot specify both pass and hexpass.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (kdfOpt->salt == NULL && kdfOpt->hexSalt == NULL) {
            AppPrintError("kdf: No salt entered.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
        if (kdfOpt->salt != NULL && kdfOpt->hexSalt != NULL) {
            AppPrintError("kdf: Cannot specify both salt and hexsalt.\n");
            return HITLS_APP_OPT_VALUE_INVALID;
        }
    }
    if (kdfOpt->keyLen == 0) {
        AppPrintError("kdf: Input keylen is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (kdfOpt->iter == 0) {
        AppPrintError("kdf: Input iter is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    if (kdfOpt->outFile != NULL && strlen((const char*)kdfOpt->outFile) > PATH_MAX) {
        AppPrintError("kdf: The output file length is invalid.\n");
        return HITLS_APP_OPT_VALUE_INVALID;
    }
    
    return HITLS_APP_SUCCESS;
}

static CRYPT_EAL_KdfCTX *InitAlgKdf(KdfOpt *kdfOpt)
{
    if (HITLS_APP_LoadProvider(kdfOpt->provider->providerPath, kdfOpt->provider->providerName) != HITLS_APP_SUCCESS) {
        return NULL;
    }
    CRYPT_EAL_KdfCTX *ctx = CRYPT_EAL_ProviderKdfNewCtx(APP_GetCurrent_LibCtx(), kdfOpt->kdfId,
        kdfOpt->provider->providerAttr);
    if (ctx == NULL) {
        (void)AppPrintError("Failed to create the algorithm(%s) context\n", kdfOpt->kdfName);
    }
    return ctx;
}

static int32_t KdfParsePass(KdfOpt *kdfOpt, uint8_t **pass, uint32_t *passLen)
{
    if (kdfOpt->pass != NULL) {
        *passLen = strlen((const char*)kdfOpt->pass);
        *pass = (uint8_t*)kdfOpt->pass;
    } else {
        int32_t ret = HITLS_APP_HexToByte(kdfOpt->hexPass, pass, passLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("kdf:Invalid pass: %s.\n", kdfOpt->hexPass);
            return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t KdfParseSalt(KdfOpt *kdfOpt, uint8_t **salt, uint32_t *saltLen)
{
    if (kdfOpt->salt != NULL) {
        *saltLen = strlen((const char*)kdfOpt->salt);
        *salt = (uint8_t*)kdfOpt->salt;
    } else {
        int32_t ret = HITLS_APP_HexToByte(kdfOpt->hexSalt, salt, saltLen);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("kdf:Invalid salt: %s.\n", kdfOpt->hexSalt);
            return ret;
        }
    }
    return HITLS_APP_SUCCESS;
}

static int32_t Pbkdf2Params(CRYPT_EAL_KdfCTX *ctx, BSL_Param *params, KdfOpt *kdfOpt)
{
    uint32_t index = 0;
    uint8_t *pass = NULL;
    uint32_t passLen = 0;
    uint8_t *salt = NULL;
    uint32_t saltLen = 0;
    int32_t ret = HITLS_APP_SUCCESS;
    do {
        ret = KdfParsePass(kdfOpt, &pass, &passLen);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = KdfParseSalt(kdfOpt, &salt, &saltLen);
        if (ret != HITLS_APP_SUCCESS) {
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_MAC_ID, BSL_PARAM_TYPE_UINT32,
            &(kdfOpt->macId), sizeof(kdfOpt->macId));
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("kdf:Init macId failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_PASSWORD, BSL_PARAM_TYPE_OCTETS, pass, passLen);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("kdf:Init pass failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_SALT, BSL_PARAM_TYPE_OCTETS, salt, saltLen);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("kdf:Init salt failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = BSL_PARAM_InitValue(&params[index++], CRYPT_PARAM_KDF_ITER, BSL_PARAM_TYPE_UINT32,
            &kdfOpt->iter, sizeof(kdfOpt->iter));
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("kdf:Init iter failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        ret = CRYPT_EAL_KdfSetParam(ctx, params);
        if (ret != CRYPT_SUCCESS) {
            (void)AppPrintError("kdf:KdfSetParam failed. ERROR:%d\n", ret);
            ret = HITLS_APP_CRYPTO_FAIL;
        }
    } while (0);
    if (kdfOpt->salt == NULL) {
        BSL_SAL_FREE(salt);
    }
    if (kdfOpt->pass == NULL) {
        BSL_SAL_FREE(pass);
    }
    return ret;
}

static int32_t PbkdfParamSet(CRYPT_EAL_KdfCTX *ctx, KdfOpt *kdfOpt)
{
    if (kdfOpt->kdfId == CRYPT_KDF_PBKDF2) {
        BSL_Param params[5] = {{0}, {0}, {0}, {0}, BSL_PARAM_END};
        return Pbkdf2Params(ctx, params, kdfOpt);
    }
    (void)AppPrintError("kdf: Unsupported KDF algorithm: %s\n", kdfOpt->kdfName);
    return HITLS_APP_OPT_VALUE_INVALID;
}

static int32_t KdfValToFinal(KdfOpt *kdfOpt, uint8_t *kdfBuf, uint32_t kdfBufLen, uint8_t **buf, uint32_t *bufLen)
{
    int32_t outRet;
    uint32_t hexBufLen = kdfBufLen * 2 + 1;
    uint8_t *hexBuf = (uint8_t *)BSL_SAL_Calloc(hexBufLen, sizeof(uint8_t));
    if (hexBuf == NULL) {
        AppPrintError("kdf: Failed to allocate hexBuf.\n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    if (kdfOpt->isBinary == 0) {
        outRet = HITLS_APP_OptToHex(kdfBuf, kdfBufLen, (char *)hexBuf, hexBufLen);
        if (outRet != HITLS_APP_SUCCESS) {
            AppPrintError("kdf: Failed to convert KDF buffer to hex string.\n");
            BSL_SAL_FREE(hexBuf);
            return HITLS_APP_ENCODE_FAIL;
        }
    } else {
        if (memcpy_s(hexBuf, hexBufLen, kdfBuf, kdfBufLen) != EOK) {
            AppPrintError("kdf: Failed to copy KDF buffer to output buffer.\n");
            BSL_SAL_FREE(hexBuf);
            return HITLS_APP_SECUREC_FAIL;
        }
    }
    uint32_t outBufLen = hexBufLen + 5;
    char *outBuf = (char *)BSL_SAL_Calloc(outBufLen, sizeof(char));
    if (outBuf == NULL) {
        (void)AppPrintError("Failed to open the format control content space\n");
        BSL_SAL_FREE(hexBuf);
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    outRet = snprintf_s(outBuf, outBufLen, outBufLen - 1, "%s\n", (char *)hexBuf);
    uint32_t len = strlen(outBuf);
    BSL_SAL_FREE(hexBuf);
    if (outRet == -1) {
        BSL_SAL_FREE(outBuf);
        (void)AppPrintError("Failed to combine the output content\n");
        return HITLS_APP_SECUREC_FAIL;
    }
    *buf = (uint8_t *)outBuf;
    *bufLen = len;
    return HITLS_APP_SUCCESS;
}

static int32_t KdfResult(CRYPT_EAL_KdfCTX *ctx, KdfOpt *kdfOpt)
{
    uint8_t *out = NULL;
    uint32_t outLen = kdfOpt->keyLen;
    uint8_t *buf = NULL;
    uint32_t bufLen = 0;

    int32_t ret = PbkdfParamSet(ctx, kdfOpt);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("PbkdfParamSet failed. \n");
        return ret;
    }

    out = BSL_SAL_Malloc(outLen);
    if (out == NULL) {
        (void)AppPrintError("kdf: Allocate memory failed. \n");
        return HITLS_APP_MEM_ALLOC_FAIL;
    }
    ret = CRYPT_EAL_KdfDerive(ctx, out, outLen);
    if (ret != CRYPT_SUCCESS) {
        (void)AppPrintError("KdfDeriv failed. ERROR:%d\n", ret);
        BSL_SAL_FREE(out);
        return HITLS_APP_CRYPTO_FAIL;
    }
    ret = KdfValToFinal(kdfOpt, out, outLen, &buf, &bufLen);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("KdfValToFinal failed. \n");
        BSL_SAL_FREE(out);
        return ret;
    }

    BSL_UIO *fileOutUio = NULL;
    fileOutUio = HITLS_APP_UioOpen(kdfOpt->outFile, 'w', 0);
    if (fileOutUio == NULL) {
        BSL_SAL_FREE(buf);
        BSL_SAL_FREE(out);
        (void)AppPrintError("kdf:UioOpen failed\n");
        return HITLS_APP_UIO_FAIL;
    }
    ret = HITLS_APP_OptWriteUio(fileOutUio, buf, bufLen, HITLS_APP_FORMAT_TEXT);
    BSL_UIO_Free(fileOutUio);
    if (ret != HITLS_APP_SUCCESS) {
        (void)AppPrintError("kdf:Failed to output the content to the screen\n");
    }
    BSL_SAL_FREE(buf);
    BSL_SAL_FREE(out);
    return ret;
}

int32_t HITLS_KdfMain(int argc, char *argv[])
{
    int32_t mainRet = HITLS_APP_SUCCESS;
    AppProvider appProvider = {"default", NULL, "provider=default"};
    KdfOpt kdfOpt = {CRYPT_MAC_HMAC_SHA256, NULL, 0, 0, NULL, NULL, NULL, NULL, NULL, 1000, &appProvider, 0};
    CRYPT_EAL_KdfCTX *ctx = NULL;
    do {
        mainRet = HITLS_APP_OptBegin(argc, argv, g_kdfOpts);
        if (mainRet != HITLS_APP_SUCCESS) {
            HITLS_APP_OptEnd();
            (void)AppPrintError("error in opt begin.\n");
            break;
        }
        mainRet = ParseKdfOpt(&kdfOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            HITLS_APP_OptEnd();
            break;
        }
        mainRet = GetKdfAlg(&kdfOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            HITLS_APP_OptEnd();
            break;
        }
        HITLS_APP_OptEnd();
        mainRet = CheckParam(&kdfOpt);
        if (mainRet != HITLS_APP_SUCCESS) {
            break;
        }
        ctx = InitAlgKdf(&kdfOpt);
        if (ctx == NULL) {
            mainRet = HITLS_APP_CRYPTO_FAIL;
            break;
        }
        mainRet = KdfResult(ctx, &kdfOpt);
    } while (0);
    CRYPT_EAL_KdfFreeCtx(ctx);
    HITLS_APP_OptEnd();
    return mainRet;
}