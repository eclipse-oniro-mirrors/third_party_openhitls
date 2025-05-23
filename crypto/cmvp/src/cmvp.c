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
#ifdef HITLS_CRYPTO_CMVP

#include <stdlib.h>
#include <stddef.h>
#include "crypt_cmvp.h"
#include "cmvp_method.h"
#include "cmvp_common.h"
#include "bsl_err.h"
#include "crypt_errno.h"
#include "crypt_types.h"
#include "crypt_algid.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_entropy.h"
#include "bsl_sal.h"
#include "bsl_errno.h"

typedef enum {
    CMVP_SELFTEST_ERROR,
    CMVP_SELFTEST_RUNNING,
    CMVP_SELFTEST_STOP,
} CMVP_SelftestStatus;

// Module status flag
static int32_t g_cmvpStatus = CRYPT_SUCCESS;
static BSL_SAL_ThreadLockHandle g_cmvpStatusLock = NULL;

typedef struct {
    uint32_t id;
    bool flag;
} CMVP_SelftestFlagMap;

// Algorithm self-check flag
static CMVP_SelftestFlagMap g_randSelfTestFlag[] = {
    {CRYPT_RAND_SHA1, false},
    {CRYPT_RAND_SHA224, false},
    {CRYPT_RAND_SHA256, false},
    {CRYPT_RAND_SHA384, false},
    {CRYPT_RAND_SHA512, false},
    {CRYPT_RAND_HMAC_SHA1, false},
    {CRYPT_RAND_HMAC_SHA224, false},
    {CRYPT_RAND_HMAC_SHA256, false},
    {CRYPT_RAND_HMAC_SHA384, false},
    {CRYPT_RAND_HMAC_SHA512, false},
    {CRYPT_RAND_AES128_CTR, false},
    {CRYPT_RAND_AES192_CTR, false},
    {CRYPT_RAND_AES256_CTR, false},
    {CRYPT_RAND_AES128_CTR_DF, false},
    {CRYPT_RAND_AES192_CTR_DF, false},
    {CRYPT_RAND_AES256_CTR_DF, false},
};
static CMVP_SelftestFlagMap g_mdSelfTestFlag[] = {
    {CRYPT_MD_MD5, false},
    {CRYPT_MD_SHA1, false},
    {CRYPT_MD_SHA224, false},
    {CRYPT_MD_SHA256, false},
    {CRYPT_MD_SHA384, false},
    {CRYPT_MD_SHA512, false},
    {CRYPT_MD_SHA3_224, false},
    {CRYPT_MD_SHA3_256, false},
    {CRYPT_MD_SHA3_384, false},
    {CRYPT_MD_SHA3_512, false},
    {CRYPT_MD_SHAKE128, false},
    {CRYPT_MD_SHAKE256, false},
    {CRYPT_MD_SM3, false},
};

static CMVP_SelftestFlagMap g_macSelfTestFlag[] = {
    { CRYPT_MAC_HMAC_MD5, false },
    { CRYPT_MAC_HMAC_SHA1, false },
    { CRYPT_MAC_HMAC_SHA224, false },
    { CRYPT_MAC_HMAC_SHA256, false },
    { CRYPT_MAC_HMAC_SHA384, false },
    { CRYPT_MAC_HMAC_SHA512, false },
    { CRYPT_MAC_HMAC_SHA3_224, false },
    { CRYPT_MAC_HMAC_SHA3_256, false },
    { CRYPT_MAC_HMAC_SHA3_384, false },
    { CRYPT_MAC_HMAC_SHA3_512, false },
    { CRYPT_MAC_HMAC_SM3, false },
    { CRYPT_MAC_CMAC_AES128, false },
    { CRYPT_MAC_CMAC_AES192, false },
    { CRYPT_MAC_CMAC_AES256, false },
    { CRYPT_MAC_GMAC_AES128, false },
    { CRYPT_MAC_GMAC_AES192, false },
    { CRYPT_MAC_GMAC_AES256, false },
    { CRYPT_MAC_SIPHASH64, false },
    { CRYPT_MAC_SIPHASH128, false }
};

static CMVP_SelftestFlagMap g_pkeySelfTestFlag[] = {
    { CRYPT_PKEY_DSA, false },
    { CRYPT_PKEY_ED25519, false },
    { CRYPT_PKEY_X25519, false },
    { CRYPT_PKEY_RSA, false },
    { CRYPT_PKEY_DH, false },
    { CRYPT_PKEY_ECDSA, false },
    { CRYPT_PKEY_ECDH, false },
    { CRYPT_PKEY_SM2, false },
};
static CMVP_SelftestFlagMap g_cipherSelfTestFlag[] = {
    { CRYPT_CIPHER_AES128_CBC, false },
    { CRYPT_CIPHER_AES192_CBC, false },
    { CRYPT_CIPHER_AES256_CBC, false },

    { CRYPT_CIPHER_AES128_CTR, false },
    { CRYPT_CIPHER_AES192_CTR, false },
    { CRYPT_CIPHER_AES256_CTR, false },

    { CRYPT_CIPHER_AES128_ECB, false },
    { CRYPT_CIPHER_AES192_ECB, false },
    { CRYPT_CIPHER_AES256_ECB, false },

    { CRYPT_CIPHER_AES128_XTS, false },
    { CRYPT_CIPHER_AES256_XTS, false },

    { CRYPT_CIPHER_AES128_CCM, false },
    { CRYPT_CIPHER_AES192_CCM, false },
    { CRYPT_CIPHER_AES256_CCM, false },

    { CRYPT_CIPHER_AES128_GCM, false },
    { CRYPT_CIPHER_AES192_GCM, false },
    { CRYPT_CIPHER_AES256_GCM, false },

    { CRYPT_CIPHER_CHACHA20_POLY1305, false },

    { CRYPT_CIPHER_SM4_XTS, false },
    { CRYPT_CIPHER_SM4_CBC, false },
    { CRYPT_CIPHER_SM4_ECB, false },
    { CRYPT_CIPHER_SM4_CTR, false },
    { CRYPT_CIPHER_SM4_GCM, false },
    { CRYPT_CIPHER_SM4_CFB, false },
    { CRYPT_CIPHER_SM4_OFB, false },

    { CRYPT_CIPHER_AES128_CFB, false },
    { CRYPT_CIPHER_AES192_CFB, false },
    { CRYPT_CIPHER_AES256_CFB, false },
    { CRYPT_CIPHER_AES128_OFB, false },
    { CRYPT_CIPHER_AES192_OFB, false },
    { CRYPT_CIPHER_AES256_OFB, false },
};
static CMVP_SelftestFlagMap g_kdfSelfTestFlag[] = {
    { CRYPT_KDF_SCRYPT, false },
    { CRYPT_KDF_PBKDF2, false },
    { CRYPT_KDF_KDFTLS12, false },
    { CRYPT_KDF_HKDF, false },
};

// Indicates whether self-check is being performed.
// The options are as follows: true: self-check is being performed; false: self-check is not being performed.
static bool g_selfTestRun = false;
static BSL_SAL_ThreadLockHandle g_cmvpSelftestLock = NULL;

bool CMVP_Pct(CRYPT_EAL_PkeyCtx *pkey);
void CMVP_EventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);

int32_t CRYPT_CMVP_StatusGet(void)
{
    (void)BSL_SAL_ThreadReadLock(g_cmvpStatusLock);
    int32_t status = g_cmvpStatus;
    (void)BSL_SAL_ThreadUnlock(g_cmvpStatusLock);
    return status;
}

void CMVP_StatusSet(int32_t status)
{
    (void)BSL_SAL_ThreadWriteLock(g_cmvpStatusLock);
    g_cmvpStatus = status;
    (void)BSL_SAL_ThreadUnlock(g_cmvpStatusLock);
}

static CMVP_SelftestFlagMap *CMVP_GetSelftestFlag(CMVP_SelftestFlagMap *stMap, uint32_t num, uint32_t id)
{
    CMVP_SelftestFlagMap *ret = NULL;
    for (uint32_t i = 0; i < num; i++) {
        if (stMap[i].id == id) {
            ret = &stMap[i];
            return ret;
        }
    }
    return NULL;
}

bool CMVP_IsSelfTestFin(CRYPT_ALGO_TYPE type, uint32_t id)
{
    CMVP_SelftestFlagMap *mapGet = NULL;
    uint32_t num;
    if (type == CRYPT_ALGO_CIPHER) {
        num = sizeof(g_cipherSelfTestFlag) / sizeof(g_cipherSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_cipherSelfTestFlag, num, id);
    } else if (type == CRYPT_ALGO_PKEY) {
        num = sizeof(g_pkeySelfTestFlag) / sizeof(g_pkeySelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_pkeySelfTestFlag, num, id);
    } else if (type == CRYPT_ALGO_MD) {
        num = sizeof(g_mdSelfTestFlag) / sizeof(g_mdSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_mdSelfTestFlag, num, id);
    } else if (type == CRYPT_ALGO_MAC) {
        num = sizeof(g_macSelfTestFlag) / sizeof(g_macSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_macSelfTestFlag, num, id);
    } else if (type == CRYPT_ALGO_KDF) {
        num = sizeof(g_kdfSelfTestFlag) / sizeof(g_kdfSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_kdfSelfTestFlag, num, id);
    } else if (type == CRYPT_ALGO_RAND) {
        num = sizeof(g_randSelfTestFlag) / sizeof(g_randSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_randSelfTestFlag, num, id);
    }
    if (mapGet != NULL) {
        return mapGet->flag;
    }
    return true;
}

void CMVP_SetSelfTestFin(CRYPT_ALGO_TYPE type, uint32_t id, bool ret)
{
    CMVP_SelftestFlagMap *mapGet = NULL;
    uint32_t num;
    if (type == CRYPT_ALGO_CIPHER) {
        num = sizeof(g_cipherSelfTestFlag) / sizeof(g_cipherSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_cipherSelfTestFlag, num, (uint32_t)id);
    } else if (type == CRYPT_ALGO_PKEY) {
        num = sizeof(g_pkeySelfTestFlag) / sizeof(g_pkeySelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_pkeySelfTestFlag, num, (uint32_t)id);
    } else if (type == CRYPT_ALGO_MD) {
        num = sizeof(g_mdSelfTestFlag) / sizeof(g_mdSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_mdSelfTestFlag, num, (uint32_t)id);
    } else if (type == CRYPT_ALGO_MAC) {
        num = sizeof(g_macSelfTestFlag) / sizeof(g_macSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_macSelfTestFlag, num, (uint32_t)id);
    } else if (type == CRYPT_ALGO_KDF) {
        num = sizeof(g_kdfSelfTestFlag) / sizeof(g_kdfSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_kdfSelfTestFlag, num, (uint32_t)id);
    } else if (type == CRYPT_ALGO_RAND) {
        num = sizeof(g_randSelfTestFlag) / sizeof(g_randSelfTestFlag[0]);
        mapGet = CMVP_GetSelftestFlag(g_randSelfTestFlag, num, (uint32_t)id);
    }
    if (mapGet != NULL) {
        mapGet->flag = ret;
    }
}

CMVP_SelftestStatus SelftestLock(void)
{
    static uint64_t tid = 0;
    if (g_selfTestRun == true && tid == BSL_SAL_ThreadGetId()) {
        return CMVP_SELFTEST_RUNNING;
    } else {
        if (BSL_SAL_ThreadWriteLock(g_cmvpSelftestLock) != BSL_SUCCESS) {
            return CMVP_SELFTEST_ERROR;
        }
        g_selfTestRun = true;
        tid = BSL_SAL_ThreadGetId();
        return CMVP_SELFTEST_STOP;
    }
}

void SelftestUnLock(void)
{
    g_selfTestRun = false;
    (void)BSL_SAL_ThreadUnlock(g_cmvpSelftestLock);
}

bool CMVP_Pct(CRYPT_EAL_PkeyCtx *pkey)
{
    CRYPT_PKEY_AlgId id = CRYPT_EAL_PkeyGetId(pkey);
    if (id == CRYPT_PKEY_DH || id == CRYPT_PKEY_X25519 || id == CRYPT_PKEY_ECDH) {
        return true;
    }
    bool ret = false;
    uint8_t *sign = NULL;
    uint32_t signLen;
    const uint8_t msg[] = { 0x01, 0x02, 0x03, 0x04 };
    uint32_t mdId = CRYPT_MD_SHA512;

    signLen = CRYPT_EAL_PkeyGetSignLen(pkey);
    sign = BSL_SAL_Malloc(signLen);
    GOTO_EXIT_IF(sign == NULL, CRYPT_MEM_ALLOC_FAIL);
    if (id == CRYPT_PKEY_RSA) {
        GOTO_EXIT_IF(CRYPT_EAL_PkeyCtrl(pkey, CRYPT_CTRL_SET_RSA_EMSA_PKCSV15, &mdId,
            sizeof(mdId)) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    GOTO_EXIT_IF(CRYPT_EAL_PkeySign(pkey, id == CRYPT_PKEY_SM2 ? CRYPT_MD_SM3 : CRYPT_MD_SHA512,
        msg, sizeof(msg), sign, &signLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    GOTO_EXIT_IF(CRYPT_EAL_PkeyVerify(pkey, id == CRYPT_PKEY_SM2 ? CRYPT_MD_SM3 : CRYPT_MD_SHA512,
        msg, sizeof(msg), sign, signLen) != CRYPT_SUCCESS, CRYPT_CMVP_ERR_ALGO_SELFTEST);

    ret = true;
EXIT:
    BSL_SAL_FREE(sign);
    if (!ret && CRYPT_CMVP_ModeGet() != CRYPT_CMVP_MODE_NDCPP) {    // NDCPP does not set error status here
        CMVP_StatusSet(CRYPT_CMVP_ERR_PAIRWISETEST);
    }
    return ret;
}

int32_t CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE mode)
{
    if (mode < CRYPT_CMVP_MODE_NONAPPROVED || mode >= CRYPT_CMVP_MODE_MAX) {
        return CRYPT_CMVP_INVALID_INPUT;
    }
    // In an error state, mode switching is prohibited.
    int32_t ret = CRYPT_CMVP_StatusGet();
    if (ret != CRYPT_SUCCESS) {
        return CRYPT_CMVP_ERR_STATUS;
    }

    const CMVP_Method *method = NULL;
    CRYPT_CMVP_MODE currentMode = CRYPT_CMVP_ModeGet();
    if (mode == currentMode) { // Already in this mode
        return CRYPT_CMVP_ALREADY_IN_MODE;
    }

    // If the mode to be switched to is not approved, the switching method of the current mode is used
    if (mode == CRYPT_CMVP_MODE_NONAPPROVED) {
        method = CMVP_FindMethod(currentMode);
    } else {
        method = CMVP_FindMethod(mode);
    }
    // The method must not be an approved method. The approved method must not be empty.
    ret = method->modeSet(mode);
    if (ret == CRYPT_SUCCESS) {
        if (mode == CRYPT_CMVP_MODE_NONAPPROVED) {
            CRYPT_EAL_RegPct(NULL);
            CRYPT_EAL_RegEventReport(NULL);
        } else {
            CRYPT_EAL_RegPct(CMVP_Pct);
            CRYPT_EAL_RegEventReport(CMVP_EventProcess);
        }
    }
    return ret;
}

void CMVP_EventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    CRYPT_CMVP_MODE mode = CRYPT_CMVP_ModeGet();
    const CMVP_Method *method = CMVP_FindMethod(mode); // Not unapproved, method must not be null.
    if (method->eventReport != NULL) {
        method->eventReport(oper, type, id, err);
    }
}

bool AlgoC2(CRYPT_CMVP_MODE mode, CRYPT_ALGO_TYPE type, uint32_t id)
{
    const CMVP_Method *method = CMVP_FindMethod(mode);
    bool ret = true;
    switch (type) {
        case CRYPT_ALGO_MD:
            if (method->mdC2 != NULL) {
                ret = method->mdC2(id);
            }
            break;
        case CRYPT_ALGO_CIPHER:
            if (method->cipherC2 != NULL) {
                ret = method->cipherC2(id);
            }
            break;
        case CRYPT_ALGO_KDF:
            if (id == CRYPT_KDF_SCRYPT) {
                if (method->kdfC2 != NULL) {
                    ret = method->kdfC2(id, NULL);
                }
            }
            break;
        case CRYPT_ALGO_RAND:
            if (method->randC2 != NULL) {
                ret = method->randC2(id);
            }
            break;
        default:
            return true;
    }
    return ret;
}

// True: the self-check is required. False: the self-check is not required.
bool IsNeedCheck(CRYPT_ALGO_TYPE type, uint32_t id, bool *ret)
{
    if (CMVP_CspFlagGet() == false) {
        CMVP_CspFlagSet(true); // CSP exists in the memory.
    }
    // In the error state, a failure message is returned.
    if (CRYPT_CMVP_StatusGet() != CRYPT_SUCCESS) {
        *ret = false;
        return false;
    }
    CRYPT_CMVP_MODE mode = CRYPT_CMVP_ModeGet();
    // The algorithm parameters do not meet the standard requirements. failure is returned.
    if (mode != CRYPT_CMVP_MODE_NONAPPROVED && AlgoC2(mode, type, id) == false) {
        *ret = false;
        return false;
    }
    if (CMVP_IsSelfTestFin(type, (uint32_t)id) == true) { // The self-check has been performed, success is returned.
        *ret = true;
        return false;
    }
    int32_t status = SelftestLock();
    if (status == CMVP_SELFTEST_ERROR) { // Locking failed. failure is returned.
        *ret = false;
        return false;
    }
    if (status == CMVP_SELFTEST_RUNNING) { // The self-check is already in progress. success is returned.
        *ret = true;
        return false;
    }
    return true; // Start the self-check.
}

static bool ExcutePkeySelftest(CRYPT_PKEY_AlgId id)
{
    if (id == CRYPT_PKEY_DSA) {
        return CRYPT_CMVP_SelftestDsa();
    }
    if (id == CRYPT_PKEY_X25519) {
        return CRYPT_CMVP_SelftestX25519();
    }
    if (id == CRYPT_PKEY_RSA) {
        return CRYPT_CMVP_SelftestRsa();
    }
    if (id == CRYPT_PKEY_DH) {
        return CRYPT_CMVP_SelftestDh();
    }
    if (id == CRYPT_PKEY_ED25519) {
        return CRYPT_CMVP_SelftestEd25519();
    }
    if (id == CRYPT_PKEY_ECDSA) {
        return CRYPT_CMVP_SelftestEcdsa();
    }
    if (id == CRYPT_PKEY_SM2) {
        return CRYPT_CMVP_SelftestSM2();
    }
    if (id == CRYPT_PKEY_ECDH) {
        return CRYPT_CMVP_SelftestEcdh();
    }
    return true;
}

static bool PreOperateC2(void)
{
    if (CMVP_CspFlagGet() == false) {
        CMVP_CspFlagSet(true); // CSP exists in the memory.
    }
    if (CRYPT_CMVP_StatusGet() != CRYPT_SUCCESS) { // Check whether the system is in an error state.
        return false;
    }
    return true;
}

bool CMVP_PkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data)
{
    if (!PreOperateC2()) {
        return false;
    }
    CRYPT_CMVP_MODE mode = CRYPT_CMVP_ModeGet();
    if (mode != CRYPT_CMVP_MODE_NONAPPROVED) {
        const CMVP_Method *method = CMVP_FindMethod(mode);
        if (method->pkeyC2 != NULL && !method->pkeyC2(id, data)) {
            return false;
        }
    }
    bool ret = false;

    if (IsNeedCheck(CRYPT_ALGO_PKEY, id, &ret) == false) {
        return ret;
    }

    ret = ExcutePkeySelftest(id);
    CMVP_SetSelfTestFin(CRYPT_ALGO_PKEY, id, ret);
    if (!ret) {
        CMVP_StatusSet(CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    SelftestUnLock();
    return ret;
}

bool CMVP_MdC2(CRYPT_MD_AlgId id)
{
    bool ret = false;
    if (IsNeedCheck(CRYPT_ALGO_MD, id, &ret) == false) { // No need to perform the following self-test
        return ret;
    }

    ret = CRYPT_CMVP_SelftestMd(id);
    CMVP_SetSelfTestFin(CRYPT_ALGO_MD, id, ret);
    if (!ret) {
        CMVP_StatusSet(CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    SelftestUnLock();
    return ret;
}

bool CMVP_CipherC2(CRYPT_CIPHER_AlgId id)
{
    static const uint32_t list[] = {
        CRYPT_CIPHER_AES128_CBC, CRYPT_CIPHER_AES192_CBC, CRYPT_CIPHER_AES256_CBC,
        CRYPT_CIPHER_AES128_CTR, CRYPT_CIPHER_AES192_CTR, CRYPT_CIPHER_AES256_CTR,
        CRYPT_CIPHER_AES128_ECB, CRYPT_CIPHER_AES192_ECB, CRYPT_CIPHER_AES256_ECB,
        CRYPT_CIPHER_AES128_XTS, CRYPT_CIPHER_AES256_XTS,
        CRYPT_CIPHER_AES128_CCM, CRYPT_CIPHER_AES192_CCM, CRYPT_CIPHER_AES256_CCM,
        CRYPT_CIPHER_AES128_GCM, CRYPT_CIPHER_AES192_GCM, CRYPT_CIPHER_AES256_GCM,
        CRYPT_CIPHER_AES128_CFB, CRYPT_CIPHER_AES192_CFB, CRYPT_CIPHER_AES256_CFB,
        CRYPT_CIPHER_AES128_OFB, CRYPT_CIPHER_AES192_OFB, CRYPT_CIPHER_AES256_OFB,
        CRYPT_CIPHER_SM4_XTS, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_ECB,
        CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_GCM, CRYPT_CIPHER_SM4_CFB,
        CRYPT_CIPHER_SM4_OFB,
    };

    bool ret = false;
    if (IsNeedCheck(CRYPT_ALGO_CIPHER, id, &ret) == false) { // No need to perform the following self-test
        return ret;
    }

    ret = true;
    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (list[i] == id) {
            ret = CRYPT_CMVP_SelftestCipher(id);
            CMVP_SetSelfTestFin(CRYPT_ALGO_CIPHER, id, ret);
        }
    }
    if (id == CRYPT_CIPHER_CHACHA20_POLY1305) {
        ret = CRYPT_CMVP_SelftestChacha20poly1305();
        CMVP_SetSelfTestFin(CRYPT_ALGO_CIPHER, id, ret);
    }
    if (!ret) {
        CMVP_StatusSet(CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    SelftestUnLock();
    return ret;
}

bool CMVP_MacC2(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    if (!PreOperateC2()) {
        return false;
    }
    CRYPT_CMVP_MODE mode = CRYPT_CMVP_ModeGet();
    if (mode != CRYPT_CMVP_MODE_NONAPPROVED) {
        const CMVP_Method *method = CMVP_FindMethod(mode);
        if (method->macC2 != NULL && !method->macC2(id, keyLen)) {
            return false;
        }
    }

    bool ret = false;
    if (IsNeedCheck(CRYPT_ALGO_MAC, id, &ret) == false) {
        return ret;
    }

    ret = CRYPT_CMVP_SelftestMac(id);
    CMVP_SetSelfTestFin(CRYPT_ALGO_MAC, id, ret);
    if (!ret) {
        CMVP_StatusSet(CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    SelftestUnLock();
    return ret;
}

bool CMVP_ScryptC2(void)
{
    bool ret = false;
    if (IsNeedCheck(CRYPT_ALGO_KDF, CRYPT_KDF_SCRYPT, &ret) == false) {
        return ret;
    }

    ret = CRYPT_CMVP_SelftestScrypt();
    CMVP_SetSelfTestFin(CRYPT_ALGO_KDF, CRYPT_KDF_SCRYPT, ret);
    if (!ret) {
        CMVP_StatusSet(CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    SelftestUnLock();
    return ret;
}

static bool CRYPT_CMVP_SelftestKdf(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data)
{
    switch (id) {
        case CRYPT_KDF_SCRYPT:
            return CRYPT_CMVP_SelftestScrypt();
        case CRYPT_KDF_KDFTLS12:
            return CRYPT_CMVP_SelftestKdfTls12();
        case CRYPT_KDF_HKDF:
            return CRYPT_CMVP_SelftestHkdf();
        case CRYPT_KDF_PBKDF2:
            if (data == NULL || data->pbkdf2 == NULL) {
                return false;
            }
            return CRYPT_CMVP_SelftestPbkdf2(data->pbkdf2->macId);
        default:
            return false;
    }
}

bool CMVP_KdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data)
{
    if (!PreOperateC2()) {
        return false;
    }
    CRYPT_CMVP_MODE mode = CRYPT_CMVP_ModeGet();
    if (mode != CRYPT_CMVP_MODE_NONAPPROVED) {
        const CMVP_Method *method = CMVP_FindMethod(mode);
        if (method->kdfC2 != NULL && !method->kdfC2(id, data)) {
            return false;
        }
    }
    if (CMVP_IsSelfTestFin(CRYPT_ALGO_KDF, id)) {
        return true;
    }

    int32_t status = SelftestLock();
    if (status == CMVP_SELFTEST_ERROR) {
        return false;
    } else if (status == CMVP_SELFTEST_RUNNING) {
        return true;
    }
    bool ret = CRYPT_CMVP_SelftestKdf(id, data);
    CMVP_SetSelfTestFin(CRYPT_ALGO_KDF, id, ret);
    if (!ret) {
        CMVP_StatusSet(CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    SelftestUnLock();
    return ret;
}

bool CMVP_RandC2(CRYPT_RAND_AlgId id)
{
    bool ret = false;
    if (IsNeedCheck(CRYPT_ALGO_RAND, id, &ret) == false) {
        return ret;
    }

    ret = CRYPT_CMVP_SelftestDrbg(id);
    CMVP_SetSelfTestFin(CRYPT_ALGO_RAND, id, ret);
    if (!ret) {
        CMVP_StatusSet(CRYPT_CMVP_ERR_ALGO_SELFTEST);
    }
    SelftestUnLock();
    return ret;
}

static void *CmvpMalloc(uint32_t len)
{
    return malloc(len);
}

void __attribute__((constructor(101))) CMVP_DefaultEntryPoint(void)
{
    // Register memory callbacks for pre-run self-test
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_MALLOC_CB_FUNC, CmvpMalloc);
    BSL_SAL_CallBack_Ctrl(BSL_SAL_MEM_FREE_CB_FUNC, free);

#if defined(HITLS_CRYPTO_ASM_CHECK)
    GetCpuInstrSupportState();
#endif
#if defined(HITLS_CRYPTO_CMVP_INTEGRITY)
    // Checking integrity
    // HITLS_CRYPTO_CMVP_MODE can be configured during compile time
    // HITLS_CRYPTO_CMVP_MODE=0 CMVP_MODE_NOT_APPROVED
    // HITLS_CRYPTO_CMVP_MODE=1 CMVP_MODE_ISO
    // HITLS_CRYPTO_CMVP_MODE=2 CMVP_MODE_FIPS
    // HITLS_CRYPTO_CMVP_MODE=3 CMVP_MODE_NDCPP
    // HITLS_CRYPTO_CMVP_MODE=4 CMVP_MODE_GM
    const CMVP_Method *method = CMVP_FindMethod(HITLS_CRYPTO_CMVP_MODE);
    if (method == NULL || method->dep == NULL) {
        return;
    }
    int32_t err = method->dep();
    if (err != CRYPT_SUCCESS) {
        CMVP_StatusSet(err); // Record whether critical errors occur.
    }
#endif

    // Callback required for registering the EAL
    CRYPT_EAL_RegPkeyC2(CMVP_PkeyC2);
    CRYPT_EAL_RegMdC2(CMVP_MdC2);
    CRYPT_EAL_RegCipherC2(CMVP_CipherC2);
    CRYPT_EAL_RegMacC2(CMVP_MacC2);
    CRYPT_EAL_RegKdfC2(CMVP_KdfC2);
    CRYPT_EAL_RegRandC2(CMVP_RandC2);
    CRYPT_CMVP_MultiThreadEnable();
    CMVP_CspFlagSet(false); // Clear the CSP flag set for the pre-run self-test
}

void __attribute__((destructor(102))) CMVP_DefaultExitPoint(void)
{
    // Reset various states
    BSL_SAL_ThreadLockFree(g_cmvpSelftestLock);
    BSL_SAL_ThreadLockFree(g_cmvpStatusLock);
    g_cmvpSelftestLock = NULL;
    g_cmvpStatusLock = NULL;

    CMVP_StatusSet(CRYPT_SUCCESS);
    CMVP_CspFlagSet(false);
    CRYPT_CMVP_ModeSet(CRYPT_CMVP_MODE_NONAPPROVED);
    CRYPT_EAL_RegPkeyC2(NULL);
    CRYPT_EAL_RegMdC2(NULL);
    CRYPT_EAL_RegCipherC2(NULL);
    CRYPT_EAL_RegMacC2(NULL);
	CRYPT_EAL_RegKdfC2(NULL);

    CRYPT_EAL_RegRandC2(NULL);
    uint32_t i;
    for (i = 0; i < sizeof(g_cipherSelfTestFlag) / sizeof(g_cipherSelfTestFlag[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_CIPHER, g_cipherSelfTestFlag[i].id, false);
    }
    for (i = 0; i < sizeof(g_pkeySelfTestFlag) / sizeof(g_pkeySelfTestFlag[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_PKEY, g_pkeySelfTestFlag[i].id, false);
    }
    for (i = 0; i < sizeof(g_mdSelfTestFlag) / sizeof(g_mdSelfTestFlag[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_MD, g_mdSelfTestFlag[i].id, false);
    }
    for (i = 0; i < sizeof(g_macSelfTestFlag) / sizeof(g_macSelfTestFlag[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_MAC, g_macSelfTestFlag[i].id, false);
    }
    for (i = 0; i < sizeof(g_kdfSelfTestFlag) / sizeof(g_kdfSelfTestFlag[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_KDF, g_kdfSelfTestFlag[i].id, false);
    }
    for (i = 0; i < sizeof(g_randSelfTestFlag) / sizeof(g_randSelfTestFlag[0]); i++) {
        CMVP_SetSelfTestFin(CRYPT_ALGO_RAND, g_randSelfTestFlag[i].id, false);
    }
}

const char *CRYPT_CMVP_GetVersion(void)
{
    return "HiTLS Version : V100R023\nlibhitls_crypto Version : V100R023_libhitls_crypto.so\nlibhitls_bsl Version : "
        "V100R023_libhitls_bsl.so";
}

int32_t CRYPT_CMVP_MultiThreadEnable(void)
{
    if (g_cmvpSelftestLock == NULL) {
        GOTO_EXIT_IF(BSL_SAL_ThreadLockNew(&g_cmvpSelftestLock) != BSL_SUCCESS, CRYPT_CMVP_ERR_LOCK);
        GOTO_EXIT_IF(BSL_SAL_ThreadLockNew(&g_cmvpStatusLock) != BSL_SUCCESS, CRYPT_CMVP_ERR_LOCK);
    }
    return CRYPT_SUCCESS;
EXIT:
    if (g_cmvpSelftestLock != NULL) {
        BSL_SAL_ThreadLockFree(g_cmvpSelftestLock);
        g_cmvpSelftestLock = NULL;
    }
    if (g_cmvpStatusLock != NULL) {
        BSL_SAL_ThreadLockFree(g_cmvpStatusLock);
        g_cmvpStatusLock = NULL;
    }
    return CRYPT_CMVP_ERR_LOCK;
}

#endif
