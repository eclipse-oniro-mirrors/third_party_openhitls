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
#ifdef HITLS_CRYPTO_CMVP_SM

#include "cmvp_sm.h"
#include "cmvp_common.h"
#include "crypt_errno.h"
#include "crypt_cmvp_selftest.h"
#include "bsl_err_internal.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "crypt_params_key.h"
#include "securec.h"
#include "bsl_sal.h"

bool CMVP_SmPkeyPct(void *ctx, int32_t algId)
{
    return CRYPT_CMVP_SelftestPkeyPct(ctx, algId);
}

bool CMVP_SmPkeyC2(int32_t algId)
{
    if (algId != CRYPT_MD_SM3) {
        return false;
    }
    return true;
}

bool CMVP_SmKdfC2(const CRYPT_EAL_KdfC2Data *data)
{
    // According to GM/T 0091-2020 A1.1 and A1.2, min saltLen is 8, min iter is 1024.
    if (data->pbkdf2->macId != CRYPT_MAC_HMAC_SM3 || data->pbkdf2->saltLen < 8 || data->pbkdf2->iter < 1024) {
        return false;
    }
    return true;
}

static bool CipherKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_CIPHER_SM4_XTS, CRYPT_CIPHER_SM4_CBC, CRYPT_CIPHER_SM4_ECB,
        CRYPT_CIPHER_SM4_CTR, CRYPT_CIPHER_SM4_GCM, CRYPT_CIPHER_SM4_CFB,
        CRYPT_CIPHER_SM4_OFB,
    };

    bool ret = false;
    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        ret = CRYPT_CMVP_SelftestProviderCipher(libCtx, attrName, list[i]);
        if (!ret) {
            return false;
        }
    }
    return true;
}

static bool MdKat(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestProviderMd(libCtx, attrName, CRYPT_MD_SM3);
}

static bool MacKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_MAC_HMAC_SM3,
        CRYPT_MAC_CBC_MAC_SM4,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderMac(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool DrbgKat(void *libCtx, const char *attrName)
{
    static const uint32_t list[] = {
        CRYPT_RAND_SM4_CTR_DF,
        CRYPT_RAND_SM3,
    };

    for (uint32_t i = 0; i < sizeof(list) / sizeof(list[0]); i++) {
        if (!CRYPT_CMVP_SelftestProviderDrbg(libCtx, attrName, list[i])) {
            return false;
        }
    }
    return true;
}

static bool KdfKat(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestProviderPbkdf2(libCtx, attrName, CRYPT_MAC_HMAC_SM3);
}

static bool PkeyKat(void *libCtx, const char *attrName)
{
    return CRYPT_CMVP_SelftestProviderSM2(libCtx, attrName);
}

int32_t CMVP_SmKat(void *libCtx, const char *attrName)
{
    bool ret = CipherKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = MdKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = MacKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = DrbgKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = KdfKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    ret = PkeyKat(libCtx, attrName);
    RETURN_RET_IF(ret == false, CRYPT_CMVP_ERR_ALGO_SELFTEST);
    return CRYPT_SUCCESS;
}

int32_t CMVP_SmCheckIntegrity(void *libCtx, const char *attrName)
{
    return CMVP_CheckIntegrity(libCtx, attrName, CRYPT_MAC_HMAC_SM3);
}

#endif /* HITLS_CRYPTO_CMVP_SM */
