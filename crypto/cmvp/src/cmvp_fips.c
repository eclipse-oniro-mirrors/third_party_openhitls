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

#include "iso19790.h"
#include "cmvp_common.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "crypt_eal_pkey.h"
#include "crypt_cmvp.h"
#include "securec.h"
#include "cmvp_fips.h"

int32_t CMVP_FipsDep(void)
{
    return ISO19790_DefaultEntryPoint();
}

int32_t CMVP_FipsModeSet(CRYPT_CMVP_MODE mode)
{
    return ISO19790_ModeSet(mode);
}

void CMVP_FipsEventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    ISO19790_EventProcess(oper, type, id, err);
}

bool CMVP_FipsPkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data)
{
    return ISO19790_AsymParamCheck(id, data);
}

bool CMVP_FipsMdC2(CRYPT_MD_AlgId id)
{
    return ISO19790_MdParamCheck(id);
}

bool CMVP_FipsCipherC2(CRYPT_CIPHER_AlgId id)
{
    return ISO19790_CipherParamCheck(id);
}

bool CMVP_FipsMacC2(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    return ISO19790_MacParamCheck(id, keyLen);
}

bool CMVP_FipsKdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data)
{
    switch (id) {
        case CRYPT_KDF_SCRYPT:
            return false;
        case CRYPT_KDF_PBKDF2:
            if (data == NULL || data->pbkdf2 == NULL) {
                return false;
            } 
            return ISO19790_PbkdfParamCheck(data->pbkdf2);
        case CRYPT_KDF_KDFTLS12:
            if (data == NULL || data->hkdf == NULL) {
                return false;
            }
            return ISO19790_KdfTls12ParamCheck(data->hkdf->macId, data->hkdf->keyLen);
        case CRYPT_KDF_HKDF:
            if (data == NULL || data->hkdf == NULL) {
                return false;
            }
            return ISO19790_HkdfParamCheck(data->hkdf->macId, data->hkdf->keyLen);
        default:
            return false;
    }
}

bool CMVP_FipsRandC2(CRYPT_RAND_AlgId id)
{
    return ISO19790_RandParamCheck(id);
}

#endif
