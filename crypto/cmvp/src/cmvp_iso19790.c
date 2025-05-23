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

#include "securec.h"
#include "iso19790.h"
#include "cmvp_common.h"
#include "bsl_err.h"
#include "crypt_cmvp_selftest.h"
#include "crypt_utils.h"
#include "cmvp_integrity_hmac.h"
#include "cmvp_iso19790.h"

int32_t CMVP_Iso19790Dep(void)
{
    return ISO19790_DefaultEntryPoint();
}

int32_t CMVP_Iso19790ModeSet(CRYPT_CMVP_MODE mode)
{
    return ISO19790_ModeSet(mode);
}

void CMVP_Iso19790EventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err)
{
    ISO19790_EventProcess(oper, type, id, err);
}

bool CMVP_Iso19790PkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data)
{
    return ISO19790_AsymParamCheck(id, data);
}

bool CMVP_Iso19790MdC2(CRYPT_MD_AlgId id)
{
    return ISO19790_MdParamCheck(id);
}

bool CMVP_Iso19790CipherC2(CRYPT_CIPHER_AlgId id)
{
    return ISO19790_CipherParamCheck(id);
}

bool CMVP_Iso19790MacC2(CRYPT_MAC_AlgId id, uint32_t keyLen)
{
    return ISO19790_MacParamCheck(id, keyLen);
}

bool CMVP_Iso19790KdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data)
{
    switch (id) {
        case CRYPT_KDF_SCRYPT:
            return false;
        case CRYPT_KDF_PBKDF2:
            return ISO19790_PbkdfParamCheck(data->pbkdf2);
        case CRYPT_KDF_KDFTLS12:
            return ISO19790_KdfTls12ParamCheck(data->hkdf->macId, data->hkdf->keyLen);
        case CRYPT_KDF_HKDF:
            return ISO19790_HkdfParamCheck(data->hkdf->macId, data->hkdf->keyLen);
        default:
            return false;
    }
}

bool CMVP_Iso19790RandC2(CRYPT_RAND_AlgId id)
{
    return ISO19790_RandParamCheck(id);
}

#endif
