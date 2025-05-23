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

#ifndef CMVP_ISO19790_H
#define CMVP_ISO19790_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP

#include <stdint.h>
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_kdf.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

int32_t CMVP_Iso19790Dep(void);
int32_t CMVP_Iso19790ModeSet(CRYPT_CMVP_MODE mode);
void CMVP_Iso19790EventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);
bool CMVP_Iso19790PkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data);
bool CMVP_Iso19790MdC2(CRYPT_MD_AlgId id);
bool CMVP_Iso19790CipherC2(CRYPT_CIPHER_AlgId id);
bool CMVP_Iso19790MacC2(CRYPT_MAC_AlgId id, uint32_t keyLen);
bool CMVP_Iso19790KdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data);
bool CMVP_Iso19790RandC2(CRYPT_RAND_AlgId id);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif // CMVP_ISO19790_H
