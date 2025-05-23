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

#ifndef CMVP_GMT_H
#define CMVP_GMT_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP

#include <stdint.h>
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_eal_kdf.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

// default entry point
int32_t CMVP_GmtDep(void);

// set mode
int32_t CMVP_GmtModeSet(CRYPT_CMVP_MODE mode);

// status indication
void CMVP_GmtEventProcess(CRYPT_EVENT_TYPE oper, CRYPT_ALGO_TYPE type, int32_t id, int32_t err);

// asym alg param check
bool CMVP_GmtPkeyC2(CRYPT_PKEY_AlgId id, const CRYPT_EAL_PkeyC2Data *data);

// md alg param check
bool CMVP_GmtMdC2(CRYPT_MD_AlgId id);

// cipher alg param check
bool CMVP_GmtCipherC2(CRYPT_CIPHER_AlgId id);

// mac alg param check
bool CMVP_GmtMacC2(CRYPT_MAC_AlgId id, uint32_t keyLen);

// kdf alg param check
bool CMVP_GmtKdfC2(CRYPT_KDF_AlgId id, const CRYPT_EAL_KdfC2Data *data);

// rand alg param check
bool CMVP_GmtRandC2(CRYPT_RAND_AlgId id);


#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif // CMVP_FIPS_H
