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

#ifndef CMVP_METHOD_H
#define CMVP_METHOD_H

#include "hitls_build.h"
#ifdef HITLS_CRYPTO_CMVP

#include <stdint.h>
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_md.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"
#include "crypt_entropy.h"

#ifdef __cplusplus
extern "C" {
#endif // __cplusplus

/* Default interface */
typedef int32_t (*Dep)(void);

/* Switching Mode Prototype */
typedef int32_t (*ModeSet)(CRYPT_CMVP_MODE mode);

typedef struct {
    Dep dep;            // Default interface
    ModeSet modeSet;    // Switching Mode
    EventReport eventReport; // event handling
    CRYPT_EAL_PkeyC2 pkeyC2; // Asymmetric compliance check
    CRYPT_EAL_MdC2 mdC2; // Hash compliance check
    CRYPT_EAL_MacC2 macC2; // MAC compliance check
    CRYPT_EAL_CipherC2 cipherC2; // Symmetric compliance check
    CRYPT_EAL_KdfC2 kdfC2; // KDF compliance check
    CRYPT_EAL_RandC2 randC2; // rand compliance check
} CMVP_Method;

const CMVP_Method *CMVP_FindMethod(CRYPT_CMVP_MODE mode);

#ifdef __cplusplus
}
#endif // __cplusplus
#endif
#endif // CMVP_METHOD_H
