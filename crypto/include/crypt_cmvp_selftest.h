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

#ifndef CRYPT_CMVP_SELFTEST_H
#define CRYPT_CMVP_SELFTEST_H

#include <stdint.h>
#include "hitls_build.h"
#include "crypt_cmvp.h"
#include "crypt_types.h"
#include "crypt_eal_pkey.h"
#include "crypt_eal_rand.h"
#include "crypt_eal_md.h"
#include "crypt_eal_mac.h"
#include "crypt_eal_cipher.h"
#include "crypt_eal_kdf.h"


bool CRYPT_CMVP_SelftestDrbg(CRYPT_RAND_AlgId id);

bool CRYPT_CMVP_SelftestMd(CRYPT_MD_AlgId id);

bool CRYPT_CMVP_SelftestRsa(void);

bool CRYPT_CMVP_SelftestCipher(CRYPT_CIPHER_AlgId id);

bool CRYPT_CMVP_SelftestChacha20poly1305(void);

bool CRYPT_CMVP_SelftestDh(void);

bool CRYPT_CMVP_SelftestDsa(void);

bool CRYPT_CMVP_SelftestEd25519(void);

bool CRYPT_CMVP_SelftestHkdf(void);

bool CRYPT_CMVP_SelftestMac(CRYPT_MAC_AlgId id);

bool CRYPT_CMVP_SelftestPbkdf2(CRYPT_MAC_AlgId id);

bool CRYPT_CMVP_SelftestScrypt(void);

bool CRYPT_CMVP_SelftestKdfTls12(void);

bool CRYPT_CMVP_SelftestX25519(void);

bool CRYPT_CMVP_SelftestEcdsa(void);

bool CRYPT_CMVP_SelftestEcdh(void);

bool CRYPT_CMVP_SelftestSM2(void);

int32_t CRYPT_CMVP_SelftestGM(void);

bool CRYPT_CMVP_SelftestCipherKat(void);

bool CRYPT_CMVP_SelftestMlkemEncapsDecaps(void);

bool CRYPT_CMVP_SelftestMldsaSignVerify(void);

bool CRYPT_CMVP_SelftestSlhdsaSignVerify(void);

#endif
