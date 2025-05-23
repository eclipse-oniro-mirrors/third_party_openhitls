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

#include <stddef.h>
#include "cmvp_common.h"
#include "cmvp_iso19790.h"
#include "cmvp_fips.h"
#include "cmvp_gmt.h"
#include "cmvp_method.h"

#define CRYPT_CMVP_IMPL_METHOD_DECLARE(name)    \
    CMVP_Method g_cmvpMethod_##name = {         \
        CMVP_##name##Dep, CMVP_##name##ModeSet, CMVP_##name##EventProcess, \
        CMVP_##name##PkeyC2, CMVP_##name##MdC2, CMVP_##name##MacC2, \
        CMVP_##name##CipherC2, CMVP_##name##KdfC2, CMVP_##name##RandC2\
    }
// NDCpp retains only algorithm self-check and key pair consistency check.
CMVP_Method g_cmvpMethodNdcpp = {
    NULL, CMVP_ModeSet, NULL,
    NULL, NULL, NULL,
    NULL, NULL, NULL,
};

CRYPT_CMVP_IMPL_METHOD_DECLARE(Iso19790);
CRYPT_CMVP_IMPL_METHOD_DECLARE(Fips);
CRYPT_CMVP_IMPL_METHOD_DECLARE(Gmt);

static const CMVP_Method *g_cmvpMethods[CRYPT_CMVP_MODE_MAX] = {
    NULL, // Non-approved
    &g_cmvpMethod_Iso19790, // ISO19790
    &g_cmvpMethod_Fips,     // Fips
    &g_cmvpMethodNdcpp,    // NDCPP
    &g_cmvpMethod_Gmt,    // GM
};

const CMVP_Method *CMVP_FindMethod(CRYPT_CMVP_MODE mode)
{
    return g_cmvpMethods[mode];
}

#endif
