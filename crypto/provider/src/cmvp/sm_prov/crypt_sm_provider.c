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

#include <stdint.h>
#include <string.h>
#include "bsl_errno.h"
#include "bsl_params.h"
#include "crypt_algid.h"
#include "crypt_errno.h"
#include "crypt_utils.h"
#include "crypt_eal_rand.h"
#include "entropy_seed_pool.h"
#include "crypt_sm_selftest.h"
#include "crypt_sm_provderimpl.h"
#include "crypt_sm_provider.h"

#define CRYPT_ENTROPY_SOURCE_ENTROPY 8
#define CRYPT_ENTROPY_SEED_POOL_SIZE 4096

static const CRYPT_EAL_AlgInfo g_smMds[] = {
    {CRYPT_MD_SM3, g_smMdSm3, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smKdfs[] = {
    {CRYPT_KDF_PBKDF2, g_smKdfPBKdf2, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smKeyMgmt[] = {
    {CRYPT_PKEY_SM2, g_smKeyMgmtSm2, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smAsymCiphers[] = {
    {CRYPT_PKEY_SM2, g_smAsymCipherSm2, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smKeyExch[] = {
    {CRYPT_PKEY_SM2, g_smExchSm2, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smSigns[] = {
    {CRYPT_PKEY_SM2, g_smSignSm2, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smMacs[] = {
    {CRYPT_MAC_HMAC_SM3, g_smMacHmac, CRYPT_EAL_SM_ATTR},
    {CRYPT_MAC_CBC_MAC_SM4, g_smMacCbcMac, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smRands[] = {
    {CRYPT_RAND_SM3, g_smRand, CRYPT_EAL_SM_ATTR},
    {CRYPT_RAND_SM4_CTR_DF, g_smRand, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smCiphers[] = {
    {CRYPT_CIPHER_SM4_XTS, g_smXts, CRYPT_EAL_SM_ATTR},
    {CRYPT_CIPHER_SM4_CBC, g_smCbc, CRYPT_EAL_SM_ATTR},
    {CRYPT_CIPHER_SM4_ECB, g_smEcb, CRYPT_EAL_SM_ATTR},
    {CRYPT_CIPHER_SM4_CTR, g_smCtr, CRYPT_EAL_SM_ATTR},
    {CRYPT_CIPHER_SM4_GCM, g_smGcm, CRYPT_EAL_SM_ATTR},
    {CRYPT_CIPHER_SM4_CFB, g_smCfb, CRYPT_EAL_SM_ATTR},
    {CRYPT_CIPHER_SM4_OFB, g_smOfb, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static const CRYPT_EAL_AlgInfo g_smSelftests[] = {
    {CRYPT_CMVP_PROVIDER_SELFTEST, g_smSelftest, CRYPT_EAL_SM_ATTR},
    CRYPT_EAL_ALGINFO_END
};

static int32_t CRYPT_EAL_SmProvQuery(void *provCtx, int32_t operaId, const CRYPT_EAL_AlgInfo **algInfos)
{
    (void)provCtx;
    int32_t ret = CRYPT_SUCCESS;
    switch (operaId) {
        case CRYPT_EAL_OPERAID_SYMMCIPHER:
            *algInfos = g_smCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYMGMT:
            *algInfos = g_smKeyMgmt;
            break;
        case CRYPT_EAL_OPERAID_SIGN:
            *algInfos = g_smSigns;
            break;
        case CRYPT_EAL_OPERAID_ASYMCIPHER:
            *algInfos = g_smAsymCiphers;
            break;
        case CRYPT_EAL_OPERAID_KEYEXCH:
            *algInfos = g_smKeyExch;
            break;
        case CRYPT_EAL_OPERAID_HASH:
            *algInfos = g_smMds;
            break;
        case CRYPT_EAL_OPERAID_MAC:
            *algInfos = g_smMacs;
            break;
        case CRYPT_EAL_OPERAID_KDF:
            *algInfos = g_smKdfs;
            break;
        case CRYPT_EAL_OPERAID_RAND:
            *algInfos = g_smRands;
            break;
        case CRYPT_EAL_OPERAID_SELFTEST:
            *algInfos = g_smSelftests;
            break;
        default:
            *algInfos = NULL;
            ret = CRYPT_NOT_SUPPORT;
            break;
    }
    return ret;
}

static void CRYPT_EAL_SmProvFree(void *provCtx)
{
    if (provCtx == NULL) {
        return;
    }
    CRYPT_EAL_SmProvCtx *temp = (CRYPT_EAL_SmProvCtx *)provCtx;
    CRYPT_EAL_SeedPoolFree(temp->pool);
    CRYPT_EAL_EsFree(temp->es);
    BSL_SAL_Free(provCtx);
}

static CRYPT_EAL_Func g_smProvOutFuncs[] = {
    {CRYPT_EAL_PROVCB_QUERY, CRYPT_EAL_SmProvQuery},
    {CRYPT_EAL_PROVCB_FREE, CRYPT_EAL_SmProvFree},
    {CRYPT_EAL_PROVCB_CTRL, NULL},
    {CRYPT_EAL_PROVCB_GETCAPS, NULL},
    CRYPT_EAL_FUNC_END
};

static int32_t ReadDevRandom(void *ctx, uint32_t timeout, uint8_t *buf, uint32_t bufLen)
{
    (void)ctx;
    (void)timeout;
    if (ENTROPY_SysEntropyGet(NULL, buf, bufLen) != bufLen) {
        return CRYPT_DRBG_FAIL_GET_ENTROPY;
    }
    return CRYPT_SUCCESS;
}

static int32_t CreateSmEs(CRYPT_EAL_Es **es)
{
    int32_t ret = CRYPT_SUCCESS;
    CRYPT_EAL_Es *esTemp = CRYPT_EAL_EsNew();
    RETURN_RET_IF(esTemp == NULL, CRYPT_MEM_ALLOC_FAIL);

    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_CF, "sm3_df", (uint32_t)strlen("sm3_df"));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    CRYPT_EAL_NsPara para = {
        "dev-random",
        false,
        5,
        {NULL, NULL, ReadDevRandom, NULL},
        {5, 39, 512},
    };
    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_ADD_NS, (void *)&para, sizeof(CRYPT_EAL_NsPara));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    bool healthTest = true;
    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_ENABLE_TEST, &healthTest, sizeof(healthTest));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    uint32_t size = CRYPT_ENTROPY_SEED_POOL_SIZE;
    ret = CRYPT_EAL_EsCtrl(esTemp, CRYPT_ENTROPY_SET_POOL_SIZE, &size, sizeof(size));
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    ret = CRYPT_EAL_EsInit(esTemp);
    GOTO_ERR_IF_TRUE(ret != CRYPT_SUCCESS, ret);

    *es = esTemp;
    return ret;

ERR:
    CRYPT_EAL_EsFree(esTemp);
    return ret;
}

static int32_t CreateSeedPool(CRYPT_EAL_SeedPoolCtx **seedPool, CRYPT_EAL_Es **es)
{
    CRYPT_EAL_SeedPoolCtx *poolTemp = NULL;
    CRYPT_EAL_Es *esTemp = NULL;

    int32_t ret = CreateSmEs(&esTemp);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }

    poolTemp = CRYPT_EAL_SeedPoolNew(true);
    if (poolTemp == NULL) {
        CRYPT_EAL_EsFree(esTemp);
        BSL_ERR_PUSH_ERROR(CRYPT_SEED_POOL_NEW_ERROR);
        return CRYPT_SEED_POOL_NEW_ERROR;
    }

    CRYPT_EAL_EsPara para = {false, CRYPT_ENTROPY_SOURCE_ENTROPY, esTemp, (CRYPT_EAL_EntropyGet)CRYPT_EAL_EsEntropyGet};
    ret = CRYPT_EAL_SeedPoolAddEs(poolTemp, &para);
    if (ret != CRYPT_SUCCESS) {
        CRYPT_EAL_SeedPoolFree(poolTemp);
        CRYPT_EAL_EsFree(esTemp);
        return ret;
    }

    *seedPool = poolTemp;
    *es = esTemp;
    return CRYPT_SUCCESS;
}

static int32_t CreateProvCtx(void *libCtx, CRYPT_EAL_ProvMgrCtx *mgrCtx, void **provCtx)
{
    CRYPT_EAL_SmProvCtx *temp = BSL_SAL_Calloc(1, sizeof(CRYPT_EAL_SmProvCtx));
    if (temp == NULL) {
        BSL_ERR_PUSH_ERROR(BSL_MALLOC_FAIL);
        return BSL_MALLOC_FAIL;
    }

    CRYPT_EAL_SetRandCallBackEx((CRYPT_EAL_RandFuncEx)CRYPT_EAL_RandbytesEx);
    int32_t ret = CreateSeedPool(&temp->pool, &temp->es);
    if (ret != CRYPT_SUCCESS) {
        BSL_SAL_Free(temp);
        return ret;
    }
    temp->libCtx = libCtx;
    temp->mgrCtx = mgrCtx;
    *provCtx = temp;
    return CRYPT_SUCCESS;
}

int32_t CRYPT_EAL_ProviderInit(CRYPT_EAL_ProvMgrCtx *mgrCtx, BSL_Param *param, CRYPT_EAL_Func *capFuncs,
    CRYPT_EAL_Func **outFuncs, void **provCtx)
{
    void *libCtx = NULL;
    CRYPT_EAL_ProvMgrCtrlCb mgrCtrl = NULL;
    int32_t index = 0;
    int32_t ret;
    while (capFuncs[index].id != 0) {
        switch (capFuncs[index].id) {
            case CRYPT_EAL_CAP_MGRCTXCTRL:
                mgrCtrl = capFuncs[index].func;
                break;
            default:
                break;
        }
        index++;
    }
    if (mgrCtrl == NULL) {
        return CRYPT_PROVIDER_NOT_SUPPORT;
    }
    ret = mgrCtrl(mgrCtx, CRYPT_EAL_MGR_GETLIBCTX, &libCtx, 0);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CRYPT_SM_Selftest(param);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    ret = CreateProvCtx(libCtx, mgrCtx, provCtx);
    if (ret != CRYPT_SUCCESS) {
        return ret;
    }
    *outFuncs = g_smProvOutFuncs;
    return CRYPT_SUCCESS;
}

#endif /* HITLS_CRYPTO_CMVP_SM */
