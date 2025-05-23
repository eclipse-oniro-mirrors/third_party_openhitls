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

#include <stdlib.h>
#include <stdint.h>
#include "hitls_build.h"
#include "tls_binlog_id.h"
#include "bsl_log_internal.h"
#include "bsl_log.h"
#include "bsl_err_internal.h"
#include "bsl_bytes.h"
#include "hitls_error.h"
#include "hitls_config.h"
#include "tls.h"
#include "hs_msg.h"
#include "hs_ctx.h"
#include "hs.h"
#include "securec.h"
#include "bsl_errno.h"
#include "bsl_sal.h"
#include "custom_extensions.h"
#include "alert.h"

bool IsPackNeedCustomExtensions(CustomExt_Methods *exts, uint32_t context)
{
    uint32_t i = 0;

    if (exts == NULL) {
        return false;
    }
    CustomExt_Method *meth = exts->meths;
    if (meth == NULL) {
        return false;
    }
    for (i = 0; i < exts->methsCount; i++, meth++) {
        if ((context & meth->context) != 0) {
            return true;
        }
    }

    return false;
}

bool IsParseNeedCustomExtensions(CustomExt_Methods *exts, uint16_t extType, uint32_t context)
{
    uint32_t i = 0;

    if (exts == NULL) {
        return false;
    }

    CustomExt_Method *meth = exts->meths;

    if (meth == NULL) {
        return false;
    }

    for (i = 0; i < exts->methsCount; i++, meth++) {
        if (extType == meth->extType && (context & meth->context) != 0) {
            return true;
        }
    }
    return false;
}

bool IsCustomExtensionTypeAdded(CustomExt_Methods *exts, uint16_t extType)
{
    uint32_t i = 0;

    if (exts == NULL) {
        return false;
    }
    CustomExt_Method *meth = exts->meths;
    if (meth == NULL) {
        return false;
    }
    for (i = 0; i < exts->methsCount; i++, meth++) {
        if (extType == meth->extType) {
            return true;
        }
    }
    return false;
}

CustomExt_Method *FindCustomExtensions(CustomExt_Methods *exts, uint16_t extType, uint32_t context)
{
    uint32_t i = 0;

    if (exts == NULL) {
        return NULL;
    }

    CustomExt_Method *meth = exts->meths;

    if (meth == NULL) {
        return NULL;
    }

    for (i = 0; i < exts->methsCount; i++, meth++) {
        if (extType == meth->extType && (context & meth->context) != 0) {
            return meth;
        }
    }
    return NULL;
}

uint32_t HITLS_CFG_AddCustomExtension(HITLS_Config *config, const HITLS_CustomExtParams *params)
{
    CustomExt_Method *meth = NULL;
    CustomExt_Method *tmp = NULL;

    if (config == NULL || params == NULL) {
        return HITLS_NULL_INPUT;
    }

    if (params->addCb == NULL && params->freeCb != NULL) {
        return HITLS_INVALID_INPUT;
    }

    CustomExt_Methods *exts = config->customExts;

    if (IsCustomExtensionTypeAdded(exts, params->extType) ||
        FindCustomExtensions(exts, params->extType, params->context) != NULL) {
        return HITLS_CONFIG_DUP_CUSTOM_EXT;
    }

    if (exts == NULL) {
        exts = (CustomExt_Methods *)BSL_SAL_Malloc(sizeof(CustomExt_Methods));
        if (exts == NULL) {
            return HITLS_MEMALLOC_FAIL;
        }
        exts->meths = NULL;
        exts->methsCount = 0;
        config->customExts = exts;
    }

    tmp = BSL_SAL_Realloc(exts->meths, (exts->methsCount + 1) * sizeof(CustomExt_Method),
                          exts->methsCount * sizeof(CustomExt_Method));
    if (tmp == NULL) {
        return HITLS_MEMALLOC_FAIL;
    }

    exts->meths = tmp;
    meth = exts->meths + exts->methsCount;

    memset_s(meth, sizeof(*meth), 0, sizeof(*meth));
    meth->extType = params->extType;
    meth->context = params->context;
    meth->addCb = params->addCb;
    meth->freeCb = params->freeCb;
    meth->addArg = params->addArg;
    meth->parseCb = params->parseCb;
    meth->parseArg = params->parseArg;
    exts->methsCount++;

    return HITLS_SUCCESS;
}

uint32_t HITLS_AddCustomExtension(HITLS_Ctx *ctx, const HITLS_CustomExtParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_NULL_INPUT;
    }

    return HITLS_CFG_AddCustomExtension(&(ctx->config.tlsConfig), params);
}


int32_t PackCustomExtensions(const struct TlsCtx *ctx, uint8_t *buf, uint32_t bufLen, uint32_t *len, uint32_t context, HITLS_X509_Cert *cert, uint32_t certIndex)
{
    uint32_t offset = 0u;
    uint32_t alert = 0u;

    if (ctx == NULL || buf == NULL || len == NULL) {
        return HITLS_NULL_INPUT;
    }

    CustomExt_Methods *exts = CUSTOM_EXT_FROM_CTX(ctx);
    CustomExt_Method *meth = NULL;
    uint32_t ret = 0;
    if (exts == NULL) {
        *len = 0;
        return HITLS_SUCCESS;
    }

    for (uint32_t i = 0; i < exts->methsCount; i++) {
        uint8_t *out = NULL;
        uint32_t outLen = 0;

        meth = exts->meths + i;

        if ((meth->context & context) == 0) {
            continue;
        }

        if (meth->addCb != NULL) {
            ret = meth->addCb(ctx, meth->extType, context, &out, &outLen, cert, certIndex, &alert, meth->addArg);
            if (ret != HITLS_ADD_CUSTOM_EXTENSION_RET_PACK && ret != HITLS_ADD_CUSTOM_EXTENSION_RET_PASS) {
                ALERT_Send(ctx, ALERT_LEVEL_FATAL, alert);
                BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17350, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                    "pack custom extension content fail.", 0, 0, 0, 0);
                return ret;
            }
        }

        if (ret == HITLS_ADD_CUSTOM_EXTENSION_RET_PACK) {
            if (bufLen - offset >= outLen + sizeof(uint16_t) + sizeof(uint16_t)) {
                BSL_Uint16ToByte(meth->extType, &buf[offset]);
                offset += sizeof(uint16_t);

                BSL_Uint16ToByte(outLen, &buf[offset]);
                offset += sizeof(uint16_t);

                (void)memcpy_s(&buf[offset], bufLen - offset, out, outLen);
                offset += outLen;
            } else {
                return HITLS_PACK_NOT_ENOUGH_BUF_LENGTH;
            }
        }

        if (meth->freeCb != NULL && out != NULL) {
            meth->freeCb(ctx, meth->extType, context, out, meth->addArg);
        }
    }

    *len = offset;
    return HITLS_SUCCESS;
}

int32_t ParseCustomExtensions(const struct TlsCtx *ctx, const uint8_t *buf, uint16_t extType, uint32_t extLen,
    uint32_t context, HITLS_X509_Cert *cert, uint32_t certIndex)
{
    uint32_t alert = 0u;

    CustomExt_Methods *exts = CUSTOM_EXT_FROM_CTX(ctx);
    CustomExt_Method *meth;

    meth = FindCustomExtensions(exts, extType, context);
    if (meth == NULL) {
        return HITLS_SUCCESS;
    }

    // Create a local pointer starting from the position after the type byte
    if (meth->parseCb != NULL) {
        uint32_t ret = meth->parseCb(ctx, meth->extType, context, &buf, &extLen, cert, certIndex, &alert, meth->parseArg);
        if (ret != HITLS_SUCCESS) {
            ALERT_Send(ctx, ALERT_LEVEL_FATAL, alert);
            BSL_LOG_BINLOG_FIXLEN(BINLOG_ID17351, BSL_LOG_LEVEL_ERR, BSL_LOG_BINLOG_TYPE_RUN,
                                  "parse custom extension content fail.", 0, 0, 0, 0);
            return ret;
        }
    }

    return HITLS_SUCCESS;
}

void FreeCustomExtensions(CustomExt_Methods *exts)
{
    if (exts == NULL) {
        return;
    }
    if (exts->meths == NULL) {
        BSL_SAL_Free(exts);
        return;
    }
    BSL_SAL_Free(exts->meths);
    BSL_SAL_Free(exts);
}

CustomExt_Methods *DupCustomExtensions(CustomExt_Methods *exts)
{
    if (exts == NULL) {
        return NULL;
    }
    CustomExt_Methods *newExts = (CustomExt_Methods *)BSL_SAL_Malloc(sizeof(CustomExt_Methods));
    if (newExts == NULL) {
        return NULL;
    }
    newExts->meths = (CustomExt_Method *)BSL_SAL_Dump(exts->meths, exts->methsCount * sizeof(CustomExt_Method));
    if (newExts->meths == NULL) {
        BSL_SAL_Free(newExts);
        return NULL;
    }
    newExts->methsCount = exts->methsCount;
    return newExts;
}