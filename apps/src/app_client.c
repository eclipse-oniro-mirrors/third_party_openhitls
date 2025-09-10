/*
 * This file is part of the openHiTLS project.
 *
 * openHiTLS is licensed under the Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *#include "hitls_config.h"
 *     http://license.coscl.org.cn/MulanPSL2
 *
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 */

#include "app_client.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <signal.h>
#include "securec.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_tls_common.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_session.h"
#include "crypt_errno.h"
#include "hitls_crypt_init.h"
#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "sal_net.h"
#include "bsl_log.h"

#define HTTP_BUF_MAXLEN (18 * 1024)
#define IS_SUPPORT_GET_EOF 1

/* Client option types */
typedef enum {
    HITLS_CLIENT_OPT_HOST = 2,
    HITLS_CLIENT_OPT_PORT,
    
    /* Protocol options */
    HITLS_CLIENT_OPT_TLCP,
    HITLS_CLIENT_OPT_DTLCP,
    HITLS_CLIENT_OPT_CIPHER,
    
    /* Certificate options */
    HITLS_CLIENT_OPT_CAFILE,
    HITLS_CLIENT_OPT_CHAINCAFILE,
    HITLS_CLIENT_OPT_NO_VERIFY,
    
    /* TLCP options */
    HITLS_CLIENT_OPT_TLCP_ENC_CERT,
    HITLS_CLIENT_OPT_TLCP_ENC_KEY,
    HITLS_CLIENT_OPT_TLCP_SIGN_CERT,
    HITLS_CLIENT_OPT_TLCP_SIGN_KEY,

    /* Output options */
    HITLS_CLIENT_OPT_QUIET,
    HITLS_CLIENT_OPT_STATE,
    HITLS_CLIENT_OPT_PREXIT,
    
    /* Format options */
    HITLS_CLIENT_OPT_CERTFORM,
    HITLS_CLIENT_OPT_KEYFORM,
    HITLS_APP_PROV_ENUM,
    HITLS_CLIENT_OPT_MAX,

} HITLS_ClientOptType;

/* Command line options for s_client */
static const HITLS_CmdOption g_clientOptions[] = {
    /* Connection options */
    {"host",        HITLS_CLIENT_OPT_HOST,        HITLS_APP_OPT_VALUETYPE_STRING,  "Target hostname or IP address"},
    {"port",        HITLS_CLIENT_OPT_PORT,        HITLS_APP_OPT_VALUETYPE_UINT,    "Target port number (default 443)"},
    
    /* Protocol options */
    {"tlcp",        HITLS_CLIENT_OPT_TLCP,        HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Use TLCP protocol"},
    {"dtlcp",       HITLS_CLIENT_OPT_DTLCP,       HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Use DTLCP protocol"},
    {"cipher",      HITLS_CLIENT_OPT_CIPHER,      HITLS_APP_OPT_VALUETYPE_STRING,   "Specify cipher suites"},
    
    /* Certificate options */
    {"CAfile",      HITLS_CLIENT_OPT_CAFILE,      HITLS_APP_OPT_VALUETYPE_IN_FILE,  "CA certificate file"},
    {"chainCAfile", HITLS_CLIENT_OPT_CHAINCAFILE, HITLS_APP_OPT_VALUETYPE_IN_FILE,  "CA file for certificate chain"},
    {"noverify",    HITLS_CLIENT_OPT_NO_VERIFY,   HITLS_APP_OPT_VALUETYPE_NO_VALUE, "Don't verify server certificate"},
    
    /* TLCP options */
    {"tlcp_enc_cert", HITLS_CLIENT_OPT_TLCP_ENC_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption certificate"},
    {"tlcp_enc_key",  HITLS_CLIENT_OPT_TLCP_ENC_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption private key"},
    {"tlcp_sign_cert", HITLS_CLIENT_OPT_TLCP_SIGN_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature certificate"},
    {"tlcp_sign_key",  HITLS_CLIENT_OPT_TLCP_SIGN_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature private key"},
    
    /* Output options */
    {"quiet",       HITLS_CLIENT_OPT_QUIET,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Quiet mode"},
    {"state",       HITLS_CLIENT_OPT_STATE,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show handshake state"},
    {"prexit",      HITLS_CLIENT_OPT_PREXIT,      HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Exit after handshake"},
    
    /* Format options */
    {"certform",    HITLS_CLIENT_OPT_CERTFORM,    HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Certificate format (PEM|DER)"},
    {"keyform",     HITLS_CLIENT_OPT_KEYFORM,     HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Private key format (PEM|DER)"},
    
    {"help",        HITLS_APP_OPT_HELP,           HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show help"},
    HITLS_APP_PROV_OPTIONS,
    {NULL,          0,                            0,                                   NULL}
};

static void InitClientParams(HITLS_ClientParams *params, AppProvider *provider)
{
    if (params == NULL || provider == NULL) {
        return;
    }
    
    memset_s(params, sizeof(HITLS_ClientParams), 0, sizeof(HITLS_ClientParams));
    
    /* Set default values */
    params->port = 4433;
    params->connectTimeout = 10;
    params->protocol = NULL;
    params->verifyDepth = 9;
    params->certFormat = BSL_FORMAT_PEM;
    params->keyFormat = BSL_FORMAT_PEM;
    params->provider = provider;
    params->verifyNone = false;
}

typedef int (*ClientOptHandleFunc)(HITLS_ClientParams *params);
typedef struct {
    int optType;
    ClientOptHandleFunc func;
} ClientOptHandleFuncMap;

static int HandleClientHost(HITLS_ClientParams *params)
{
    params->host = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleClientPort(HITLS_ClientParams *params)
{
    return HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), (uint32_t*)&params->port);
}

static int HandleClientTLCP(HITLS_ClientParams *params)
{
    params->protocol = "tlcp";
    return HITLS_APP_SUCCESS;
}
static int HandleClientDTLCP(HITLS_ClientParams *params)
{
    params->protocol = "dtlcp";
    return HITLS_APP_SUCCESS;
}
static int HandleClientCipher(HITLS_ClientParams *params)
{
    params->cipherSuites = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleClientCAFile(HITLS_ClientParams *params)
{
    params->caFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int HandleClientCAChain(HITLS_ClientParams *params)
{
    params->caChain = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int HandleClientNoVerify(HITLS_ClientParams *params)
{
    params->verifyNone = true;
    return HITLS_APP_SUCCESS;
}
static int HandleClientTLCPEncCert(HITLS_ClientParams *params)
{
    params->tlcpEncCert = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleClientTLCPEncKey(HITLS_ClientParams *params)
{
    params->tlcpEncKey = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}

static int HandleClientTLCPSignCert(HITLS_ClientParams *params)
{
    params->tlcpSignCert = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleClientTLCPSignKey(HITLS_ClientParams *params)
{
    params->tlcpSignKey = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleClientQuiet(HITLS_ClientParams *params)
{
    params->quiet = true;
    return HITLS_APP_SUCCESS;
}
static int HandleClientState(HITLS_ClientParams *params)
{
    params->state = true;
    return HITLS_APP_SUCCESS;
}
static int HandleClientPrexit(HITLS_ClientParams *params)
{
    params->prexit = true;
    return HITLS_APP_SUCCESS;
}

static int HandleClientCertForm(HITLS_ClientParams *params)
{
    return HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(),
        HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->certFormat);
}
static int HandleClientKeyForm(HITLS_ClientParams *params)
{
    return HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(),
        HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->keyFormat);
}
static int HandleClientHelp(HITLS_ClientParams *params)
{
    (void)params; // Unused parameter
    HITLS_APP_OptHelpPrint(g_clientOptions);
    return HITLS_APP_HELP;
}

static const ClientOptHandleFuncMap g_clientOptHandleFuncMap[] = {
    {HITLS_CLIENT_OPT_HOST, HandleClientHost},
    {HITLS_CLIENT_OPT_PORT, HandleClientPort},
    {HITLS_CLIENT_OPT_TLCP, HandleClientTLCP},
    {HITLS_CLIENT_OPT_DTLCP, HandleClientDTLCP},
    {HITLS_CLIENT_OPT_CIPHER, HandleClientCipher},
    {HITLS_CLIENT_OPT_CAFILE, HandleClientCAFile},
    {HITLS_CLIENT_OPT_CHAINCAFILE, HandleClientCAChain},
    {HITLS_CLIENT_OPT_NO_VERIFY, HandleClientNoVerify},
    {HITLS_CLIENT_OPT_TLCP_ENC_CERT, HandleClientTLCPEncCert},
    {HITLS_CLIENT_OPT_TLCP_ENC_KEY, HandleClientTLCPEncKey},
    {HITLS_CLIENT_OPT_TLCP_SIGN_CERT, HandleClientTLCPSignCert},
    {HITLS_CLIENT_OPT_TLCP_SIGN_KEY, HandleClientTLCPSignKey},
    {HITLS_CLIENT_OPT_QUIET, HandleClientQuiet},
    {HITLS_CLIENT_OPT_STATE, HandleClientState},
    {HITLS_CLIENT_OPT_PREXIT, HandleClientPrexit},
    {HITLS_CLIENT_OPT_CERTFORM, HandleClientCertForm},
    {HITLS_CLIENT_OPT_KEYFORM, HandleClientKeyForm},
    {HITLS_APP_OPT_HELP, HandleClientHelp},
};

static int ParseClientOptLoop(HITLS_ClientParams *params)
{
    int ret = HITLS_APP_SUCCESS;
    int opt;
    while ((opt = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF && ret == HITLS_APP_SUCCESS) {
        for (size_t i = 0; i < sizeof(g_clientOptHandleFuncMap)/sizeof(g_clientOptHandleFuncMap[0]); ++i) {
            if (g_clientOptHandleFuncMap[i].optType == opt) {
                ret = g_clientOptHandleFuncMap[i].func(params);
                break;
            }
        }
        HITLS_APP_PROV_CASES(opt, params->provider)
    }
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("pkeyutl: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return HITLS_APP_SUCCESS;
}

int ParseClientOptions(int argc, char *argv[], HITLS_ClientParams *params, AppProvider *provider)
{
    if (params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }

    InitClientParams(params, provider);

    int opt = HITLS_APP_OptBegin(argc, argv, g_clientOptions);
    if (opt !=  HITLS_APP_SUCCESS) {
        AppPrintError("Failed to initialize option parser\n");
        return opt;
    }

    int loopRet = ParseClientOptLoop(params);
    if (loopRet != HITLS_APP_SUCCESS && loopRet != HITLS_APP_SUCCESS) {
        return loopRet;
    }
    
    HITLS_APP_OptEnd();
    
    /* Validate required parameters */
    if (params->host == NULL) {
        AppPrintError("Host must be specified\n");
        return HITLS_APP_INVALID_ARG;
    }

    return HITLS_APP_SUCCESS;
}

static HITLS_Config *CreateClientConfig(HITLS_ClientParams *params)
{
    if (params == NULL) {
        return NULL;
    }
    
    /* Determine protocol type */
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    
    /* Create base configuration */
    HITLS_Config *config = CreateProtocolConfig(protocol, params->provider);
    if (config == NULL) {
        return NULL;
    }
    
    int ret = HITLS_SUCCESS;
    
    /* Configure cipher suites */
    if (params->cipherSuites) {
        ret = ConfigureCipherSuites(config, params->cipherSuites, protocol);
        if (ret != HITLS_APP_SUCCESS) {
            HITLS_CFG_FreeConfig(config);
            return NULL;
        }
    }
    
    /* Configure certificate verification */
    APP_CertConfig certConfig = {
        .caFile = params->caFile,
        .caChain = params->caChain,
        .certFormat = params->certFormat,
        .keyFormat = params->keyFormat,
        .tlcpEncCert = params->tlcpEncCert,
        .tlcpEncKey = params->tlcpEncKey,
        .tlcpSignCert = params->tlcpSignCert,
        .tlcpSignKey = params->tlcpSignKey,
        .provider = params->provider
    };
    
    ret = ConfCertVerification(config, &certConfig, !params->verifyNone, params->verifyDepth);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    
    /* Configure client certificate if provided */
    if (protocol == APP_PROTOCOL_TLCP || protocol == APP_PROTOCOL_DTLCP) {
        ret = ConfigureTLCPCertificates(config, &certConfig);
    }
    
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }

    return config;
}

static BSL_UIO *CreateClientConnection(HITLS_ClientParams *params)
{
    if (params == NULL || params->host == NULL) {
        return NULL;
    }
    
    APP_NetworkAddr addr = {
        .host = params->host,
        .port = params->port,
    };
    
    int sockfd = -1;
    BSL_UIO *uio = NULL;
    
    /* Create socket based on protocol */
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    if (protocol == APP_PROTOCOL_DTLCP) {
        sockfd = CreateUDPSocket(&addr, params->connectTimeout);
        uio = BSL_UIO_New(BSL_UIO_UdpMethod());
    } else {
        sockfd = CreateTCPSocket(&addr, params->connectTimeout);
        uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    }
    
    if (sockfd < 0 || uio == NULL) {
        if (sockfd >= 0) {
            BSL_SAL_SockClose(sockfd);
        }
        if (uio) {
            BSL_UIO_Free(uio);
        }
        return NULL;
    }
    
    /* Set socket to UIO */
    int ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(sockfd), &sockfd);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to set socket to UIO: 0x%x\n", ret);
        BSL_SAL_SockClose(sockfd);
        BSL_UIO_Free(uio);
        return NULL;
    }

    if (protocol == APP_PROTOCOL_DTLCP) {
        BSL_SAL_SockAddr serverAddr = NULL;
        ret = SAL_SockAddrNew(&serverAddr);
        if (ret != BSL_SUCCESS) {
            BSL_UIO_Free(uio);
            BSL_SAL_SockClose(sockfd);
            return NULL;
        }
        int32_t addrLen = (int32_t)SAL_SockAddrSize(serverAddr);
        if (getpeername(sockfd, (struct sockaddr*)serverAddr, (socklen_t *)&addrLen) == 0) {
            ret = BSL_UIO_Ctrl(uio, BSL_UIO_UDP_SET_CONNECTED, addrLen, serverAddr);
            if (ret != BSL_SUCCESS) {
                SAL_SockAddrFree(serverAddr);
                BSL_SAL_SockClose(sockfd);
                BSL_UIO_Free(uio);
                return NULL;
            }
        }
        SAL_SockAddrFree(serverAddr);
    }

    BSL_UIO_SetInit(uio, true);
    
    if (!params->quiet) {
        AppPrintInfo("Connected to %s:%d\n", params->host, params->port);
    }
    
    return uio;
}

static int PerformClientHandshake(HITLS_Ctx *ctx, HITLS_ClientParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    if (!params->quiet) {
        AppPrintInfo("Starting TLS handshake...\n");
    }
    
    /* Perform handshake */
    int ret;
    do {
        ret = HITLS_Connect(ctx);
        if (ret == HITLS_SUCCESS) {
            break;
        }
        if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY && ret != HITLS_REC_NORMAL_IO_BUSY) {
            AppPrintError("TLS handshake failed: 0x%x\n", ret);
            return HITLS_APP_ERR_HANDSHAKE;
        }
        /* Non-blocking I/O, retry */
        BSL_SAL_Sleep(10000); /* Sleep 10ms */
    } while (ret == HITLS_REC_NORMAL_RECV_BUF_EMPTY || ret == HITLS_REC_NORMAL_IO_BUSY);
    
    if (!params->quiet) {
        AppPrintInfo("TLS handshake completed successfully\n");
        
        /* Print connection information */
        PrintConnectionInfo(ctx, params->state);
    }
    
    return HITLS_APP_SUCCESS;
}

static int HandleClientDataExchange(HITLS_Ctx *ctx, HITLS_ClientParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_APP_SUCCESS;
    bool isEof = false;
    uint32_t readLen = 0;
    BSL_UIO *readUio = HITLS_APP_UioOpen(NULL, 'r', 0);
    BSL_UIO_SetIsUnderlyingClosedByUio(readUio, true);
    if (readUio == NULL) {
        AppPrintError("s_client: Failed to open stdin\n");
        return HITLS_APP_UIO_FAIL;
    }

    /* Interactive mode if no specific data to send */
    if (!params->prexit) {
        if (!params->quiet) {
            AppPrintInfo("Interactive mode - type messages (Ctrl+C to exit):\n");
        }
        
        char inputBuffer[HTTP_BUF_MAXLEN];
        while (BSL_UIO_Ctrl(readUio, BSL_UIO_FILE_GET_EOF, IS_SUPPORT_GET_EOF, &isEof) == BSL_SUCCESS && !isEof) {
            if (BSL_UIO_Read(readUio, inputBuffer, HTTP_BUF_MAXLEN, &readLen) != BSL_SUCCESS) {
                BSL_UIO_Free(readUio);
                (void)AppPrintError("Failed to obtain the content from the STDIN\n");
                return HITLS_APP_STDIN_FAIL;
            }
            if (readLen > 0 && inputBuffer[readLen - 1] == '\n') {
                inputBuffer[readLen - 1] = '\0';
                readLen--;
            }
            if (readLen == 0) {
                continue;
            }
            uint32_t written = 0;
            ret = HITLS_Write(ctx, (const uint8_t *)inputBuffer, readLen, &written);
            if (ret != HITLS_SUCCESS) {
                AppPrintError("Failed to send data: 0x%x\n", ret);
                break;
            }
            
            /* Try to read response */
            uint8_t response[HTTP_BUF_MAXLEN];
            uint32_t read_len = 0;
            ret = HITLS_Read(ctx, response, sizeof(response) - 1, &read_len);
            if (ret == HITLS_SUCCESS && read_len > 0) {
                response[read_len] = '\0';
                AppPrintInfo("Response: %s\n", response);
            }
        }
    }
    BSL_UIO_Free(readUio);
    return HITLS_APP_SUCCESS;
}

static void CleanupClientResources(HITLS_Ctx *ctx, HITLS_Config *config, BSL_UIO *uio)
{
    if (ctx) {
        HITLS_Close(ctx);
        HITLS_Free(ctx);
    }
    
    if (config) {
        HITLS_CFG_FreeConfig(config);
    }
    
    if (uio) {
        /* Close socket */
        int fd = -1;
        BSL_UIO_Ctrl(uio, BSL_UIO_GET_FD, 0, &fd);
        if (fd >= 0) {
            BSL_SAL_SockClose(fd);
        }
        BSL_UIO_Free(uio);
    }
}

int HITLS_ClientMain(int argc, char *argv[])
{
    AppProvider appProvider = {"default", NULL, "provider=default"};
    HITLS_ClientParams params = {0};
    HITLS_Config *config = NULL;
    HITLS_Ctx *ctx = NULL;
    BSL_UIO *uio = NULL;
    int ret = HITLS_APP_SUCCESS;
    
    /* Initialize library */
    /* BSL memory callbacks are already set up in BSL module */
    BSL_ERR_Init();
    
    /* Initialize print UIO for error and info output */
    ret = AppPrintErrorUioInit(stderr);
    if (ret != HITLS_APP_SUCCESS) {
        return HITLS_APP_INIT_FAILED;
    }
    
    ret = CRYPT_EAL_Init(CRYPT_EAL_INIT_ALL);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Failed to initialize crypto library: 0x%x\n", ret);
        return HITLS_APP_INIT_FAILED;
    }
    
    HITLS_CertMethodInit();
    HITLS_CryptMethodInit();
    
    /* Parse command line options */
    ret = ParseClientOptions(argc, argv, &params, &appProvider);
    if (ret != HITLS_APP_SUCCESS) {
        goto cleanup;
    }

    if (HITLS_APP_LoadProvider(params.provider->providerPath, params.provider->providerName) != HITLS_APP_SUCCESS) {
        goto cleanup;
    }

    ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SHA256,
        params.provider->providerAttr, NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Failed to initialize random: 0x%x\n", ret);
        return HITLS_APP_INIT_FAILED;
    }
    
    /* Create TLS configuration */
    config = CreateClientConfig(&params);
    if (config == NULL) {
        AppPrintError("Failed to create TLS configuration\n");
        ret = HITLS_APP_INVALID_ARG;
        goto cleanup;
    }
    
    /* Establish network connection */
    uio = CreateClientConnection(&params);
    if (uio == NULL) {
        AppPrintError("Failed to establish network connection\n");
        ret = HITLS_APP_ERR_CONNECT;
        goto cleanup;
    }
    
    /* Create TLS context */
    ctx = HITLS_New(config);
    if (ctx == NULL) {
        AppPrintError("Failed to create TLS context\n");
        ret = HITLS_APP_ERR_CREATE_CTX;
        goto cleanup;
    }
    
    /* Associate UIO with TLS context */
    ret = HITLS_SetUio(ctx, uio);
    if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to set UIO: 0x%x\n", ret);
        ret = HITLS_APP_UIO_FAIL;
        goto cleanup;
    }
    
    /* Perform TLS handshake */
    ret = PerformClientHandshake(ctx, &params);
    if (ret != HITLS_APP_SUCCESS) {
        goto cleanup;
    }
    
    /* Exit after handshake if requested */
    if (params.prexit) {
        if (!params.quiet) {
            AppPrintInfo("Handshake completed, exiting as requested\n");
        }
        ret = HITLS_APP_SUCCESS;
        goto cleanup;
    }
    
    /* Handle data exchange */
    ret = HandleClientDataExchange(ctx, &params);
    
cleanup:
    CleanupClientResources(ctx, config, uio);
    
    if (!params.quiet && ret == HITLS_APP_SUCCESS) {
        AppPrintInfo("Client completed successfully\n");
    }
    
    /* Cleanup print UIO */
    AppPrintErrorUioUnInit();
    
    return ret;
}