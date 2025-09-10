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

#include "app_server.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <signal.h>
#include "securec.h"
#include "app_errno.h"
#include "app_print.h"
#include "app_opt.h"
#include "app_tls_common.h"
#include "hitls.h"
#include "hitls_cert_init.h"
#include "hitls_crypt_init.h"
#include "hitls_session.h"
#include "crypt_errno.h"
#include "bsl_uio.h"
#include "crypt_eal_init.h"
#include "crypt_eal_rand.h"
#include "bsl_sal.h"
#include "bsl_err.h"
#include "bsl_log.h"

#define HTTP_BUF_MAXLEN (18 * 1024) /* 18KB */

/* Server option types */
typedef enum {
    HITLS_SERVER_OPT_ACCEPT = 2,
    HITLS_SERVER_OPT_PORT,
    
    /* Protocol options */
    HITLS_SERVER_OPT_TLCP,
    HITLS_SERVER_OPT_DTLCP,
    HITLS_SERVER_OPT_CIPHER,
    
    /* Certificate options */
    HITLS_SERVER_OPT_CAFILE,
    HITLS_SERVER_OPT_CHAINCAFILE,
    
    /* TLCP options */
    HITLS_SERVER_OPT_TLCP_ENC_CERT,
    HITLS_SERVER_OPT_TLCP_ENC_KEY,
    HITLS_SERVER_OPT_TLCP_SIGN_CERT,
    HITLS_SERVER_OPT_TLCP_SIGN_KEY,
    
    /* Service options */
    HITLS_SERVER_OPT_ACCEPT_ONCE,
    
    /* Output options */
    HITLS_SERVER_OPT_QUIET,
    HITLS_SERVER_OPT_STATE,
    
    /* Format options */
    HITLS_SERVER_OPT_CERTFORM,
    HITLS_SERVER_OPT_KEYFORM,
    HITLS_APP_PROV_ENUM,
    HITLS_SERVER_OPT_MAX,
} HITLS_ServerOptType;

/* Command line options for s_server */
static const HITLS_CmdOption g_serverOptions[] = {
    /* Listen options */
    {"accept",      HITLS_SERVER_OPT_ACCEPT,      HITLS_APP_OPT_VALUETYPE_STRING,      "Listen on host:port"},
    {"port",        HITLS_SERVER_OPT_PORT,        HITLS_APP_OPT_VALUETYPE_UINT,        "Listen port (default 4433)"},
    
    /* Protocol options */
    {"tlcp",        HITLS_SERVER_OPT_TLCP,        HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use TLCP protocol"},
    {"dtlcp",       HITLS_SERVER_OPT_DTLCP,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Use DTLCP protocol"},
    {"cipher",      HITLS_SERVER_OPT_CIPHER,      HITLS_APP_OPT_VALUETYPE_STRING,      "Specify cipher suites"},
    
    /* Certificate options */
    {"CAfile",      HITLS_SERVER_OPT_CAFILE,      HITLS_APP_OPT_VALUETYPE_IN_FILE,     "CA certificate file"},
    {"chainCAfile", HITLS_SERVER_OPT_CHAINCAFILE, HITLS_APP_OPT_VALUETYPE_IN_FILE,     "CA file for certificate chain"},
    
    /* TLCP options */
    {"tlcp_enc_cert", HITLS_SERVER_OPT_TLCP_ENC_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption certificate"},
    {"tlcp_enc_key",  HITLS_SERVER_OPT_TLCP_ENC_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP encryption private key"},
    {"tlcp_sign_cert", HITLS_SERVER_OPT_TLCP_SIGN_CERT, HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature certificate"},
    {"tlcp_sign_key",  HITLS_SERVER_OPT_TLCP_SIGN_KEY,  HITLS_APP_OPT_VALUETYPE_IN_FILE, "TLCP signature private key"},
    
    /* Service options */
    {"accept_once", HITLS_SERVER_OPT_ACCEPT_ONCE, HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Accept only one connection"},
    
    /* Output options */
    {"quiet",       HITLS_SERVER_OPT_QUIET,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Quiet mode"},
    {"state",       HITLS_SERVER_OPT_STATE,       HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show handshake state"},
    
    /* Format options */
    {"certform",    HITLS_SERVER_OPT_CERTFORM,    HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Certificate format (PEM|DER)"},
    {"keyform",     HITLS_SERVER_OPT_KEYFORM,     HITLS_APP_OPT_VALUETYPE_FMT_PEMDER,  "Private key format (PEM|DER)"},
    
    {"help",        HITLS_APP_OPT_HELP,           HITLS_APP_OPT_VALUETYPE_NO_VALUE,    "Show help"},
    HITLS_APP_PROV_OPTIONS,
    {NULL,          0,                            0,                                   NULL}
};

typedef int (*ServerOptHandleFunc)(HITLS_ServerParams *);
typedef struct {
    int optType;
    ServerOptHandleFunc func;
} ServerOptHandleFuncMap;

static void InitServerParams(HITLS_ServerParams *params, AppProvider *provider)
{
    if (params == NULL || provider == NULL) {
        return;
    }
    
    memset_s(params, sizeof(HITLS_ServerParams), 0, sizeof(HITLS_ServerParams));
    
    /* Set default values */
    params->port = 4433;
    params->backlog = 5;
    params->protocol = NULL;
    params->verifyDepth = 9;
    params->certFormat = BSL_FORMAT_PEM;
    params->keyFormat = BSL_FORMAT_PEM;
    params->maxConnections = 0;   /* No limit */
    params->provider = provider;
    params->verifyClient = true;
}

static int HandleServerAccept(HITLS_ServerParams *params)
{
    APP_NetworkAddr addr = {0};
    if (ParseConnectString(HITLS_APP_OptGetValueStr(), &addr) == HITLS_APP_SUCCESS) {
        params->bindAddr = addr.host;
        params->port = addr.port;
    }
    return HITLS_APP_SUCCESS;
}
static int HandleServerPort(HITLS_ServerParams *params)
{
    HITLS_APP_OptGetUint32(HITLS_APP_OptGetValueStr(), (uint32_t*)&params->port);
    return HITLS_APP_SUCCESS;
}
static int HandleServerTLCP(HITLS_ServerParams *params)
{
    params->protocol = "tlcp";
    return HITLS_APP_SUCCESS;
}
static int HandleServerDTLCP(HITLS_ServerParams *params)
{
    params->protocol = "dtlcp";
    return HITLS_APP_SUCCESS;
}
static int HandleServerCipher(HITLS_ServerParams *params)
{
    params->cipherSuites = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleServerCAFile(HITLS_ServerParams *params)
{
    params->caFile = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleServerChainCAFile(HITLS_ServerParams *params)
{
    params->caChain = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleServerTLCPEncCert(HITLS_ServerParams *params)
{
    params->tlcpEncCert = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleServerTLCPEncKey(HITLS_ServerParams *params)
{
    params->tlcpEncKey = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleServerTLCPSignCert(HITLS_ServerParams *params)
{
    params->tlcpSignCert = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleServerTLCPSignKey(HITLS_ServerParams *params)
{
    params->tlcpSignKey = HITLS_APP_OptGetValueStr();
    return HITLS_APP_SUCCESS;
}
static int HandleServerAcceptOnce(HITLS_ServerParams *params)
{
    params->acceptOnce = true;
    return HITLS_APP_SUCCESS;
}
static int HandleServerQuiet(HITLS_ServerParams *params)
{
    params->quiet = true;
    return HITLS_APP_SUCCESS;
}
static int HandleServerState(HITLS_ServerParams *params)
{
    params->state = true;
    return HITLS_APP_SUCCESS;
}
static int HandleServerCertForm(HITLS_ServerParams *params)
{
    HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->certFormat);
    return HITLS_APP_SUCCESS;
}
static int HandleServerKeyForm(HITLS_ServerParams *params)
{
    HITLS_APP_OptGetFormatType(HITLS_APP_OptGetValueStr(), HITLS_APP_OPT_VALUETYPE_FMT_PEMDER, &params->keyFormat);
    return HITLS_APP_SUCCESS;
}
static int HandleServerHelp(HITLS_ServerParams *params)
{
    (void)params;
    HITLS_APP_OptHelpPrint(g_serverOptions);
    return HITLS_APP_HELP;
}

    // 映射表
static const ServerOptHandleFuncMap g_serverOptHandleFuncMap[] = {
    {HITLS_SERVER_OPT_ACCEPT, HandleServerAccept},
    {HITLS_SERVER_OPT_PORT, HandleServerPort},
    {HITLS_SERVER_OPT_TLCP, HandleServerTLCP},
    {HITLS_SERVER_OPT_DTLCP, HandleServerDTLCP},
    {HITLS_SERVER_OPT_CIPHER, HandleServerCipher},
    {HITLS_SERVER_OPT_CAFILE, HandleServerCAFile},
    {HITLS_SERVER_OPT_CHAINCAFILE, HandleServerChainCAFile},
    {HITLS_SERVER_OPT_TLCP_ENC_CERT, HandleServerTLCPEncCert},
    {HITLS_SERVER_OPT_TLCP_ENC_KEY, HandleServerTLCPEncKey},
    {HITLS_SERVER_OPT_TLCP_SIGN_CERT, HandleServerTLCPSignCert},
    {HITLS_SERVER_OPT_TLCP_SIGN_KEY, HandleServerTLCPSignKey},
    {HITLS_SERVER_OPT_ACCEPT_ONCE, HandleServerAcceptOnce},
    {HITLS_SERVER_OPT_QUIET, HandleServerQuiet},
    {HITLS_SERVER_OPT_STATE, HandleServerState},
    {HITLS_SERVER_OPT_CERTFORM, HandleServerCertForm},
    {HITLS_SERVER_OPT_KEYFORM, HandleServerKeyForm},
    {HITLS_APP_OPT_HELP, HandleServerHelp},
};

static int ParseServerOptLoop(HITLS_ServerParams *params)
{
    int ret = HITLS_APP_SUCCESS;
    int optType = HITLS_APP_OPT_ERR;
    while ((ret == HITLS_APP_SUCCESS) && ((optType = HITLS_APP_OptNext()) != HITLS_APP_OPT_EOF)) {
        for (size_t i = 0; i < sizeof(g_serverOptHandleFuncMap)/sizeof(g_serverOptHandleFuncMap[0]); ++i) {
            if (optType == g_serverOptHandleFuncMap[i].optType) {
                ret = g_serverOptHandleFuncMap[i].func(params);
                break;
            }
        }
        HITLS_APP_PROV_CASES(optType, params->provider)
    }
    if (HITLS_APP_GetRestOptNum() != 0) {
        AppPrintError("Extra arguments given.\n");
        AppPrintError("pkeyutl: Use -help for summary.\n");
        return HITLS_APP_OPT_UNKOWN;
    }
    return ret;
}

static int ParseServerOptions(int argc, char *argv[], HITLS_ServerParams *params, AppProvider *provider)
{
    int ret = HITLS_APP_SUCCESS;
    if (params == NULL || provider == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    InitServerParams(params, provider);
    
    int opt = HITLS_APP_OptBegin(argc, argv, g_serverOptions);
    if (opt !=  HITLS_APP_SUCCESS) {
        AppPrintError("Failed to initialize option parser\n");
        return opt;
    }

    ret = ParseServerOptLoop(params);
    if (ret != HITLS_APP_SUCCESS) {
        AppPrintError("Failed to parse server options: 0x%x\n", ret);
        return ret;
    }
    
    HITLS_APP_OptEnd();
    return HITLS_APP_SUCCESS;
}

static HITLS_Config *CreateServerConfig(HITLS_ServerParams *params)
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
    
    ret = ConfCertVerification(config, &certConfig, params->verifyClient, params->verifyDepth);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    
    ret = ConfigureTLCPCertificates(config, &certConfig);
    if (ret != HITLS_APP_SUCCESS) {
        HITLS_CFG_FreeConfig(config);
        return NULL;
    }
    
    return config;
}

static int CreateListenSocket(HITLS_ServerParams *params)
{
    if (params == NULL) {
        return -1;
    }
    
    APP_NetworkAddr addr = {
        .host = params->bindAddr,
        .port = params->port,
    };
    
    int listenFd = -1;
    
    /* Create listen socket based on protocol */
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);

    if (protocol == APP_PROTOCOL_DTLCP) {
        listenFd = CreateUDPListenSocket(&addr);
    } else {
        listenFd = CreateTCPListenSocket(&addr, params->backlog);
    }
    
    if (listenFd < 0) {
        return -1;
    }
    
    if (!params->quiet) {
        AppPrintInfo("Listening on %s:%d (%s)\n", addr.host ? addr.host : "0.0.0.0", params->port,
            protocol == APP_PROTOCOL_DTLCP ? "UDP" : "TCP");
    }
    
    return listenFd;
}

static BSL_UIO *CreateServerUIO(int clientFd, HITLS_ServerParams *params)
{
    BSL_UIO *uio = NULL;
    
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    if (protocol == APP_PROTOCOL_DTLCP) {
        uio = BSL_UIO_New(BSL_UIO_UdpMethod());
    } else {
        uio = BSL_UIO_New(BSL_UIO_TcpMethod());
    }
    
    int ret = BSL_UIO_Ctrl(uio, BSL_UIO_SET_FD, sizeof(clientFd), &clientFd);
    if (ret != BSL_SUCCESS) {
        AppPrintError("Failed to set socket to UIO: 0x%x\n", ret);
        BSL_UIO_Free(uio);
        return NULL;
    }
    
    return uio;
}

static int HandleClientConnection(HITLS_Ctx *ctx, HITLS_ServerParams *params)
{
    if (ctx == NULL || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int ret = HITLS_APP_SUCCESS;
    
    if (!params->quiet) {
        AppPrintInfo("Starting TLS handshake with client...\n");
    }
    
    /* Perform handshake */
    do {
        ret = HITLS_Accept(ctx);
        if (ret == HITLS_SUCCESS) {
            break;
        }
        if (ret != HITLS_REC_NORMAL_RECV_BUF_EMPTY && ret != HITLS_REC_NORMAL_IO_BUSY) {
            AppPrintInfo("TLS handshake failed: 0x%x\n", ret);
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
    
    /* Handle data exchange */
    uint8_t buffer[HTTP_BUF_MAXLEN];
    uint32_t read_len = 0;
    
    /* Read client data */
    ret = HITLS_Read(ctx, buffer, sizeof(buffer) - 1, &read_len);
    if (ret == HITLS_SUCCESS && read_len > 0) {
        buffer[read_len] = '\0';
        
        if (!params->quiet) {
            AppPrintInfo("Received %u bytes from client:\n%s\n", read_len, buffer);
        }
        
        /* Send response */
        const char *response = "HTTP/1.1 200 OK\r\nContent-Length: 12\r\n\r\nHello World!";
        uint32_t written = 0;
        
        ret = HITLS_Write(ctx, (const uint8_t *)response, strlen(response), &written);
        if (ret == HITLS_SUCCESS) {
            if (!params->quiet) {
                AppPrintInfo("Sent %u bytes response to client\n", written);
            }
        } else {
            AppPrintError("Failed to send response: 0x%x\n", ret);
        }
    } else if (ret != HITLS_SUCCESS) {
        AppPrintError("Failed to read client data: 0x%x\n", ret);
    }
    
    return HITLS_APP_SUCCESS;
}

static void CleanupConnection(HITLS_Ctx *ctx, BSL_UIO *uio, int clientFd)
{
    if (ctx) {
        HITLS_Close(ctx);
        HITLS_Free(ctx);
    }
    
    if (uio) {
        BSL_UIO_Free(uio);
    }
    
    if (clientFd >= 0) {
        BSL_SAL_SockClose(clientFd);
    }
}

static int ServerMainLoop(HITLS_Config *config, int listenFd, HITLS_ServerParams *params)
{
    if (config == NULL || listenFd < 0 || params == NULL) {
        return HITLS_APP_INVALID_ARG;
    }
    
    int connections = 0;
    APP_ProtocolType protocol = ParseProtocolType(params->protocol);
    
    if (!params->quiet) {
        AppPrintInfo("Server started, waiting for connections...\n");
    }
    
    while (1) {
        int clientFd = -1;
        BSL_UIO *uio = NULL;
        HITLS_Ctx *ctx = NULL;
        
        if (protocol == APP_PROTOCOL_DTLCP) {
            /* For DTLS, we use the same socket for communication */
            clientFd = listenFd;
        } else {
            clientFd = AcceptTCPConnection(listenFd);
            if (clientFd < 0) {
                continue;
            }
        }

        /* Create UIO and TLS context */
        uio = CreateServerUIO(clientFd, params);
        ctx = HITLS_New(config);
        if (uio == NULL || ctx == NULL) {
            AppPrintError("Failed to create UIO or TLS context\n");
            CleanupConnection(ctx, uio, (protocol != APP_PROTOCOL_DTLCP) ? clientFd : -1);
            continue;
        }
        
        int ret = HITLS_SetUio(ctx, uio);
        if (ret != HITLS_SUCCESS) {
            AppPrintError("Failed to set UIO: 0x%x\n", ret);
            CleanupConnection(ctx, uio, -1);
            continue;
        }
        
        /* Handle client connection */
        ret = HandleClientConnection(ctx, params);
        if (ret != HITLS_APP_SUCCESS) {
            AppPrintError("Failed to handle client connection\n");
        }
        
        CleanupConnection(ctx, uio, -1);
        
        connections++;
        
        if (!params->quiet) {
            AppPrintInfo("Connection %d completed\n", connections);
        }
        
        /* Check if we should exit */
        if (params->acceptOnce ||
            (params->maxConnections > 0 && connections >= params->maxConnections)) {
            if (!params->quiet) {
                AppPrintInfo("Reached connection limit, exiting\n");
            }
            break;
        }
    }
    
    return HITLS_APP_SUCCESS;
}

static void CleanupServerResources(HITLS_Config *config, int listenFd)
{
    if (config) {
        HITLS_CFG_FreeConfig(config);
    }
    
    if (listenFd >= 0) {
        BSL_SAL_SockClose(listenFd);
    }
}

int HITLS_ServerMain(int argc, char *argv[])
{
    AppProvider appProvider = {"default", NULL, "provider=default"};
    HITLS_ServerParams params = {0};
    HITLS_Config *config = NULL;
    int listenFd = -1;
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
    ret = ParseServerOptions(argc, argv, &params, &appProvider);
    if (ret != HITLS_APP_SUCCESS) {
        goto cleanup;
    }
    if (HITLS_APP_LoadProvider(params.provider->providerPath, params.provider->providerName) != HITLS_APP_SUCCESS) {
        goto cleanup;
    }

    ret = CRYPT_EAL_ProviderRandInitCtx(APP_GetCurrent_LibCtx(), CRYPT_RAND_SM4_CTR_DF,
        params.provider->providerAttr, NULL, 0, NULL);
    if (ret != CRYPT_SUCCESS) {
        AppPrintError("Failed to initialize random: 0x%x\n", ret);
        return HITLS_APP_INIT_FAILED;
    }
    
    /* Create TLS configuration */
    config = CreateServerConfig(&params);
    if (config == NULL) {
        AppPrintError("Failed to create TLS configuration\n");
        ret = HITLS_APP_INVALID_ARG;
        goto cleanup;
    }
    
    /* Create listening socket */
    listenFd = CreateListenSocket(&params);
    if (listenFd < 0) {
        AppPrintError("Failed to create listening socket\n");
        ret = HITLS_APP_ERR_LISTEN;
        goto cleanup;
    }
    
    /* Handle SIGCHLD for child processes */
    signal(SIGCHLD, SIG_IGN);
    
    /* Enter main server loop */
    ret = ServerMainLoop(config, listenFd, &params);
    
cleanup:
    CleanupServerResources(config, listenFd);
    
    if (!params.quiet && ret == HITLS_APP_SUCCESS) {
        AppPrintInfo("Server completed successfully\n");
    }
    
    /* Cleanup print UIO */
    AppPrintErrorUioUnInit();
    
    return ret;
}