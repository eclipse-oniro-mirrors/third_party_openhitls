# openHiTLS
本仓库包含开源软件openHiTLS，为OpenHarmony提供高效、敏捷的全场景开源密码学开发套件。

## 概述

openHiTLS架构高度模块化，可通过模块和特性配置。RAM/ROM尺寸取决于所选的特性。openHiTLS为密码算法提供最佳性能优化。当前已支持5个组件和算法特性可按需配置，支持ARM、x86架构CPU上的算法性能优化，更多架构和特性待规划。

## 特性简介

功能特性主要包含如下：

- 协议：支持TLS1.3, TLS1.3-Hybrid-Key-Exchange, TLS-Provider, TLS-Multi-KeyShare, TLS-Custom-Extension, TLCP, DTLCP, TLS1.2, DTLS1.2, Auth；
- 算法：支持ML-DSA，ML-KEM，SLH-DSA，AES，SM4，Chacha20，RSA，RSA-Bind，DSA，ECDSA，ECDH，DH，SM2，DRBG，DRBG-GM，HKDF，SCRYPT，PBKDF2，SHA2，SHA3，MD5，SM3，HMAC等；
- 证书：支持证书、CRL解析，证书、CRL验证，证书请求、生成等；


## 组件简介

目前，openHiTLS有5个组件，其中BSL组件需和其他组件一起使用。
- BSL是Base Support Layer的缩写，提供基础C类标准的增强功能和OS适配器，需与其他模块一起使用
- 密码算法组件（Crypto）提供了完整的密码功能，且性能较优。该组件既可以被TLS使用，也可与BSL一起使用
- TLS是Transport Layer Security的缩写，涵盖了TLS1.3及之前的TLS版本，会与Crypto、BSL以及其他三方密码组件或PKI库一起使用
- PKI组件提供证书、CRL解析，证书、CRL验证以及证书请求、生成等功能
- Auth认证组件提供了认证功能，当前提供了基于RFC9578的publicly token认证功能

## 构建指导

适配OpenHarmony平台的编译脚本请见[gn构建脚本](BUILD.gn)。


以rk3568平台为例，编译命令为：
```bash
./build.sh --product-name rk3568 --ccache --build-target openhitls
```
编译完成后会在out/rk3568/thirdparty/openhitls目录下生成所有的动态库。

## OpenHarmony如何使用openHiTLS

OpenHarmony中系统部件需要在BUILD.gn中引用openhitls部件以使用openHiTLS。

以Crypto模块为例，需要引用openhitls_crypto部件，具体模块信息可参考[bundle.json](bundle.json)。
 
```
// BUILD.gn
external_deps += [ "liburing:liburing" ]
```

## 详细介绍文档

本文档旨在帮助开发者和贡献者更快地上手openHiTLS，详情参考[文档列表](docs/index/index.md) 。


## License

Mulan PSL v2

见[LICENSE](LICENSE).
