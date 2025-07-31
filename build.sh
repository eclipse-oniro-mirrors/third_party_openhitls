#!/bin/bash

# This file is part of the openHiTLS project.
#
# openHiTLS is licensed under the Mulan PSL v2.
# You can use this software according to the terms and conditions of the Mulan PSL v2.
# You may obtain a copy of Mulan PSL v2 at:
#
#     http://license.coscl.org.cn/MulanPSL2
#
# THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
# EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
# MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
# See the Mulan PSL v2 for more details.

set -e

HITLS_ROOT_DIR=`pwd`

hitls_compile_option=()

paramList=$@
paramNum=$#
add_options=""
del_options=""
dis_options=""
subdir="CMVP"
target_arch="PURE_C"
libname=""

clean()
{
    rm -rf ${HITLS_ROOT_DIR}/build
    mkdir ${HITLS_ROOT_DIR}/build
}

down_depend_code()
{
    if [ ! -d "${HITLS_ROOT_DIR}/platform" ]; then
        cd ${HITLS_ROOT_DIR}
        mkdir platform
    fi

    if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C" ]; then
        cd ${HITLS_ROOT_DIR}/platform
        git clone https://gitee.com/openeuler/libboundscheck.git  Secure_C
    fi
}

build_depend_code()
{
    if [ ! -d "${HITLS_ROOT_DIR}/platform/Secure_C/lib" ]; then
        mkdir -p ${HITLS_ROOT_DIR}/platform/Secure_C/lib
        cd ${HITLS_ROOT_DIR}/platform/Secure_C
        make -j
    fi
}

build_hitls_code()
{
    # Compile openHiTLS
    cd ${HITLS_ROOT_DIR}/build
    python3 ../configure.py --add_options="$add_options" --del_options="$del_options" \
        --feature_config=./config/json/${subdir}/${target_arch}/${subdir}_feature_config.json \
        --compile=./config/json/${subdir}/${target_arch}/${subdir}_compile_config.json \
        --lib_type=shared
    cmake .. -DCMAKE_SKIP_RPATH=TRUE -DCMAKE_INSTALL_PREFIX=../output/${subdir}/${target_arch}
    make -j
    make install
    cd ../output/${subdir}/${target_arch}/lib
    mv libhitls.so $libname
    mv libhitls.so.hmac $libname.hmac
}

parse_option()
{
    for i in $paramList
    do
        key=${i%%=*}
        value=${i#*=}
        case "${key}" in
            "debug")
                add_options="${add_options} -O0 -g3 -gdwarf-2"
                del_options="${del_options} -O2 -D_FORTIFY_SOURCE=2"
                ;;
            "iso")
                add_options="${add_options} -DHITLS_CRYPTO_CMVP_ISO19790"
                libname="libhitls_iso.so"
                ;;
            "fips")
                add_options="${add_options} -DHITLS_CRYPTO_CMVP_FIPS"
                libname="libhitls_fips.so"
                ;;
            "gm")
                add_options="${add_options} -DHITLS_CRYPTO_CMVP_GM"
                libname="libhitls_gm.so"
                ;;
            "armv8_le")
                target_arch="ARMV8_LE"
                ;;
            "pure_c")
                target_arch="PURE_C"
                ;;
            "x8664")
                target_arch="X8664"
                ;;
            "subdir")
                subdir=$value
                ;;
            "help")
                show_help
                exit 0
                ;;
            *)
                echo "${i} option is not recognized, Please run 'bash build.sh help' to get supported options."
                exit -1
                ;;
        esac
    done
}

show_help()
{
    echo "Usage: bash build.sh <crypto_mode> [arch_type] [debug]"
    echo ""
    echo "Required parameters:"
    echo "  crypto_mode    One of: iso, fips, gm (must select exactly one)"
    echo ""
    echo "Optional parameters:"
    echo "  arch_type      One of: armv8_le, pure_c, x8664 (default: pure_c)"
    echo "  debug          Add debug compilation flags (-O0 -g3 -gdwarf-2)"
    echo ""
    echo "Examples:"
    echo "  bash build.sh iso x8664"
    echo "  bash build.sh fips armv8_le"
    echo "  bash build.sh gm pure_c debug"
    echo "  bash build.sh iso debug"
    echo ""
    echo "Note:"
    echo "  - crypto_mode is mandatory (iso, fips, or gm)"
    echo "  - arch_type defaults to pure_c if not specified"
    echo "  - debug is optional and can be combined with any other options"
    echo ""
    echo "For more information, run: bash build.sh help"
}

validate_crypto_mode()
{
    if [ -z "$libname" ]; then
        echo "Error: One of the crypto modes (iso, fips, or gm) must be selected."
        echo "Usage examples:"
        echo "  bash build.sh iso x8664"
        echo "  bash build.sh fips x8664"
        echo "  bash build.sh gm x8664"
        echo "Run 'bash build.sh help' for more information."
        exit 1
    fi
}

clean
parse_option
validate_crypto_mode
down_depend_code
build_depend_code
build_hitls_code
