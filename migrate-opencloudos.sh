#!/usr/bin/bash
#shellcheck shell=bash

SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
# 获取脚本路径，用于定位同路径其他功能性脚本或者数据文件
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck disable=SC2034
declare -r SCRIPT_PATH SCRIPT_NAME

# 脚本必须以 root 身份启动
if ((EUID != 0)); then
    echo >&2 "You must run this script as root. Either use sudo or 'su -c ${0}'" >&2
    exit 1
fi

# 需要在 C.UTF-8 模式下运行，以保证可以正确记录过程中所有输出的信息
valid_locale="$(localectl list-locales | grep -iEo '^C.UTF[-]?8')"
# shellcheck disable=SC2181
if [[ $? -ne 0 ]] || [[ -z "${valid_locale}" ]]; then
    echo >&2 "C.UTF-8 locale is not available."
    exit 1
fi

export LANG="${valid_locale}"
export LC_ALL="${valid_locale}"
unset LANGUAGE

# 需要使用关联数组功能，这要求 bash 版本不低于 4.2，在 CloudOS 8 中是满足的，
# 但还是应该检查一下，以确认脚本确实是在目标系统上运行的。
if [ -z "${BASH_VERSION}" ]; then
    echo >&2 "BASH_VERSION not set. Please run the script with bash."
    exit 1
fi

if [ $((BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1])) -lt 402 ]; then
    echo >&2 "BASH version 4.2+ is required. Please update bash."
    exit 1
fi

# 启用扩展 glob 功能
shopt -s extglob
# 启用空字符串匹配功能
shopt -s nullglob
# 禁用 bash 中设置的 CDPATH 环境变量
unset CDPATH

# 日志文件定义，最多保存 10 份以前的日志
declare -r LOG_FILE="/root/migrate8to9.log"
declare -ri MAXLOG_NUM=5
# 这是一条需要复用的日志输出内容，使用一个变量临时保存
err_message="Unable to rotate logfiles, continuing without rotation."
if ! \mv -f "${LOG_FILE}" "${LOG_FILE}.0"; then
    echo >&2 "${err_message}"
else
    for ((i = MAXLOG_NUM; i > 0; i--)); do
        if [[ -e "${LOG_FILE}.$((i - 1))" ]]; then
            if ! \mv -f "${LOG_FILE}.$((i - 1))" "${LOG_FILE}.${i}"; then
                echo >&2 "${err_message}"
                break
            fi
        fi
    done
fi
unset err_message

# 定义日志输出函数
declare -rA logger_color=(
    ["FATAL"]=160
    ["ERROR"]=1
    ["WARNING"]=9
    ["INFO"]=5
    ["DEBUG"]=195
    ["OK"]=2
)

function print2stdout() {
    local -i log_level=${1}
    shift 1
    printf '\e[48;5;%dm%s\e[0m \n' "${log_level}" "${*}"
}

function print2logfile() {
    printf '%s\n' "$*" >>"${LOG_FILE}"
}

function process_logger() {
    local log_level="${1}"
    shift 1
    local message_timestamp
    message_timestamp="$(date '+%Y-%m-%d %H:%M:%S.%N' | cut -c -23)"
    local output_message=""
    if [ "$#" -gt 0 ]; then
        output_message="${message_timestamp} | [${log_level}] | $*"
        print2stdout "${logger_color["${log_level}"]}" "${output_message}"
        print2logfile "${output_message}"
    else
        printf '\n'
    fi
}

function logger_fatal() {
    process_logger "FATAL" "${@}"
}

function logger_error() {
    process_logger "ERROR" "${@}"
}

function logger_warning() {
    process_logger "WARNING" "${@}"
}

function logger_info() {
    process_logger "INFO" "${@}"
}

function logger_debug() {
    process_logger "DEBUG" "${@}"
}

function logger_ok() {
    process_logger "OK" "${@}"
}

function finish_print() {
    print2stdout "${logger_color["INFO"]}" "A log of this migration can be found at ${LOG_FILE}"
}

function final_message() {
    logger_error "An error occurred while we were attempting to upgrade your system to" \
        "OpenCloudOS 9. Your system may be unstable. Script will now exit to" \
        "prevent possible damage."
    finish_print
}

function error_exit() {
    logger_error "${@}"
    final_message
    exit 1
}

# 正式开始迁移工作
logger_info "MigrateCloudOS 8to9 - Begin logging at $(date +'%c')."
# 记录当前运行的机器架构
ARCH="$(arch)"
# OpenCloudOS-9 更新了 GPG KEY，需要使用新的 KEY 进行验证
# 这个 key 文件是从 OpenCloudOS-9 的 opencloudos-repos RPM 包中提取出来的
declare -r GPG_KEY_FILE="${SCRIPT_PATH}/OpenCloud-9-gpgkey/RPM-GPG-KEY-OpenCloudOS-9"
declare -r GPG_KEY_SHA512="238c0f8cb3c22bfdedf6f4a7f9e3e86393101304465a442f8e359da9668aad075da06f50b8263dcec6edc3da5711234f4fc183581367b3b48fb24f505429b579"
# 所有的仓库需要确保 rpm 包都可以使用 $GPG_KEY_FILE 进行签名验证，
# OpenCloudOS-9 的仓库与 OpenCloudOS-8 的仓库结构不同，不能复用 OpenCloudOS-8 的 repo 配置，
# 这里直接列出所有可用仓库的 URL
declare -A repo_urls=(
    ["cloudosbaseos"]="https://mirrors.opencloudos.tech/opencloudos/9/BaseOS/${ARCH}/os/"
    ["cloudosappstream"]="https://mirrors.opencloudos.tech/opencloudos/9/AppStream/${ARCH}/os/"
    ["cloudosextras"]="https://mirrors.opencloudos.tech/opencloudos/9/extras/${ARCH}/os/"
)
