#!/usr/bin/bash
# shellcheck shell=bash
# shellcheck disable=SC2031,SC2001

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
# 确认系统确实支持C.UTF-8，这里只设置使用C，避免后续命令返回值与预期不一致。
export LANG=C
export LC_ALL=C
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

# 日志文件定义
declare -r LOG_DIR="${SCRIPT_PATH:?}/upgrade-logs"
declare -r LOG_FILE="${LOG_DIR}/migrate8to9.log"
function log_rotate() {
    # 如果没有目录，则先创建目录，此时必然没有日志文件，跳过日志转储操作
    [[ -d "${LOG_DIR}" ]] || {
        mkdir -p "${LOG_DIR}"
        return
    }
    # 如果没有原始日志，则不做日志转储
    [[ -f "${LOG_FILE}" ]] || return
    # 转储历史日志
    local err_message="Unable to rotate logfiles, continuing without rotation."
    if ! \mv -f "${LOG_FILE}" "${LOG_FILE}.0"; then
        echo >&2 "${err_message}"
    else
        # 最多保存 5 份以前的日志
        for i in {5..1}; do
            if [[ -e "${LOG_FILE}.$((i - 1))" ]]; then
                if ! \mv -f "${LOG_FILE}.$((i - 1))" "${LOG_FILE}.${i}"; then
                    echo >&2 "${err_message}"
                    break
                fi
            fi
        done
    fi
}

log_rotate

# 定义日志输出函数
declare -rA logger_color=(
    ["FATAL"]=160
    ["ERROR"]=1
    ["WARNING"]=9
    ["INFO"]=5
    ["DEBUG"]=195
    ["OK"]=2
)

function write_logfile() {
    printf '%s\n' "$*" >>"${LOG_FILE}"
}

function output_log_message() {
    local -ri log_level="${1}"
    shift 1
    printf '\e[48;5;%dm%s\e[0m \n' "${log_level}" "${*}"
    write_logfile "${*}"
}

function process_logger() {
    local -r log_level="${1}"
    shift 1
    local message_timestamp
    message_timestamp="$(date '+%Y-%m-%d %H:%M:%S.%N' | cut -c -23)"
    if [ "$#" -gt 0 ]; then
        output_log_message "${logger_color["${log_level}"]}" "${message_timestamp} | [${log_level}] | $*"
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
    output_log_message "${logger_color["INFO"]}" "A log of this migration can be found at ${LOG_FILE}"
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

################################################################################

START_DATETIME="$(date +%Y%m%d-%H%M%S)"
declare -gr START_DATETIME
# 正式开始迁移工作
logger_info "MigrateCloudOS 8to9 - Begin logging at $(date +'%c')."
# 记录当前运行的机器架构
ARCH="$(arch)"
# OpenCloudOS-9 更新了 GPG KEY，需要使用新的 KEY 进行验证
# 这个 key 文件是从 OpenCloudOS-9 的 opencloudos-repos RPM 包中提取出来的
declare -r GPG_KEY_REMOTE="${SCRIPT_PATH}/resources/RPM-GPG-KEY-OpenCloudOS-9"
declare -r GPG_KEY_SHA512="bac9dcdded32ddef41ec0fe79562c8f6bb8b2247a802cf55cd7a05c3200d50400a445d8831d013347c823a32cf75ba72caa604bc4d0263898d34e669a5cb9f0b"
# 所有的仓库需要确保 rpm 包都可以使用 $GPG_KEY_REMOTE 进行签名验证，
# OpenCloudOS-9 的仓库与 OpenCloudOS-8 的仓库结构不同，不能复用 OpenCloudOS-8 的 repo 配置，
# 这里直接列出所有可用仓库的 URL
declare -A REPO_URLS=(
    ["cloudosbaseos"]="https://mirrors.opencloudos.tech/opencloudos/9/BaseOS/${ARCH}/os/"
    ["cloudosappstream"]="https://mirrors.opencloudos.tech/opencloudos/9/AppStream/${ARCH}/os/"
    ["cloudosextras"]="https://mirrors.opencloudos.tech/opencloudos/9/extras/${ARCH}/os/"
)

#####################################全局变量#####################################
# 指示升级到 OpenCloudOS 9
declare -gi UPGRADE_TO_OC9=0
# 指示验证所有的 RPM 包
declare -gi VERIFY_ALL_RPMS=0
# 预先升级系统到当前版本的最新状态
declare -gi PRE_UPDATE=0
# 检测匹配的 RPM
declare -gi CHECK_MATCHING_RPM=0
# 是否升级 efi
declare -gi UPDATE_EFI=0
# 脚本执行过程中使用的临时目录
declare -g TEMP_DIRECTORY
# 用于容器标记
declare -g CONTAINER_MACROS
# 升级过程中生成的信息流存储目录
declare -gr UPGRADE_INFO_DIR="${SCRIPT_PATH}/upgrade-info"
# EFI 挂载点
declare -ga EFI_DISK=()
declare -ga EFI_PARTITION=()
# 可能有一些需要额外安装的软件包，先声明一个数组对象，后续会按照检测情况进行填充
declare -ga ALWAYS_INSTALL=()
# 当前系统中安装的 opencloudos 标识软件包
declare -ga PROVIDER_PKG_MAP=()
# 新版本的 opencloudos 标识软件包，默认包含一个无映射的 opencloudos-repos，这个包是 9 版本新增包
declare -gA UPDATE_PROVIDER_PKG_MAP=(
    ["opencloudos-repos"]=""
)
# 新版本 dnf 源信息
declare -ga DNF_PARAMS_SWAPS=()
# 使用新版本 dnf 源的扩展参数
declare -ga DNF_PARAMS_SWAP_EXT=()
# 用于存储当前系统的名字
declare -g PRETTY_NAME
# 当前系统启用的模块化，这些模块将被禁用
declare -ga ENABLED_MODULES=()
# 版本同步输出的错误日志，要被用来解析以决定新增包还是删除包
declare -gr DISTRO_SYNC_ERROR_LOG="${UPGRADE_INFO_DIR}/distro-sync-error.log"
# DNF 版本同步脚本
declare -gr DNF_DISTRO_SYNC_SCRIPTS="${UPGRADE_INFO_DIR}/dnf-distro-sync.txt"
# 老版本系统中安装的软件包
declare -gr PACKAGES_IN_SYSTEM="${UPGRADE_INFO_DIR}/${START_DATETIME}-packages-in-system.txt"
# 来自镜像或者DNF仓库中的包
declare -gr PACKAGES_FROM_REPO="${UPGRADE_INFO_DIR}/${START_DATETIME}-packages-from-repo.txt"
# 未知来源的软件包
declare -gr PACKAGES_UNKNOWN_SOURCE="${UPGRADE_INFO_DIR}/${START_DATETIME}-packages-unknown-source.txt"
# 对应在新版本仓库中可以找到的软件包
declare -gr NEW_PACKAGES_IN_REPO="${UPGRADE_INFO_DIR}/${START_DATETIME}-new-packages-in-repo.txt"
# 对应在新版本仓库中找不到的软件包
declare -gr NEW_PACKAGE_NOT_FOUND="${UPGRADE_INFO_DIR}/${START_DATETIME}-new-package-not-found.txt"

# shim 和 grub2 软件包的名字有架构后缀，需要根据当前系统的架构来选择正确的软件包，
# 映射关系如下：
# | 架构    | grub2-efi      | shim      |
# | ------- | -------------- | --------- |
# | x86_64  | grub2-efi-x64  | shim-x64  |
# | aarch64 | grub2-efi-aa64 | shim-aa64 |
# 声明架构替代字符串
declare -A CPU_ARCH_SUFFIX_MAPPING=(
    ["x86_64"]="x64"
    ["aarch64"]="aa64"
)

# 这些目录需要至少预留有规定大小的空间，单位是 MiB
declare -A DIR_SPACE_MAPPING=(
    ["/usr"]=250
    ["/var"]=1536
    ["/boot"]=50
)

#####################################逻辑函数#####################################
# 打印脚本用法
function print_usage() {
    {
        echo -e "Usage: ${SCRIPT_NAME} [OPTIONS]"
        echo -e ""
        echo -e "Options:"
        echo -e "\t-h\tDisplay this help"
        echo -e "\t-m\tCheck for matching RPM packages on the new DNF repo"
        echo -e "\t-u\tUpgrade to OpenCloudOS 9"
        echo -e "\t-U\tPre-upgrade the system to the latest status"
        echo -e "\t-V\tVerify rpms in the system"
    } >&2
    exit 1
}

# 解析参数
function args_parse() {
    local -i noopts=0
    while getopts "humUV" option; do
        ((noopts++))
        case "${option}" in
        h)
            print_usage
            ;;
        m)
            CHECK_MATCHING_RPM=1
            ;;
        u)
            UPGRADE_TO_OC9=1
            ;;
        U)
            PRE_UPDATE=1
            ;;
        V)
            VERIFY_ALL_RPMS=1
            ;;
        *)
            printf "Invalid argument" >&2
            print_usage
            ;;
        esac
    done

    if ((!noopts)); then
        print_usage
    fi
}

# 检查 os-release 中是否存在必要的字段，如果存在，则返回字段值，否则返回 1
# 使用 () 定义函数而不是 {} 定义函数，以确保从 os-release 导出的环境变量，不会影响全局
function linux_dist_info() (
    . /etc/os-release
    # 将参数视为变量名，返回变量值
    [[ -z ${!1} ]] && return 1
    echo "${!1}"
)

# 环境预设置：创建临时目录
function pre_setup() {
    local tmpdir
    if ! tmpdir=$(mktemp -d /tmp/migrate-opencloudos.XXXXXXXXXXXXXXXX) ||
        [[ ! -d "${tmpdir}" ]]; then
        error_exit "Error creating temp dir"
    fi
    # 使用 failglob 和 dotglob 检测目录是否为空，如果目录中有任何文件存在，都会导致 if 失败
    if (
        shopt -s failglob dotglob
        : "${tmpdir}"/*
    ) 2>/dev/null; then
        error_exit "Temp dir not empty"
    fi
    # 临时目录一旦设置，在当次脚本执行过程中不允许修改
    TEMP_DIRECTORY="${tmpdir}"
    # 将该全局变量设置为只读，避免开发阶段误操作
    declare -r TEMP_DIRECTORY
    # 获取当前系统的发行版名称
    PRETTY_NAME="$(linux_dist_info PRETTY_NAME)"
    test -d "${UPGRADE_INFO_DIR}" || mkdir -p "${UPGRADE_INFO_DIR}" || {
        error_exit "Failed to create ${UPGRADE_INFO_DIR}."
    }
}

# 退出脚本时必做的清理工作
function exit_clean() {
    local -a directory_to_remove=(
        "${TEMP_DIRECTORY}"
    )
    for dir in "${directory_to_remove[@]}"; do
        if [[ -d "${dir}" ]]; then
            rm -rf "${dir}"
        fi
    done

    local -a file_to_remove=(
        "${CONTAINER_MACROS}"
        "${DISTRO_SYNC_ERROR_LOG}"
        "${DNF_DISTRO_SYNC_SCRIPTS}"
    )
    for fn in "${file_to_remove[@]}"; do
        if [[ -f "${fn}" ]]; then
            rm -f "${fn}"
        fi
    done
}

# 运行前检查
function pre_check() {
    # 首先确保 dnf 命令可以正常运行
    if ! dnf -y check; then
        error_exit "Errors found in dnf/rpm database. Please correct before running ${SCRIPT_NAME}"
    fi

    # 如果当前环境中没有安装内核（如：docker 容器、chroot 环境），则忽略 /boot 需要的空间
    if ! rpm -q --quiet kernel; then
        DIR_SPACE_MAPPING["/boot"]=0
    fi

    # 用于记录错误信息
    local -a errs=()
    # 必须检查空间余量的目录集合
    local -a dirs=("${!DIR_SPACE_MAPPING[@]}")
    local dir mount avail
    local -i i=0
    local -A mount_avail_map mount_space_map
    while read -r mount avail; do
        # 忽略标题行
        [[ "${mount}" == 'Filesystem' ]] && continue

        dir="${dirs["$((i++))"]}"
        # 去除 df 查询的空间显示最后面的单位 M
        mount_avail_map["${mount}"]="${avail%M}"
        ((mount_space_map["${mount}"] += DIR_SPACE_MAPPING["${dir}"]))
    done < <(df -BM --output=source,avail "${dirs[@]}")

    for mount in "${!mount_space_map[@]}"; do
        ((avail = mount_avail_map["${mount}"] * 95 / 100))
        if ((avail < mount_space_map["${mount}"])); then
            errs+=("Not enough space in ${mount}, ${mount_space_map[${mount}]}M required, ${avail}M available.")
        fi
    done

    # 如果在空间检查阶段，发现指定目录的空间不足，则打印错误消息并退出
    ((${#errs[@]})) && error_exit "${errs[*]}"
}

# UEFI 环境检查
function efi_check() {
    if ! [[ -d "/sys/class/block" ]]; then
        error_exit "/sys is not accessible."
    fi

    # 如果是在容器中运行，则做一个容器标记
    if systemd-detect-virt --quiet --container; then
        CONTAINER_MACROS="$(mktemp "/etc/rpm/macros.zXXXXXX")"
        # 将不得更改的路径添加到容器标记中
        echo '%_netsharedpath /sys:/proc' | tee "${CONTAINER_MACROS}"
    elif [[ -d "/sys/firmware/efi/" ]]; then
        # 否则检查是否是 UEFI 系统
        UPDATE_EFI=1
    fi
}

function bin_check() {
    # 仅支持升级 OpenCloudOS 8 到 OpenCloudOS 9
    if [[ $(linux_dist_info PLATFORM_ID) != "platform:oc8" ]]; then
        error_exit "This script must be run on OpenCloudOS 8. Upgrade from" \
            "other distributions is not supported."
    fi

    # 基础命令
    local -a bins=(
        arch awk cat column comm curl df dnf grep head mkdir mktemp rm
        rmdir rpm sed sha512sum sort tee tput uniq echo printf readarray
        read systemd-detect-virt
    )
    # 如果是 EFI 环境，还应该包含额外的命令
    if (("${UPDATE_EFI}")); then
        bins+=(findmnt grub2-mkconfig efibootmgr mokutil lsblk)
    fi

    local -a missing
    for bin in "${bins[@]}"; do
        if ! type "${bin}" &>/dev/null; then
            missing+=("${bin}")
        fi
    done

    ((${#missing[@]})) && error_exit "Commands not found: ${missing[*]}." \
        "Possible bad PATH setting or corrupt installation."
}

function generate_rpm_info() {
    logger_info "Creating a list of RPMs installed: ${1}"
    # shellcheck disable=SC2140
    rpm_info_fields="%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|"
    rpm_info_fields+="%{BUILDTIME}|%{BUILDHOST}|%{SOURCERPM}|%{LICENSE}|%{PACKAGER}"
    local -r rpm_info_fields
    rpm -qa |
        xargs -P"$(nproc)" -I'{rpmf}' \
            rpm -q --qf "${rpm_info_fields}\n" --nosignature '{rpmf}' |
        sort >"${UPGRADE_INFO_DIR}/${HOSTNAME}-rpm-list-${1}.log"

    logger_info "Verifying RPMs installed against RPM database: ${1}"
    # 信息越少越好
    rpm -Va | sort -k3 >"${UPGRADE_INFO_DIR}/${HOSTNAME}-rpm-list-verified-${1}.log"
}

# 如果你将一个空参数作为软件包规范之一传递给rpm，它将匹配系统上的每个软件包。
# 这个函数只是将任何空参数剥离掉，并将剩下的参数传递给rpm，以避免这种副作用。
function saferpm() (
    local -a args=()
    local a
    for a in "${@}"; do
        if [[ "${a}" ]]; then
            args+=("${a}")
        fi
    done
    rpm "${args[@]}"
)

# 创建一个与 saferpm 函数类似的函数，用于执行 dnf 命令
function safednf() (
    local -a args=()
    local a
    for a in "${@}"; do
        if [[ "${a}" ]]; then
            args+=("${a}")
        fi
    done
    dnf "${args[@]}"
)

function collect_efi_info() {
    # 如果是 UEFI 环境，则应该检查挂载点
    if (("${UPDATE_EFI}")); then
        local efi_mount kname
        efi_mount="$(findmnt --mountpoint /boot/efi --output SOURCE --noheadings)" ||
            error_exit "Can't find EFI mount. No EFI  boot detected."
        kname=$(lsblk -dno kname "${efi_mount}")
        EFI_DISK=("$(lsblk -dno pkname "/dev/${kname}")")

        if [[ "${EFI_DISK[0]}" ]]; then
            EFI_PARTITION=("$(<"/sys/block/${EFI_DISK[0]}/${kname}/partition")")
        else
            # 这可能是一个 md-raid 或其他类型的虚拟磁盘，我们需要进一步查找实际的物理磁盘和分区。
            kname=$(lsblk -dno kname "${efi_mount}")
            cd "/sys/block/${kname}/slaves" ||
                error_exit "Unable to gather EFI data: Can't cd to /sys/block/${kname}/slaves."
            if ! (
                shopt -s failglob
                : ./*
            ) 2>/dev/null; then
                error_exit "Unable to gather EFI data: No slaves found in /sys/block/${kname}/slaves."
            fi
            EFI_DISK=()
            for d in *; do
                EFI_DISK+=("$(lsblk -dno pkname "/dev/${d}")")
                EFI_PARTITION+=("$(<"${d}/partition")")
                if [[ ! ${EFI_DISK[-1]} || ! ${EFI_PARTITION[-1]} ]]; then
                    error_exit "Unable to gather EFI data: Can't find disk name or partition number for ${d}."
                fi
            done
            cd - || :
        fi

        # 我们需要确保这些软件包始终在 EFI 系统中安装。
        ALWAYS_INSTALL+=(
            "shim-${CPU_ARCH_SUFFIX_MAPPING[${ARCH}]}"
            "grub2-efi-${CPU_ARCH_SUFFIX_MAPPING[${ARCH}]}"
        )
    fi
}

function build_swap_dnf_params() {
    DNF_PARAMS_SWAP_EXT+=(
        "--disablerepo=*"
        "--noautoremove"
        "--setopt=protected_packages="
        "--setopt=keepcache=True"
    )

    local repo
    for repo in "${!REPO_URLS[@]}"; do
        DNF_PARAMS_SWAPS+=("--repofrompath=${repo},${REPO_URLS[${repo}]}")
        DNF_PARAMS_SWAPS+=("--setopt=${repo}.gpgcheck=1")
        DNF_PARAMS_SWAPS+=("--setopt=${repo}.gpgkey=file://${GPG_KEY_FILE}")
    done
}

function swap_dnf() {
    safednf -y "${DNF_PARAMS_SWAP_EXT[@]}" "${DNF_PARAMS_SWAPS[@]}" "$@"
}

function check_provider_pkgs() {
    local -a provider_pkg=(
        "opencloudos-backgrounds"
        "opencloudos-indexhtml"
        "opencloudos-logos"
        "opencloudos-release"
        "opencloudos-logos-httpd"
        "opencloudos-logos-ipa"
        "opencloudos-tools"
    )

    local pkg
    for pkg in "${provider_pkg[@]}"; do
        rpm -q "${pkg}" --quiet && PROVIDER_PKG_MAP+=("${pkg}")
    done

    local remote_pkg remote_pkg_name
    for pkg in "${PROVIDER_PKG_MAP[@]}"; do
        remote_pkg="$(
            swap_dnf repoquery -q --whatprovides "${pkg}"
        )" || continue
        if [[ "${remote_pkg}" ]]; then
            remote_pkg_name="$(
                swap_dnf repoquery -q --qf='%{NAME}' --whatprovides "${pkg}"
            )" || continue
            if [[ "${remote_pkg_name}" ]]; then
                UPDATE_PROVIDER_PKG_MAP["${remote_pkg_name}"]="${pkg}"
            fi
        fi
    done

    logger_info "Found the following system packages which map from ${PRETTY_NAME} to OpenCloudOS 9:"
    local message_tmp
    printf -v message_tmp '%s\n' "Package in OpenCloudOS 9 - Package in ${PRETTY_NAME}"
    for pkg in "${!UPDATE_PROVIDER_PKG_MAP[@]}"; do
        printf -v message_tmp '%s%s\n' "${message_tmp}" "${pkg} - ${UPDATE_PROVIDER_PKG_MAP[${pkg}]}"
    done
    logger_info "${message_tmp}"
}

function collect_services_info() {
    logger_info "Collecting system services info ..."
    # skip
}

function collect_core_components_info() {
    logger_info "Collecting core components info ..."
    # skip
}

function collect_modules_info() {
    logger_info "Collecting modules info ..."
    # 检查当前系统上开启了哪些模块化，将“模块名:流”记录下来
    readarray -t ENABLED_MODULES < <(
        set -e -o pipefail
        safednf -y -q module list --enabled |
            awk '
            $1 == "@modulefailsafe", /^$/ {next}
            $1 == "Name", /^$/ {if ($1!="Name" && !/^$/) print $1":"$2}
            ' | sort -u
        set +e +o pipefail
    )
}

function collect_system_info() {
    # 删除已有 dnf/rpm 缓存
    logger_info "Removing dnf/rpm cache"
    rm -rf /var/cache/{dnf,rpm} || {
        error_exit "Failed to remove dnf/rpm cache."
    }

    # 收集系统 EFI 信息
    collect_efi_info
    # 收集系统服务信息
    collect_services_info
    # 收集系统关键组件配置信息
    collect_core_components_info
    # 手机系统模块化信息
    collect_modules_info
}

# openCloudOS 9 更换了 GPGKEY，不能使用 openCloudOS 8 的 GPGKEY 进行 RPM 包验证
# 这里将迁移工具附带的 GPG 密钥放置到迁移环境上，然后使用该密钥进行 RPM 包验证
function establish_gpg_trust() {
    # 临时存储 GPGKEY 的目录
    declare -gr GPG_TMP_DIR="${TEMP_DIRECTORY:?}/gpg"
    # 临时存储 GPGKEY 的文件名
    declare -gr GPG_KEY_FILE="${GPG_TMP_DIR}/${GPG_KEY_REMOTE##*/}"

    if ! mkdir -p "${GPG_TMP_DIR}" || [[ ! -d "${GPG_TMP_DIR}" ]]; then
        error_exit "Error creating temp dir"
    fi
    if (
        shopt -s failglob dotglob
        : "${GPG_TMP_DIR}"/*
    ) 2>/dev/null; then
        error_exit "Temp dir not empty"
    fi

    if ! cp -fv "${GPG_KEY_REMOTE}" "${GPG_KEY_FILE}"; then
        rm -rf "${GPG_TMP_DIR}"
        error_exit "Error getting the OpenCloudOS 9 signing key."
    fi

    if ! sha512sum --quiet -c <<<"${GPG_KEY_SHA512} ${GPG_KEY_FILE}"; then
        rm -rf "${GPG_TMP_DIR}"
        error_exit "Error validating the signing key."
    fi
}

function pre_update() {
    # 将当前系统升级到最新
    logger_info "Running dnf update before we attempt the migration."

    safednf -y update ||
        error_exit "Error running pre-update. Stopping now to avoid putting the" \
            "system in an unstable state. Please correct the issues shown here and try again."
}

function disable_modules() {
    local dnf_module_dir="/etc/dnf/modules.d"
    if ((${#ENABLED_MODULES[@]})); then
        logger_info "Disabling modules..."
        safednf -y module disable "${ENABLED_MODULES[@]}" ||
            error_exit "Can't disable modules ${ENABLED_MODULES[*]}"
        # 删除系统上记录的模块信息
        mkdir -p "${dnf_module_dir}/module-bak"
        find "${dnf_module_dir}/" -maxdepth 1 -type f -name '*.module' \
            -exec mv -fv {} "${dnf_module_dir}/module-bak/" \;
    fi
}

function analyse_installed() {
    # 重建 dnf 缓存
    dnf -yq shell \
        <<EOF
    clean all
    makecache
    run
    exit
EOF
    # 检查当前启用的 DNF 仓库
    local -a enabled_repos
    readarray -t enabled_repos < <(
        dnf repolist | awk '
$1 == "repo" && $2 == "id" && $3 == "repo" {reading=1; next}
reading && NF {print $1}
!NF {reading=0}
'
    )
    # 检查系统上安装了什么软件包，这些软件包只能来自于 dnf 源和 anaconda
    local valid_repos
    valid_repos="anaconda|@System|$(echo "${enabled_repos[*]}" |
        tr ' ' '|')"
    # 获取系统上所有软件包的名字
    rpm -qa --qf='%{NAME}\n' --nosignature | sort >"${PACKAGES_IN_SYSTEM}"
    # 获取到所有来自于仓库和镜像中的软件包
    dnf list --showduplicate | grep -E "@(${valid_repos})" |
        awk '{print $1}' |
        xargs -P"$(nproc)" -I'{rpmf}' rpm -q --qf="%{NAME}\n" --nosignature '{rpmf}' |
        sort >"${PACKAGES_FROM_REPO}"
    # 求解在PACKAGES_IN_SYSTEM但不在PACKAGES_FROM_REPO中的软件包
    comm -23 "${PACKAGES_IN_SYSTEM}" "${PACKAGES_FROM_REPO}" >"${PACKAGES_UNKNOWN_SOURCE}"

    # 日志记录安装的软件包的数量
    logger_info "Installed packages: $(
        wc -l <"${PACKAGES_IN_SYSTEM}"
    ), please check ${PACKAGES_IN_SYSTEM}"
    logger_info "Packages from repo: $(
        wc -l <"${PACKAGES_FROM_REPO}"
    ), please check ${PACKAGES_FROM_REPO}"

    local -i unknown_pkg_cnt
    unknown_pkg_cnt="$(wc -l <"${PACKAGES_UNKNOWN_SOURCE}")"
    if ((unknown_pkg_cnt)); then
        logger_info "Packages unknown source: $(
            wc -l <"${PACKAGES_UNKNOWN_SOURCE}"
        ), please check ${PACKAGES_UNKNOWN_SOURCE}"
    else
        rm -f "${PACKAGES_UNKNOWN_SOURCE}"
    fi
}

function check_from_update_repo() {
    # 清理当前 dnf 缓存
    dnf -yq clean all
    # 更新 dnf 缓存
    swap_dnf -yq makecache

    local rpmf rpm_fullname rpm_purename
    while IFS=, read -r rpmf _; do
        # 从新版本 dnf 源上查询是否有这样的软件包，如果有多个，取第一个
        rpm_fullname="$(
            swap_dnf repoquery --whatprovides "${rpmf}" 2>/dev/null | head -1
        )"
        # shellcheck disable=SC2001
        if [[ "${rpm_fullname}" ]]; then
            rpm_purename="$(echo "${rpm_fullname}" | sed 's/\(^.*\)-.*-.*/\1/g')"
            echo "${rpm_purename}" >>"${NEW_PACKAGES_IN_REPO}"
        else
            echo "${rpmf}" >>"${NEW_PACKAGE_NOT_FOUND}"
        fi
    done <"${PACKAGES_FROM_REPO}"

    logger_info "Found new packages in repo: $(wc -l <"${NEW_PACKAGES_IN_REPO}")"
    logger_info "Packages not found in repo: $(wc -l <"${NEW_PACKAGE_NOT_FOUND}")"
    # 可替换的软件包的数量
    logger_info "Packages to be replaced: $(wc -l <"${NEW_PACKAGES_IN_REPO}")"

    # 清理当前 dnf 缓存
    dnf -yq clean all
}

function swap_brand_pkg() {
    # 删除特定软件包
    saferpm -e --nodeps "${PROVIDER_PKG_MAP[@]}" ||
        error_exit "Failed to remove packages: ${PROVIDER_PKG_MAP[*]}"
    # 安装特定软件包
    swap_dnf --nobest install "${!UPDATE_PROVIDER_PKG_MAP[@]}" ||
        error_exit "Failed to install packages: ${!UPDATE_PROVIDER_PKG_MAP[*]}"
}

function move_dbpath() {
    local -r RPM_MACROS="/usr/lib/rpm/macros"
    [[ -f "${RPM_MACROS}" ]] || {
        logger_error "File not found: ${RPM_MACROS}"
        return
    }

    local old_rpm_db_path new_rpm_db_path
    old_rpm_db_path="$(realpath "$(rpm --eval '%_dbpath')")"
    logger_info "Update rpm db path from ${old_rpm_db_path} to $(rpm --eval "%{_usr}")/lib/sysimage/rpm"
    sed -i.bak 's|\(^%_dbpath[[:space:]]\).*$|\1%{_usr}/lib/sysimage/rpm|g' "${RPM_MACROS}"
    new_rpm_db_path="$(realpath "$(rpm --eval '%_dbpath')")"

    if [[ "${old_rpm_db_path}" == "${new_rpm_db_path}" ]]; then
        logger_warning "No need to move rpm db path: ${old_rpm_db_path}"
        return
    fi

    if [[ -d "${new_rpm_db_path}" ]]; then
        mv -fv "${new_rpm_db_path}" "${new_rpm_db_path}-${START_DATETIME}"
        logger_debug "Move rpm db path from ${new_rpm_db_path} to ${new_rpm_db_path}-${START_DATETIME}"
    fi

    mkdir -p "${new_rpm_db_path}"
    find "${old_rpm_db_path}/" -maxdepth 1 | grep -vE "^${old_rpm_db_path}/$" |
        xargs -P"$(nproc)" -I'{}' cp -av '{}' "${new_rpm_db_path}/"
}

function do_update() {
    logger_debug "Total number of RPM packages in the current system: $(
        rpm -qa --qf='%{NAME}\n' | wc -l
    )"
    # 将系统强制设置为非 SELinux
    setenforce 0
    # 移动原始 rpm 数据库
    move_dbpath
    # 然后执行升级
    local pkg_fullname
    local -a package_to_remove package_to_install package_to_ignore package_addtional_remove
    local -i continue_mark=0
    local -i _run_distro_sync_cnt=0

    function _mark_continue() {
        continue_mark=1
    }

    function _unmark_continue() {
        continue_mark=0
    }

    function _run_distro_sync() {
        logger_debug "Total number of RPM packages in the current system: $(
            rpm -qa --qf='%{NAME}\n' | wc -l
        )"

        local -i first_run=${1:-0}
        # 运行计数器+1
        ((_run_distro_sync_cnt++))
        # 处理要被从数据库中移除的软件包
        if ((${#package_to_ignore[@]})); then
            # 去重
            readarray -t package_to_ignore < <(
                echo "${package_to_ignore[*]}" | tr '[:space:]' '\n' | sort -u | sed '/^$/d'
            )
            logger_info "Remove the following packages from the RPM database: ${package_to_ignore[*]}"
            local rpmf
            for rpmf in "${package_to_ignore[@]}"; do
                saferpm -q --quiet "${rpmf}" &&
                    saferpm -e --justdb --nodeps "${rpmf}"
            done
            package_to_ignore=()
            rpm --rebuilddb
            logger_debug "Total number of RPM packages in the current system: $(
                rpm -qa --qf='%{NAME}\n' | wc -l
            )"
        fi

        # 整理要被删除的软件包
        if ((${#package_addtional_remove[@]})); then
            logger_info "Remove the following packages from the RPM database: ${package_addtional_remove[*]}"
            # 去重
            readarray -t package_addtional_remove < <(
                echo "${package_addtional_remove[*]}" | tr '[:space:]' '\n' | sort -u | sed '/^$/d'
            )
            local pkg_name rpm_file_line rpm_found found_count new_pkg_name
            local -A found_pkgs
            # 遍历要被删除的软件包
            logger_info "Find alternative packages for the packages that will be removed."
            for pkg_name in "${package_addtional_remove[@]}"; do
                # 如果要被删除的软件包在新版本源上可以找到替代，还应该加入到 package_to_install 中
                new_pkg_name="$(
                    dnf repoquery -q --whatprovides "${pkg_name}" 2>/dev/null |
                        sed 's|\(^.*\)-.*-.*$|\1|g' | tr '\n' ' '
                )"
                if [[ "${new_pkg_name}" ]]; then
                    # 找到的替代软件包，直接添加到待安装列表
                    # shellcheck disable=SC2206 # 如果在源上找到多个包，全部加入待安装列表
                    package_to_install+=(${new_pkg_name})
                    logger_debug "Replace ${pkg_name} with ${new_pkg_name}"
                else
                    # 没有直接提供对应符号的软件包，按照文件的形式去 DNF 源上搜索，如果找到则安装
                    found_count=0
                    while read -r rpm_file_line; do
                        [[ "${rpm_file_line}" ]] || continue
                        # 虽然确实有可能同一个文件在多个不同的包中，但是这里仍然只取第一个
                        rpm_found="$(dnf repoquery -q "${rpm_file_line}" |
                            sed 's|\(^.*\)-.*-.*|\1|g' | head -1)"
                        # 源上没有找到包含这个文件的包，则继续处理下一行
                        [[ "${rpm_found}" ]] || continue
                        # 如果找到了包含这个文件的包，但是还没有记录，则添加到待安装列表
                        [[ "${found_pkgs["${rpm_found}"]}" ]] || {
                            found_pkgs["${rpm_found}"]=1
                            package_to_install+=("${rpm_found}")
                            logger_debug "Replace ${pkg_name} with ${rpm_found}"
                            continue
                        }
                        # 对一个软件包而言，如果找到了3个新软件包包含这个包中某些文件，就不再找了，理论上，不会有这种情况出现
                        ((found_count++))
                        if ((found_count >= 3)); then
                            break
                        fi
                    done < <(rpm -q -l "${pkg_name}" 2>/dev/null |
                        xargs -P"$(nproc)" -I'{}' file '{}' 2>/dev/null |
                        grep -viE '[[:space:]]directory' | cut -d: -f 1 |
                        grep -E '(^/(usr/|)((s|)bin|lib(|64)))' |
                        grep -vE '/(.build-id|lib/modules|__pycache__|/site-packages/.*/tests/test_)/' |
                        sed 's|/python3.6/|/\*/|g')
                    continue
                fi
            done

            package_to_remove+=("${package_addtional_remove[@]}")
            package_addtional_remove=()
        fi

        readarray -t package_to_install < <(echo "${package_to_install[*]}" |
            tr '[:space:]' '\n' | sort -u | sed '/^$/d')

        readarray -t package_to_remove < <(echo "${package_to_remove[*]}" |
            tr '[:space:]' '\n' | sort -u | sed '/^$/d')

        logger_info "Running dnf distro-sync, round ${_run_distro_sync_cnt}"
        logger_debug "Total number of RPM packages in the current system: $(
            rpm -qa --qf='%{NAME}\n' | wc -l
        )"

        # 构造 dnf 脚本
        echo 'distro-sync' >"${DNF_DISTRO_SYNC_SCRIPTS}"
        # 如果有待删除软件包，则添加 remove 命令
        ((${#package_to_remove[@]})) && {
            logger_info "The package you are trying to remove: ${package_to_remove[*]}"
            echo "remove ${package_to_remove[*]}" >>"${DNF_DISTRO_SYNC_SCRIPTS}"
        }
        # 如果有待安装软件包，则添加 install 命令
        ((${#package_to_install[@]})) && {
            logger_info "The package you are trying to install: ${package_to_install[*]}"
            echo "install ${package_to_install[*]}" >>"${DNF_DISTRO_SYNC_SCRIPTS}"
        }
        # 要被忽略的软件包已经使用 rpm 命令处理了，不需要 dnf 处理
        ((${#package_to_ignore[@]})) && {
            logger_info "The package you are trying to ignore: ${package_to_ignore[*]}"
        }
        # dnf 脚本运行和结束指令
        echo 'run' >>"${DNF_DISTRO_SYNC_SCRIPTS}"
        echo 'exit' >>"${DNF_DISTRO_SYNC_SCRIPTS}"
        # 执行版本同步，DNF 运行的错误日志保存在一个单独的文件中
        {
            if ((first_run)); then
                _mark_continue
                # 首次执行，仅做一个虚拟测试，以便于生成错误日志，用于替换包的分析
                dnf --assumeno --releasever 9 distro-sync
            else
                # 尝试执行升级
                dnf --assumeyes --releasever 9 --allowerasing --nobest shell <"${DNF_DISTRO_SYNC_SCRIPTS}"
            fi
        } 2> >(tee "${DISTRO_SYNC_ERROR_LOG}" >&2)
        # 不论处于什么情况，都需要重建 rpmdb
        rpm --rebuilddb
    }

    function _parse_dnf_problems() {
        logger_info "Processing dnf problems ..."
        # 循环读取 dnf 错误日志，按照预定类型逐行处理
        while read -r line; do
            if [[ "${line}" =~ "cannot install both" ]]; then
                local new old
                IFS=, read -r new old <<<"$(echo "${line}" |
                    sed -n 's/.*cannot install both \(.*\)-.*-.* and \(.*\)-.*-.*$/\1,\2/p')"
                package_to_install+=("${new}")
                package_addtional_remove+=("${old}")
                _mark_continue
            elif [[ "${line}" =~ "but none of the providers can be installed" ]]; then
                pkg_fullname="$(echo "${line}" |
                    sed -n 's/.*package \(.*\) requires .*/\1/p')"
                # 如果 pkg_fullname 包含 .oc9
                if [[ "${pkg_fullname}" =~ .oc9 ]]; then
                    continue
                fi
                package_addtional_remove+=("$(echo "${pkg_fullname}" |
                    sed 's|\(^.*\)-.*-.*|\1|g')")
                _mark_continue
            elif [[ "${line}" =~ installed\ package\ .*\ obsoletes ]]; then
                package_to_ignore+=("$(echo "${line}" |
                    sed 's/.*installed package \(.*\)-.*-.* obsoletes.*/\1/g')")
                _mark_continue
            fi
        done <"${DISTRO_SYNC_ERROR_LOG}"
    }

    # 文件冲突的包，先删除老包，然后安装新包
    function _parse_dnf_conflicts() {
        logger_info "Processing dnf conflicts ..."
        local conflicts_line
        conflicts_line="$(
            grep -E 'file .* from install of .* conflicts with file from package .*' \
                "${DISTRO_SYNC_ERROR_LOG}"
        )" || return
        while IFS=, read -r new old; do
            package_to_install+=("${new}")
            package_to_ignore+=("${old}")
            _mark_continue
        done < <(
            echo "${conflicts_line}" |
                sed 's/^.* install of \(.*\)-.*-.* conflicts.* package \(.*\)-.*-.*$/\1,\2/' |
                sort -u
        )
    }

    function _circle_run() {
        local -i circle_depth=$1
        # 用于标记是否第一次运行，第一次运行与后续运行逻辑不同，主要在 _run_distro_sync 函数中
        local -i first_run=$2
        # 避免无限递归，在异常情况下，最多允许10次递归
        ((circle_depth > 10)) && {
            error_exit "Error: dnf distro-sync failed"
        }

        # 然后解决文件冲突问题
        _run_distro_sync ${first_run}
        if ! ((first_run)); then
            # 清除继续处理的标记
            _unmark_continue
        fi
        # 处理报错
        _parse_dnf_problems
        _parse_dnf_conflicts
        # 如果标记为继续处理，则重新执行同步
        if ((continue_mark)); then
            _circle_run $((circle_depth + 1)) 0
        fi
    }

    # 递归执行，直到没有文件冲突
    _circle_run 1 1
    logger_debug "Total number of RPM packages in the current system: $(
        rpm -qa --qf='%{NAME}\n' | wc -l
    )"

    if ((${#ALWAYS_INSTALL[@]})); then
        logger_info "Installing packages: ${ALWAYS_INSTALL[*]}"
        safednf -y install "${ALWAYS_INSTALL[@]}" ||
            error_exit "Error installing required packages: ${ALWAYS_INSTALL[*]}"
        logger_debug "Total number of RPM packages in the current system: $(
            rpm -qa --qf='%{NAME}\n' | wc -l
        )"
    fi
    logger_ok "System upgrade completed"
}

function system_update() {
    # 构造 dnf 参数
    build_swap_dnf_params
    # 收集系统上现有软件包
    analyse_installed
    # 确认 opencloudos 开头的软件包有哪些
    check_provider_pkgs
    # 禁用系统模块化
    disable_modules
    # 检查系统现有软件包是否在新版本仓库上（not use）
    if ((CHECK_MATCHING_RPM)); then
        check_from_update_repo
    fi
    # 切换产品标识包
    swap_brand_pkg
    # 执行实际升级
    do_update
}

function fix_efi() {
    grub2-mkconfig -o "/boot/efi/EFI/opencloudos/grub.cfg" ||
        error_exit "Error updating the grub config."
    local i
    for i in "${!EFI_DISK[@]}"; do
        efibootmgr -c -d "/dev/${EFI_DISK[${i}]}" -p "${EFI_PARTITION[${i}]}" \
            -L "OpenCloudOS" -l "/EFI/opencloudos/shim${CPU_ARCH_SUFFIX_MAPPING[${ARCH}]}.efi" ||
            error_exit "Error updating uEFI firmware."
    done
}

function main() {
    # 解析传入的参数
    args_parse "$@"
    pre_setup
    trap exit_clean EXIT
    pre_check
    efi_check
    bin_check

    if ((VERIFY_ALL_RPMS)); then
        generate_rpm_info begin
    fi

    if ((UPGRADE_TO_OC9)); then
        collect_system_info
        if ((PRE_UPDATE)); then
            pre_update
        fi
        establish_gpg_trust
        system_update
    fi

    if ((VERIFY_ALL_RPMS && UPGRADE_TO_OC9)); then
        generate_rpm_info finish
        logger_info "You may review the following files:"
        local rpmlist_file
        printf -v rpmlist_file '%s\n' "${UPGRADE_INFO_DIR}/${HOSTNAME}-rpm-list-"*.log
        logger_info "${rpmlist_file}"
    fi

    if ((UPDATE_EFI && UPGRADE_TO_OC9)); then
        fix_efi
    fi

    printf '\n\n\n'

    if ((UPGRADE_TO_OC9)); then
        logger_ok "Done, please reboot your system."
    fi
    finish_print
}

main "$@"
