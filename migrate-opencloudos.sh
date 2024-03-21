#!/usr/bin/bash
# shellcheck shell=bash
# shellcheck disable=SC2031

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

################################################################################

# 正式开始迁移工作
logger_info "MigrateCloudOS 8to9 - Begin logging at $(date +'%c')."
# 记录当前运行的机器架构
ARCH="$(arch)"
# OpenCloudOS-9 更新了 GPG KEY，需要使用新的 KEY 进行验证
# 这个 key 文件是从 OpenCloudOS-9 的 opencloudos-repos RPM 包中提取出来的
declare -r GPG_KEY_REMOTE="${SCRIPT_PATH}/OpenCloud-9-gpgkey/RPM-GPG-KEY-OpenCloudOS-9"
declare -r GPG_KEY_SHA512="238c0f8cb3c22bfdedf6f4a7f9e3e86393101304465a442f8e359da9668aad075da06f50b8263dcec6edc3da5711234f4fc183581367b3b48fb24f505429b579"
# 所有的仓库需要确保 rpm 包都可以使用 $GPG_KEY_REMOTE 进行签名验证，
# OpenCloudOS-9 的仓库与 OpenCloudOS-8 的仓库结构不同，不能复用 OpenCloudOS-8 的 repo 配置，
# 这里直接列出所有可用仓库的 URL
declare -A REPO_URLS=(
    ["cloudosbaseos"]="https://mirrors.opencloudos.tech/opencloudos/9/BaseOS/${ARCH}/os/"
    ["cloudosappstream"]="https://mirrors.opencloudos.tech/opencloudos/9/AppStream/${ARCH}/os/"
    ["cloudosextras"]="https://mirrors.opencloudos.tech/opencloudos/9/extras/${ARCH}/os/"
)

# 全局变量声明
# 指示升级到 OpenCloudOS 9
declare -g UPGRADE_TO_OC9
# 指示验证所有的 RPM 包
declare -g VERIFY_ALL_RPMS
# 脚本执行过程中使用的临时目录
declare -g TEMP_DIRECTORY
# 用于容器标记
declare -g CONTAINER_MACROS
# 是否升级 efi
declare -g UPDATE_EFI=false
# 升级过程中生成的信息流存储目录
declare -rg UPGRADE_INFO_DIR="/root/upgrade_oc9"
# 临时存储 GPGKEY 的目录
declare -rg GPG_TMP_DIR="${TEMP_DIRECTORY}/gpg"
# 临时存储 GPGKEY 的文件名
declare -rg GPG_KEY_FILE="${GPG_TMP_DIR}/${GPG_KEY_REMOTE##*/}"
# EFI 挂载点
declare -ga EFI_DISK
declare -ga EFI_PARTITION
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

# 函数实现
function print_usage() {
    {
        echo -e "Usage: ${SCRIPT_NAME} [OPTIONS]"
        echo -e ""
        echo -e "Options:"
        echo -e "\t-h Display this help"
        echo -e "\t-u Upgrade to OpenCloudOS 9"
        echo -e "\t-V Verify switch"
    } >&2
    exit 1
}

# Parse the arguments passed to the script and set corresponding flags based on
# the options provided.
function args_parse() {
    local -i noopts=0
    while getopts "huVR" option; do
        ((noopts++))
        case "${option}" in
        h)
            print_usage
            ;;
        u)
            UPGRADE_TO_OC9=true
            ;;
        V)
            VERIFY_ALL_RPMS=true
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

function pre_setup() {
    local tmpdir
    if ! tmpdir=$(mktemp -d) || [[ ! -d "${tmpdir}" ]]; then
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
}

function exit_clean() {
    if [[ -d "${TEMP_DIRECTORY}" ]]; then
        rm -rf "${TEMP_DIRECTORY}"
    fi

    if [[ -f "${CONTAINER_MACROS}" ]]; then
        rm -f "${CONTAINER_MACROS}"
    fi
}
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
        UPDATE_EFI=true
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

function bin_check() {
    # 仅支持升级 OpenCloudOS 8 到 OpenCloudOS 9
    if [[ $(linux_dist_info PLATFORM_ID) != "platform:oc8" ]]; then
        error_exit "This script must be run on OpenCloudOS 8. Upgrade from" \
            "other distributions is not supported."
    fi

    # 基础命令
    local -a bins=(
        rpm dnf awk column tee tput mkdir cat arch sort uniq rmdir df
        rm head curl sha512sum mktemp systemd-detect-virt sed grep
    )
    # 如果是 EFI 环境，还应该包含额外的命令
    if [[ "${UPDATE_EFI}" == "true" ]]; then
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
    test -d "${UPGRADE_INFO_DIR}" || mkdir -p "${UPGRADE_INFO_DIR}" || {
        error_exit "Failed to create ${UPGRADE_INFO_DIR}."
    }

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
    args=()
    for a in "${@}"; do
        if [[ "${a}" ]]; then
            args+=("${a}")
        fi
    done
    rpm "${args[@]}"
)

# 创建一个与 saferpm 函数类似的函数，用于执行 dnf 命令
function safednf() (
    args=()
    for a in "${@}"; do
        if [[ "${a}" ]]; then
            args+=("${a}")
        fi
    done
    dnf "${args[@]}"
)

function collect_efi_info() {
    # 如果是 UEFI 环境，则应该检查挂载点
    if [[ "${UPDATE_EFI}" == "true" ]]; then
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
            remote_pkg_name=$(swap_dnf repoquery -q --qf='%{NAME}' --whatprovides "${pkg}") || continue
            if [[ "${remote_pkg_name}" ]]; then
                UPDATE_PROVIDER_PKG_MAP["${remote_pkg_name}"]="${pkg}"
            fi
        fi
    done

    logger_info "Found the following system packages which map from ${PRETTY_NAME} to OpenCloudOS 9:"
    logger_info "Package in OpenCloudOS 9 - Package in ${PRETTY_NAME}"
    for pkg in "${!UPDATE_PROVIDER_PKG_MAP[@]}"; do
        logger_info "${pkg} - ${UPDATE_PROVIDER_PKG_MAP[${pkg}]}"
    done
}

function collect_system_info() {
    # 删除已有 dnf/rpm 缓存
    logger_info "Removing dnf/rpm cache"
    rm -rf /var/cache/{dnf,rpm} || {
        error_exit "Failed to remove dnf/rpm cache."
    }

    # 收集系统 EFI 信息
    collect_efi_info
    # 构造升级 dnf 仓库信息
    build_swap_dnf_params
    # 确认 opencloudos 开头的软件包有哪些，记录在 provider_pkg_map 中
    check_provider_pkgs
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

# openCloudOS 9 更换了 GPGKEY，不能使用 openCloudOS 8 的 GPGKEY 进行 RPM 包验证
# 这里将迁移工具附带的 GPG 密钥放置到迁移环境上，然后使用该密钥进行 RPM 包验证
function establish_gpg_trust() {
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
    # FIXME
    # safednf -y "${DNF_PARAMS_SWAP_EXT[@]}" update ||
    #     error_exit "Error running pre-update. Stopping now to avoid putting the""\
    #     system in an unstable state. Please correct the issues shown here and try again."
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

function swap_brand_pkg() {
    # 删除特定软件包
    swap_dnf remove "${PROVIDER_PKG_MAP[@]}" ||
        error_exit "Failed to remove packages: ${PROVIDER_PKG_MAP[*]}"
    # 安装特定软件包，强制升级系统
    swap_dnf --nobest install "${!UPDATE_PROVIDER_PKG_MAP[@]}" ||
        error_exit "Failed to install packages: ${!UPDATE_PROVIDER_PKG_MAP[*]}"
}

function do_update() {
    logger_info "Update system release..."
    dnf -y --allowerasing --nobest upgrade || error_exit "Error during upgrade."

    if ((${#ALWAYS_INSTALL[@]})); then
        safednf -y install "${ALWAYS_INSTALL[@]}" ||
            error_exit "Error installing required packages: ${ALWAYS_INSTALL[*]}"
    fi
}

function analyse_installed() {
    return
}

function system_update() {
    # 禁用系统模块化
    disable_modules
    # 收集系统上现有软件包，记录文件与源码关系，
    analyse_installed
    # 切换产品标识包
    swap_brand_pkg
    # 移除临时目录
    rm -rf "${TEMP_DIRECTORY}"
    # 执行实际升级
    do_update
}

function fix_efi() {
    grub2-mkconfig -o "/boot/efi/EFI/opencloudos/grub.cfg" ||
        error_exit "Error updating the grub config."
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

    PRETTY_NAME="$(linux_dist_info PRETTY_NAME)"

    if [[ "${VERIFY_ALL_RPMS}" == "true" ]]; then
        generate_rpm_info begin
    fi

    if [[ "${UPGRADE_TO_OC9}" == "true" ]]; then
        collect_system_info
        establish_gpg_trust
        pre_update
        system_update
    fi

    if [[ "${VERIFY_ALL_RPMS}" == "true" && "${UPGRADE_TO_OC9}" == "true" ]]; then
        generate_rpm_info finish
        logger_info "You may review the following files:"
        printf '%s\n' "${UPGRADE_INFO_DIR}/${HOSTNAME}-rpm-list-"*.log
    fi

    if [[ ${update_efi} && ${UPGRADE_TO_OC9} ]]; then
        fix_efi
    fi

    printf '\n\n\n'

    if [[ ${UPGRADE_TO_OC9} ]]; then
        logger_info "Done, please reboot your system."
    fi
    finish_print
}

main "$@"
