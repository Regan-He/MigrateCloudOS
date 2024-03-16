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
        "OpenCloud OS 9. Your system may be unstable. Script will now exit to" \
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
declare -A repo_urls
repo_urls=(
    ["cloudosbaseos"]="https://mirrors.opencloudos.tech/opencloudos/9.0/BaseOS/${ARCH}/os/"
    ["cloudosappstream"]="https://mirrors.opencloudos.tech/opencloudos/9.0/AppStream/${ARCH}/os/"
    ["cloudosextras"]="https://mirrors.opencloudos.tech/opencloudos/9.0/extras/${ARCH}/os/"
)

# 可能有一些需要额外安装的软件包，先声明一个数组对象，后续会按照检测情况进行填充
declare -a always_install=()

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

# 检查 os-release 中是否存在必要的字段，如果存在，则返回字段值，否则返回 1
# 使用 () 定义函数而不是 {} 定义函数，以确保从 os-release 导出的环境变量，不会影响全局
function linux_dist_info() (
    . /etc/os-release
    # 将参数视为变量名，返回变量值
    [[ -z ${!1} ]] && return 1
    echo "${!1}"
)

# 创建一个临时工作目录
function pre_setup() {
    if ! tmp_dir=$(mktemp -d) || [[ ! -d "${tmp_dir}" ]]; then
        error_exit "Error creating temp dir"
    fi
    # 使用 failglob 和 dotglob 检测目录是否为空，如果目录中有任何文件存在，都会导致 if 失败
    if (
        shopt -s failglob dotglob
        : "${tmp_dir}"/*
    ) 2>/dev/null; then
        error_exit "Temp dir not empty"
    fi
    # 临时目录一旦设置，在当次脚本执行过程中不允许修改
    declare -rg TMP_DIR="${tmp_dir}"
}

# 清理函数，用于清理临时工作目录
function exit_clean() {
    if [[ -d "${TMP_DIR}" ]]; then
        rm -rf "${TMP_DIR}"
    fi
    if [[ -f "${CONTAINER_MACROS}" ]]; then
        rm -f "${CONTAINER_MACROS}"
    fi
}

function pre_check() {
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
    local dir mount avail i=0
    local -A mount_avail_map mount_space_map
    while read -r mount avail; do
        # 忽略标题行
        if [[ "${mount}" == 'Filesystem' ]]; then
            continue
        fi

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
    if ((${#errs[@]})); then
        error_exit "${errs[*]}"
    fi
}

# 脚本所需的命令都在 OpenCloud OS 8 的最小安装中，所有必须的二进制都在 /bin 目录中
# 除非运行环境本身已经损坏，否则迁移脚本在这里不应该失败。
function bin_check() {
    # 仅支持升级 OpenCloud OS 8 到 OpenCloud OS 9
    if [[ $(linux_dist_info PLATFORM_ID) != "platform:oc8" ]]; then
        error_exit 'This script must be run on OpenCloud OS 8. Upgrade from other distributions is not supported.'
    fi

    local -a bins=(
        rpm dnf awk column tee tput mkdir cat arch sort uniq rmdir df
        rm head curl sha512sum mktemp systemd-detect-virt sed grep
    )
    if [[ ${update_efi} ]]; then
        bins+=(findmnt grub2-mkconfig efibootmgr mokutil lsblk)
    fi

    local -a missing
    for bin in "${bins[@]}"; do
        if ! type "${bin}" &>/dev/null; then
            missing+=("${bin}")
        fi
    done

    if ((${#missing[@]})); then
        error_exit "Commands not found: ${missing[*]}. Possible bad PATH setting or corrupt installation."
    fi
}

# 禁用 epel 仓库以避免 extras 仓库错误映射
function repoquery() {
    local name val prev result
    # 禁用 epel 仓库
    result=$(safednf -y -q "${dist_repourl_swaps[@]}" \
        --setopt=epel.excludepkgs=epel-release repoquery -i "${1}") ||
        error_exit "Failed to fetch info for package ${1}."
    if ! [[ ${result} ]]; then
        # 没有查询到任何信息
        return 1
    fi
    declare -gA repoquery_results=()
    while IFS=" :" read -r name val; do
        if [[ -z "${name}" ]]; then
            repoquery_results["${prev}"]+=" ${val}"
        else
            prev="${name}"
            repoquery_results["${name}"]="${val}"
        fi
    done <<<"${result}"
}

function _repoinfo() {
    local name val result
    result=$(
        safednf -y -q --repo="${1}" "${dist_repourl_swaps[@]}" repoinfo "${1}"
    ) || return
    if [[ ${result} == 'Total packages: 0' ]]; then
        # 不匹配这个仓库
        return 1
    fi
    declare -gA repoinfo_results=()
    while IFS=" :" read -r name val; do
        if [[ ! ("${name}" || "${val}") ]]; then
            continue
        fi
        if [[ -z "${name}" ]]; then
            repoinfo_results["${prev}"]+=" ${val}"
        else
            prev="${name}"
            repoinfo_results["${name}"]="${val}"
        fi
    done <<<"${result}"

    # 设置启用状态
    if [[ ! "${enabled_repo_check["${1}"]}" ]]; then
        repoinfo_results["Repo-status"]="disabled"
    fi

    # shellcheck disable=SC2154
    repoinfo_results["Repo-gpgkey"]=$(
        awk '
            $0=="['"${repoinfo_results["Repo-id"]}"']",$0=="end_of_file" {
                if (l++ < 1) {next}
                else if (/^\[.*\]$/) {nextfile}
                else if (sub(/^gpgkey\s*=\s*file:\/\//,"")) {print; nextfile}
                else {next}
            }
        ' <"${repoinfo_results["Repo-filename"]}"
    )

    # 添加一个指示是否为订阅管理的仓库的标识符。
    repoinfo_results["Repo-managed"]=$(
        awk '
            BEGIN {FS="[)(]"}
            /^# Managed by \(.*\) subscription-manager$/ {print $2}
        ' <"${repoinfo_results["Repo-filename"]}"
    )
}

# 现在将仓库信息储存到一个缓存中
declare -g -A repoinfo_results_cache=()
function repoinfo() {
    local k
    if [[ ! ${repoinfo_results_cache["${1}"]} ]]; then
        _repoinfo "${@}" || return
        repoinfo_results_cache["${1}"]=1
        for k in "${!repoinfo_results[@]}"; do
            repoinfo_results_cache["${1}:${k}"]="${repoinfo_results["${k}"]}"
        done
    else
        repoinfo_results=()
        for k in "${!repoinfo_results_cache[@]}"; do
            local repo="${k%%:*}" key="${k#*:}"
            if [[ ${repo} != "${1}" ]]; then
                continue
            fi

            repoinfo_results["${key}"]="${repoinfo_results_cache["${k}"]}"
        done
    fi
}

provides_pkg() (
    if [[ ! ${1} ]]; then
        return 0
    fi

    set -o pipefail
    provides=$(
        safednf -y -q "${dist_repourl_swaps[@]}" provides "${1}" |
            awk '{print $1; nextfile}'
    ) ||
        return 1
    set +o pipefail
    pkg=$(rpm -q --queryformat '%{NAME}\n' "${provides}") ||
        pkg=$(
            safednf -y -q "${dist_repourl_swaps[@]}" repoquery \
                --queryformat '%{NAME}\n' "${provides}"
        ) || error_exit "Can't get package name for ${provides}."
    printf '%s\n' "${pkg}"
)

# 如果你将一个空参数作为软件包规范之一传递给rpm，它将匹配系统上的每个软件包。
# 这个函数只是将任何空参数剥离掉，并将剩下的参数传递给rpm，以避免这种副作用。
function saferpm() (
    args=()
    for a in "${@}"; do
        if [[ ${a} ]]; then
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

function collect_system_info() {
    # Dump the DNF cache first so we start with a clean slate.
    logger_info 'Removing dnf cache'
    rm -rf /var/cache/{yum,dnf}
    # 首先检查 efi 挂载点，如果不存在，我们可以在进行其他检查之前立即退出。
    if [[ ${update_efi} ]]; then
        local efi_mount kname
        declare -g -a efi_disk efi_partition
        efi_mount=$(findmnt --mountpoint /boot/efi --output SOURCE \
            --noheadings) ||
            error_exit "Can't find EFI mount. No EFI  boot detected."
        kname=$(lsblk -dno kname "${efi_mount}")
        efi_disk=("$(lsblk -dno pkname "/dev/${kname}")")

        if [[ ${efi_disk[0]} ]]; then
            efi_partition=("$(<"/sys/block/${efi_disk[0]}/${kname}/partition")")
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
            efi_disk=()
            for d in *; do
                efi_disk+=("$(lsblk -dno pkname "/dev/${d}")")
                efi_partition+=("$(<"${d}/partition")")
                if [[ ! ${efi_disk[-1]} || ! ${efi_partition[-1]} ]]; then
                    error_exit "Unable to gather EFI data: Can't find disk name or partition number for ${d}."
                fi
            done
            cd -
        fi

        # 我们需要确保这些软件包始终在 EFI 系统中安装。
        always_install+=(
            "shim-${CPU_ARCH_SUFFIX_MAPPING[${ARCH}]}"
            "grub2-efi-${CPU_ARCH_SUFFIX_MAPPING[${ARCH}]}"
        )
    fi

    # 我们需要将 OpenCloud 仓库的名称映射到源发行版中相应的仓库。
    # 为此，我们查找每个仓库中已知的软件包，并查看它们来自哪个仓库。
    # 我们需要使用repoquery来进行此操作，而repoquery需要下载软件包，
    # 因此我们选择相对较小的软件包进行此操作。
    declare -g -A repo_map pkg_repo_map
    declare -g -a managed_repos
    pkg_repo_map=(
        [baseos]=rootfiles.noarch
        [appstream]=apr-util-ldap.${ARCH}
        [highavailability]=pacemaker-doc.noarch
        [crb]=python3-mpich.${ARCH}
        [extras]=epel-release.noarch
    )

    dist_id=$(linux_dist_info ID)
    PRETTY_NAME=$(linux_dist_info PRETTY_NAME)
    logger_info "Preparing to migrate ${PRETTY_NAME} to OpenCloudOS 9.0."

    # 检查是否需要更改任何系统仓库的 repourl
    local -A dist_repourl_map
    dist_repourl_map=(
    )

    # 我们需要列出启用的仓库
    local -a enabled_repos=()
    declare -g -A enabled_repo_check=()
    declare -g -a dist_repourl_swaps=()
    readarray -s 1 -t enabled_repos < <(dnf -q -y repolist --enabled)
    for r in "${enabled_repos[@]}"; do
        enabled_repo_check[${r%% *}]=1
    done

    # 最后设置一些 dnf 选项来替换这些仓库的 baseurl
    local k
    for k in "${!dist_repourl_map[@]}"; do
        local d=${k%%:*} r=${k#*:}
        if [[ ${d} != "${dist_id}" || ! ${enabled_repo_check[${r}]} ]]; then
            continue
        fi

        dist_repourl_swaps+=(
            "--setopt=${r}.mirrorlist="
            "--setopt=${r}.metalink="
            "--setopt=${r}.baseurl="
            "--setopt=${r}.baseurl=${dist_repourl_map[${k}]}"
        )

        logger_info "Baseurl for ${r} is invalid, setting to ${dist_repourl_map[${k}]}."
    done

    logger_info "Determining repository names for ${PRETTY_NAME}"

    for r in "${!pkg_repo_map[@]}"; do
        printf '.'
        p="${pkg_repo_map["${r}"]}"
        repoquery "${p}" || continue
        repo_map["${r}"]="${repoquery_results["Repository"]}"
    done

    logger_info "Getting system package names for ${PRETTY_NAME}"

    # 我们不知道这些软件包的名称，我们必须通过各种方式来发现它们。
    # 最常见的方式是查找通用的提供者或文件名。
    # 在某些情况下，我们需要通过一些手段来获取特定源发行版提供的文件名。
    # 获取每个仓库的信息，以确定哪些是订阅管理的。
    for r in "${!repo_map[@]}"; do
        repoinfo "${repo_map["${r}"]}" ||
            error_exit "Failed to fetch info for repository ${repo_map[${r}]}."

        if [[ "${r}" == "baseos" ]]; then
            local baseos_filename="system-release"
            if [[ ! "${repoinfo_results["Repo-managed"]}" ]]; then
                baseos_filename="${repoinfo_results["Repo-filename"]}"
            fi
            local baseos_gpgkey="${repoinfo_results["Repo-gpgkey"]}"
        fi
        if [[ "${repoinfo_results["Repo-managed"]}" ]]; then
            managed_repos+=("${repo_map["${r}"]}")
        fi
    done

    # 首先获取 baseos 仓库的信息，以确定我们是否需要更改 baseos 仓库的 repourl
    repoinfo "${repo_map[baseos]}" ||
        error_exit "Failed to fetch info for repository ${repo_map[baseos]}."

    # TODO:这里的映射影响后续升级产品标志包，造成了升级异常
    declare -g -A pkg_map provides_pkg_map
    declare -g -a addl_provide_removes addl_pkg_removes
    provides_pkg_map=(
        ["opencloudos-backgrounds"]=system-backgrounds
        ["opencloudos-indexhtml"]=opencloudos-indexhtml
        ["opencloudos-repos"]="${baseos_filename}"
        ["opencloudos-logos"]=system-logos
        ["opencloudos-logos-httpd"]=system-logos-httpd
        ["opencloudos-logos-ipa"]=system-logos-ipa
        ["opencloudos-gpg-keys"]="${baseos_gpgkey}"
        ["opencloudos-release"]=system-release
    )

    for pkg in "${!provides_pkg_map[@]}"; do
        printf '.'
        prov="${provides_pkg_map["${pkg}"]}"
        pkg_map["${pkg}"]="$(provides_pkg "${prov}")" ||
            error_exit "Can't get package that provides ${prov}."
    done
    for prov in "${addl_provide_removes[@]}"; do
        printf '.'
        local pkg
        pkg=$(provides_pkg "${prov}") || continue
        addl_pkg_removes+=("${pkg}")
    done

    # shellcheck disable=SC2140
    logger_info "Found the following system packages which map from ${PRETTY_NAME} to OpenCloud OS 9:"
    for p in "${!pkg_map[@]}"; do
        logger_info "${pkg_map[${p}]} - ${p}"
    done

    logger_info "Getting list of installed system packages."

    readarray -t installed_packages < <(
        saferpm -qa --queryformat="%{NAME}\n" "${pkg_map[@]}"
    )
    declare -g -A installed_pkg_check installed_pkg_map
    for p in "${installed_packages[@]}"; do
        installed_pkg_check["${p}"]=1
    done
    for p in "${!pkg_map[@]}"; do
        if [[ "${pkg_map["${p}"]}" && "${installed_pkg_check[${pkg_map[${p}]}]}" ]]; then
            installed_pkg_map["${p}"]="${pkg_map["${p}"]}"
        fi
    done

    # shellcheck disable=SC2140
    logger_info "We will replace the following ${PRETTY_NAME} packages with their OpenCloud OS 9"
    # TODO:检查映射
    for p in "${!installed_pkg_map[@]}"; do
        logger_info "${installed_pkg_map[${p}]} - ${p}"
    done

    if ((${#addl_pkg_removes[@]})); then
        logger_info "In addition to the above the following system packages will be removed: ${addl_pkg_removes[*]}"
    fi

    logger_info "Getting a list of enabled modules for the system repositories."

    # 获取系统已经启用的模块流
    readarray -t enabled_modules < <(
        set -e -o pipefail
        safednf -y -q "${repo_map[@]/#/--repo=}" "${dist_repourl_swaps[@]}" \
            module list --enabled |
            awk '
            $1 == "@modulefailsafe", /^$/ {next}
            $1 == "Name", /^$/ {if ($1!="Name" && !/^$/) print $1":"$2}
            ' | sort -u
        set +e +o pipefail
    )

    # 与已知的模块流进行比较，如果有不匹配的，则将其添加到 disable_modules 数组中
    disable_modules=()
    local i mod
    for i in "${!enabled_modules[@]}"; do
        mod="${enabled_modules[${i}]}"
        if [[ "${mod}" != "${enabled_modules[${i}]}" ]]; then
            disable_modules+=("${enabled_modules[${i}]}")
            enabled_modules["${i}"]="${mod}"
        fi
    done

    # 不启用的模块流
    declare -g -a module_excludes
    module_excludes=()
    # 删除与任何被排除的模块相匹配的条目。
    if ((${#module_excludes[@]})); then
        printf '%s\n' '' "Excluding modules:" "${module_excludes[@]}"
        local -A module_check='()'
        local -a tmparr='()'
        for m in "${module_excludes[@]}"; do
            module_check[${m}]=1
        done
        for m in "${enabled_modules[@]}"; do
            if [[ ! "${module_check["${m}"]}" ]]; then
                tmparr+=("${m}")
            fi
        done
        enabled_modules=("${tmparr[@]}")
    fi

    logger_info "Found the following modules to re-enable at completion: ${enabled_modules[*]}"

    if ((${#managed_repos[@]})); then
        logger_info "In addition, since this system uses subscription-manager the following managed ""\
        repos will be disabled: ${managed_repos[*]}"
    fi
}

upgrade_info_dir=/root/upgrade_oc9
unset upgrade_to_oc9 reinstall_all_rpms verify_all_rpms update_efi CONTAINER_MACROS

# 生成一个已安装RPM的列表，并将其与RPM数据库进行核对。
function generate_rpm_info() {
    mkdir -p "${upgrade_info_dir}"
    logger_info "Creating a list of RPMs installed: ${1}"
    # shellcheck disable=SC2140
    local rpm_info_fields="%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|"
    rpm_info_fields+="%{BUILDTIME}|%{BUILDHOST}|%{SOURCERPM}|%{LICENSE}|%{PACKAGER}"
    rpm -qa --qf "${rpm_info_fields}\n" |
        sort >"${upgrade_info_dir}/${HOSTNAME}-rpm-list-${1}.log"
    logger_info "Verifying RPMs installed against RPM database: ${1}"
    rpm -Va | sort -k3 >"${upgrade_info_dir}/${HOSTNAME}-rpm-list-verified-${1}.log"
}

# 在真正开始迁移前，先执行一次 dnf update，确保当前系统已经是最新的，这样可以尽可能的减少与目标版本的差异
function pre_update() {
    logger_info '%s\n' "Running dnf update before we attempt the migration."
    safednf -y "${dist_repourl_swaps[@]}" update ||
        error_exit "Error running pre-update. Stopping now to avoid putting the""\
        system in an unstable state. Please correct the issues shown here and try again."
}

# 该功能通过准备仓库参数并使用safednf命令来移除和安装包来执行包交换。它还处理所需包的移除和安装，
# 以及启用和禁用仓库、模块，并排除某些模块。最后，它会同步包，并在指定的情况下安装所需的包。
function package_swaps() {
    # 准备仓库参数
    local -a dnfparameters
    for repo in "${!repo_urls[@]}"; do
        dnfparameters+=("--repofrompath=${repo},${repo_urls[${repo}]}")
        dnfparameters+=("--setopt=${repo}.gpgcheck=1")
        dnfparameters+=("--setopt=${repo}.gpgkey=file://${gpg_key_file}")
    done

    safednf -y shell --disablerepo='*' --noautoremove \
        "${dist_repourl_swaps[@]}" \
        --setopt=protected_packages= --setopt=keepcache=True \
        "${dnfparameters[@]}" \
        <<EOF
        remove ${installed_pkg_map[@]} ${addl_pkg_removes[@]}
        install ${!installed_pkg_map[@]}
        run
        exit
EOF

    # 新版本的 opencloudos-repos 已经安装，包含了我们预置的 GPG-KEY，现在可以删除临时文件
    rm -rf "${gpg_tmp_dir}"

    local -a check_removed check_installed
    readarray -t check_removed < <(
        saferpm -qa --qf '%{NAME}\n' "${installed_pkg_map[@]}" \
            "${addl_pkg_removes[@]}" | sort -u
    )

    if ((${#check_removed[@]})); then
        logger_info "Packages found on system that should still be removed. Forcibly removing them with rpm:"
        for pkg in "${check_removed[@]}"; do
            if [[ -z "${pkg}" ]]; then
                continue
            fi
            printf '%s\n' "${pkg}"
            saferpm -e --allmatches --nodeps "${pkg}" ||
                saferpm -e --allmatches --nodeps --noscripts --notriggers "${pkg}"
        done
    fi

    readarray -t check_installed < <(
        {
            printf '%s\n' "${!installed_pkg_map[@]}" | sort -u
            saferpm -qa --qf '%{NAME}\n' "${!installed_pkg_map[@]}" | sort -u
        } | sort | uniq -u
    )
    if ((${#check_installed[@]})); then
        logger_info "Some required packages were not installed by dnf. Attempting to force with rpm:"
        local -A rpm_map
        local -a file_list
        for rpm in /var/cache/dnf/{cloudosbaseos,cloudosappstream}-*/packages/*.rpm; do
            rpm_map["$(rpm -q --qf '%{NAME}\n' --nodigest "${rpm}" 2>/dev/null)"]="${rpm}"
        done

        # Attempt to install.
        for pkg in "${check_installed[@]}"; do
            printf '%s\n' "${pkg}"
            if ! rpm -i --force --nodeps --nodigest "${rpm_map[${pkg}]}" 2>/dev/null; then
                rpm -i --force --justdb --nodeps --nodigest "${rpm_map[${pkg}]}" 2>/dev/null

                readarray -t file_list < <(
                    rpm -V "${pkg}" 2>/dev/null | awk '$1!="missing" {print $2}'
                )
                for file in "${file_list[@]}"; do
                    rmdir "${file}" || rm -f "${file}" || rm -rf "${file}"
                done

                rpm -i --reinstall --force --nodeps --nodigest "${rpm_map[${pkg}]}" 2>/dev/null
            fi
        done
    fi

    logger_info "Ensuring repos are enabled before the package swap."
    safednf -y --enableplugin=config_manager config-manager --set-enabled "${!repo_map[@]}" || {
        printf '%s\n' 'Repo name missing?'
        exit 25
    }

    if ((${#managed_repos[@]})); then
        readarray -t managed_repos < <(
            safednf -y -q repolist "${managed_repos[@]}" | awk '$1!="repo" {print $1}'
        )

        if ((${#managed_repos[@]})); then
            logger_info "Disabling subscription managed repos"
            safednf -y --enableplugin=config_manager config-manager --disable "${managed_repos[@]}"
        fi
    fi

    if ((${#disable_modules[@]})); then
        logger_info "Disabling modules..."
        safednf -y module disable "${disable_modules[@]}" || error_exit "Can't disable modules ${disable_modules[*]}"
    fi

    if ((${#enabled_modules[@]})); then
        logger_info "Enabling modules..."
        safednf -y module enable "${enabled_modules[@]}" || error_exit "Can't enable modules ${enabled_modules[*]}"
    fi

    # Make sure that excluded modules are disabled.
    if ((${#module_excludes[@]})); then
        logger_info "Disabling excluded modules..."
        safednf -y module disable "${module_excludes[@]}" || error_exit "Can't disable modules ${module_excludes[*]}"
    fi

    logger_info "Syncing packages..."
    dnf -y --allowerasing distro-sync || error_exit "Error during distro-sync."

    if ((${#always_install[@]})); then
        safednf -y install "${always_install[@]}" || error_exit "Error installing required packages: ${always_install[*]}"
    fi
}

function efi_check() {
    if ! [[ -d /sys/class/block ]]; then
        error_exit "/sys is not accessible."
    fi

    if systemd-detect-virt --quiet --container; then
        declare -g CONTAINER_MACROS
        CONTAINER_MACROS=$(mktemp /etc/rpm/macros.zXXXXXX)
        printf '%s\n' '%_netsharedpath /sys:/proc' >"${CONTAINER_MACROS}"
    elif [[ -d /sys/firmware/efi/ ]]; then
        declare -g update_efi=true
    fi
}

function fix_efi() (
    grub2-mkconfig -o /boot/efi/EFI/opencloudos/grub.cfg ||
        error_exit "Error updating the grub config."
    for i in "${!efi_disk[@]}"; do
        efibootmgr -c -d "/dev/${efi_disk[${i}]}" -p "${efi_partition[${i}]}" \
            -L "OpenCloud OS" -l "/EFI/opencloudos/shim${CPU_ARCH_SUFFIX_MAPPING[${ARCH}]}.efi" ||
            error_exit "Error updating uEFI firmware."
    done
)

function establish_gpg_trust() {
    declare -g gpg_tmp_dir
    gpg_tmp_dir="${TMP_DIR}/gpg"
    if ! mkdir "${gpg_tmp_dir}" || [[ ! -d "${gpg_tmp_dir}" ]]; then
        error_exit "Error creating temp dir"
    fi
    if (
        shopt -s failglob dotglob
        : "${gpg_tmp_dir}"/*
    ) 2>/dev/null; then
        error_exit "Temp dir not empty"
    fi

    declare -g gpg_key_file="${gpg_tmp_dir}/${GPG_KEY_FILE##*/}"

    if ! cp -fv "${GPG_KEY_FILE}" "${gpg_key_file}"; then
        rm -rf "${gpg_tmp_dir}"
        error_exit "Error getting the OpenCloud OS signing key."
    fi

    if ! sha512sum --quiet -c <<<"${GPG_KEY_SHA512} ${gpg_key_file}"; then
        rm -rf "${gpg_tmp_dir}"
        error_exit "Error validating the signing key."
    fi
}

function usage() {
    printf '%s\n' \
        "Usage: ${0##*/} [OPTIONS]" \
        '' \
        'Options:' \
        '-h Display this help' \
        '-u Upgrade to OpenCloud OS 9' \
        '-V Verify switch' \
        '   !! USE WITH CAUTION !!'
    exit 1
} >&2

noopts=0
while getopts "huVR" option; do
    ((noopts++))
    case "${option}" in
    h)
        usage
        ;;
    u)
        upgrade_to_oc9=true
        ;;
    V)
        verify_all_rpms=true
        ;;
    *)
        logger_error "Invalid argument"
        usage
        ;;
    esac
done

if ((!noopts)); then
    usage
fi

pre_setup
trap exit_clean EXIT
pre_check
efi_check
bin_check

if [[ ${verify_all_rpms} ]]; then
    generate_rpm_info begin
fi

if [[ ${upgrade_to_oc9} ]]; then
    collect_system_info
    establish_gpg_trust
    pre_update
    package_swaps
fi

if [[ ${verify_all_rpms} && ${upgrade_to_oc9} ]]; then
    generate_rpm_info finish
    logger_info "You may review the following files:"
    printf '%s\n' "${upgrade_info_dir}/${HOSTNAME}-rpm-list-"*.log
fi

if [[ ${update_efi} && ${upgrade_to_oc9} ]]; then
    fix_efi
fi

printf '\n\n\n'

if [[ ${upgrade_to_oc9} ]]; then
    logger_info "Done, please reboot your system."
fi
finish_print
