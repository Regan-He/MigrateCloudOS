#!/usr/bin/bash
#shellcheck shell=bash

SCRIPT_NAME=$(basename "${BASH_SOURCE[0]}")
# 获取脚本路径，用于定位同路径其他功能性脚本
SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
# shellcheck disable=SC2034
declare -r SCRIPT_PATH SCRIPT_NAME

# 脚本必须以root身份启动
if ((EUID != 0)); then
    echo >&2 "You must run this script as root. Either use sudo or 'su -c ${0}'" >&2
    exit 1
fi

# 需要在C.UTF-8模式下运行，以保证可以正确记录过程中所有输出的信息
if ! localectl list-locales | grep -qE '^C.UTF-8'; then
    echo >&2 "C.UTF-8 not found."
    exit 1
fi

export LANG=C.UTF-8
export LC_ALL=C.UTF-8
unset LANGUAGE

# 需要使用关联数组功能，这要求bash版本不低于4.2，在CloudOS8中是满足的
if [ -z "$BASH_VERSION" ]; then
    echo >&2 "BASH_VERSION not set. Please run the script with bash."
    exit 1
fi

if [ $((BASH_VERSINFO[0] * 100 + BASH_VERSINFO[1])) -lt 402 ]; then
    echo >&2 "BASH version 4.2+ is required. Please update bash."
    exit 1
fi

# 启用扩展glob功能
shopt -s extglob

# 日志文件定义，最多保存10份以前的日志
declare -r LOG_FILE="/var/log/migrate8to9.log"
declare -ri MAXLOG_NUM=10
# 这是一条需要复用的日志输出内容，使用一个变量临时保存
err_message="Unable to rotate logfiles, continuing without rotation."
if ! mv -f "$LOG_FILE" "$LOG_FILE.0"; then
    echo >&2 "${err_message}"
else
    for ((i = MAXLOG_NUM; i > 0; i--)); do
        if [[ -e "$LOG_FILE.$((i - 1))" ]]; then
            if ! mv -f "$LOG_FILE.$((i - 1))" "$LOG_FILE.$i"; then
                echo >&2 "${err_message}"
                break
            fi
        fi
    done
fi
unset err_message

# 定义日志输出函数
declare -rA logger_color=(
    ["OK"]=2
    ["FATAL"]=160
    ["ERROR"]=1
    ["WARNING"]=9
    ["INFO"]=5
    ["DEBUG"]=195
)

function print2stdout() {
    local -i color_code=$1
    shift 1
    printf '\e[48;5;%dm%s\e[0m \n' "${color_code}" "${*}"
}

function print2logfile() {
    if [ -z "${LOG_FILE}" ]; then
        return
    fi
    local -r message="$*"
    local -r log_file="/tmp/logger.log"
    printf '%s\n' "${message}" >>"${log_file}"
}

function process_logger() {
    local color_code="$1"
    shift 1
    local message_timestamp
    message_timestamp="$(date '+%Y-%m-%d %H:%M:%S').$(date '+%N' | cut -c -3)"
    local output_message=""
    if [ "$#" -gt 0 ]; then
        output_message="${message_timestamp} | [${color_code}] | $*"
        print2stdout "${logger_color["${color_code}"]}" "${output_message}"
        print2logfile "${output_message}"
    else
        printf '\n'
    fi
}

function logger_ok() {
    process_logger "OK" "${@}"
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

function error_exit() {
    logger_error "$@"
    final_message
    exit 1
}

function final_message() {
    logger_error "An error occurred while we were attempting to upgrade your system to" \
        "openCloud OS 9. Your system may be unstable. Script will now exit to" \
        "prevent possible damage."
    finish_print
}

function finish_print() {
    print2stdout "${logger_color["INFO"]}" "A log of this installation can be found at $LOG_FILE"
}

# 正式开始迁移工作
logger_info "MigrateCloudOS 8to9 - Begin logging at $(date +'%c')."
# 启用空字符串匹配功能
shopt -s nullglob
# 禁用 bash 中设置的 CDPATH 环境变量
unset CDPATH

# 支持的系统版本是 openCloudOS 8
SUPPORTED_MAJOR="8"
# TODO 确认这是什么值
SUPPORTED_PLATFORM="platform:el$SUPPORTED_MAJOR"
ARCH=$(arch)

# FIXME 更新这个值
declare -r GPG_KEY_URL="https://dl.rockylinux.org/pub/rocky/RPM-GPG-KEY-Rocky-9"
# FIXME 更新这个值
declare -r GPG_KEY_SHA512="ead288baa8daad12d6f340f1a392d47413f8614425673fe310e82d4ead94ca15eb2e1329b30389e6a7f93dd406da255df410306cffd7a1a24f0dfb4c8e23fbfe"

# TODO 这是红帽的订阅管理平台通信证书，CloudOS应该已经移除了，但是还是要确认一下
sm_ca_dir=/etc/rhsm/ca
unset tmp_sm_ca_dir

# 所有的仓库需要确保 rpm 包都可以使用 $GPG_KEY_URL 进行签名验证
declare -A repo_urls
repo_urls=(
    # FIXME 需要更新 URL
    ["cloudosbaseos"]="https://dl.rockylinux.org/pub/rocky/${SUPPORTED_MAJOR}/BaseOS/$ARCH/os/"
    ["cloudosappstream"]="https://dl.rockylinux.org/pub/rocky/${SUPPORTED_MAJOR}/AppStream/$ARCH/os/"
)

# 可能有一些需要额外安装的软件包，在这里列出来
always_install=()

# 流仓库软件包需要特殊处理
declare -g -A stream_repos_pkgs
stream_repos_pkgs=(
    # FIXME
    [rocky - repos]=centos-stream-repos
    [epel - release]=epel-next-release
)

# | 架构    | grub2-efi      | shim      |
# | ------- | -------------- | --------- |
# | x86_64  | grub2-efi-x64  | shim-x64  |
# | aarch64 | grub2-efi-aa64 | shim-aa64 |
declare -A CPU_ARCH_SUFFIX_MAPPING=(
    ["x86_64"]=x64
    ["aarch64"]=aa64
)

# 重命名时添加在 openCloud OS 流仓库文件的前缀
STREAM_PREFIX_STR="stream-"

# TODO Always replace these stream packages with their Rocky Linux equivalents.
stream_always_replace=(
    fwupdate\*
    grub2-\*
    shim-\*
    kernel
    kernel-\*
)

# 这些目录需要预留有这么大的空间，单位是 MiB
declare -A DIR_SPACE_MAPPING
DIR_SPACE_MAPPING=(
    ["/usr"]=250
    ["/var"]=1536
    ["/boot"]=50
)

# 检查 os-release 中是否存在必要的字段，如果存在，则返回字段值，否则返回 1
# 使用 () 定义函数而不是 {} 定义函数，以确保从 os-release 导出的环境变量，不会影响全局
function linux_dist_info() (
    # shellcheck source=/dev/null
    . /etc/os-release
    [[ -z ${!1} ]] && return 1
    echo "${!1}"
)

# 创建一个临时工作目录
function pre_setup() {
    if ! tmp_dir=$(mktemp -d) || [[ ! -d "$tmp_dir" ]]; then
        error_exit "Error creating temp dir"
    fi
    # 使用 failglob 和 dotglob 检测目录是否为空，如果目录中有任何文件存在，都会导致if失败
    if (
        shopt -s failglob dotglob
        : "$tmp_dir"/*
    ) 2>/dev/null; then
        error_exit "Temp dir not empty"
    fi

    declare -rg TMP_DIR="${tmp_dir}"
}

# 清理函数，用于清理临时工作目录
function exit_clean() {
    if [[ -d "$TMP_DIR" ]]; then
        rm -rf "$TMP_DIR"
    fi
    if [[ -f "$CONTAINER_MACROS" ]]; then
        rm -f "$CONTAINER_MACROS"
    fi
}

function pre_check() {
    # TODO: 检查环境特征，必须是 openCloudOS
    : something

    if ! dnf -y check; then
        error_exit "Errors found in dnf/rpm database. Please correct before running ${SCRIPT_NAME}"
    fi

    # 如果当前环境中没有安装内核（docker容器、chroot环境），则忽略 /boot 需要的空间
    if ! rpm -q --quiet kernel; then
        DIR_SPACE_MAPPING["/boot"]=0
    fi

    local -a errs dirs=("${!DIR_SPACE_MAPPING[@]}")
    local dir mount avail i=0
    local -A mount_avail_map mount_space_map
    while read -r mount avail; do
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

    if ((${#errs[@]})); then
        error_exit "${errs[*]}"
    fi
}

# 脚本所需的命令都在 openCloud OS 8 的最小安装中，所有必须的二进制都在 /bin 目录中
# 除非运行环境本身已经损坏，否则迁移脚本在这里不会失败。
function bin_check() {
    # 我们仅支持升级 openCloud OS 8 到 openCloud OS 9
    if [[ $(linux_dist_info PLATFORM_ID) != "$SUPPORTED_PLATFORM" ]]; then
        error_exit 'This script must be run on an EL9 distribution. Migration from other distributions is not supported.'
    fi

    local -a missing
    local -a bins=(
        rpm dnf awk column tee tput mkdir cat arch sort uniq rmdir df
        rm head curl sha512sum mktemp systemd-detect-virt sed grep
    )
    if [[ $update_efi ]]; then
        bins+=(findmnt grub2-mkconfig efibootmgr mokutil lsblk)
    fi
    for bin in "${bins[@]}"; do
        if ! type "$bin" &>/dev/null; then
            missing+=("$bin")
        fi
    done

    local -A pkgs
    pkgs=(
        ["dnf"]=4.2
        ["dnf-plugins-core"]=0
    )

    # 比较新老版本的版本号，现在使用 sort -V 进行版本检查
    function pkg_ver() (
        _ver=$(rpm -q --qf '%{VERSION}\n' "$1") || return 2
        if [[ $(sort -V <<<"${_ver}"$'\n'"$2" | head -1) != "$2" ]]; then
            return 1
        fi
        return 0
    )

    for pkg in "${!pkgs[@]}"; do
        ver=${pkgs[$pkg]}
        if ! pkg_ver "$pkg" "$ver"; then
            error_exit "$pkg >= $ver is required for this script. Please run 'dnf install $pkg; dnf update' first."
        fi
    done

    if ((${#missing[@]})); then
        error_exit "Commands not found: ${missing[*]}. Possible bad PATH setting or corrupt installation."
    fi
}

# 禁用 epel 仓库以避免 extras 仓库错误映射
function repoquery() {
    local name val prev result
    # TODO 检查是否有 epel 仓库
    result=$(safednf -y -q "${dist_repourl_swaps[@]}" \
        --setopt=epel.excludepkgs=epel-release repoquery -i "$1") ||
        error_exit "Failed to fetch info for package $1."
    if ! [[ ${result} ]]; then
        # 没有查询到任何信息
        return 1
    fi
    declare -gA repoquery_results=()
    while IFS=" :" read -r name val; do
        if [[ -z "${name}" ]]; then
            repoquery_results["${prev}"]+=" $val"
        else
            prev="${name}"
            repoquery_results["${name}"]="${val}"
        fi
    done <<<"${result}"
}

function _repoinfo() {
    local name val result
    result=$(
        safednf -y -q --repo="$1" "${dist_repourl_swaps[@]}" repoinfo "$1"
    ) || return
    if [[ $result == 'Total packages: 0' ]]; then
        # We didn't match this repo.
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

    # Set the enabled state
    if [[ ! "${enabled_repo_check["$1"]}" ]]; then
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

    # Add an indicator of whether this is a subscription-manager managed
    # repository.
    # shellcheck disable=SC2154
    repoinfo_results["Repo-managed"]=$(
        awk '
            BEGIN {FS="[)(]"}
            /^# Managed by \(.*\) subscription-manager$/ {print $2}
        ' <"${repoinfo_results["Repo-filename"]}"
    )
}

# We now store the repoinfo results in a cache.
declare -g -A repoinfo_results_cache=()
function repoinfo() {
    local k
    if [[ ! ${repoinfo_results_cache[$1]} ]]; then
        _repoinfo "$@" || return
        repoinfo_results_cache[$1]=1
        for k in "${!repoinfo_results[@]}"; do
            repoinfo_results_cache["${1}:${k}"]=${repoinfo_results[$k]}
        done
    else
        repoinfo_results=()
        for k in "${!repoinfo_results_cache[@]}"; do
            local repo=${k%%:*} key=${k#*:}
            if [[ $repo != "$1" ]]; then
                continue
            fi

            repoinfo_results[$key]=${repoinfo_results_cache[$k]}
        done
    fi
}

provides_pkg() (
    if [[ ! $1 ]]; then
        return 0
    fi

    set -o pipefail
    provides=$(
        safednf -y -q "${dist_repourl_swaps[@]}" provides "$1" |
            awk '{print $1; nextfile}'
    ) ||
        return 1
    set +o pipefail
    pkg=$(rpm -q --queryformat '%{NAME}\n' "$provides") ||
        pkg=$(
            safednf -y -q "${dist_repourl_swaps[@]}" repoquery \
                --queryformat '%{NAME}\n' "$provides"
        ) || error_exit "Can't get package name for $provides."
    printf '%s\n' "$pkg"
)

# If you pass an empty arg as one of the package specs to rpm it will match
# every package on the system. This function simply strips out any empty args
# and passes the rest to rpm to avoid this side-effect.
saferpm() (
    args=()
    for a in "$@"; do
        if [[ $a ]]; then
            args+=("$a")
        fi
    done
    rpm "${args[@]}"
)

# And a similar function for dnf
safednf() (
    args=()
    for a in "$@"; do
        if [[ $a ]]; then
            args+=("$a")
        fi
    done
    dnf "${args[@]}"
)

#
# Three ways we check the repourl. If dnf repoinfo fails then we assume the URL
# is bad. A missing URL is also considered bad. Lastly we check to see if we
# can fetch the repomd.xml file from the repository, and if not then the repourl
# is considered bad. In any of these cases we'll end up replacing the repourl
# with a good one from our mirror of CentOS vault.
#
function check_repourl() {
    repoinfo "$1" || return
    if [[ ! ${repoinfo_results["Repo - baseurl"]} ]]; then
        return 1
    fi

    local -a urls
    IFS=, read -r -a urls <<<"${repoinfo_results["Repo - baseurl"]}"
    local u url
    for url in "${urls[@]}"; do
        # FIXME: 这里要做个什么事？
        u="${url}"
        curl -sfLI "${u%% *}repodata/repomd.xml" >/dev/null && return
    done
    return "$(($? ? $? : 1))"
}

function collect_system_info() {
    # Dump the DNF cache first so we start with a clean slate.
    infomsg $'\nRemoving dnf cache\n'
    rm -rf /var/cache/{yum,dnf}
    # Check the efi mount first, so we can bail before wasting time on all these
    # other checks if it's not there.
    if [[ $update_efi ]]; then
        local efi_mount kname
        declare -g -a efi_disk efi_partition
        efi_mount=$(findmnt --mountpoint /boot/efi --output SOURCE \
            --noheadings) ||
            error_exit "Can't find EFI mount. No EFI  boot detected."
        kname=$(lsblk -dno kname "$efi_mount")
        efi_disk=("$(lsblk -dno pkname "/dev/$kname")")

        if [[ ${efi_disk[0]} ]]; then
            efi_partition=("$(<"/sys/block/${efi_disk[0]}/$kname/partition")")
        else
            # This is likely an md-raid or other type of virtual disk, we need
            # to dig a little deeper to find the actual physical disks and
            # partitions.
            kname=$(lsblk -dno kname "$efi_mount")
            cd "/sys/block/$kname/slaves" || error_exit \
                "Unable to gather EFI data: Can't cd to /sys/block/$kname/slaves."
            if ! (
                shopt -s failglob
                : ./*
            ) 2>/dev/null; then
                error_exit \
                    "Unable to gather EFI data: No slaves found in /sys/block/$kname/slaves."
            fi
            efi_disk=()
            for d in *; do
                efi_disk+=("$(lsblk -dno pkname "/dev/$d")")
                efi_partition+=("$(<"$d/partition")")
                if [[ ! ${efi_disk[-1]} || ! ${efi_partition[-1]} ]]; then
                    error_exit \
                        "Unable to gather EFI data: Can't find disk name or partition number for $d."
                fi
            done
            cd -
        fi

        # We need to make sure that these packages are always installed in an
        # EFI system.
        always_install+=(
            "shim-${CPU_ARCH_SUFFIX_MAPPING[$ARCH]}"
            "grub2-efi-${CPU_ARCH_SUFFIX_MAPPING[$ARCH]}"
        )
    fi

    # Don't enable these module streams, even if they are enabled in the source
    # distro.
    declare -g -a module_excludes
    module_excludes=(
    )

    # Some OracleLinux modules have stream names of ol9 instead of rhel9 and ol
    # instead of rhel. This is a map that does a glob match and replacement.
    local -A module_glob_map
    module_glob_map=(
        ['%:ol9']=:rhel9
        ['%:ol']=:rhel
    )

    # We need to map rockylinux repository names to the equivalent repositories
    # in the source distro. To do that we look for known packages in each
    # repository and see what repo they came from. We need to use repoquery for
    # this which requires downloading the package, so we pick relatively small
    # packages for this.
    declare -g -A repo_map pkg_repo_map
    declare -g -a managed_repos
    pkg_repo_map=(
        [baseos]=rootfiles.noarch
        [appstream]=apr-util-ldap.$ARCH
        [highavailability]=pacemaker-doc.noarch
        [crb]=python3-mpich.$ARCH
        [extras]=epel-release.noarch
        #        [devel]=quota-devel.$ARCH
    )

    dist_id=$(linux_dist_info ID)
    # We need a different dist ID for CentOS Linux vs CentOS Stream
    if [[ $dist_id == centos ]] && rpm --quiet -q centos-stream-release; then
        dist_id+=-stream
    fi

    PRETTY_NAME=$(linux_dist_info PRETTY_NAME)
    infomsg '%s' \
        "Preparing to migrate $PRETTY_NAME to Rocky Linux 9."$'\n\n'

    # Check to see if we need to change the repourl on any system repositories
    local -A dist_repourl_map
    dist_repourl_map=(
    )

    # We need a list of enabled repositories
    local -a enabled_repos=()
    declare -g -A enabled_repo_check=()
    declare -g -a dist_repourl_swaps=()
    readarray -s 1 -t enabled_repos < <(dnf -q -y repolist --enabled)
    for r in "${enabled_repos[@]}"; do
        enabled_repo_check[${r%% *}]=1
    done

    # ...and finally set a number of dnf options to replace the baseurl of these
    # repos
    local k
    for k in "${!dist_repourl_map[@]}"; do
        local d=${k%%:*} r=${k#*:}
        if [[ $d != "$dist_id" || ! ${enabled_repo_check[$r]} ]] ||
            check_repourl "$r"; then
            continue
        fi

        dist_repourl_swaps+=(
            "--setopt=$r.mirrorlist="
            "--setopt=$r.metalink="
            "--setopt=$r.baseurl="
            "--setopt=$r.baseurl=${dist_repourl_map[$k]}"
        )

        infomsg 'Baseurl for %s is invalid, setting to %s.\n' \
            "$r" "${dist_repourl_map[$k]}"
    done

    infomsg '%s' "Determining repository names for $PRETTY_NAME"

    for r in "${!pkg_repo_map[@]}"; do
        printf '.'
        p=${pkg_repo_map[$r]}
        repoquery "$p" || continue
        repo_map[$r]=${repoquery_results[Repository]}
    done

    printf '%s\n' '' '' \
        "Found the following repositories which map from $PRETTY_NAME to Rocky Linux 9:"
    column -t -s $'\t' -N "$PRETTY_NAME,Rocky Linux 9" < <(
        for r in "${!repo_map[@]}"; do
            printf '%s\t%s\n' "${repo_map[$r]}" "$r"
        done
    )

    infomsg $'\n'"Getting system package names for $PRETTY_NAME"

    # We don't know what the names of these packages are, we have to discover
    # them via various means. The most common means is to look for either a
    # distro-agnostic provides or a filename. In a couple of cases we need to
    # jump through hoops to get a filename that is provided specifically by the
    # source distro.
    # Get info for each repository to determine which ones are subscription
    # managed.
    # system-release here is a bit of a hack, but it ensures that the
    # rocky-repos package will get installed.
    for r in "${!repo_map[@]}"; do
        repoinfo "${repo_map[$r]}" ||
            error_exit "Failed to fetch info for repository ${repo_map[$r]}."

        if [[ $r == "baseos" ]]; then
            local baseos_filename=system-release
            if [[ ! ${repoinfo_results[Repo - managed]} ]]; then
                baseos_filename="${repoinfo_results[Repo - filename]}"
            fi
            local baseos_gpgkey="${repoinfo_results[Repo - gpgkey]}"
        fi
        if [[ ${repoinfo_results[Repo - managed]} ]]; then
            managed_repos+=("${repo_map[$r]}")
        fi
    done

    # First get info for the baseos repo
    repoinfo "${repo_map[baseos]}" ||
        error_exit "Failed to fetch info for repository ${repo_map[baseos]}."

    declare -g -A pkg_map provides_pkg_map
    declare -g -a addl_provide_removes addl_pkg_removes
    provides_pkg_map=(
        [rocky - backgrounds]=system-backgrounds
        [rocky - indexhtml]=redhat-indexhtml
        [rocky - repos]="$baseos_filename"
        [rocky - logos]=system-logos
        [rocky - logos - httpd]=system-logos-httpd
        [rocky - logos - ipa]=system-logos-ipa
        [rocky - gpg - keys]="$baseos_gpgkey"
        [rocky - release]=system-release
    )
    addl_provide_removes=(
        redhat-release
        redhat-release-eula
    )

    # Check to make sure that we don't already have a full or partial
    # RockyLinux install.
    if [[ $(rpm -qa "${!provides_pkg_map[@]}") ]]; then
        error_exit \
            $'Found a full or partial RockyLinux install already in place. Aborting\n' \
            $'because continuing with the migration could cause further damage to system.'
    fi

    for pkg in "${!provides_pkg_map[@]}"; do
        printf '.'
        prov=${provides_pkg_map[$pkg]}
        pkg_map[$pkg]=$(provides_pkg "$prov") ||
            error_exit "Can't get package that provides $prov."
    done
    for prov in "${addl_provide_removes[@]}"; do
        printf '.'
        local pkg
        pkg=$(provides_pkg "$prov") || continue
        addl_pkg_removes+=("$pkg")
    done

    # shellcheck disable=SC2140
    printf '%s\n' '' '' \
        "Found the following system packages which map from $PRETTY_NAME to Rocky ""\
Linux 9:"
    column -t -s $'\t' -N "$PRETTY_NAME,Rocky Linux 9" < <(
        for p in "${!pkg_map[@]}"; do
            printf '%s\t%s\n' "${pkg_map[$p]}" "$p"
        done
    )

    infomsg $'\n'"Getting list of installed system packages."$'\n'

    readarray -t installed_packages < <(
        saferpm -qa --queryformat="%{NAME}\n" "${pkg_map[@]}"
    )
    declare -g -A installed_pkg_check installed_pkg_map
    for p in "${installed_packages[@]}"; do
        installed_pkg_check[$p]=1
    done
    for p in "${!pkg_map[@]}"; do
        if [[ ${pkg_map[$p]} && ${installed_pkg_check[${pkg_map[$p]}]} ]]; then
            installed_pkg_map[$p]=${pkg_map[$p]}
        fi
    done

    # Special Handling for CentOS Stream Repos
    installed_sys_stream_repos_pkgs=()
    installed_stream_repos_pkgs=()
    for p in "${!stream_repos_pkgs[@]}"; do
        if [[ ${installed_pkg_map[$p]} &&
            ${installed_pkg_map[$p]} == "${stream_repos_pkgs[$p]}" ]]; then
            # System package that needs to be swapped / disabled
            installed_pkg_map[$p]=
            installed_sys_stream_repos_pkgs+=("${stream_repos_pkgs[$p]}")
        elif rpm --quiet -q "${stream_repos_pkgs[$p]}"; then
            # Non-system package, repos just need to be disabled.
            installed_stream_repos_pkgs+=("${stream_repos_pkgs[$p]}")
        fi
    done

    # shellcheck disable=SC2140
    printf '%s\n' '' \
        "We will replace the following $PRETTY_NAME packages with their Rocky Linux 9 ""\
equivalents"
    column -t -s $'\t' -N "Packages to be Removed,Packages to be Installed" < <(
        for p in "${!installed_pkg_map[@]}"; do
            printf '%s\t%s\n' "${installed_pkg_map[$p]}" "$p"
        done
    )

    if ((${#installed_sys_stream_repos_pkgs[@]})); then
        # shellcheck disable=SC2026
        printf '%s\n' '' \
            'Also to aid the transition from CentOS Stream the following packages will be ''removed from the rpm database but the included repos will be renamed and ''retained but disabled:' \
            "${installed_sys_stream_repos_pkgs[@]}"
    fi

    if ((${#installed_stream_repos_pkgs[@]})); then
        # shellcheck disable=SC2026
        printf '%s\n' '' \
            'Also to aid the transition from CentOS Stream the repos included in the ''following packages will be renamed and retained but disabled:' \
            "${installed_stream_repos_pkgs[@]}"
    fi

    if ((${#addl_pkg_removes[@]})); then
        printf '%s\n' '' \
            "In addition to the above the following system packages will be removed:" \
            "${addl_pkg_removes[@]}"
    fi

    # Release packages that are part of SIG's should be listed below when they
    # are available.
    # UPDATE: We may or may not do something with SIG's here, it could just be
    # left as a separate exercise to swap out the sig repos.
    #sigs_to_swap=()

    infomsg '%s' $'\n' \
        $'Getting a list of enabled modules for the system repositories.\n'

    # Get a list of system enabled modules.
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

    # Map the known module name differences.
    disable_modules=()
    local i gl repl mod
    for i in "${!enabled_modules[@]}"; do
        mod=${enabled_modules[$i]}
        for gl in "${!module_glob_map[@]}"; do
            repl=${module_glob_map[$gl]}
            mod=${mod/$gl/$repl}
        done
        if [[ $mod != "${enabled_modules[$i]}" ]]; then
            disable_modules+=("${enabled_modules[$i]}")
            enabled_modules["$i"]=$mod
        fi
    done

    # Remove entries matching any excluded modules.
    if ((${#module_excludes[@]})); then
        printf '%s\n' '' "Excluding modules:" "${module_excludes[@]}"
        local -A module_check='()'
        local -a tmparr='()'
        for m in "${module_excludes[@]}"; do
            module_check[$m]=1
        done
        for m in "${enabled_modules[@]}"; do
            if [[ ! ${module_check[$m]} ]]; then
                tmparr+=("$m")
            fi
        done
        enabled_modules=("${tmparr[@]}")
    fi

    printf '%s\n' '' "Found the following modules to re-enable at completion:" \
        "${enabled_modules[@]}" ''

    if ((${#managed_repos[@]})); then
        # shellcheck disable=SC2026
        printf '%s\n' '' \
            'In addition, since this system uses subscription-manager the following ''managed repos will be disabled:' \
            "${managed_repos[@]}"
    fi
}

convert_info_dir=/root/convert
unset convert_to_rocky reinstall_all_rpms verify_all_rpms update_efi \
    CONTAINER_MACROS

function usage() {
    printf '%s\n' \
        "Usage: ${0##*/} [OPTIONS]" \
        '' \
        'Options:' \
        '-h Display this help' \
        '-r Convert to rocky' \
        '-V Verify switch' \
        '   !! USE WITH CAUTION !!'
    exit 1
} >&2

function generate_rpm_info() {
    mkdir -p "$convert_info_dir"
    infomsg "Creating a list of RPMs installed: $1"$'\n'
    # shellcheck disable=SC2140
    rpm -qa --qf \
        "%{NAME}|%{VERSION}|%{RELEASE}|%{INSTALLTIME}|%{VENDOR}|%{BUILDTIME}|""\
%{BUILDHOST}|%{SOURCERPM}|%{LICENSE}|%{PACKAGER}\n" |
        sort >"${convert_info_dir}/$HOSTNAME-rpm-list-$1.log"
    infomsg "Verifying RPMs installed against RPM database: $1"$'\n\n'
    rpm -Va | sort -k3 >"\
${convert_info_dir}/$HOSTNAME-rpm-list-verified-$1.log"
}

# Run a dnf update before the actual migration.
function pre_update() {
    infomsg '%s\n' "Running dnf update before we attempt the migration."
    safednf -y "${dist_repourl_swaps[@]}" update || error_exit \
        $'Error running pre-update. Stopping now to avoid putting the system in an\n'$'unstable state. Please correct the issues shown here and try again.'
}

function package_swaps() {
    # Save off any subscription-manager keys, just in case.
    if (
        shopt -s failglob dotglob
        : "$sm_ca_dir"/*
    ) 2>/dev/null; then
        tmp_sm_ca_dir=$TMP_DIR/sm-certs
        mkdir "$tmp_sm_ca_dir" ||
            error_exit "Could not create directory: $tmp_sm_ca_dir"
        cp -f -dR --preserve=all "$sm_ca_dir"/* "$tmp_sm_ca_dir/" ||
            error_exit "Could not copy certs to $tmp_sm_ca_dir"
    fi

    # prepare repo parameters
    local -a dnfparameters
    for repo in "${!repo_urls[@]}"; do
        dnfparameters+=("--repofrompath=${repo},${repo_urls[${repo}]}")
        dnfparameters+=("--setopt=${repo}.gpgcheck=1")
        dnfparameters+=("--setopt=${repo}.gpgkey=file://${gpg_key_file}")
    done

    # CentOS Stream specific processing
    if ((${#installed_stream_repos_pkgs[@]} || ${#installed_sys_stream_repos_pkgs[@]})); then
        # Get a list of the repo files.
        local -a repos_files
        readarray -t repos_files < <(
            saferpm -ql "${installed_sys_stream_repos_pkgs[@]}" \
                "${installed_stream_repos_pkgs[@]}" |
                grep '^/etc/yum\.repos\.d/.\+\.repo$'
        )

        if ((${#installed_sys_stream_repos_pkgs[@]})); then
            # Remove the package from the rpm db.
            saferpm -e --justdb --nodeps -a \
                "${installed_sys_stream_repos_pkgs[@]}" ||
                error_exit \
                    "Could not remove packages from the rpm db: ${installed_sys_stream_repos_pkgs[*]}"
        fi

        # Rename the stream repos with a prefix and fix the baseurl.
        # shellcheck disable=SC2016
        sed -i \
            -e 's/^\[/['"$STREAM_PREFIX_STR"'/' \
            -e 's|^mirrorlist=|#mirrorlist=|' \
            -e 's|^#baseurl=http://mirror.centos.org/$contentdir/$stream/|baseurl=http://mirror.centos.org/centos/9-stream/|' \
            -e 's|^baseurl=http://vault.centos.org/$contentdir/$stream/|baseurl=https://vault.centos.org/centos/9-stream/|' \
            "${repos_files[@]}"
    fi

    # Use dnf shell to swap the system packages out.
    safednf -y shell --disablerepo=\* --noautoremove \
        "${dist_repourl_swaps[@]}" \
        --setopt=protected_packages= --setopt=keepcache=True \
        "${dnfparameters[@]}" \
        <<EOF
        remove ${installed_pkg_map[@]} ${addl_pkg_removes[@]}
        install ${!installed_pkg_map[@]}
        run
        exit
EOF

    # rocky-repos and rocky-gpg-keys are now installed, so we don't need the
    # key file anymore
    rm -rf "$gpg_tmp_dir"

    # We need to check to make sure that all of the original system packages
    # have been removed and all of the new ones have been added. If a package
    # was supposed to be removed and one with the same name added back then
    # we're kind of screwed for this check, as we can't be certain, but all the
    # packages we're adding start with "rocky-*" so this really shouldn't happen
    # and we can safely not check for it. The worst that will happen is a rocky
    # linux package will be removed and then installed again.
    local -a check_removed check_installed
    readarray -t check_removed < <(
        saferpm -qa --qf '%{NAME}\n' "${installed_pkg_map[@]}" \
            "${addl_pkg_removes[@]}" | sort -u
    )

    if ((${#check_removed[@]})); then
        infomsg '%s' $'\n' \
            "Packages found on system that should still be removed. Forcibly" \
            " removing them with rpm:"$'\n'
        # Removed packages still found on the system. Forcibly remove them.
        for pkg in "${check_removed[@]}"; do
            # Extra safety measure, skip if empty string
            if [[ -z $pkg ]]; then
                continue
            fi
            printf '%s\n' "$pkg"
            saferpm -e --allmatches --nodeps "$pkg" ||
                saferpm -e --allmatches --nodeps --noscripts --notriggers "$pkg"
        done
    fi

    # Check to make sure we installed everything we were supposed to.
    readarray -t check_installed < <(
        {
            printf '%s\n' "${!installed_pkg_map[@]}" | sort -u
            saferpm -qa --qf '%{NAME}\n' "${!installed_pkg_map[@]}" | sort -u
        } | sort | uniq -u
    )
    if ((${#check_installed[@]})); then
        infomsg '%s' $'\n' \
            "Some required packages were not installed by dnf. Attempting to" \
            " force with rpm:"$'\n'

        # Get a list of rpm packages to package names
        local -A rpm_map
        local -a file_list
        for rpm in /var/cache/dnf/{cloudosbaseos,cloudosappstream}-*/packages/*.rpm; do
            rpm_map[$(
                rpm -q --qf '%{NAME}\n' --nodigest "$rpm" 2>/dev/null
            )]=$rpm
        done

        # Attempt to install.
        for pkg in "${check_installed[@]}"; do
            printf '%s\n' "$pkg"
            if ! rpm -i --force --nodeps --nodigest "${rpm_map[$pkg]}" \
                2>/dev/null; then
                # Try to install the package in just the db, then clean it up.
                rpm -i --force --justdb --nodeps --nodigest "${rpm_map[$pkg]}" \
                    2>/dev/null

                # Get list of files that are still causing problems and donk
                # them.
                readarray -t file_list < <(
                    rpm -V "$pkg" 2>/dev/null | awk '$1!="missing" {print $2}'
                )
                for file in "${file_list[@]}"; do
                    rmdir "$file" ||
                        rm -f "$file" ||
                        rm -rf "$file"
                done

                # Now try re-installing the package to replace the missing
                # files. Regardless of the outcome here we just accept it and
                # move on and hope for the best.
                rpm -i --reinstall --force --nodeps --nodigest \
                    "${rpm_map[$pkg]}" 2>/dev/null
            fi
        done
    fi

    # Distrosync
    infomsg $'Ensuring repos are enabled before the package swap\n'
    safednf -y --enableplugin=config_manager config-manager \
        --set-enabled "${!repo_map[@]}" || {
        printf '%s\n' 'Repo name missing?'
        exit 25
    }

    if ((${#managed_repos[@]})); then
        # Filter the managed repos for ones still in the system.
        readarray -t managed_repos < <(
            safednf -y -q repolist "${managed_repos[@]}" |
                awk '$1!="repo" {print $1}'
        )

        if ((${#managed_repos[@]})); then
            infomsg $'\nDisabling subscription managed repos\n'
            safednf -y --enableplugin=config_manager config-manager \
                --disable "${managed_repos[@]}"
        fi
    fi

    if ((${#disable_modules[@]})); then
        infomsg $'Disabling modules\n\n'
        safednf -y module disable "${disable_modules[@]}" ||
            error_exit "Can't disable modules ${disable_modules[*]}"
    fi

    if ((${#enabled_modules[@]})); then
        infomsg $'Enabling modules\n\n'
        safednf -y module enable "${enabled_modules[@]}" ||
            error_exit "Can't enable modules ${enabled_modules[*]}"
    fi

    # Make sure that excluded modules are disabled.
    if ((${#module_excludes[@]})); then
        infomsg $'Disabling excluded modules\n\n'
        safednf -y module disable "${module_excludes[@]}" ||
            error_exit "Can't disable modules ${module_excludes[*]}"
    fi

    infomsg $'\nSyncing packages\n\n'
    dnf -y --allowerasing distro-sync ||
        error_exit "Error during distro-sync."

    # Disable Stream repos.
    if ((${#installed_sys_stream_repos_pkgs[@]} || ${#installed_stream_repos_pkgs[@]})); then
        dnf -y --enableplugin=config_manager config-manager --set-disabled \
            "$STREAM_PREFIX_STR*" ||
            logger_error \
                $'Failed to disable CentOS Stream repos, please check and disable manually.'

        if ((${#stream_always_replace[@]})) &&
            [[ $(saferpm -qa "${stream_always_replace[@]}") ]]; then
            safednf -y distro-sync "${stream_always_replace[@]}" ||
                error_exit "Error during distro-sync."
        fi

        infomsg $'\nCentOS Stream Migration Notes:\n\n'
        cat <<EOF
Because CentOS Stream leads RockyLinux by the next point release many packages
in Stream will have higher version numbers than those in RockyLinux, some will
even be rebased to a new upstream version. Downgrading these packages to the
versions in RockyLinux carries the risk that the older version may not
recognize config files, data or other files generated by the newer version in
Stream.

To avoid issues with this the newer package versions from CentOS Stream have
been retained. Also the CentOS Stream repositories have been retained but
renamed with a prefix of "stream-" to avoid clashing with RockyLinux
repositories, but these same repos have also been disabled so that future
package installs will come from the stock RockyLinux repositories.

If you do nothing except update to the next point release of RockyLinux when it
becomes available then the packages retained from Stream should be replaced at
that time. If you need to update a package from Stream (eg: to fix a bug or
security issue) then you will need to enable the appropriate repository to do
so.
EOF
    fi

    if rpm --quiet -q subscription-manager; then
        infomsg $'Subscription Manager found on system.\n\n'
        cat <<EOF
If you're converting from a subscription-managed distribution such as RHEL then
you may no longer need subscription-manager or dnf-plugin-subscription-manager.
While it won't hurt anything to have it on your system you may be able to safely
remove it with:

"dnf remove subscription-manager dnf-plugin-subscription-manager".

Take care that it doesn't remove something that you want to keep.

The subscription-manager dnf plugin may be enabled for the benefit of
Subscription Management. If no longer desired, you can use
"subscription-manager config --rhsm.auto_enable_yum_plugins=0" to block this
behavior.
EOF
    fi

    if ((${#always_install[@]})); then
        safednf -y install "${always_install[@]}" || error_exit \
            "Error installing required packages: ${always_install[*]}"
    fi

    if [[ $tmp_sm_ca_dir ]]; then
        # Check to see if there's Subscription Manager certs which have been
        # removed
        local -a removed_certs
        readarray -t removed_certs < <((
            shopt -s nullglob dotglob
            local -a certs
            cd "$sm_ca_dir" && certs=(*)
            cd "$tmp_sm_ca_dir" && certs+=(*)
            IFS=$'\n'
            printf '%s' "${certs[*]}"
        ) | sort | uniq -u)

        if ((${#removed_certs[@]})); then
            cp -n -dR --preserve=all "$tmp_sm_ca_dir"/* "$sm_ca_dir/" ||
                error_exit "Could not copy certs back to $sm_ca_dir"

            infomsg '%s' \
                $'Some Subscription Manager certificates ' \
                "were restored to $sm_ca_dir after"$'\n' \
                $'migration so that the subscription-manager ' \
                $'command will continue to work:\n\n'
            printf '%s\n' "${removed_certs[@]}" ''
            cat <<EOF
If you no longer need to use the subscription-manager command then you may
safely remove these files.
EOF
        fi
    fi
}

# Check if this system is running on EFI
# If yes, we'll need to run fix_efi() at the end of the conversion
function efi_check() {
    # Check if we have /sys mounted and it is looking sane
    if ! [[ -d /sys/class/block ]]; then
        error_exit "/sys is not accessible."
    fi

    # Now that we know /sys is reliable, use it to check if we are running on
    # EFI or not
    if systemd-detect-virt --quiet --container; then
        declare -g CONTAINER_MACROS
        CONTAINER_MACROS=$(mktemp /etc/rpm/macros.zXXXXXX)
        printf '%s\n' '%_netsharedpath /sys:/proc' >"$CONTAINER_MACROS"
    elif [[ -d /sys/firmware/efi/ ]]; then
        declare -g update_efi
        update_efi=true
    fi
}

# Called to update the EFI boot.
fix_efi() (
    grub2-mkconfig -o /boot/efi/EFI/rocky/grub.cfg ||
        error_exit "Error updating the grub config."
    for i in "${!efi_disk[@]}"; do
        efibootmgr -c -d "/dev/${efi_disk[$i]}" -p "${efi_partition[$i]}" \
            -L "Rocky Linux" -l "/EFI/rocky/shim${CPU_ARCH_SUFFIX_MAPPING[$ARCH]}.efi" ||
            error_exit "Error updating uEFI firmware."
    done
)

# Download and verify the Rocky Linux package signing key
function establish_gpg_trust() {
    # create temp dir and verify it is really created and empty, so we are sure
    # deleting it afterwards won't cause any harm
    declare -g gpg_tmp_dir
    gpg_tmp_dir=$TMP_DIR/gpg
    if ! mkdir "$gpg_tmp_dir" || [[ ! -d "$gpg_tmp_dir" ]]; then
        error_exit "Error creating temp dir"
    fi
    # failglob makes pathname expansion fail if empty, dotglob adds files
    # starting with . to pathname expansion
    if (
        shopt -s failglob dotglob
        : "$gpg_tmp_dir"/*
    ) 2>/dev/null; then
        error_exit "Temp dir not empty"
    fi

    # extract the filename from the url, use the temp dir just created
    declare -g gpg_key_file="$gpg_tmp_dir/${GPG_KEY_URL##*/}"

    if ! curl -L -o "$gpg_key_file" --silent --show-error "$GPG_KEY_URL"; then
        rm -rf "$gpg_tmp_dir"
        error_exit "Error downloading the Rocky Linux signing key."
    fi

    if ! sha512sum --quiet -c <<<"$GPG_KEY_SHA512 $gpg_key_file"; then
        rm -rf "$gpg_tmp_dir"
        error_exit "Error validating the signing key."
    fi
}

## End actual work

noopts=0
while getopts "hrVR" option; do
    ((noopts++))
    case "$option" in
    h)
        usage
        ;;
    r)
        convert_to_rocky=true
        ;;
    V)
        verify_all_rpms=true
        ;;
    *)
        logger_error $'Invalid switch'
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

if [[ $verify_all_rpms ]]; then
    generate_rpm_info begin
fi

if [[ $convert_to_rocky ]]; then
    collect_system_info
    establish_gpg_trust
    pre_update
    package_swaps
fi

if [[ $verify_all_rpms && $convert_to_rocky ]]; then
    generate_rpm_info finish
    infomsg $'You may review the following files:\n'
    printf '%s\n' "$convert_info_dir/$HOSTNAME-rpm-list-"*.log
fi

if [[ $update_efi && $convert_to_rocky ]]; then
    fix_efi
fi

printf '\n\n\n'
if [[ $convert_to_rocky ]]; then
    infomsg $'\nDone, please reboot your system.\n'
fi
finish_print
