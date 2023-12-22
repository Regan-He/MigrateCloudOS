#!/usr/bin/bash
#shellcheck shell=bash

declare -rA _logger_color=(
    [ok]=2
    [fatal]=160
    [error]=1
    [warning]=9
    [info]=5
    [debug]=195
)

function print2stdout() {
    local -i color_code=$1
    shift 1
    printf '\e[48;5;%dm%s\e[0m \n' "${color_code}" "${@}"
}

function process_logger() {
    local color_code="$1"
    shift 1
    local -a message=("${@}")

    print2stdout "${_logger_color["${color_code}"]}" "${message[@]}"
}

function logger_ok() {
    process_logger "ok" "${@}"
}

function logger_fatal() {
    process_logger "fatal" "${@}"
}

function logger_error() {
    process_logger "error" "${@}"
}

function logger_warning() {
    process_logger "warning" "${@}"
}

function logger_info() {
    process_logger "info" "${@}"
}

function logger_debug() {
    process_logger "debug" "${@}"
}
