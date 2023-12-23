#!/usr/bin/bash
#shellcheck shell=bash

declare -A logger_color
logger_color["OK"]=2
logger_color["FATAL"]=160
logger_color["ERROR"]=1
logger_color["WARNING"]=9
logger_color["INFO"]=5
logger_color["DEBUG"]=195
declare -rA logger_color

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
