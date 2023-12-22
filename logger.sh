#!/usr/bin/bash
#shellcheck shell=bash

function _logger_out() {
    local -i color_code=$1
    shift 1
    printf '\e[48;5;%dm%s\e[0m \n' "${color_code}" "${@}"
}

function logger_ok() {
    logger_out 2 "${@}"
}

function logger_critical() {
    logger_out 160 "${@}"
}

function logger_error() {
    logger_out 1 "${@}"
}

function logger_warning() {
    logger_out 9 "${@}"
}

function logger_info() {
    logger_out 5 "${@}"
}

function logger_debug() {
    logger_out 195 "${@}"
}
