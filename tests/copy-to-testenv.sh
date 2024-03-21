#!/usr/bin/bash
#shellcheck shell=bash

SCRIPT_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
declare -r SCRIPT_PATH
scp -r "${SCRIPT_PATH}"/../..//MigrateCloudOS X64-oc8-root:~/

# clear; bash -x ~/MigrateCloudOS/migrate-opencloudos.sh -uV 2>&1 | tee ~/upgrade.log
# clear; bash -x ~/MigrateCloudOS/migrate-opencloudos.sh -uU 2>&1 | tee ~/upgrade.log
# clear; bash -x ~/MigrateCloudOS/migrate-opencloudos.sh -u 2>&1 | tee ~/upgrade.log
