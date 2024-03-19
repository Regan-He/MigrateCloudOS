#!/usr/bin/bash
#shellcheck shell=bash

scp -r /data/sourcecode/github/regan-he/MigrateCloudOS X64-oc8-root:~/

# clear; bash -x ~/MigrateCloudOS/migrate-cloudos.sh -uV 2>&1 | tee ~/upgrade.log
