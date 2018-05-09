#!/bin/bash
set -x
export test_set=${test_set:-"-I 1,5"}

export script_dir="$(dirname $(readlink -f $0))"

. ${script_dir}/set_env_local.sh
#${script_dir}/start_multiple_mariadb.sh

#ctest ${test_set} -VV
set +x
