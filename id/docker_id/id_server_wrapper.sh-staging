set -o pipefail
set -u

#set -x

PYTHON=python3
COVERAGE="coverage run"
PYTEST=pytest

mode=
MONGO_PORT_ARGS=
mongo_ip_port=
LOG_DIR=../id_logs
progname=$(basename $0)

usage()
{
    cat <<USAGE
Usage: $progname -mode {oper|test} --mongo-ip-port <port>
Description:
	Run id server, as appropriate for mode
USAGE

    exit $1
}

# extract pid for supplied tag
# tag is of form "[p]olicy_server" rather than just "policy_server"
# so grep command does not find itself.
get_pid()
{
    ps_tag=$1
    pid=$(ps aux | grep "/$ps_tag" | awk '{ print $2 }')
    echo $pid
}

while [ $# != 0 ]; do
    case $1 in
    -mode)
	shift
	mode=$1
	;;
    --mongo-ip-port)
	shift
	mongo_ip_port=$1
	;;
    *)
	echo "$progname: FATAL: Unknown argument ($1)" >&2
	exit 1
	;;
    esac
    shift
done

case "$mode" in
oper)
    # valid mode
    ;;
test)
    # valid mode
    ;;
"")
    echo "$progname: FATAL: mode not specified" >&2
    usage 1
    ;;
*)
    echo "$progname: FATAL: Unknown mode ($mode)" >&2
    usage 1
    ;;
esac

if [ -n "$mongo_ip_port"  ]; then
    MONGO_PORT_ARGS="--mongo-ip-port $mongo_ip_port"
fi

case $mode in
oper)
    echo "************  EXECUTING ID SERVICE ************"
    ${PYTHON} ./id_service/id_server.py \
	    $MONGO_PORT_ARGS \
	    --console-log-level info \
	    --log-dir $LOG_DIR &
    ;;
test)
    echo " ==========  PRETEST CLEANING =========="
    rm -rf coverage_html_report
    coverage erase
    ID_PID=$(get_pid "[i]d_server.py")
    if [ ! -z "$ID_PID" ]; then
       echo "ERROR: server(s) already running: id_pid: ${ID_PID:-none}"
       exit 1
    fi
    echo "************  EXECUTING ID SERVICE WITH COVERAGE ************"
    ${COVERAGE} ./id_service/id_server.py \
	    --test \
	    $MONGO_PORT_ARGS \
	    --log-dir $LOG_DIR &
    ;;
esac



case $mode in
oper)
    # for oper, this script is the primary job: leave script active until
    # servers exit, otherwise docker container will exit
    wait
    ;;
test)
    # for test, this script exits to allow pytest to run
    sleep 2
    ${PYTEST} tests
    pytest_res=$?
    ID_PID=$(get_pid "[i]d_server.py")
    echo "************  CLEANING UP SERVICES (ID_PID:${ID_PID}) ************"
    # use kill -2 on module-under-test to collect coverage information
    if [ $pytest_res = 0 ]; then
	echo "************  TESTS PASSED: COLLECTING COVERAGE ************"
	ps_sig=2 # if tests succeeded, generate coverate
    else
	echo "************  TESTS FAILED: SKIPPING COVERAGE ************"
	ps_sig=9
    fi
    kill -$ps_sig ${ID_PID}
    if [ $pytest_res = 0 ]; then
	sleep 1
	coverage report
	coverage html
    fi
    exit $pytest_res
    ;;
esac
