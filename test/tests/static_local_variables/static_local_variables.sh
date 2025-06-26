#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Check if variables with format "VAR_NAME.%d" are properly mapped.

FILES="net/ipv4/tcp_ipv4.c"
DESCRIPTION="Static local variables"
. test/common.sh

mappingTest()
{
	local file="net/ipv4/tcp_ipv4.c"
	local text="[$SCRIPT_NAME] DEKU %s"
	local srcDir=$(sourceDir $KERNEL_VER)
	local functions=(tcp_v4_init_seq tcp_v4_connect __tcp_v4_send_check tcp_v4_send_check tcp_v4_send_ack)
	local functions2=(tcp_v4_connect tcp_v4_mtu_reduced do_redirect tcp_ld_RTO_revert tcp_v4_err tcp_v4_send_reset tcp_v4_send_ack tcp_v4_timewait_ack tcp_v4_reqsk_send_ack tcp_v4_inbound_md5_hash tcp_v4_init_req tcp_v4_route_req tcp_v4_conn_request tcp_v4_syn_recv_sock)
	local functionsFun=(tcp_v4_init_seq tcp_v4_init_ts_off tcp_twsk_unique tcp_v4_pre_connect tcp_v4_init_seq tcp_v4_connect __tcp_v4_send_check tcp_v4_send_check tcp_v4_inbound_md5_hash  tcp_v4_send_synack tcp_v4_reqsk_destructor)

	logStep "Check mapping ambiguous symbol..."

	appendBeforeFunction "$srcDir/$file" tcp_v4_init_seq "static inline int deku_static_test_function(void){static int deku_static_test_var;return deku_static_test_var+=2;}" > /dev/null

	for (( i=0; i<${#functions[@]}; i++ )); do
		appendToFunction "$srcDir/$file" ${functions[$i]} "printk(KERN_INFO \"$text/${functions[$i]} - func:%d\", __func__, deku_static_test_function());" > /dev/null
	done

	# for fun in ${functionsFun[*]}; do
	# 	appendToFunction "$srcDir/$file" $fun "printk(KERN_INFO \"$text/$fun\", __func__);" > /dev/null
	# done

	buildKernel || exitError 1
	runQemu

	for (( i=0; i<${#functions[@]}; i++ )); do
		appendToFunction "$srcDir/$file" ${functions[$i]} "static int deku_static_test_var=1; printk(KERN_INFO \"$text/${functions[$i]} - func:%d - var:%d\", __func__, deku_static_test_function(), deku_static_test_var+=2);" > /dev/null
	done

	# for fun in ${functions2[*]}; do
	# 	appendToFunction "$srcDir/$file" $fun "printk(KERN_INFO \"$text/$fun X\", __func__);" > /dev/null
	# done

	out=$(dekuDeploy --log -v) || { logErr "Fail"; exitError 2; }
	grep -qF "Ambiguous symbol " <<< "$out" || { logErr "Fail"; exitError 3; }
	grep -qF "Swap deku_static_test_var." <<< "$out" || { logErr "Fail"; exitError 4; }

	readelf -s -W "$WORKDIR/patch_e9fa88a1_tcp_ipv4/tcp_ipv4.o" >> $LOG_FILE

	remoteSh wget -q --spider google.com

	local lastVal=
	while read -r line
	do
		if grep -qF " - var:" <<< "$line"; then
			local valAfterUpdate=$(sed -nr 's/^.+ - func:(.+) - var:.+/\1/p' <<< "$line")
			[[ $((lastVal+2)) != $valAfterUpdate ]] && { logErr "Value after update is invalid $((lastVal+2)) != $valAfterUpdate"; exitError 5; }
			break
		fi
		lastVal=$(sed -n -e 's/^.* - func://p' <<< "$line")
	done < <(remoteShOut 'dmesg | grep -F DEKU')

	logInfo "OK"

	logStep "Check mapping __func__ macro..."
	# TODO:
}

test()
{
	mappingTest
}

main()
{
	[[ $KERNEL_VER == v5.10 ]] && return;
	[[ $KERNEL_VER == v5.15 ]] && return;
	[[ $KERNEL_VER == v6.1 ]] && return;
	[[ $KERNEL_VER == v6.6 ]] && return;
	[[ $KERNEL_VER == v6.12 ]] && return;
	[[ $KERNEL_VER == upstream ]] && return;

	if [[ $LOCAL_TEST != "" ]]; then
		:
	else
		test
	fi
}

main $@
