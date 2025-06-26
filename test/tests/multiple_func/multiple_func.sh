#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# A test case for a modified file that is built-in to vmlinux, and the klp
# relocation points to a non-exported function that is present in vmlinux and
# the module. Check if klp relocatoin points to function from vmlinux.
#
# Note: Seems it only work on chromeos

FILES="net/ipv6/netfilter/nf_tproxy_ipv6.c net/sunrpc/svcsock.c"
DESCRIPTION="multiple_func"
. test/common.sh

test()
{
	local text="pr_info(\"test\");"

	prepareKernel $KERNEL_VER +CONFIG_NF_SOCKET_IPV6 +CONFIG_NF_TPROXY_IPV6

	git -C "$SOURCE_DIR" apply "`pwd`/$MAIN_PATH/5_10/test.patch" 2>/dev/null

	dekuBuild || exit 1

	# look for: local_bh_enable
	# look for: skb_gro_incr_csum_unnecessary in net/ipv4/udp_offload.c and net/ipv6/udp_offload.c
	# error code ERROR_UNSUPPORTED_REF_SYM_FROM_MODULE
}

main()
{
	MAIN_PATH=`dirname "$0"`

	test
}

main $@
