#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test wif notrace function can be patched by patching parent functions

FILES=""
DESCRIPTION=""
. test/common.sh

main()
{
	# TODO: modify __devm_ioremap_resource in devres and check if
	# devm_ioremap_resource and devm_ioremap_resource_wc are marked as modified
	MAIN_PATH=`dirname "$0"`
}

main $@
