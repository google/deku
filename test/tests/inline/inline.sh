#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test that changes in inline functions are contained in callers functions

FILES="fs/timerfd.c drivers/gpu/drm/i915/display/intel_dvo.c drivers/input/evdev.c"
DESCRIPTION="Inline"
. test/common.sh

inlineTest()
{
	local file=$1
	local functions=$2
	local srcDir=$(sourceDir $KERNEL_VER)

	for function in ${functions//,/ }
	do
		appendToFunction "$srcDir/$file" $function "printk(KERN_INFO \"\");"
	done

	out=$(dekuBuild --log -v) || { echo "$out"; echo "Failed with return code: $res"; exitError 1; }

	shift 2
	local symcnt=$#
	local modlinecnt=`grep "Modified function: " <<< "$out" | wc -l`
	[[ $modlinecnt > $symcnt ]] && { echo "Symbols file for $file contains more symbols than expected ($modlinecnt/$symcnt)"; exitError 2; }
	local foundAll=1
	for sym in "$@"
	do
		if ! grep -q "\bModified function: $sym\b" <<< "$out"; then
			logInfo "Symbol '$sym' not found for $file"
			foundAll=
		fi
	done

	[[ $foundAll != 1 ]] && exitError 3
	logStep "Symbols relocation for $file matches... OK"
}

test()
{
	prepareKernel $KERNEL_VER

	inlineTest "fs/timerfd.c" "timerfd_triggered" timerfd_tmrproc timerfd_alarmproc
	if [[ $KERNEL_VER == v5.10* ]] || [[ $KERNEL_VER == v5.15* ]] || [[ $KERNEL_VER == v6.1.* ]]; then
		inlineTest "drivers/gpu/drm/i915/display/intel_dvo.c" "intel_attached_dvo" intel_dvo_mode_valid intel_dvo_connector_get_hw_state intel_dvo_detect
	else
		inlineTest "drivers/gpu/drm/i915/display/intel_dvo.c" "enc_to_dvo" intel_dvo_mode_valid intel_dvo_connector_get_hw_state intel_enable_dvo intel_dvo_detect intel_dvo_enc_destroy intel_dvo_compute_config intel_disable_dvo
	fi
	if [[ $LOCAL_TEST$VM_TEST$CHROMEOS == "" ]]; then
		prepareKernel v5.4.200
		inlineTest "drivers/input/evdev.c" "evdev_get_mask_cnt,__evdev_is_filtered,evdev_pass_values" evdev_do_ioctl evdev_pass_values evdev_events evdev_event
	fi
}

main()
{
	if [[ $LOCAL_TEST != "" ]]; then
		:
	else
		test
	fi
}

main $@
