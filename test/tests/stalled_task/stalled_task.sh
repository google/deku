#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test detection of stalled kernel task name that prevent form applying changes.

FILES="mm/oom_kill.c"
DESCRIPTION="Stalled task"
. test/common.sh

stalledTaskTest()
{
	local srcDir=$(sourceDir $KERNEL_VER)

	logStep -n "Check if stalled task is properly detected... "
	sed -i "s/oom_reap_task(tsk);/{oom_reap_task(tsk);pr_info(\"\");}/g" "$srcDir/mm/oom_kill.c"

	remoteSh "for i in \$(seq 2 \$(nproc)); do echo 0 | sudo tee /sys/devices/system/cpu/cpu\$((i-1))/online > /dev/null; done"
	out=$(dekuDeploy --log) && { logErr "Fail"; exitError 1; }

	grep -q "The oom_reaper \[PID: [0-9][0-9]*\] blocks the application of changes" <<< "$out" || { logErr "Fail"; exitError 2; }
	grep -q "^Failed to apply changes\b" <<< "$out" || { logErr "Fail"; exitError 3; }

	logStep "OK"
}

test()
{
	stalledTaskTest
}

main()
{
	test
}

main $@
