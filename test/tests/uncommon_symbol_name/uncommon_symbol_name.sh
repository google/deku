#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test whether symbols with uncommon name are properly handled

FILES="sound/soc/codecs/rt286.c net/devlink/health.c"
DESCRIPTION="Uncommon symbol name"
. test/common.sh

test()
{
	local srcDir=$(sourceDir $KERNEL_VERSION)
	appendToFunction "$srcDir/sound/soc/codecs/rt286.c" "rt286_set_dai_fmt" "WARN_ON(1);"
	[[ -f "$srcDir/net/devlink/health.c" ]] && appendToFunction "$srcDir/net/devlink/health.c" "devlink_health_report" "WARN_ON(1);"
	dekuBuild || exit 1
}

main()
{
	test
}

main $@
