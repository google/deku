#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku
#
# Test if all callers are properly detected

. test/common.sh

main()
{
	MAIN_PATH=`dirname "$0"`

	#TODO: Check if i915_gem_object_lock is called by i915_vm_lock_objects
	#TODO: Check if i915_vm_lock_objects is calls i915_gem_object_lock
}

main $@
