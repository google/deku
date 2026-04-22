#!/bin/bash

declare -A Tests

addTest()
{
	local name=$1
	local desc=$2
	Tests["$name"]="$desc"
}

prepareTests()
{
	[[ $VM_TEST == "" ]] && addTest relocation "Relocation"
	# [[ $VM_TEST == "" ]] && addTest all_versions "All kernel versions"

	# addTest inline "Inline"
	addTest notraceable "No traceable functions"
	addTest builderror "Build after fixing errors"
	addTest static_global_symbol "Static and Global symbol"
	addTest dissasembly "Dissasembly"
	addTest convert_to_reloc "Convert to relocations"
	addTest detect_object_file "Detect object file"
	addTest multi_files "Multi files"
	addTest unknown_type "Relocate unknown type"
	addTest tracepoint_str "Copy tracepoint_str"
	addTest uncommon_symbol_name "Uncommon symbol name"
	addTest header_files_basic "Basic changes in header file"
	addTest filter_symbols "Filter symbols"
	# Tests on QEMU
	addTest symbol_index "Symbol index"
	addTest global_variables "Global variables"
	addTest no_valid_changes "No valid changes"
	addTest function_call "Function call"
	addTest bug "BUG()"
	addTest string_changed "String changed"
	addTest static_keys "Static keys"
	addTest dependent_changes
	addTest weak_function "Weak function"
	addTest atomic_replace "atomic_replace"
	addTest dependend_module "Dependent module"
	addTest patch
	addTest static_local_variables
	addTest stalled_task
	addTest oot_module

	# Other
	# addTest disassembler_all

	# Tests on Chromebook
	# addTest chromebook "Chromebook"

	# Deprecated tests
	# addTest unload "Unload"
	# addTest modules_order "Modules order"
	# addTest optimisation_cold "Optimisation - Cold"

	# Unknown tests
	# addTest elfsym "ELF symbols"
	# addTest unrelatedchanges "Unrelated changes"
	# addTest symbol_index_ext "Symbol index ext"
	# addTest multiple_func "multiple_func"
	# addTest jmp_cross_referencjump across functions" # need to finish / probably enough in disassembly test that is already checked
	# addTest calls "Callee and caller" # TODO: finish
	# addTest current_task "Current task"
}

function runTests()
{
	local kernelVersions=$@

	# Run tests
	for kernelVersion in $kernelVersions; do
		for test in "${!Tests[@]}"; do
			./test/run.sh --android --kernel $kernelVersion --test $test
			# break
		done
	done
}

main()
{
	# addTest patch
	prepareTests
	runTests 6.12
}

main $@
