#!/bin/bash
# Author: Marek Maślanka
# Project: DEKU
# URL: https://github.com/MarekMaslanka/deku

MAIN_DIR=$HOME/ct
Id=$(hostname)

logDebug()
{
	[[ "$LOG_LEVEL" > 0 ]] && return
	echo "[DEBUG] $@"
}

logInfo()
{
	if [[ $1 == "-e" ]]; then
		shift 1
		echo -e "$@"
	else
		echo "$@"
	fi
}
export -f logInfo

logWarn()
{
	echo -e "$ORANGE$@$NC"
}

logErr()
{
	echo -e "$RED$@$NC" >&2
}

runJob()
{
	local timeout=60
	local command_to_run="$@"
	local timeouted=

	# Start the command in the background and capture its PID
	$command_to_run &
	pid=$!
	local exit_code=$? #capture exit code before the background process becomes detached.

	# Create a named pipe (FIFO) to capture stdout and stderr
	local fifo=$(mktemp -u)
	mkfifo "$fifo"

	# Redirect the command's output to the FIFO
	exec {stdout_fd}<> "$fifo"
	exec {stderr_fd}>&"$stdout_fd"

	# Monitor the FIFO
	local last_output_time=$(date +%s)
	while kill -0 "$pid" 2>/dev/null; do #check if process still exists.
		if read -r -t 1 line <&"$stdout_fd"; then
			last_output_time=$(date +%s)
			[[ $line == "Building the kernel..." ]] && timeout=15 || timeout=8
			[[ $line == "Building the kernel..." ]] && "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
			# echo "+$line+" # Optional: print the output
			echo zzzzzzzz
		else
			local current_time=$(date +%s)
			local elapsed=$((current_time - last_output_time))
			echo "TIMEOUT: $timeout"

			if [[ $elapsed -ge $timeout ]]; then
				echo "Timeout reached. Killing process $pid"
				kill "$pid" 2>/dev/null # Ignore "no such process" error
				timeouted=1
				break
			fi
		fi
	done

	rm -f "$fifo"
	wait "$pid"
	exit_code=$?
	[[ $timeouted != "" ]] && exit_code=254

	return $exit_code
}

waitForJob()
{
	while true; do
		[ ! -f "$MAIN_DIR/wait/$Id" ] && touch $MAIN_DIR/wait/$Id
		if [ -f "$MAIN_DIR/job/$Id" ]; then
			local params=$(<$MAIN_DIR/job/$Id)
			[[ $params != *--test* ]] && logErr "No test parameter" && return 1
			[[ $params != *--system* ]] && logErr "No system parameter" && return 1
			[[ $params != *--kernel* ]] && logErr "No kernel parameter" && return 1
			rm $MAIN_DIR/wait/$Id
			mv $MAIN_DIR/job/$Id $MAIN_DIR/pending/
			echo "Job parameters: $params"

			# measure execution time of run.sh
			start=$(date +%s%N)
			./test/run.sh $params --continue
			rc=$?
			end=$(date +%s%N)
			runtime=$(( (end - start) / 1000000000 ))

			echo -e "$params\n$rc\n$runtime\n" > $MAIN_DIR/done/$Id
			rm $MAIN_DIR/pending/$Id
			# echo -e "\033[1;37m===============================================================\033[0m"
			blue=$(tput setaf 4)
			normal=$(tput sgr0)
			printf "${blue}%*s${normal}" "${COLUMNS:-$(tput cols)}" '' | tr ' ' /
			break
		fi
		sleep 1
	done
}

main()
{
	tput 2>/dev/null || export TERM=xterm

	if [[ $CROS_WORKON_SRCROOT != "" ]]; then
		Id+=_cros
		MAIN_DIR=$HOME/chromiumos/ct/
		[ ! -s $HOME/chromiumos/id ] && echo "No ID file" && exit 1
		Id+=_$(<$HOME/chromiumos/id)
	else
		[ ! -e $HOME/ct ] && MAIN_DIR=$HOME
	fi

	# check if MAIN_DIR is empty if so then exit with error
	find $MAIN_DIR -mindepth 1 -maxdepth 1 | read || { \
		echo "$MAIN_DIR is empty"; \
		exit 1; \
	}

	MAIN_DIR+=/deku_test/

	# add current PID to /tmp/deku_test_pid file
	# echo $$ >> /tmp/deku_test_pid
	# check of how many other instances of current script is running concurrently
	local count=$(pgrep -f $(basename "$0") | wc -l)
	Id+=_$((count-1))

	logInfo "Agent: $Id"
	trap "rm -f $MAIN_DIR/wait/$Id" EXIT
	trap "rm -f $MAIN_DIR/pending/$Id" EXIT
	while true; do
		waitForJob || sleep 2
	done
}

main @
