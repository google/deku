package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	ui "github.com/webui-dev/go-webui/v2"
)

var w ui.Window
var testStarted = false

func slicesIndex(s []string, v string) int {
	for i := range s {
		if v == s[i] {
			return i
		}
	}
	return -1
}

func slicesContains(s []string, name string) bool {
	return slicesIndex(s, name) != -1
}

func myCountFunc(e ui.Event) any {
	// count, _ := e.Window.Script("return count;", ui.ScriptOptions{})
	// i, _ := strconv.Atoi(count)
	// e.Window.Run(fmt.Sprintf("SetCount(%v);", i+10))
	// e.Window.Run(fmt.Sprintf("SetCount(%s);", "testName"))
	addTests(e.Window)
	return nil
}

type KernelSet struct {
	name    string
	kernels []string
}

var kernelSets = []KernelSet{
	KernelSet{"qemu", []string{"v5.10", "v5.15", "v6.1", "v6.6", "v6.12", "origin/master"}},
	KernelSet{"cros", []string{"v5.10", "v5.15", "v6.1", "v6.6", "v6.12"}},
	KernelSet{"vm-ubuntu", []string{"v6.8", "v6.11"}},
}

var testNames = []string{
	"relocation",
	// "multi_build",
	"inline",
	"notraceable",
	"builderror",
	"static_global_symbol",
	"dissasembly",
	"convert_to_reloc",
	"detect_object_file",
	"multi_files",
	"unknown_type",
	"tracepoint_str",
	"uncommon_symbol_name",
	"header_files_basic",
	"filter_symbols",
	"symbol_index",
	"global_variables",
	"no_valid_changes",
	"function_call",
	"bug",
	"string_changed",
	"static_keys",
	"dependent_changes",
	"weak_function",
	"atomic_replace",
	"dependend_module",
	"patch",
	"static_local_variables",
}

type TestEntity struct {
	name    string
	system  string
	kernel  string
	status  string
	agent   string
	started time.Time
}

var tests = []TestEntity{}
var allAgents = []string{}
var agentsPerSystem = make(map[string][]string)
var scheduledTests = []TestEntity{}

func getSystemForAgent(agent string) string {
	if strings.Contains(agent, "_cros_") {
		return "cros"
		// } else if strings.Contains(agent, "_qemu_") {
		// 	return "qemu"
	} else {
		return "vm-ubuntu"
	}
}

func runTest(agent string) {
	w.Run(fmt.Sprintf("runTest('%s');", agent))
}

func runCountForSystem(system, testName string) int {
	count := 0
	for _, test := range tests {
		if test.system == system && test.name == testName && test.status != "" {
			count++
		}
	}

	return count
}

func findNextTestIndexForSystem(system, kernel string, withMinimalRun bool) int {
	var min = 999999
	var nextTestName = ""

	for _, testName := range testNames {
		c := runCountForSystem(system, testName)
		if c < min {
			min = c
			nextTestName = testName
		}
	}

	for i, test := range tests {
		if (!withMinimalRun || test.name == nextTestName) && test.system == system && test.kernel == kernel && test.status == "" {
			return i
		}
	}

	// for i, test := range tests {
	// 	if test.name == nextTestName && test.system == system && test.status == "" {
	// 		return i
	// 	}
	// }

	return -1
}

func findNextTestIndexFor(agent string) int {
	var min = 999999
	var nextTestName = ""
	systems := []KernelSet{}
	if getSystemForAgent(agent) == "cros" {
		systems = append(systems, kernelSets[1 /*"cros"*/])
	} else {
		systems = append(systems, kernelSets[0 /*"qemu"*/])
		systems = append(systems, kernelSets[2 /*"vm-ubuntu"*/])
	}

	for _, system := range systems {
		var agentIndex = slicesIndex(agentsPerSystem[getSystemForAgent(agent)], agent)
		var agentsCount = 0
		for _, a := range allAgents {
			if getSystemForAgent(a) == getSystemForAgent(agent) {
				agentsCount++
			}
		}
		for i := 0; i < len(system.kernels); i++ {
			index := findNextTestIndexForSystem(system.name, system.kernels[(agentIndex+(i*agentsCount))%len(system.kernels)], true)
			if index != -1 {
				return index
			}
			index = findNextTestIndexForSystem(system.name, system.kernels[(agentIndex+i)%len(system.kernels)], false)
			if index != -1 {
				return index
			}
		}
	}
	return -1

	///////////////////////////////

	for _, testName := range testNames {
		cnt := 0
		for _, test := range tests {
			for _, system := range systems {
				if test.name == testName && test.system == system.name && test.status != "" {
					cnt++
				}
			}
		}

		if cnt < min {
			min = cnt
			nextTestName = testName
		}
	}

	min = 999999
	kernelVer := ""
	for _, system := range systems {
		for _, kernel := range system.kernels {
			cnt := 0
			for _, test := range tests {
				if test.system == system.name && test.kernel == kernel && test.status != "" {
					cnt++
				}
			}
			if cnt < min {
				min = cnt
				kernelVer = kernel
			}
		}
		for i, test := range tests {
			for _, set2 := range systems {
				if test.name == nextTestName && test.system == set2.name && test.kernel == kernelVer && test.status == "" {
					return i
				}
			}
		}
	}

	// for _, testName := range testNames {
	// }

	return -1
}

func setKernelSets(w ui.Window) {
	for _, system := range kernelSets {
		kernels := ""
		for _, kernel := range system.kernels {
			kernels += ", '" + kernel + "'"
		}
		w.Run(fmt.Sprintf("addKernelSet('%s' %s);", system.name, kernels))
	}
}

func addTests(w ui.Window) {
	for _, test := range testNames {
		w.Run(fmt.Sprintf("addTest('%s');", test))
	}
}

func showAgents(w ui.Window) {
	w.Run(fmt.Sprintf("showAgents('%s');", "test"))
}

const TESTS_MAIN_DIR = "/usr/local/google/home/mmaslanka/"

func getAgentFor(dir string) []string {
	agents := []string{}
	err := filepath.Walk(TESTS_MAIN_DIR+"/deku_test/"+dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			fmt.Println(err)
			return err
		}
		if !info.IsDir() {
			agents = append(agents, info.Name())
		}
		return nil
	})
	if err != nil {
		fmt.Println(err)
	}

	return agents
}

func getTestIndexFor(testName, system, kernel string) int {
	for i, test := range tests {
		if test.name == testName && test.system == system && test.kernel == kernel {
			return i
		}
	}

	return -1
}

func getLineFromAgentFile(agentName, state string, index int) string {
	bytes, err := os.ReadFile(TESTS_MAIN_DIR + "/deku_test/" + state + "/" + agentName)
	if err != nil {
		fmt.Println(err)
	}

	content := string(bytes)
	if strings.Contains(content, "\n") {
		fmt.Println("====================" + state + "/" + agentName + "====================")
		fmt.Print(content)
		fmt.Println("=======================================================")
	}
	if len(bytes) > 0 {
		lines := strings.Split(content, "\n")
		if len(lines) >= index {
			return lines[index]
		}
	}

	return ""
}

func getTestIndexFromAgentFile(agentName, state string) int {
	firstLine := getLineFromAgentFile(agentName, state, 0)
	if firstLine == "" {
		return -1
	}

	arr := strings.Split(firstLine, " ")
	testName := arr[1]
	system := arr[3]
	kernel := arr[5]
	return getTestIndexFor(testName, system, kernel)
}

func runTestOnAgent(agent string, index int) {
	test := tests[index]
	agentIndex := slicesIndex(allAgents, agent)
	testParams := fmt.Sprintf("--test %s --system %s --kernel %s --index %d", test.name, test.system, test.kernel, agentIndex)
	if test.system == "qemu" {
		testParams += fmt.Sprintf(" --lts")
	} else if test.system == "cros" {
		testParams += fmt.Sprintf(" --chromebook --port %d", 2244)
	} else if test.system == "vm-ubuntu" {
		testParams += fmt.Sprintf(" --vm --port %d", 22220)
	}

	err := os.WriteFile(TESTS_MAIN_DIR+"/deku_test/job/"+agent, []byte(testParams), 0644)
	if err != nil {
		fmt.Println(err)
	}

	test.status = "Running on " + agent
	tests[index].status = "Running on " + agent
	tests[index].started = time.Now()
	tests[index].agent = agent
	w.Run(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", test.name, test.system, test.kernel, "..."))
}

func scheduleTestOnAgent(e ui.Event) any {
	args, _ := ui.GetArg[string](e)
	agent := strings.Split(args, " ")[0]
	testName := strings.Split(args, " ")[1]
	system := strings.Split(args, " ")[2]
	kernel := strings.Split(args, " ")[3]

	scheduledTests = append(scheduledTests, TestEntity{testName, system, kernel, "", agent, time.Now()})
	return nil
}

func watchForAgents() {
	lastWaitCheckTime := time.Time{}

	for true {
		w.Run(fmt.Sprintf("clearAgents();"))

		doneAgents := getAgentFor("done")
		for _, agent := range doneAgents {
			index := getTestIndexFromAgentFile(agent, "done")
			if index != -1 {
				status := getLineFromAgentFile(agent, "done", 1)
				if status == "0" {
					tests[index].status = "done"
					status = `<div align="center"><img height=22pt src="pngegg.png" /></div>`
				} else {
					tests[index].status = "error: " + status
					status = "error: " + status
				}

				tests[index].started = time.Time{}
				os.Remove(TESTS_MAIN_DIR + "/deku_test/done/" + agent)
				w.Run(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", tests[index].name, tests[index].system, tests[index].kernel, status))
				fmt.Printf("Done job: %s [%s %s]: %s\n", tests[index].name, tests[index].system, tests[index].kernel, tests[index].status)
			}
		}

		text := "Waiting:"
		text += "<br />"
		waitingAgents := getAgentFor("wait")
		if time.Since(lastWaitCheckTime) > 20*time.Second {
			for _, agent := range waitingAgents {
				os.Remove(TESTS_MAIN_DIR + "/deku_test/wait/" + agent)
			}
			lastWaitCheckTime = time.Now()
			if len(waitingAgents) > 0 {
				waitingAgents = []string{}
				continue
			}
		}

		for _, agent := range waitingAgents {
			text += agent

			if slicesIndex(allAgents, agent) == -1 {
				allAgents = append(allAgents, agent)
				agentsPerSystem[getSystemForAgent(agent)] = append(agentsPerSystem[getSystemForAgent(agent)], agent)
			}

			jobAgents := getAgentFor("job")
			if slicesContains(jobAgents, agent) {
				// get time elapsed since the job file was created
				fileInfo, err := os.Stat(TESTS_MAIN_DIR + "/deku_test/job/" + agent)
				if err != nil {
					fmt.Println(err)
					text += "<br />"
					continue
				}

				creationTime := fileInfo.ModTime()
				elapsed := time.Since(creationTime)
				if elapsed > 1*time.Minute {
					fmt.Printf("Found broken job for %s\n", agent)
					os.Remove(TESTS_MAIN_DIR + "/deku_test/wait/" + agent)
					os.Remove(TESTS_MAIN_DIR + "/deku_test/job/" + agent)
					continue
				}

				text += fmt.Sprintf("[%v]", elapsed)
				text += "<br />"
				continue
			}

			text += "<br />"
			w.Run(fmt.Sprintf("addAgent('%s');", agent))

			if len(scheduledTests) > 0 {
				st := scheduledTests[0]
				if st.agent == agent {
					scheduledTests = scheduledTests[1:]
					runTestOnAgent(agent, getTestIndexFor(st.name, st.system, st.kernel))
					continue
				}
			}

			if !testStarted {
				continue
			}

			index := findNextTestIndexFor(agent)
			if index == -1 {
				continue
			}

			runTestOnAgent(agent, index)
		}

		text += "<br />"
		text += "Running:"
		text += "<br />"
		pendingAgents := getAgentFor("pending")
		for _, agent := range pendingAgents {
			text += agent
			w.Run(fmt.Sprintf("addAgent('%s');", agent))

			index := getTestIndexFromAgentFile(agent, "pending")
			if index == -1 {
				fmt.Println("Error to find information about pending job for " + agent)
				text += "<br />"
				continue
			}
			line := getLineFromAgentFile(agent, "pending", 0)
			if line == "" {
				text += "<br />"
				continue
			}
			r := regexp.MustCompile(`.*--test ([^ .]+) --system ([^ .]+) --kernel ([^ ]+)[ $]+.*`)
			params := r.FindStringSubmatch(line)
			text += fmt.Sprintf(" [%s %s %s]", params[1], params[2], params[3])
			text += "<br />"
			test := tests[index]
			status := `<div align="center"><img height=22pt src="running2.png" /></div>`
			w.Run(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", test.name, test.system, test.kernel, status))
		}

		for _, test := range tests {
			if !test.started.IsZero() && time.Now().After(test.started.Add(20*time.Minute)) {
				if slicesContains(pendingAgents, test.agent) {
					fmt.Println("Found stalled test", test)
					w.Run(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", test.name, test.system, test.kernel, "Broken agent"))
					test.agent = ""
				}
			}
		}

		w.Run(fmt.Sprintf("showAgents('%s');", text))
		time.Sleep(time.Second / 4)
	}
}

func startTests(e ui.Event) any {
	text := "Start tests"
	testStarted = !testStarted
	if testStarted {
		text = "Stop tests"
	}
	w.Run(fmt.Sprintf("document.getElementById('StartButton').innerHTML = '%s';", text))
	return nil
}

func events(e ui.Event) any {
	if e.EventType == ui.Connected {
		setKernelSets(e.Window)
		addTests(e.Window)
		go watchForAgents()
	}

	return nil
}

func initTests() {
	for _, testName := range testNames {
		for _, system := range kernelSets {
			for _, kernel := range system.kernels {
				tests = append(tests, TestEntity{testName, system.name, kernel, "", "", time.Time{}})
			}
		}
	}
}

func main() {
	initTests()

	w = ui.NewWindow()
	w.Bind("StartButton", startTests)
	ui.Bind(w, "scheduleTestOnAgent", scheduleTestOnAgent)
	w.Show("index.html")
	w.Bind("", events)
	ui.Wait()
}
