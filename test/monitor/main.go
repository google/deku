package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	ui "github.com/webui-dev/go-webui/v2"
)

type Agent struct {
	name          string
	lastTestIndex int
	index         int
}

type TestEntity struct {
	name    string
	system  string
	kernel  string
	status  string
	agent   *Agent
	started time.Time
}

var (
	w             ui.Window
	testStarted   = false
	activeSystems = []string{}
	mutex         sync.Mutex

	tests           = []TestEntity{}
	allAgents       = []Agent{}
	agentsPerSystem = make(map[string][]string)
	scheduledTests  = []TestEntity{}
)

type KernelSet struct {
	name    string
	kernels []string
}

var kernelSets = []KernelSet{
	KernelSet{"qemu", []string{"v5.10", "v5.15", "v6.1", "v6.6", "v6.12", "origin/master"}},
	KernelSet{"cros", []string{"v5.10", "v5.15", "v6.1", "v6.6", "v6.12"}},
	KernelSet{"vm-ubuntu", []string{"v6.8", "v6.11", "v6.14"}},
	KernelSet{"android", []string{"v6.12"}},
}

var testNames = []string{
	"relocation",
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
	"stalled_task",
	"oot_module",
}

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

func runJS(cmd string) {
	mutex.Lock()
	defer mutex.Unlock()
	w.Run(cmd)
}

func getKernelSet(system string) KernelSet {
	for _, set := range kernelSets {
		if set.name == system {
			return set
		}
	}
	return KernelSet{}
}

func getSystemForAgent(agent string) string {
	if strings.Contains(agent, "_cros_") {
		return "cros"
		// } else if strings.Contains(agent, "_qemu_") {
		// 	return "qemu"
	} else {
		return "vm-ubuntu"
	}
}

func getAgentByName(name string) *Agent {
	for i, agent := range allAgents {
		if agent.name == name {
			return &allAgents[i]
		}
	}
	return nil
}

func runTest(agent string) {
	runJS(fmt.Sprintf("runTest('%s');", agent))
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
		systems = append(systems, getKernelSet("cros"))
	} else {
		systems = append(systems, getKernelSet("qemu"))
		systems = append(systems, getKernelSet("vm-ubuntu"))
		systems = append(systems, getKernelSet("android"))
	}

	for _, system := range systems {
		if slicesIndex(activeSystems, system.name) == -1 {
			continue
		}

		var agentIndex = slicesIndex(agentsPerSystem[getSystemForAgent(agent)], agent)
		var agentsCount = 0
		for _, a := range allAgents {
			if getSystemForAgent(a.name) == getSystemForAgent(agent) {
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
		if system.name != "android" {
			activeSystems = append(activeSystems, system.name)
		}
		kernels := ""
		for _, kernel := range system.kernels {
			kernels += ", '" + kernel + "'"
		}
		runJS(fmt.Sprintf("addKernelSet('%s' %s);", system.name, kernels))
	}
}

func addTests(w ui.Window) {
	for _, test := range testNames {
		runJS(fmt.Sprintf("addTest('%s');", test))
	}
}

func showAgents(w ui.Window) {
	runJS(fmt.Sprintf("showAgents('%s');", "test"))
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

func runTestOnAgent(agent string, index int, rerun bool) {
	test := tests[index]
	rerunParam := ""
	if rerun {
		rerunParam = "--rerun"
	}
	ag := getAgentByName(agent)
	testParams := fmt.Sprintf("--test %s --system %s --kernel %s --index %d %s", test.name, test.system, test.kernel, ag.index, rerunParam)
	if test.system == "qemu" {
		testParams += fmt.Sprintf(" --lts")
	} else if test.system == "cros" {
		testParams += fmt.Sprintf(" --chromebook --port %d", 2244)
	} else if test.system == "vm-ubuntu" {
		testParams += fmt.Sprintf(" --vm --port %d", 22220)
	} else if test.system == "android" {
		// testParams += fmt.Sprintf("")
	}

	err := os.WriteFile(TESTS_MAIN_DIR+"/deku_test/job/"+agent, []byte(testParams), 0644)
	if err != nil {
		fmt.Println(err)
	}

	test.status = "Running on " + agent
	tests[index].status = "Running on " + agent
	tests[index].started = time.Now()
	tests[index].agent = ag
	ag.lastTestIndex = index
	runJS(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", test.name, test.system, test.kernel, "..."))
}

func scheduleTestOnAgent(e ui.Event) any {
	args, _ := ui.GetArg[string](e)
	agent := strings.Split(args, " ")[0]
	testName := strings.Split(args, " ")[1]
	system := strings.Split(args, " ")[2]
	kernel := strings.Split(args, " ")[3]
	priority := strings.Split(args, " ")[4]

	if testName == "*" && priority == "low" {
		kernelSet := getKernelSet(system)
		for _, ker := range kernelSet.kernels {
			if kernel != ker {
				continue
			}
			for _, testName := range testNames {
				scheduledTests = append(scheduledTests, TestEntity{testName, system, kernel, "", nil, time.Now()})
			}
		}
	} else {
		test := TestEntity{testName, system, kernel, "", getAgentByName(agent), time.Now()}
		if priority == "high" {
			scheduledTests = append([]TestEntity{test}, scheduledTests...)
		} else {
			scheduledTests = append(scheduledTests, test)
		}
	}
	return nil
}

func reRunTest(e ui.Event) any {
	args, _ := ui.GetArg[string](e)
	agent := strings.Split(args, " ")[0]
	if agent == "sdsd" {

		runTestOnAgent(agent, getAgentByName(agent).lastTestIndex, true)
	}
	return nil
}

//lint:ignore U1000 it's used in the UI
func filteredSystemToRunTests(e ui.Event) any {
	args, _ := ui.GetArg[string](e)
	activeSystems = strings.Split(args, " ")
	return nil
}

func setSuccessTestStatus(e ui.Event) any {
	args, _ := ui.GetArg[string](e)
	testState, _ := strconv.Atoi(strings.Split(args, " ")[1])
	testIndex, _ := strconv.Atoi(strings.Split(args, " ")[0])
	fmt.Println("Set success test status", testIndex, testState)
	return nil
}

func watchForAgents() {
	lastWaitCheckTime := time.Time{}

	for {
		runJS("clearAgents();")

		doneAgents := getAgentFor("done")
		for _, agent := range doneAgents {
			index := getTestIndexFromAgentFile(agent, "done")
			if index != -1 {
				status := getLineFromAgentFile(agent, "done", 1)
				if status == "0" {
					tests[index].status = "done"
					status = `<div align="center"><img class="testStatusSuccess" id="testSuccess_` + strconv.Itoa(index) + `" height=22pt src="successful.png" /></div>`
				} else {
					tests[index].status = "error: " + status
					status = "error: " + status
				}

				tests[index].started = time.Time{}
				os.Remove(TESTS_MAIN_DIR + "/deku_test/done/" + agent)
				runJS(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", tests[index].name, tests[index].system, tests[index].kernel, status))
				fmt.Printf("Done job: %s [%s %s]: %s\n", tests[index].name, tests[index].system, tests[index].kernel, tests[index].status)
			}
		}

		agentsStatusText := ""
		waitingAgents := getAgentFor("wait")
		if time.Since(lastWaitCheckTime) > 20*time.Second {
			for _, agent := range waitingAgents {
				os.Remove(TESTS_MAIN_DIR + "/deku_test/wait/" + agent)
			}
			lastWaitCheckTime = time.Now()
			if len(waitingAgents) > 0 {
				continue
			}
		}

		for _, agent := range waitingAgents {
			agentsStatusText += "<div class=\"agentStatusText\">[Waiting] " + agent

			if getAgentByName(agent) == nil {
				allAgents = append(allAgents, Agent{agent, -1, len(allAgents)})
				agentsPerSystem[getSystemForAgent(agent)] = append(agentsPerSystem[getSystemForAgent(agent)], agent)
			}
			ag := getAgentByName(agent)
			if ag.lastTestIndex != -1 {
				test := tests[ag.lastTestIndex]
				agentsStatusText += fmt.Sprintf(`<span class="reRunLastTest" onclick=\'runTestOnAgent("%s", "%s", "%s", "%s", true)\' title="Run %s"></span>`, agent, test.name, test.system, test.kernel, test.name)
			}

			jobAgents := getAgentFor("job")
			if slicesContains(jobAgents, agent) {
				// get time elapsed since the job file was created
				fileInfo, err := os.Stat(TESTS_MAIN_DIR + "/deku_test/job/" + agent)
				if err != nil {
					fmt.Println(err)
					agentsStatusText += "</div>"
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

				agentsStatusText += fmt.Sprintf(" [%v]", elapsed)
				agentsStatusText += "</div>"
				continue
			}

			agentsStatusText += "</div>"
			runJS(fmt.Sprintf("addAgent('%s');", agent))

			if len(scheduledTests) > 0 {
				st := scheduledTests[0]
				if st.agent == nil /*&& getSystemForAgent(agent) == st.system*/ {
					if st.system == "cros" {
						if strings.Contains(agent, "cros") {
							st.agent = ag
						}
					} else {
						if !strings.Contains(agent, "cros") {
							st.agent = ag
						}
					}
				}
				if st.agent.name == agent {
					scheduledTests = scheduledTests[1:]
					runTestOnAgent(agent, getTestIndexFor(st.name, st.system, st.kernel), true)
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

			runTestOnAgent(agent, index, false)
		}

		pendingAgents := getAgentFor("pending")
		for _, agent := range pendingAgents {
			agentsStatusText += "<div class=\"agentStatusText\">[Running] " + agent
			runJS(fmt.Sprintf("addAgent('%s');", agent))

			index := getTestIndexFromAgentFile(agent, "pending")
			if index == -1 {
				fmt.Println("Error to find information about pending job for " + agent)
				agentsStatusText += "</div>"
				continue
			}
			line := getLineFromAgentFile(agent, "pending", 0)
			if line == "" {
				agentsStatusText += "</div>"
				continue
			}
			r := regexp.MustCompile(`.*--test ([^ .]+) --system ([^ .]+) --kernel ([^ ]+)[ $]+.*`)
			params := r.FindStringSubmatch(line)
			agentsStatusText += fmt.Sprintf(" [%s %s %s]", params[1], params[2], params[3])
			agentsStatusText += "</div>"
			test := tests[index]
			status := `<div align="center"><img height=22pt src="running2.png" /></div>`
			runJS(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", test.name, test.system, test.kernel, status))
		}

		for _, test := range tests {
			if !test.started.IsZero() && time.Now().After(test.started.Add(20*time.Minute)) {
				if slicesContains(pendingAgents, test.agent.name) {
					fmt.Println("Found stalled test", test)
					runJS(fmt.Sprintf("setTestStatus('%s', '%s', '%s', '%s');", test.name, test.system, test.kernel, "Broken agent"))
					test.agent = nil
				}
			}
		}

		runJS(fmt.Sprintf("showAgents('%s');", agentsStatusText))
		time.Sleep(time.Second / 4)
	}
}

func startTests(e ui.Event) any {
	text := "Start tests"
	testStarted = !testStarted
	if testStarted {
		text = "Stop tests"

		for i, test := range tests {
			if strings.HasPrefix(test.status, "error:") {
				tests[i].status = ""
			}
		}
	}
	runJS(fmt.Sprintf("document.getElementById('StartButton').innerHTML = '%s';", text))
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
				tests = append(tests, TestEntity{testName, system.name, kernel, "", nil, time.Time{}})
			}
		}
	}
}

func main() {
	initTests()

	// ui.setLogging(true)
	w = ui.NewWindow()
	w.Bind("", events)
	w.Bind("StartButton", startTests)
	ui.Bind(w, "scheduleTestOnAgent", scheduleTestOnAgent)
	ui.Bind(w, "filteredSystemToRunTests", filteredSystemToRunTests)
	ui.Bind(w, "setSuccessTestStatus", setSuccessTestStatus)
	ui.Bind(w, "reRunTest", reRunTest)
	w.ShowBrowser("index.html", ui.ChromiumBased)
	ui.Wait()
}
