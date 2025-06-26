
// let count = document.getElementById("count").innerHTML;
var kernels = new Map();
var kernelsSetNames = [];
var agents = [];
const last = "w";
// webui.setLogging(true);
console.log("sss");

function addKernelSet(name, ...versions)
{
	kernels[name] = versions;
	kernelsSetNames.push(name);
	const headRow = document.getElementById("zz");
	const kernelCell = headRow.insertCell();
	kernelCell.outerHTML = '<th colspan='+versions.length+'>' + name + '</th>';

	const headRowV = document.getElementById("kernelVersions");
	for (let i = 0; i < versions.length; i++) {
		const kernelCellV = headRowV.insertCell();
		let text = versions[i];
		if (!text.startsWith("v"))
			text = "v6.x"
		kernelCellV.outerHTML = '<th>' + text + '</th>';
	}
}

function showAgents(text)
{
	document.getElementById("agents").innerHTML = text;
}

function addAgent(agent)
{
	agents.push(agent);
}

function clearAgents()
{
	agents = [];
}

function addTest(testName)
{
	const table = document.querySelector('tbody');
	const newRow = table.insertRow();
	const teamCell = newRow.insertCell();
	teamCell.outerHTML = '<th class="tableStickLeftColumn">' + testName + '</th>';
	for (let i = 0; i < kernelsSetNames.length; i++) {
		let systemName = kernelsSetNames[i];
		for (let j = 0; j < kernels[systemName].length; j++) {
			const cell = newRow.insertCell();
			let id = testName+"_"+ systemName+"_"+kernels[systemName][j]
			cell.innerHTML = "<div style='display:flex'><span style='flex-grow: 1' id='" + id + "'>&nbsp;</span><div class='cellMenu'></div></div>";
			// display sample vertical menu on click on the element with class "cellMenu".
			// This menu will disappear after click on outside of menu.
			// The menu is display as a separate layer on top of everything.
			// Each item in menu have an hover effect.
			// On click on item the "runTest" function is called.
			cell.querySelector('.cellMenu').addEventListener('click', function(event) {
				event.stopPropagation();
				let menu = document.createElement('div');
				menu.className = 'testMenu';
				menu.style.zIndex = 1000;
				let rect = cell.getBoundingClientRect();
				menu.style.left = rect.left + 'px';
				menu.style.top = rect.bottom + 'px';

				copyAgents = agents;
				for (let i = 0; i < copyAgents.length; i++) {
					let item = document.createElement('div');
					item.textContent = 'Run on ' + copyAgents[i];
					item.className = 'testMenuItem';
					item.addEventListener('click', function() {
						runTestOnAgent(copyAgents[i], testName, systemName, kernels[systemName][j]);
						document.body.removeChild(menu);
					});
					menu.appendChild(item);
				}

				let item2 = document.createElement('div');
				item2.textContent = 'Cancel';
				item2.className = 'testMenuItem';
				item2.addEventListener('click', function() {
					document.body.removeChild(menu);
				});
				menu.appendChild(item2);

				document.body.appendChild(menu);

				document.addEventListener('click', function(e) {
					if (!menu.contains(e.target)) {
						document.body.removeChild(menu);
					}
				}, { once: true });
			});

		}
	}
}

function setTestStatus(test, system, kernel, status)
{
	let id = test+"_"+ system+"_"+kernel
	const elem = document.getElementById(id);
	elem.innerHTML = status;
}

function SetCount(number)
{
	document.getElementById("count").innerHTML = number;
	// count = number;
	// add new row to table
	const table = document.querySelector('table');
	const newRow = table.insertRow();
	const teamCell = newRow.insertCell();
	// make teamCell as a "th"
	teamCell.outerHTML = '<th>' +"Teams " + number + '</th>';
	for (let i = 0; i < 10; i++) {
		const cell = newRow.insertCell();
		cell.textContent = Math.floor(Math.random() * 5);
	}
}