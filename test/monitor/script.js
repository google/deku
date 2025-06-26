
// let count = document.getElementById("count").innerHTML;
var kernels = new Map();
var kernelsSetNames = [];
var agents = [];
const last = "w";
// webui.setLogging(true);
console.log("sss");

function addCellMenu(cell, testName, systemName, kernel, querySelector=".cellMenu")
{
	// display sample vertical menu on click on the element with class "cellMenu".
	// This menu will disappear after click on outside of menu.
	// The menu is display as a separate layer on top of everything.
	// Each item in menu have an hover effect.
	// On click on item the "runTest" function is called.
	cell.querySelector(querySelector).addEventListener('click', function(event) {
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
				runTestOnAgent(copyAgents[i], testName, systemName, kernel);
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

function addKernelSet(name, ...versions)
{
	kernels[name] = versions;
	kernelsSetNames.push(name);
	const headRow = document.getElementById("zz");
	const kernelCell = headRow.insertCell();
	kernelCell.outerHTML = '<th class="za" colspan='+versions.length+'><div style="display:flex"><div style="flex-grow: 1">' + name + '</div><div id="cellMenu_'+name+'" class="cellMenu"></div></div></th>';
	addCellMenu(headRow, "*", name, "*", '#cellMenu_'+name);

	const headRowV = document.getElementById("kernelVersions");
	for (let i = 0; i < versions.length; i++) {
		const kernelCellV = headRowV.insertCell();
		let text = versions[i];
		if (!text.startsWith("v"))
			text = "v6.x"
		kernelCellV.innerHTML = '<th><div style="display:flex"><div style="flex-grow: 1">' + text + '</div><div class="cellMenu"></div></div></th>';
		addCellMenu(kernelCellV, "testName2", "systemName2", "kernels2[systemName][j]");
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
	const testRow = table.insertRow();
	const testNameCell = testRow.insertCell();
	testNameCell.innerHTML = '<th class="tableStickLeftColumn"><div style="display:flex"><div style="flex-grow: 1">' + testName + '</div><div class="cellMenu"></div></div></th>';
	addCellMenu(testNameCell, testName, "*", "*");
	for (let i = 0; i < kernelsSetNames.length; i++) {
		let systemName = kernelsSetNames[i];
		for (let j = 0; j < kernels[systemName].length; j++) {
			const cell = testRow.insertCell();
			let id = testName+"_"+ systemName+"_"+kernels[systemName][j];
			cell.innerHTML = "<div style='display:flex'><span style='flex-grow: 1' id='" + id + "'>&nbsp;</span><div class='cellMenu'></div></div>";
			addCellMenu(cell, testName, systemName, kernels[systemName][j]);
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