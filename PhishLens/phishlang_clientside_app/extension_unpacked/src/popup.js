import { onPhishStatusAsync } from './utils.js';

/**
 * @param {Element|string} elementOrId
 * @param {string} text
 * @returns {void}
 */
function setElementText(elementOrId, text) {
	const element = typeof elementOrId === 'string'
		? document.getElementById(elementOrId)
		: elementOrId;
	element.textContent = text;
}

/**
 * @param {string} text
 * @param {string} [textFallback='N/A']
 * @returns {string}
 */
function stringOrNone(text, textFallback = 'N/A') {
	return text === ''
		? textFallback
		: text
}

/**
 * @param {URLSearchParams} params
 * @returns void
 */
function setSearchParams(params) {
	const parent = document.getElementById('uri-searchparams');
	if (params.size === 0) {
		const noneFound = document.createElement('p');
		noneFound.className = 'text-zinc-300';
		noneFound.textContent = 'No search params found';
		parent.appendChild(noneFound);
		return
	}

	const dlElement = document.createElement('dl');
	dlElement.className = 'grid grid-cols-2 gap-x-1 gap-y-2';
	for (const [key, value] of params.entries()) {
		// create container element
		const container = document.createElement('div');
		container.className = 'flex flex-col';

		// create key element
		const keyElement = document.createElement('dt');
		keyElement.textContent = key;

		// create value element
		const valueElement = document.createElement('dd');
		valueElement.setAttribute('title', value);
		valueElement.className = 'text-zinc-300 truncate font-mono';
		valueElement.textContent = value;

		// attach key+value elements to container,
		// then attach key-value container to parent
		container.appendChild(keyElement);
		container.appendChild(valueElement);
		dlElement.append(container);
	}
	parent.appendChild(dlElement);
}

/**
 * Remove CSS classes for an element that match a given predicate pattern
 * @param {Element} element
 * @param {(s: string) => boolean} predicate
 * @returns {void}
 */
function classRemoveBy(element, predicate) {
	const classList = element.classList;

	// not very safe to remove while iterating, do it after
	/** @type string[] */
	const candidates = [];
	classList.forEach((classToken) => {
		if (predicate(classToken)) {
			candidates.push(classToken);
		}
	});
	candidates.forEach(c => classList.remove(c));
}

/**
 * @param {HTMLElement} element
 * @param {string} prefix
 * @param {string} newClass
 */
function toggleTwClass(element, prefix, newClass) {
	classRemoveBy(element, s => s.startsWith(prefix));
	element.classList.add(newClass);
}

document.addEventListener('DOMContentLoaded', function () {
	chrome.tabs.query({ active: true, currentWindow: true }, function (tabs) {
		const currentTab = tabs[0];
		const url = new URL(currentTab.url);
		const domain = url.hostname;

		chrome.runtime.sendMessage({ action: 'getCheckResult', domain: domain }, (response) => {
			// toggle checkbox
			const checkboxBlocklist = document.getElementById('checkbox-blocklist');
			const openAiKey = document.getElementById('openai-key');

			// listen for changes
			checkboxBlocklist.addEventListener('change', () => {
				let checkedStatus = checkboxBlocklist.checked;
				console.log(`changed to ${checkboxBlocklist.checked}`);
				if (checkedStatus === true) {
					openAiKey.classList.remove('hidden');
					openAiKey.classList.add('flex');
				}
				else {
					openAiKey.classList.remove('flex');
					openAiKey.classList.add('hidden');
				}

				chrome.storage.local.set({ showBlocklist: checkboxBlocklist.checked });
				chrome.storage.local.get('showBlocklist', (result) => {
					console.log(result.showBlocklist);
				});
			});

			// set the checkbox's default checked value
			chrome.storage.local.get('showBlocklist', (result) => {
				checkboxBlocklist.checked = result.showBlocklist;
			});

			setElementText('base-url', domain);
			setElementText('full-url', url.toString());
			setElementText('uri-protocol', url.protocol);
			setElementText('uri-pathname', url.pathname);
			setElementText('uri-search', stringOrNone(url.search));
			setSearchParams(url.searchParams);

			const warningElementTwStyles = 'text-left p-4 pb-2';
			const warningElement = document.getElementById('warning');
			const statusElement = document.getElementById('status');
			const popupHeader = document.getElementById('popup-header');

			if (url.protocol === 'chrome:' || url.protocol === 'chrome-extension:') {
				statusElement.textContent = 'This is a special page, please try visiting a different page.';
				return
			}

			onPhishStatusAsync(response.phish, {
				onPhishing: async () => {
					setElementText(statusElement, 'Phishing');
					setElementText(warningElement, 'This website has been detected as dangerous by PhishLang, please do not access this website or share any personal information.');
					warningElement.className = warningElementTwStyles;

					toggleTwClass(popupHeader, 'bg-', 'bg-red-500');
				},
				onSuspicious: async () => {
					setElementText(statusElement, 'Suspicious');
					setElementText(warningElement, 'This website looks suspicious. Please take caution when entering any information on this website.');
					warningElement.className = warningElementTwStyles;

					toggleTwClass(popupHeader, 'bg-', 'bg-orange-500');
				},
				onSafe: async () => {
					setElementText(statusElement, 'Safe');
					setElementText(warningElement, '');
					warningElement.className = '';

					toggleTwClass(popupHeader, 'bg-', 'bg-blue-700');

					const statusContainer = document.getElementById('website-status');

					const reportParent = document.createElement('div');
					reportParent.className = 'mt-4 flex flex-row gap-2 items-start text-left justify-between';

					let reportText = document.createElement('div');
					reportText.textContent = 'Does this website not seem safe? Let us know by reporting it.';
					reportParent.appendChild(reportText);

					const reportButton = document.createElement('div');
					reportButton.className = 'inline-flex bg-red-500 rounded-md px-4 py-2 font-medium text-white';
					reportButton.textContent = 'Report';
					reportButton.addEventListener('click', async (e) => {
						reportButton.textContent = 'Website reported';
						reportText.textContent = 'Thank you for reporting.';
					});

					reportParent.appendChild(reportButton);
					statusContainer.appendChild(reportParent);
				},
				onDefault: async () => {
					setElementText(statusElement, 'Not checked');
					setElementText(warningElement, '');
					warningElement.className = '';

					toggleTwClass(popupHeader, 'bg-', 'bg-blue-700');
				},
			});
		});
	});
});
