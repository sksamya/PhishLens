import { onPhishStatusAsync } from './utils.js';
import { generateSiteExplanationWithOpenAI } from './openai-service.js';

/**
 * @param {Element|string} elementOrId
 * @param {string} text
 * @returns {void}
 */
function setElementText(elementOrId, text) {
	const element = typeof elementOrId === 'string'
		? document.getElementById(elementOrId)
		: elementOrId;
	if (element) element.textContent = text;
}

/**
 * @param {string} text
 * @param {string} [textFallback='N/A']
 * @returns {string}
 */
function stringOrNone(text, textFallback = 'N/A') {
	return text === ''
		? textFallback
		: text;
}

/**
 * @param {URLSearchParams} params
 * @returns void
 */
function setSearchParams(params) {
	const parent = document.getElementById('uri-searchparams');
	if (!parent) return;
	if (params.size === 0) {
		const noneFound = document.createElement('p');
		noneFound.className = 'text-zinc-300';
		noneFound.textContent = 'No search params found';
		parent.appendChild(noneFound);
		return;
	}

	const dlElement = document.createElement('dl');
	dlElement.className = 'grid grid-cols-2 gap-x-1 gap-y-2';
	for (const [key, value] of params.entries()) {
		const container = document.createElement('div');
		container.className = 'flex flex-col';

		const keyElement = document.createElement('dt');
		keyElement.textContent = key;

		const valueElement = document.createElement('dd');
		valueElement.setAttribute('title', value);
		valueElement.className = 'text-zinc-300 truncate font-mono';
		valueElement.textContent = value;

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

/**
 * Render the current status into the popup UI.
 * Called with the phish status string from the service worker,
 * OR 'backend-offline' / 'error' when the backend can't be reached.
 *
 * @param {string|undefined} phishStatus
 * @param {URL} url
 */
async function renderStatus(phishStatus, url) {
	const warningElementTwStyles = 'text-left p-4 pb-2';
	const warningElement = document.getElementById('warning');
	const statusElement = document.getElementById('status');
	const popupHeader = document.getElementById('popup-header');

	if (!statusElement || !warningElement || !popupHeader) return;

	// Handle special statuses that bypass the normal phish check
	if (phishStatus === 'backend-offline' || phishStatus === 'unchecked') {
		setElementText(statusElement, 'Backend Offline');
		setElementText(warningElement,
			'The PhishLens AI backend is not running. Start the backend server at localhost:5000 or localhost:5024 to enable full AI model detection.');
		warningElement.className = warningElementTwStyles;
		toggleTwClass(popupHeader, 'bg-', 'bg-zinc-600');
		return;
	}

	if (phishStatus === 'error') {
		setElementText(statusElement, 'Error');
		setElementText(warningElement, 'An unexpected error occurred. Check the extension console for details.');
		warningElement.className = warningElementTwStyles;
		toggleTwClass(popupHeader, 'bg-', 'bg-zinc-600');
		return;
	}

	await onPhishStatusAsync(phishStatus, {
		onPhishing: async () => {
			setElementText(statusElement, 'Phishing ⚠️');
			setElementText(warningElement, 'This website has been detected as dangerous by PhishLens. Do not access this website or share any personal information.');
			warningElement.className = warningElementTwStyles;
			toggleTwClass(popupHeader, 'bg-', 'bg-red-500');
		},
		onSuspicious: async () => {
			setElementText(statusElement, 'Suspicious ⚡');
			setElementText(warningElement, 'This website looks suspicious. Please take caution when entering any information.');
			warningElement.className = warningElementTwStyles;
			toggleTwClass(popupHeader, 'bg-', 'bg-orange-500');
		},
		onSafe: async () => {
			setElementText(statusElement, 'Safe ✓');
			setElementText(warningElement, '');
			warningElement.className = '';
			toggleTwClass(popupHeader, 'bg-', 'bg-blue-700');

			const statusContainer = document.getElementById('website-status');
			if (statusContainer && !statusContainer.querySelector('.report-btn-wrapper')) {
				const reportParent = document.createElement('div');
				reportParent.className = 'mt-4 flex flex-row gap-2 items-start text-left justify-between report-btn-wrapper';

				let reportText = document.createElement('div');
				reportText.textContent = 'Does this website not seem safe? Let us know by reporting it.';
				reportParent.appendChild(reportText);

				const reportButton = document.createElement('div');
				reportButton.className = 'inline-flex bg-red-500 rounded-md px-4 py-2 font-medium text-white cursor-pointer';
				reportButton.textContent = 'Report';
				reportButton.addEventListener('click', async () => {
					reportButton.textContent = 'Website reported';
					reportText.textContent = 'Thank you for reporting.';
				});

				reportParent.appendChild(reportButton);
				statusContainer.appendChild(reportParent);
			}
		},
		onDefault: async () => {
			// Domain not yet checked by backend (e.g. first visit with backend just starting)
			setElementText(statusElement, 'Not checked yet');
			setElementText(warningElement, 'PhishLens has not analysed this page yet. Try reloading the tab once the backend is running.');
			warningElement.className = warningElementTwStyles;
			toggleTwClass(popupHeader, 'bg-', 'bg-zinc-600');
		},
	});
}

/**
 * Fetch the status of the current tab from the service worker with a timeout.
 * Returns the phish status string, 'backend-offline', or 'error'.
 * @param {string} domain
 * @param {string} [fullUrl]
 * @returns {Promise<string|undefined>}
 */
function getCheckResultWithTimeout(domain, fullUrl) {
	return new Promise((resolve) => {
		// Hard timeout: if service worker doesn't respond in 4 seconds, resolve with error
		const timer = setTimeout(() => resolve('backend-offline'), 4000);

		try {
			chrome.runtime.sendMessage({ action: 'getCheckResult', domain, fullUrl }, (response) => {
				clearTimeout(timer);
				if (chrome.runtime.lastError) {
					console.warn('[PhishLens Popup] Service worker error:', chrome.runtime.lastError.message);
					resolve('error');
					return;
				}
				resolve(response ? response.phish : undefined);
			});
		} catch (e) {
			clearTimeout(timer);
			console.error('[PhishLens Popup] sendMessage threw:', e);
			resolve('error');
		}
	});
}

document.addEventListener('DOMContentLoaded', async function () {
	// Get the active tab
	const [currentTab] = await chrome.tabs.query({ active: true, currentWindow: true });
	if (!currentTab || !currentTab.url) {
		setElementText('status', 'No active tab');
		return;
	}

	let url;
	try {
		url = new URL(currentTab.url);
	} catch {
		setElementText('status', 'Invalid URL');
		return;
	}

	const domain = url.hostname;

	// Fill in URL fields immediately (doesn't depend on backend)
	setElementText('base-url', domain);
	setElementText('full-url', url.toString());
	setElementText('uri-protocol', url.protocol);
	setElementText('uri-pathname', url.pathname);
	setElementText('uri-search', stringOrNone(url.search));
	setSearchParams(url.searchParams);

	// Handle special browser pages
	if (url.protocol === 'chrome:' || url.protocol === 'chrome-extension:' || url.protocol === 'about:') {
		setElementText('status', 'Special page — no check needed');
		const popupHeader = document.getElementById('popup-header');
		if (popupHeader) toggleTwClass(popupHeader, 'bg-', 'bg-blue-700');
		return;
	}

	// Setup checkbox preference and OpenAI API key storage
	const checkboxBlocklist = document.getElementById('checkbox-blocklist');
	const openAiKeySection = document.getElementById('openai-key-section');
	const openAiKeyInput = document.getElementById('openai-key-input');
	const openAiKeySaved = document.getElementById('openai-key-saved');

	if (checkboxBlocklist) {
		chrome.storage.local.get(['showBlocklist', 'openaiApiKey'], (result) => {
			const isChecked = !!result.showBlocklist;
			checkboxBlocklist.checked = isChecked;
			if (openAiKeySection) {
				openAiKeySection.classList.toggle('hidden', !isChecked);
				openAiKeySection.classList.toggle('flex', isChecked);
			}
			if (openAiKeyInput && result.openaiApiKey) {
				openAiKeyInput.value = result.openaiApiKey;
			}
		});

		checkboxBlocklist.addEventListener('change', () => {
			const checked = checkboxBlocklist.checked;
			if (openAiKeySection) {
				openAiKeySection.classList.toggle('hidden', !checked);
				openAiKeySection.classList.toggle('flex', checked);
			}
			chrome.storage.local.set({ showBlocklist: checked });
		});
	}

	if (openAiKeyInput) {
		openAiKeyInput.addEventListener('change', () => {
			const key = openAiKeyInput.value.trim();
			chrome.storage.local.set({ openaiApiKey: key }, () => {
				if (openAiKeySaved) {
					openAiKeySaved.classList.remove('hidden');
					setTimeout(() => openAiKeySaved.classList.add('hidden'), 2500);
				}
			});
		});
	}

	// --- Main check ---
	const phishStatus = await getCheckResultWithTimeout(domain, url.toString());
	await renderStatus(phishStatus, url);

	// --- Behavioral signals panel (Phase 1-4) ---
	try {
		chrome.runtime.sendMessage({ action: 'getBehavioralSignals', tabId: currentTab.id }, (bRes) => {
			if (chrome.runtime.lastError || !bRes || !bRes.signals || bRes.signals.length === 0) return;

			const reportContainer = document.getElementById('website-report');
			if (!reportContainer) return;

			reportContainer.innerHTML = '';
			const banner = document.createElement('div');
			banner.className = 'p-3 bg-amber-900/40 border border-amber-500 rounded text-xs text-amber-200 mx-4 my-2 flex flex-col gap-1';

			const title = document.createElement('span');
			title.className = 'font-bold';
			title.textContent = '⚡ Dynamic Behavioural Signals:';
			banner.appendChild(title);

			bRes.signals.slice(-5).forEach((sig) => {
				const item = document.createElement('div');
				item.className = 'text-[11px] text-zinc-300';
				const severity = sig.severity ? ` [${sig.severity}]` : '';
				item.textContent = `• ${sig.type}${severity}`;
				banner.appendChild(item);
			});

			reportContainer.appendChild(banner);
		});
	} catch (e) {
		// Non-critical — don't let this break the popup
		console.debug('[PhishLens Popup] getBehavioralSignals failed:', e);
	}

	// --- OpenAI In-Depth Site Security Explanation ---
	setupOpenAIInsights({
		url: url.toString(),
		domain,
		verdict: phishStatus || 'unknown',
		tabId: currentTab.id
	});
});

/**
 * Configure and trigger OpenAI in-depth explanation UI
 * @param {object} params
 */
function setupOpenAIInsights({ url, domain, verdict, tabId }) {
	const container = document.getElementById('openai-explanation-container');
	const refreshBtn = document.getElementById('openai-refresh-btn');
	const loadingEl = document.getElementById('openai-loading');
	const errorEl = document.getElementById('openai-error');
	const resultEl = document.getElementById('openai-result');
	const summaryEl = document.getElementById('openai-summary');
	const explEl = document.getElementById('openai-explanation');
	const recsEl = document.getElementById('openai-recommendations');

	if (!container) return;

	chrome.storage.local.get(['showBlocklist', 'openaiApiKey'], (stored) => {
		if (!stored.showBlocklist) {
			container.classList.add('hidden');
			return;
		}

		container.classList.remove('hidden');

		async function fetchExplanation() {
			const apiKey = stored.openaiApiKey;
			if (!apiKey) {
				errorEl.textContent = 'Please enter and save your OpenAI API key above in User Settings.';
				errorEl.classList.remove('hidden');
				resultEl.classList.add('hidden');
				return;
			}

			errorEl.classList.add('hidden');
			loadingEl.classList.remove('hidden');
			resultEl.classList.add('hidden');
			if (refreshBtn) refreshBtn.disabled = true;

			try {
				// Fetch recent behavioral signals to provide rich context to OpenAI
				let signals = [];
				try {
					signals = await new Promise((res) => {
						chrome.runtime.sendMessage({ action: 'getBehavioralSignals', tabId }, (r) => {
							res(r?.signals || []);
						});
					});
				} catch {}

				const report = await generateSiteExplanationWithOpenAI(apiKey, {
					url,
					domain,
					verdict,
					signals
				});

				summaryEl.textContent = report.threatSummary || '';
				explEl.textContent = report.explanation || '';
				if (report.recommendations && report.recommendations.length > 0) {
					recsEl.innerHTML = '<strong class="text-zinc-300">Recommendations:</strong><ul class="list-disc list-inside mt-1">' +
						report.recommendations.map(r => `<li>${r}</li>`).join('') +
						'</ul>';
				} else {
					recsEl.innerHTML = '';
				}

				resultEl.classList.remove('hidden');
			} catch (err) {
				errorEl.textContent = err.message || 'Failed to generate OpenAI explanation.';
				errorEl.classList.remove('hidden');
			} finally {
				loadingEl.classList.add('hidden');
				if (refreshBtn) refreshBtn.disabled = false;
			}
		}

		if (refreshBtn) {
			refreshBtn.addEventListener('click', () => {
				// Re-read storage in case key was just entered
				chrome.storage.local.get(['openaiApiKey'], (curr) => {
					stored.openaiApiKey = curr.openaiApiKey;
					fetchExplanation();
				});
			});
		}

		// Auto-fetch if key is already present and site is flagged (or user enabled blocklist)
		if (stored.openaiApiKey && (verdict === 'phishing' || verdict === 'suspicious')) {
			fetchExplanation();
		}
	});
}
