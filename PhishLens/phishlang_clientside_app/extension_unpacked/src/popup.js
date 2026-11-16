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
async function renderStatus(phishStatus, url, tabId) {
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
		onUnverified: async () => {
			setElementText(statusElement, 'Unverified Destination 🛡️');
			warningElement.textContent = '';
			warningElement.className = '';
			const banner = document.createElement('div');
			banner.className = 'mt-3 rounded-md p-3 text-left';
			banner.style.cssText = 'margin-top:12px;border:1px solid #eab308;border-radius:6px;background:#422006;color:#fef3c7;padding:12px;text-align:left';
			banner.setAttribute('role', 'alert');
			const message = document.createElement('p');
			message.className = 'mb-3';
			message.textContent = 'We could not verify this page. Treat it as unverified and proceed cautiously.';
			const actions = document.createElement('div');
			actions.className = 'flex justify-end gap-2';
			const dismissButton = document.createElement('button');
			dismissButton.type = 'button';
			dismissButton.className = 'rounded px-3 py-1.5 text-white';
			dismissButton.style.cssText = 'border:0;border-radius:4px;background:#a16207;color:white;padding:6px 12px;cursor:pointer';
			dismissButton.textContent = 'Dismiss';
			dismissButton.addEventListener('click', () => banner.remove());
			const exitButton = document.createElement('button');
			exitButton.type = 'button';
			exitButton.className = 'rounded px-3 py-1.5 text-white';
			exitButton.style.cssText = 'border:0;border-radius:4px;background:#3f3f46;color:white;padding:6px 12px;cursor:pointer';
			exitButton.textContent = 'Exit';
			exitButton.addEventListener('click', () => {
				if (Number.isInteger(tabId)) chrome.tabs.remove(tabId);
			});
			actions.append(dismissButton, exitButton);
			banner.append(message, actions);
			warningElement.appendChild(banner);
			toggleTwClass(popupHeader, 'bg-', 'bg-yellow-600');
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
function getCheckResultWithTimeout(domain, fullUrl, tabId) {
	return new Promise((resolve) => {
		// Hard timeout: if service worker doesn't respond in 4 seconds, resolve with error
		const timer = setTimeout(() => resolve('backend-offline'), 4000);

		try {
			chrome.runtime.sendMessage({ action: 'getCheckResult', domain, fullUrl, tabId }, (response) => {
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

	// Content scripts are not injected into file:// pages by this extension.
	// Do not let the URL-only fallback present an unscanned local file as safe.
	if (url.protocol === 'file:') {
		setElementText('status', 'Local file — not scanned');
		setElementText('warning', 'PhishLens cannot inspect this file page. Serve the demo over http://localhost and scan that page instead.');
		const warningElement = document.getElementById('warning');
		if (warningElement) warningElement.className = 'text-left p-4 pb-2';
		const popupHeader = document.getElementById('popup-header');
		if (popupHeader) toggleTwClass(popupHeader, 'bg-', 'bg-yellow-600');
		return;
	}

	// --- Main check ---
	const phishStatus = await getCheckResultWithTimeout(domain, url.toString(), currentTab.id);
	await renderStatus(phishStatus, url, currentTab.id);

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

			const humanReadableReasons = {
				'DYNAMIC_SENSITIVE_INPUT_INSERTED': 'Delayed credential field dynamically inserted into DOM',
				'DYNAMIC_FORM_INSERTED': 'Hidden/delayed form dynamically injected into page',
				'DYNAMIC_LOGIN_MODAL_OVERLAY': 'Deceptive login modal overlay presented to user',
				'HIDDEN_FORM_REVEALED': 'Previously hidden form suddenly made visible',
				'HIDDEN_SENSITIVE_INPUT_REVEALED': 'Hidden password or payment input revealed',
				'FORM_ACTION_MODIFIED': 'Form submission destination modified at runtime',
				'SUSPICIOUS_CROSS_ORIGIN_SUBMIT': 'Login form sends data to an unexpected external destination',
				'CLICKJACKING_OVERLAY_DETECTED': 'A transparent overlay may be intercepting your clicks',
				'CLICK_TARGET_MISMATCH': 'Visual click target differs from actual DOM recipient',
				'IMAGE_BRAND_IMPERSONATION': 'Recognizable brand login prompt rendered as static image',
				'IMAGE_CREDENTIAL_PROMPT_DETECTED': 'Credential prompt presented inside an image',
				'QR_CODE_PHISHING_CONFIRMED': 'Scanned QR code leads to a confirmed phishing destination',
				'QR_CODE_UNVERIFIED': 'Unverified QR destination (could not decode safely)',
				'INTERSTITIAL_CAPTCHA_DETECTED': 'Page access blocked by security check/bot challenge',
				'OUT_OF_BAND_CROSS_ORIGIN_REQUEST': 'Out-of-band request to external domain after credential interaction',
				'SUSPICIOUS_MULTI_HOP_REDIRECT_CHAIN': 'Multi-hop cross-domain redirect chain detected'
			};

			bRes.signals.slice(-5).forEach((sig) => {
				const item = document.createElement('div');
				item.className = 'text-[11px] text-zinc-300';
				const severity = sig.severity ? ` [${sig.severity}]` : '';
				const friendlyDesc = humanReadableReasons[sig.type] || sig.type;
				item.textContent = `• ${friendlyDesc}${severity}`;
				banner.appendChild(item);
			});

			reportContainer.appendChild(banner);
		});
	} catch (e) {
		// Non-critical — don't let this break the popup
		console.debug('[PhishLens Popup] getBehavioralSignals failed:', e);
	}

});
