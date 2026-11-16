/**
 * PhishLens - Dynamic Behavioural Threat Detection Content Script
 *
 * Phase 1: DOM MutationObserver & Continuous User Interaction Monitoring
 * Phase 2: Sensitive Form Inspection & Real-Time Form Locking Guard
 * Phase 3: Network / Redirect correlation signals (sent to service-worker)
 * Phase 4: Visual Threat Detection (Clickjacking, QR Phishing, Image Impersonation)
 *
 * STRICT PRIVACY GUARANTEE:
 * This script NEVER reads, logs, stores, or transmits input values (e.g. input.value),
 * keystrokes, passwords, OTPs, cookies, or clipboard contents.
 * It tracks strictly structural metadata (tag name, input type, form action/method, visibility, timestamps).
 */

(() => {
	'use strict';

	// Prevent duplicate injection in the same frame
	if (window.__phishLensContentScriptInjected) {
		return;
	}
	window.__phishLensContentScriptInjected = true;

	/* ==========================================================================
	   CONFIGURATION & CONSTANTS
	   ========================================================================== */

	const CONFIG = {
		BATCH_DELAY_MS: 150,               // Debounce window for DOM mutation batching
		CORRELATION_WINDOW_MS: 3000,       // Max time between user interaction and DOM change to correlate
		EVALUATION_TIMEOUT_MS: 2500,       // Max time to wait for background risk evaluation before fallback
		MAX_INTERACTION_HISTORY: 20,       // Rolling interaction buffer limit
		MAX_SIGNALS_PER_PAGE: 100,         // Prevent unbounded memory growth
		UI_IGNORE_SELECTORS: [             // Extension's own UI elements to ignore
			'#freephishing-warning-page',
			'#phishlens-global-phishing-banner',
			'[data-phishlens-ui]',
			'.phishlang-overlay',
			'.phishlang-ui'
		]
	};

	/**
	 * Legitimate Identity Provider (IdP) Host Patterns
	 * Used to differentiate legitimate OAuth/SSO login redirects from credential harvesting
	 */
	const LEGITIMATE_IDP_PATTERNS = [
		/^accounts\.google\.com$/,
		/^(login\.)?microsoftonline\.com$/,
		/^(login|account)\.live\.com$/,
		/^appleid\.apple\.com$/,
		/^(www\.)?github\.com$/,
		/^[a-zA-Z0-9-]+\.okta\.com$/,
		/^[a-zA-Z0-9-]+\.auth0\.com$/,
		/^(signin\.)?aws\.amazon\.com$/,
		/^(www\.)?amazon\.com$/,
		/^(www\.)?facebook\.com$/,
		/^(www\.)?paypal\.com$/,
		/^(checkout|api)\.stripe\.com$/,
		/^[a-zA-Z0-9-]+\.pingidentity\.com$/,
		/^[a-zA-Z0-9-]+\.onelogin\.com$/,
		/^[a-zA-Z0-9-]+\.duosecurity\.com$/
	];

	/**
	 * Trusted same-org CDN / API domain pairs.
	 * Key = registrable domain of the page; value = set of trusted external registrable domains.
	 * Mirrors the list in service-worker.js so both layers agree on trust.
	 */
	const TRUSTED_ORG_DOMAINS = {
		'google.com':    ['googleapis.com', 'gstatic.com', 'googleusercontent.com', 'googlevideo.com', 'ggpht.com', 'doubleclick.net', 'googletagmanager.com', 'google.com', 'youtube.com'],
		'youtube.com':   ['googlevideo.com', 'gstatic.com', 'googleapis.com', 'ggpht.com', 'google.com', 'ytimg.com', 'yt3.ggpht.com'],
		'netflix.com':   ['nflxso.net', 'nflxext.com', 'nflximg.net', 'nflxvideo.net', 'netflixdns.net', 'nflximg.com', 'netflix.net'],
		'microsoft.com': ['office.com', 'live.com', 'microsoftonline.com', 'azureedge.net', 'azure.com', 'msftauth.net', 'msauth.net', 'msecnd.net', 'sharepoint.com'],
		'outlook.com':   ['microsoft.com', 'live.com', 'microsoftonline.com', 'office.com', 'msftauth.net'],
		'office.com':    ['microsoft.com', 'microsoftonline.com', 'sharepoint.com', 'msftauth.net', 'azureedge.net'],
		'apple.com':     ['icloud.com', 'mzstatic.com', 'apple-cloudkit.com', 'aaplimg.com'],
		'icloud.com':    ['apple.com', 'mzstatic.com', 'aaplimg.com'],
		'facebook.com':  ['fbcdn.net', 'instagram.com', 'whatsapp.com', 'facebook.net', 'cdninstagram.com'],
		'instagram.com': ['fbcdn.net', 'facebook.com', 'cdninstagram.com'],
		'amazon.com':    ['amazonaws.com', 'cloudfront.net', 'ssl-images-amazon.com', 'media-amazon.com', 'amazon-adsystem.com'],
		'twitter.com':   ['twimg.com', 't.co'],
		'x.com':         ['twimg.com', 'twitter.com', 't.co'],
		'github.com':    ['githubusercontent.com', 'githubassets.com', 'github.io'],
		'linkedin.com':  ['licdn.com'],
		'reddit.com':    ['redd.it', 'redditmedia.com', 'reddituploads.com', 'redditstatic.com'],
		'twitch.tv':     ['jtvnw.net', 'twitchsvc.net', 'twitchdisrupt.com', 'ext-twitch.tv'],
		'spotify.com':   ['scdn.co', 'spotifycdn.com', 'spotifycdn.net'],
		'twitter.com':   ['twimg.com', 't.co', 'abs.twimg.com'],
	};

	/**
	 * Extract eTLD+1 from a hostname (best-effort, mirrors service-worker logic)
	 * @param {string} hostname
	 * @returns {string}
	 */
	function getRegistrableDomainCS(hostname) {
		if (!hostname) return '';
		const parts = hostname.split('.');
		const knownSLD = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'sch']);
		if (parts.length >= 3 && knownSLD.has(parts[parts.length - 2])) {
			return parts.slice(-3).join('.');
		}
		return parts.slice(-2).join('.');
	}

	/** Registrable domain of the current page */
	const pageRegDomain = getRegistrableDomainCS(window.location.hostname);

	/**
	 * Returns true if externalOrigin is a trusted same-org domain for the current page.
	 * @param {string} externalOrigin  e.g. "https://nflxso.net"
	 * @returns {boolean}
	 */
	function isTrustedSameOrgOrigin(externalOrigin) {
		if (!externalOrigin) return false;
		try {
			const extHost = new URL(externalOrigin).hostname;
			const extReg = getRegistrableDomainCS(extHost);
			// Same registrable domain (sub1.foo.com → sub2.foo.com)
			if (extReg === pageRegDomain) return true;
			// Org-level trusted pair
			const trustedList = TRUSTED_ORG_DOMAINS[pageRegDomain];
			if (trustedList && trustedList.includes(extReg)) return true;
			// Reverse: check if current page is in a CDN set that trusts extReg
			for (const [org, list] of Object.entries(TRUSTED_ORG_DOMAINS)) {
				if (list.includes(pageRegDomain) && (org === extReg || list.includes(extReg))) return true;
			}
			return false;
		} catch { return false; }
	}

	// State
	let pendingMutations = [];
	let batchTimer = null;
	const interactionHistory = [];
	const trackedForms = new WeakMap();     // Tracks initial action, method, and field count of forms
	const reportedSignalHashes = new Set(); // Prevent duplicate identical signal spam
	let totalSignalsSent = 0;

	// Submit control tracking
	let lastClickedSubmitButton = null;
	let lastClickedTime = 0;

	// Phase 4 — set after the visual detector is defined below
	let _p4_runVisualThreatDetection = null;
	let _p4_runClickRedressingCheck = null;
	let _p4_rescanOnMutation = null;

	/* ==========================================================================
	   HELPER UTILITIES & CLASSIFIERS
	   ========================================================================== */

	/**
	 * Check if a node belongs to the extension's own UI
	 * @param {Node} node
	 * @returns {boolean}
	 */
	function isExtensionUI(node) {
		if (!node || node.nodeType !== Node.ELEMENT_NODE) {
			return false;
		}
		const el = /** @type {Element} */ (node);
		for (const selector of CONFIG.UI_IGNORE_SELECTORS) {
			if (el.matches && (el.matches(selector) || el.closest(selector))) {
				return true;
			}
		}
		return false;
	}

	/**
	 * Check if an element is visible in the DOM
	 * @param {HTMLElement} el
	 * @returns {boolean}
	 */
	function isElementVisible(el) {
		if (!el) return false;
		if (el.hidden) return false;
		const style = window.getComputedStyle(el);
		if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') {
			return false;
		}
		return el.offsetWidth > 0 || el.offsetHeight > 0 || el.getClientRects().length > 0;
	}

	/**
	 * Extract safe origin from a given URL string
	 * @param {string} urlString
	 * @returns {string|null}
	 */
	function getSafeOrigin(urlString) {
		if (!urlString || urlString.startsWith('javascript:') || urlString.startsWith('data:')) {
			return null;
		}
		try {
			const resolved = new URL(urlString, window.location.href);
			return resolved.origin;
		} catch {
			return null;
		}
	}

	/**
	 * Check if a destination origin belongs to a legitimate known Identity Provider
	 * @param {string|null} destinationOrigin
	 * @returns {boolean}
	 */
	function isKnownLegitimateIdP(destinationOrigin) {
		if (!destinationOrigin) return false;
		try {
			const host = new URL(destinationOrigin).hostname.toLowerCase();
			return LEGITIMATE_IDP_PATTERNS.some((pattern) => pattern.test(host));
		} catch {
			return false;
		}
	}

	/**
	 * Extract accessible label text for an input without touching its value
	 * @param {HTMLInputElement} input
	 * @returns {string[]}
	 */
	function getAccessibleFieldLabels(input) {
		const labels = [];
		if (input.labels && input.labels.length > 0) {
			for (const l of input.labels) {
				const txt = (l.textContent || '').trim().replace(/\s+/g, ' ');
				if (txt) labels.push(txt.slice(0, 50));
			}
		}
		const ariaLabel = input.getAttribute('aria-label');
		if (ariaLabel) labels.push(ariaLabel.trim().slice(0, 50));

		const ariaLabelledBy = input.getAttribute('aria-labelledby');
		if (ariaLabelledBy) {
			const el = document.getElementById(ariaLabelledBy);
			if (el) labels.push((el.textContent || '').trim().slice(0, 50));
		}

		const placeholder = input.getAttribute('placeholder');
		if (placeholder) labels.push(placeholder.trim().slice(0, 50));

		return labels;
	}

	/**
	 * Classify if an input element is sensitive (password, email, OTP, payment)
	 * STRICT PRIVACY: NEVER reads input.value!
	 * @param {HTMLInputElement} input
	 * @returns {{ isSensitive: boolean, category?: string, severity?: string }}
	 */
	function classifyInputElement(input) {
		if (!input || input.tagName !== 'INPUT') {
			return { isSensitive: false };
		}

		const type = (input.type || 'text').toLowerCase();
		const name = (input.name || '').toLowerCase();
		const id = (input.id || '').toLowerCase();
		const autocomplete = (input.autocomplete || '').toLowerCase();

		// 1. Password field
		if (type === 'password' || autocomplete.includes('password')) {
			return { isSensitive: true, category: 'PASSWORD', severity: 'high' };
		}

		// 2. One-Time Passcode (OTP / 2FA / Verification code)
		const isOtp = autocomplete.includes('one-time-code') ||
			/(otp|one.?time.?code|2fa|mfa|verification.?code|auth.?code)/i.test(name) ||
			/(otp|one.?time.?code|2fa|mfa|verification.?code|auth.?code)/i.test(id);
		if (isOtp) {
			return { isSensitive: true, category: 'OTP', severity: 'high' };
		}

		// 3. Payment / Credit Card details
		const isPayment = autocomplete.includes('cc-') ||
			/(card.?num|credit.?card|card.?holder|cvv|cvc|expir)/i.test(name) ||
			/(card.?num|credit.?card|card.?holder|cvv|cvc|expir)/i.test(id);
		if (isPayment) {
			return { isSensitive: true, category: 'PAYMENT', severity: 'high' };
		}

		// 4. Email / Account Identifier
		if (type === 'email' || autocomplete.includes('email') || /(user.?email|user.?login)/i.test(name)) {
			return { isSensitive: true, category: 'EMAIL', severity: 'medium' };
		}

		// 5. Telephone / SMS MFA
		if (type === 'tel' || autocomplete.includes('tel') || /(phone|mobile)/i.test(name)) {
			return { isSensitive: true, category: 'PHONE', severity: 'medium' };
		}

		return { isSensitive: false };
	}

	/**
	 * Inspect safe form metadata and sensitivity analysis (NO input values!)
	 * @param {HTMLFormElement} form
	 * @returns {object}
	 */
	function getSafeFormMetadata(form) {
		const action = form.getAttribute('action') || form.action || '';
		const method = (form.getAttribute('method') || 'GET').toUpperCase();
		const destinationOrigin = getSafeOrigin(action) || window.location.origin;
		const isCrossOrigin = destinationOrigin !== window.location.origin;
		const isIdP = isKnownLegitimateIdP(destinationOrigin);

		let sensitiveFieldsCount = 0;
		let hasPassword = false;
		let hasOtp = false;
		let hasPayment = false;
		let hasEmail = false;
		const sensitiveCategories = [];
		const sensitiveLabels = [];

		const inputs = form.querySelectorAll('input, select, textarea');
		for (const input of inputs) {
			if (input.tagName === 'INPUT') {
				const classification = classifyInputElement(/** @type {HTMLInputElement} */ (input));
				if (classification.isSensitive) {
					sensitiveFieldsCount++;
					if (!sensitiveCategories.includes(classification.category)) {
						sensitiveCategories.push(classification.category);
					}
					if (classification.category === 'PASSWORD') hasPassword = true;
					if (classification.category === 'OTP') hasOtp = true;
					if (classification.category === 'PAYMENT') hasPayment = true;
					if (classification.category === 'EMAIL') hasEmail = true;

					const labels = getAccessibleFieldLabels(/** @type {HTMLInputElement} */ (input));
					if (labels.length > 0) {
						sensitiveLabels.push(...labels);
					}
				}
			}
		}

		const isSensitive = hasPassword || hasOtp || hasPayment || (hasEmail && inputs.length <= 5);

		return {
			actionUrl: action,
			destinationOrigin,
			isCrossOrigin,
			isIdP,
			method,
			isSensitive,
			hasPassword,
			hasOtp,
			hasPayment,
			hasEmail,
			sensitiveFieldsCount,
			sensitiveCategories,
			sensitiveLabels: Array.from(new Set(sensitiveLabels)).slice(0, 5),
			formId: form.id || null,
			formName: form.name || null
		};
	}

	/* ==========================================================================
	   SIGNAL DISPATCHER
	   ========================================================================== */

	/**
	 * Send a behavioral threat signal to the background service worker
	 * @param {object} signal
	 */
	function emitBehavioralSignal(signal) {
		if (totalSignalsSent >= CONFIG.MAX_SIGNALS_PER_PAGE) {
			return;
		}

		const hash = `${signal.type}_${signal.severity}_${JSON.stringify(signal.details)}`;
		if (reportedSignalHashes.has(hash)) {
			return;
		}
		reportedSignalHashes.add(hash);
		totalSignalsSent++;

		const payload = {
			...signal,
			url: window.location.href,
			pageOrigin: window.location.origin,
			timestamp: Date.now()
		};

		try {
			chrome.runtime.sendMessage({
				action: 'behavioralThreatSignal',
				payload
			}, () => {
				if (chrome.runtime.lastError) {
					// Background context may be reloading
				}
			});
		} catch {
			// Catch context invalidated errors
		}
	}

	/* ==========================================================================
	   PHASE 2: FORM LOCKING GUARD & PRE-SUBMISSION INTERCEPTION
	   ========================================================================== */

	let isPageFlaggedAsPhishing = false;
	let phishingLockInterval = null;

	const FormLockGuard = {
		/**
		 * Apply temporary protected state and evaluate submission risk
		 * @param {HTMLFormElement} form
		 * @param {string} destinationUrl
		 * @param {string} destinationOrigin
		 * @param {object} formMeta
		 */
		evaluateAndProtect(form, destinationUrl, destinationOrigin, formMeta) {
			// 1. Temporarily lock the form controls
			FormLockGuard.lock(form, 'Verifying destination security...');

			let responded = false;

			// 2. Safety timeout fallback: Never permanently lock benign pages if worker fails
			const timeoutTimer = setTimeout(() => {
				if (!responded) {
					responded = true;
					FormLockGuard.showTimeoutFallback(form, destinationOrigin);
				}
			}, CONFIG.EVALUATION_TIMEOUT_MS);

			// 3. Request evaluation from background worker
			try {
				chrome.runtime.sendMessage({
					action: 'evaluateSubmissionRisk',
					payload: {
						pageUrl: window.location.href,
						pageOrigin: window.location.origin,
						destinationUrl,
						destinationOrigin,
						isCrossOrigin: formMeta.isCrossOrigin,
						isKnownIdP: formMeta.isIdP,
						sensitiveCategories: formMeta.sensitiveCategories
					}
				}, (response) => {
					if (responded) return;
					responded = true;
					clearTimeout(timeoutTimer);

					if (chrome.runtime.lastError || !response) {
						FormLockGuard.showTimeoutFallback(form, destinationOrigin);
						return;
					}

					if (response.verdict === 'ALLOW') {
						// Verified safe destination — unlock and proceed
						FormLockGuard.unlock(form);
						FormLockGuard.proceedWithNativeSubmit(form);
					} else if (response.verdict === 'WARN') {
						// Suspicious but not confirmed — unlock with a visible caution notice.
						// Do NOT permanently block; let the user decide.
						FormLockGuard.unlock(form);
						FormLockGuard.showWarningBanner(form, response.reason, destinationOrigin);
						FormLockGuard.proceedWithNativeSubmit(form);
					} else if (response.verdict === 'UNVERIFIED') {
						// Phase 5: Destination verification blocked by security check/CAPTCHA
						FormLockGuard.unlock(form);
						FormLockGuard.showUnverifiedDestinationBanner(form, response.reason, destinationOrigin);
					} else {
						// BLOCK — multiple correlated indicators of phishing confirmed
						FormLockGuard.block(form, response.reason, destinationOrigin);
					}
				});
			} catch {
				if (!responded) {
					responded = true;
					clearTimeout(timeoutTimer);
					FormLockGuard.showTimeoutFallback(form, destinationOrigin);
				}
			}
		},

		/**
		 * Temporarily lock form controls and render an accessible verification badge
		 * @param {HTMLFormElement} form
		 * @param {string} statusText
		 */
		lock(form, statusText) {
			form.setAttribute('aria-busy', 'true');
			form.setAttribute('data-phishlens-locked', 'true');

			// Disable all interactive input fields, selects, textareas, and buttons in the form
			const controls = form.querySelectorAll('input:not([type="hidden"]), select, textarea, button');
			controls.forEach((control) => {
				const htmlControl = /** @type {HTMLInputElement} */ (control);
				if (!htmlControl.hasAttribute('data-phishlens-disabled')) {
					htmlControl.setAttribute('data-phishlens-disabled', 'true');
					htmlControl.setAttribute('aria-disabled', 'true');
					htmlControl.disabled = true;
					htmlControl.style.pointerEvents = 'none';
					htmlControl.style.opacity = '0.6';
					htmlControl.style.cursor = 'not-allowed';
				}
			});

			// Render or update scoped banner
			let banner = form.querySelector('[data-phishlens-ui="lock-banner"]');
			if (!banner) {
				banner = document.createElement('div');
				banner.setAttribute('data-phishlens-ui', 'lock-banner');
				banner.setAttribute('role', 'status');
				banner.setAttribute('aria-live', 'polite');
				banner.style.cssText = `
					margin: 8px 0;
					padding: 10px 14px;
					border-radius: 6px;
					background: #1e293b;
					border: 1px solid #3b82f6;
					color: #93c5fd;
					font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
					font-size: 13px;
					line-height: 1.4;
					display: flex;
					align-items: center;
					gap: 8px;
					z-index: 1000;
				`;
				form.prepend(banner);
			}

			banner.innerHTML = `
				<svg style="width: 16px; height: 16px; animation: spin 1s linear infinite;" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
					<circle cx="12" cy="12" r="10" stroke-opacity="0.25"></circle>
					<path d="M12 2a10 10 0 0 1 10 10" stroke-linecap="round"></path>
				</svg>
				<span><strong>PhishLens:</strong> ${statusText}</span>
				<style>@keyframes spin { 100% { transform: rotate(360deg); } }</style>
			`;
		},

		/**
		 * Unlock form controls and remove verification banner
		 * @param {HTMLFormElement} form
		 */
		unlock(form) {
			form.removeAttribute('aria-busy');
			form.removeAttribute('data-phishlens-locked');

			const lockedControls = form.querySelectorAll('[data-phishlens-disabled="true"]');
			lockedControls.forEach((control) => {
				const htmlControl = /** @type {HTMLInputElement} */ (control);
				htmlControl.removeAttribute('data-phishlens-disabled');
				htmlControl.removeAttribute('aria-disabled');
				htmlControl.disabled = false;
				htmlControl.style.pointerEvents = '';
				htmlControl.style.opacity = '';
				htmlControl.style.cursor = '';
			});

			const banner = form.querySelector('[data-phishlens-ui="lock-banner"]');
			if (banner) {
				banner.remove();
			}
		},

		/**
		 * Block submission definitively and display accessible warning with user options
		 * @param {HTMLFormElement} form
		 * @param {string} reason
		 * @param {string} destinationOrigin
		 */
		block(form, reason, destinationOrigin) {
			form.setAttribute('aria-busy', 'false');
			form.setAttribute('data-phishlens-blocked', 'true');

			// Lock all inputs, selects, textareas, and submit buttons permanently on block
			const controls = form.querySelectorAll('input:not([type="hidden"]), select, textarea, button');
			controls.forEach((control) => {
				const htmlControl = /** @type {HTMLInputElement} */ (control);
				htmlControl.setAttribute('data-phishlens-disabled', 'true');
				htmlControl.setAttribute('aria-disabled', 'true');
				htmlControl.setAttribute('disabled', 'true');
				htmlControl.setAttribute('readonly', 'true');
				htmlControl.setAttribute('tabindex', '-1');
				htmlControl.disabled = true;
				htmlControl.readOnly = true;
				htmlControl.style.setProperty('pointer-events', 'none', 'important');
				htmlControl.style.setProperty('opacity', '0.45', 'important');
				htmlControl.style.setProperty('cursor', 'not-allowed', 'important');
				htmlControl.style.setProperty('user-select', 'none', 'important');
				if (document.activeElement === htmlControl) htmlControl.blur();
			});

			// Mark page-level phishing lock active
			isPageFlaggedAsPhishing = true;

			let banner = form.querySelector('[data-phishlens-ui="lock-banner"]');
			if (!banner) {
				banner = document.createElement('div');
				banner.setAttribute('data-phishlens-ui', 'lock-banner');
				form.prepend(banner);
			}

			banner.setAttribute('role', 'alert');
			banner.setAttribute('aria-live', 'assertive');
			banner.style.cssText = `
				margin: 12px 0;
				padding: 14px 16px;
				border-radius: 8px;
				background: #450a0a;
				border: 2px solid #ef4444;
				color: #fee2e2;
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
				font-size: 13px;
				line-height: 1.5;
				display: flex;
				flex-direction: column;
				gap: 10px;
				box-shadow: 0 4px 6px -1px rgba(0,0,0,0.2);
				z-index: 10000;
			`;

			const safeRedactedDestination = _redactUrl(destinationOrigin || '');
			banner.innerHTML = `
				<div style="display: flex; align-items: flex-start; gap: 8px;">
					<span style="font-size: 20px; line-height: 1;">🚫</span>
					<div>
						<strong style="color: #fca5a5; font-size: 14px;">Submission Blocked by PhishLens</strong>
						<p style="margin: 4px 0 0 0; color: #fecaca;">${reason}</p>
						<p style="margin: 2px 0 0 0; font-size: 12px; color: #f87171;">Suspicious Destination: <code>${safeRedactedDestination}</code></p>
					</div>
				</div>
				<div style="display: flex; gap: 8px; margin-top: 4px; justify-content: flex-end; flex-wrap: wrap;">
					<button type="button" id="phishlens-btn-cancel" style="padding: 6px 12px; border-radius: 4px; border: 1px solid #7f1d1d; background: #7f1d1d; color: #fff; cursor: pointer; font-size: 12px; font-weight: 500;">
						Go Back
					</button>
					<button type="button" id="phishlens-btn-close" style="padding: 6px 12px; border-radius: 4px; border: 1px solid #991b1b; background: #dc2626; color: #fff; cursor: pointer; font-size: 12px; font-weight: 600;">
						Close Tab (Recommended)
					</button>
					<button type="button" id="phishlens-btn-override" style="padding: 6px 10px; border-radius: 4px; border: 1px solid transparent; background: transparent; color: #f87171; cursor: pointer; font-size: 11px; text-decoration: underline;">
						Proceed Anyway (Unsafe)
					</button>
				</div>
			`;

			// Wire up accessible actions
			banner.querySelector('#phishlens-btn-cancel').addEventListener('click', () => {
				if (window.history.length > 1) {
					window.history.back();
				} else {
					unlockEntirePageAfterUserOverride();
				}
			});

			banner.querySelector('#phishlens-btn-close').addEventListener('click', () => {
				chrome.runtime.sendMessage({ action: 'closeCurrentTab' });
			});

			banner.querySelector('#phishlens-btn-override').addEventListener('click', () => {
				unlockEntirePageAfterUserOverride();
				FormLockGuard.proceedWithNativeSubmit(form);
			});
		},

		/**
		 * Show a non-blocking caution banner for WARN verdict (suspicious but not confirmed phishing).
		 * Submission proceeds — user is informed but NOT blocked.
		 * @param {HTMLFormElement} form
		 * @param {string} reason
		 * @param {string} destinationOrigin
		 */
		showWarningBanner(form, reason, destinationOrigin) {
			let banner = form.querySelector('[data-phishlens-ui="warn-banner"]');
			if (banner) return;  // already shown

			banner = document.createElement('div');
			banner.setAttribute('data-phishlens-ui', 'warn-banner');
			banner.setAttribute('role', 'status');
			banner.setAttribute('aria-live', 'polite');
			banner.style.cssText = `
				margin: 10px 0;
				padding: 12px 14px;
				border-radius: 6px;
				background: #451a03;
				border: 1px solid #f59e0b;
				color: #fef3c7;
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
				font-size: 13px;
				display: flex;
				flex-direction: column;
				gap: 8px;
				z-index: 9999;
			`;
			banner.innerHTML = `
				<div style="display: flex; align-items: flex-start; gap: 8px;">
					<span style="font-size: 18px; line-height: 1;">⚡</span>
					<div>
						<strong style="color: #fde68a;">PhishLens Warning</strong>
						<p style="margin: 4px 0 0 0; color: #fef3c7;">${reason}</p>
					</div>
				</div>
				<div style="display: flex; justify-content: flex-end;">
					<button type="button" data-phishlens-dismiss style="padding: 4px 10px; border-radius: 4px; border: 1px solid #78350f; background: transparent; color: #fde68a; cursor: pointer; font-size: 11px;">Dismiss</button>
				</div>
			`;
			banner.querySelector('[data-phishlens-dismiss]').addEventListener('click', () => banner.remove());
			form.prepend(banner);
			setTimeout(() => { if (banner.isConnected) banner.remove(); }, 8000);
		},

		/**
		 * Show a dedicated "Unverified Destination" alert (Phase 5)
		 * Displayed when inspection hits a security check / bot challenge / 401 / 403.
		 * Never attempts to solve or bypass CAPTCHAs.
		 * @param {HTMLFormElement} form
		 * @param {string} reason
		 * @param {string} destinationOrigin
		 */
		showUnverifiedDestinationBanner(form, reason, destinationOrigin) {
			let banner = form.querySelector('[data-phishlens-ui="unverified-banner"]');
			if (banner) return;

			banner = document.createElement('div');
			banner.setAttribute('data-phishlens-ui', 'unverified-banner');
			banner.setAttribute('role', 'alert');
			banner.setAttribute('aria-live', 'assertive');
			banner.style.cssText = `
				margin: 12px 0;
				padding: 14px 16px;
				border-radius: 8px;
				background: #27272a;
				border: 2px solid #eab308;
				color: #fef08a;
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
				font-size: 13px;
				line-height: 1.5;
				display: flex;
				flex-direction: column;
				gap: 10px;
				z-index: 10000;
			`;

			banner.innerHTML = `
				<div style="display: flex; align-items: flex-start; gap: 8px;">
					<span style="font-size: 20px; line-height: 1;">🛡️</span>
					<div>
						<strong style="color: #fde047; font-size: 14px;">Unverified Destination</strong>
						<p style="margin: 4px 0 0 0; color: #fef9c3;">
							We couldn't verify the destination page because access is blocked by a security check. Treat this destination as unverified and proceed cautiously.
						</p>
						<p style="margin: 4px 0 0 0; font-size: 11px; color: #a1a1aa;">
							Target: <code>${destinationOrigin}</code>
						</p>
					</div>
				</div>
				<div style="display: flex; gap: 8px; justify-content: flex-end; margin-top: 4px;">
					<button type="button" id="phishlens-btn-unverified-cancel" style="padding: 5px 12px; border-radius: 4px; border: 1px solid #71717a; background: #3f3f46; color: #fff; cursor: pointer; font-size: 12px;">
						Cancel
					</button>
					<button type="button" id="phishlens-btn-unverified-proceed" style="padding: 5px 12px; border-radius: 4px; border: 1px solid #ca8a04; background: #eab308; color: #000; cursor: pointer; font-size: 12px; font-weight: 600;">
						Proceed with Caution
					</button>
				</div>
			`;

			banner.querySelector('#phishlens-btn-unverified-cancel').addEventListener('click', () => {
				banner.remove();
			});

			banner.querySelector('#phishlens-btn-unverified-proceed').addEventListener('click', () => {
				banner.remove();
				FormLockGuard.proceedWithNativeSubmit(form);
			});

			form.prepend(banner);
		},

		/**
		 * Fallback when service worker evaluation times out or is unreachable
		 * @param {HTMLFormElement} form
		 * @param {string} destinationOrigin
		 */
		showTimeoutFallback(form, destinationOrigin) {
			form.setAttribute('aria-busy', 'false');

			let banner = form.querySelector('[data-phishlens-ui="lock-banner"]');
			if (!banner) {
				banner = document.createElement('div');
				banner.setAttribute('data-phishlens-ui', 'lock-banner');
				form.prepend(banner);
			}

			banner.setAttribute('role', 'status');
			banner.setAttribute('aria-live', 'polite');
			banner.style.cssText = `
				margin: 10px 0;
				padding: 12px 14px;
				border-radius: 6px;
				background: #451a03;
				border: 1px solid #f59e0b;
				color: #fef3c7;
				font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
				font-size: 13px;
				display: flex;
				flex-direction: column;
				gap: 8px;
			`;

			banner.innerHTML = `
				<div style="display: flex; align-items: center; gap: 8px;">
					<span>⚠️</span>
					<span><strong>PhishLens:</strong> Unable to verify destination security in time (${destinationOrigin}). Proceed with caution.</span>
				</div>
				<div style="display: flex; gap: 8px; justify-content: flex-end;">
					<button type="button" id="phishlens-btn-cancel-timeout" style="padding: 4px 10px; border-radius: 4px; border: 1px solid #78350f; background: #78350f; color: #fff; cursor: pointer; font-size: 12px;">
						Cancel
					</button>
					<button type="button" id="phishlens-btn-proceed-timeout" style="padding: 4px 10px; border-radius: 4px; border: 1px solid #b45309; background: #d97706; color: #fff; cursor: pointer; font-size: 12px; font-weight: 600;">
						Proceed Anyway
					</button>
				</div>
			`;

			banner.querySelector('#phishlens-btn-cancel-timeout').addEventListener('click', () => {
				FormLockGuard.unlock(form);
			});

			banner.querySelector('#phishlens-btn-proceed-timeout').addEventListener('click', () => {
				FormLockGuard.unlock(form);
				FormLockGuard.proceedWithNativeSubmit(form);
			});
		},

		/**
		 * Safely dispatch native form submission bypassing recursive interception
		 * @param {HTMLFormElement} form
		 */
		proceedWithNativeSubmit(form) {
			form.__phishLensBypassSubmission = true;
			if (typeof form.requestSubmit === 'function') {
				try {
					form.requestSubmit(lastClickedSubmitButton || undefined);
				} catch {
					HTMLFormElement.prototype.submit.call(form);
				}
			} else {
				HTMLFormElement.prototype.submit.call(form);
			}
		}
	};

	/* ==========================================================================
	   PRE-SUBMISSION INTERCEPTION LISTENERS
	   ========================================================================== */

	// 1. Capture click on submit controls to track formaction overrides + Phase 4 click-redressing
	document.addEventListener('click', (e) => {
		const target = /** @type {HTMLElement} */ (e.target);
		if (!target || isExtensionUI(target)) return;

		// Track submit button clicked
		const btn = target.closest('button, input[type="submit"], input[type="image"], input[type="button"]');
		if (btn) {
			lastClickedSubmitButton = btn;
			lastClickedTime = Date.now();

			// If the button is inside a form and the form is not yet locked or bypassing, check if it's a submit action
			const form = btn.closest('form');
			if (form && !form.__phishLensBypassSubmission && !form.hasAttribute('data-phishlens-locked') && !form.hasAttribute('data-phishlens-blocked')) {
				const isSubmit = btn.type === 'submit' || !btn.type || (btn.tagName === 'INPUT' && btn.type === 'image');
				if (isSubmit) {
					// Check target action
					let targetAction = btn.getAttribute('formaction') || form.getAttribute('action') || form.action || '';
					const destinationOrigin = getSafeOrigin(targetAction) || window.location.origin;
					const formMeta = getSafeFormMetadata(form);
					formMeta.destinationOrigin = destinationOrigin;
					formMeta.isCrossOrigin = destinationOrigin !== window.location.origin;
					formMeta.isIdP = isKnownLegitimateIdP(destinationOrigin);

					if (formMeta.isSensitive || formMeta.isCrossOrigin) {
						e.preventDefault();
						e.stopImmediatePropagation();
						FormLockGuard.evaluateAndProtect(form, targetAction, destinationOrigin, formMeta);
						return;
					}
				}
			}
		}

		// Phase 4: Check for UI redressing on every click (non-blocking)
		if (_p4_runClickRedressingCheck) {
			_p4_runClickRedressingCheck(/** @type {MouseEvent} */ (e));
		}
	}, { capture: true });

	// 2. Capture-phase submission interception
	document.addEventListener('submit', (e) => {
		const form = /** @type {HTMLFormElement} */ (e.target);
		if (!form || isExtensionUI(form)) {
			return;
		}

		// Bypass flag allows verified submissions to proceed without recursion
		if (form.__phishLensBypassSubmission) {
			delete form.__phishLensBypassSubmission;
			return;
		}

		// Immediate pre-transmission destination re-check
		let targetAction = form.getAttribute('action') || form.action || '';
		if (lastClickedSubmitButton && (Date.now() - lastClickedTime < 1500)) {
			const formaction = lastClickedSubmitButton.getAttribute('formaction');
			if (formaction) {
				targetAction = formaction;
			}
		}

		const destinationOrigin = getSafeOrigin(targetAction) || window.location.origin;
		const formMeta = getSafeFormMetadata(form);
		formMeta.destinationOrigin = destinationOrigin;
		formMeta.isCrossOrigin = destinationOrigin !== window.location.origin;
		formMeta.isIdP = isKnownLegitimateIdP(destinationOrigin);

		// If form handles sensitive credentials or submits cross-origin, guard and evaluate
		if (formMeta.isSensitive || formMeta.isCrossOrigin) {
			e.preventDefault();
			e.stopImmediatePropagation();

			FormLockGuard.evaluateAndProtect(form, targetAction, destinationOrigin, formMeta);
		}
	}, { capture: true });

	/* ==========================================================================
	   USER INTERACTION TRACKING & CORRELATION (PHASE 1)
	   ========================================================================== */

	/**
	 * Record a user interaction event into the rolling history buffer
	 * PRIVACY: Never records keystrokes, typed text, or values!
	 * @param {Event} e
	 */
	function recordInteraction(e) {
		const target = /** @type {HTMLElement} */ (e.target);
		if (!target || isExtensionUI(target)) {
			return;
		}

		const tag = (target.tagName || '').toLowerCase();
		const type = target.getAttribute('type') || null;

		const record = {
			eventType: e.type,
			tagName: tag,
			inputType: type,
			elementId: target.id || null,
			elementName: target.getAttribute('name') || null,
			isFormElement: tag === 'form' || tag === 'input' || tag === 'button' || tag === 'select',
			isClickable: tag === 'a' || tag === 'button' || type === 'submit' || type === 'button',
			timestamp: Date.now()
		};

		if (tag === 'a' && target.hasAttribute('href')) {
			record.targetOrigin = getSafeOrigin(target.getAttribute('href'));
		}

		interactionHistory.push(record);
		if (interactionHistory.length > CONFIG.MAX_INTERACTION_HISTORY) {
			interactionHistory.shift();
		}
	}

	function getRecentInteraction(windowMs = CONFIG.CORRELATION_WINDOW_MS) {
		const now = Date.now();
		for (let i = interactionHistory.length - 1; i >= 0; i--) {
			const item = interactionHistory[i];
			const delta = now - item.timestamp;
			if (delta <= windowMs) {
				return { ...item, deltaMs: delta };
			}
		}
		return null;
	}

	['click', 'pointerdown', 'focusin', 'change'].forEach((eventType) => {
		document.addEventListener(eventType, recordInteraction, { capture: true, passive: true });
	});

	/* ==========================================================================
	   DYNAMIC DOM MUTATION OBSERVER (PHASE 1)
	   ========================================================================== */

	function inspectAddedNode(element) {
		if (isExtensionUI(element)) {
			return;
		}

		const tag = (element.tagName || '').toLowerCase();

		// 1. Dynamic form insertion
		if (tag === 'form') {
			const formMeta = getSafeFormMetadata(/** @type {HTMLFormElement} */ (element));
			trackedForms.set(element, {
				action: formMeta.actionUrl,
				method: formMeta.method
			});

			const recentInteraction = getRecentInteraction();
			emitBehavioralSignal({
				type: 'DYNAMIC_FORM_INSERTED',
				severity: formMeta.isCrossOrigin && formMeta.sensitiveFieldsCount > 0 ? 'high' : 'medium',
				details: {
					form: formMeta,
					recentInteraction,
					isCorrelatedWithInteraction: !!recentInteraction
				}
			});
		}

		// 2. Dynamic input element insertion
		if (tag === 'input') {
			const classification = classifyInputElement(/** @type {HTMLInputElement} */ (element));
			if (classification.isSensitive) {
				const recentInteraction = getRecentInteraction();
				emitBehavioralSignal({
					type: 'DYNAMIC_SENSITIVE_INPUT_INSERTED',
					severity: classification.severity || 'high',
					details: {
						category: classification.category,
						inputType: element.type,
						elementId: element.id || null,
						elementName: element.name || null,
						recentInteraction,
						isCorrelatedWithInteraction: !!recentInteraction
					}
				});
			}
		}

		// 3. Dynamic external script injection
		// Only flag if the script comes from an origin that is NOT a trusted same-org CDN.
		// Dedup by type+origin so multiple scripts from the same CDN don't each fire.
		if (tag === 'script') {
			const src = element.getAttribute('src');
			if (src) {
				const scriptOrigin = getSafeOrigin(src);
				if (scriptOrigin && scriptOrigin !== window.location.origin && !isTrustedSameOrgOrigin(scriptOrigin)) {
					// Dedup by type+origin (not full details) so the same CDN doesn't fire repeatedly
					const dedupKey = `DYNAMIC_EXTERNAL_SCRIPT_INJECTED_${scriptOrigin}`;
					if (!reportedSignalHashes.has(dedupKey)) {
						reportedSignalHashes.add(dedupKey);
						emitBehavioralSignal({
							type: 'DYNAMIC_EXTERNAL_SCRIPT_INJECTED',
							severity: 'medium',
							details: { scriptOrigin, hasCrossDomainScript: true }
						});
					}
				}
			}
		}

		// 4. Dynamic iframe injection
		// Only flag cross-origin iframes that are NOT trusted same-org embeds.
		// Same-origin iframes (about:blank, blob:, same-site) are routine SPA patterns.
		if (tag === 'iframe') {
			const src = element.getAttribute('src');
			if (src && src !== 'about:blank' && !src.startsWith('blob:') && !src.startsWith('javascript:')) {
				const iframeOrigin = getSafeOrigin(src);
				const isCrossOrigin = iframeOrigin && iframeOrigin !== window.location.origin;
				const isTrustedEmbed = isCrossOrigin && isTrustedSameOrgOrigin(iframeOrigin);
				if (isCrossOrigin && !isTrustedEmbed) {
					// Dedup by type+origin
					const dedupKey = `DYNAMIC_IFRAME_INJECTED_${iframeOrigin}`;
					if (!reportedSignalHashes.has(dedupKey)) {
						reportedSignalHashes.add(dedupKey);
						emitBehavioralSignal({
							type: 'DYNAMIC_IFRAME_INJECTED',
							severity: 'high',
							details: { iframeOrigin, isCrossOrigin: true }
						});
					}
				}
			}
		}

		// 5. Dynamic login overlay — only when it contains a password field
		if (element.classList && (
			element.classList.contains('modal') ||
			element.classList.contains('dialog') ||
			(element.id && element.id.toLowerCase().includes('login')) ||
			(element.id && element.id.toLowerCase().includes('modal'))
		)) {
			const hasSensitiveInputs = element.querySelector('input[type="password"]') !== null;
			if (hasSensitiveInputs) {
				const recentInteraction = getRecentInteraction();
				emitBehavioralSignal({
					type: 'DYNAMIC_LOGIN_MODAL_OVERLAY',
					severity: 'high',
					details: {
						overlayId: element.id || null,
						recentInteraction,
						isCorrelatedWithInteraction: !!recentInteraction
					}
				});
			}
		}

		// Subtree recursion — only recurse for forms and inputs, NOT scripts/iframes.
		// Scripts and iframes are already delivered as individual childList mutations
		// by MutationObserver when added inside a container; re-querying them here
		// would cause each one to be inspected twice → duplicate signals.
		if (element.children && element.children.length > 0) {
			element.querySelectorAll('form').forEach(inspectAddedNode);
			element.querySelectorAll('input').forEach(inspectAddedNode);
		}

		if (isPageFlaggedAsPhishing) {
			enforceInputLockdown();
		}
	}

	function inspectAttributeMutation(mutation) {
		const target = /** @type {HTMLElement} */ (mutation.target);
		if (!target || isExtensionUI(target)) {
			return;
		}

		const tag = (target.tagName || '').toLowerCase();
		const attrName = mutation.attributeName;

		// Form Action/Method modification
		if (tag === 'form') {
			const form = /** @type {HTMLFormElement} */ (target);
			const currentAction = form.getAttribute('action') || form.action || '';
			const currentMethod = (form.getAttribute('method') || 'GET').toUpperCase();

			const tracked = trackedForms.get(form) || {};
			const actionChanged = tracked.action !== undefined && tracked.action !== currentAction;
			const methodChanged = tracked.method !== undefined && tracked.method !== currentMethod;

			if (actionChanged || methodChanged) {
				const formMeta = getSafeFormMetadata(form);
				trackedForms.set(form, { action: currentAction, method: currentMethod });

				const recentInteraction = getRecentInteraction();
				emitBehavioralSignal({
					type: 'FORM_ACTION_MODIFIED',
					severity: formMeta.isCrossOrigin ? 'high' : 'medium',
					details: {
						previousAction: tracked.action || '',
						newAction: currentAction,
						destinationOrigin: formMeta.destinationOrigin,
						isCrossOrigin: formMeta.isCrossOrigin,
						method: currentMethod,
						sensitiveFieldsCount: formMeta.sensitiveFieldsCount,
						recentInteraction,
						isCorrelatedWithInteraction: !!recentInteraction
					}
				});
			}
		}

		// Hidden form or sensitive field becoming visible
		if (attrName === 'style' || attrName === 'class' || attrName === 'hidden') {
			if (isElementVisible(target)) {
				if (tag === 'form') {
					const formMeta = getSafeFormMetadata(/** @type {HTMLFormElement} */ (target));
					if (formMeta.sensitiveFieldsCount > 0) {
						const recentInteraction = getRecentInteraction();
						emitBehavioralSignal({
							type: 'HIDDEN_FORM_REVEALED',
							severity: formMeta.isCrossOrigin ? 'high' : 'medium',
							details: {
								form: formMeta,
								recentInteraction,
								isCorrelatedWithInteraction: !!recentInteraction
							}
						});
					}
				} else if (tag === 'input') {
					const classification = classifyInputElement(/** @type {HTMLInputElement} */ (target));
					if (classification.isSensitive) {
						const recentInteraction = getRecentInteraction();
						emitBehavioralSignal({
							type: 'HIDDEN_SENSITIVE_INPUT_REVEALED',
							severity: classification.severity || 'high',
							details: {
								category: classification.category,
								inputType: target.getAttribute('type'),
								elementId: target.id || null,
								recentInteraction,
								isCorrelatedWithInteraction: !!recentInteraction
							}
						});
					}
				}
			}
		}
	}

	function processMutationBatch() {
		const mutations = pendingMutations;
		pendingMutations = [];
		batchTimer = null;

		for (const mutation of mutations) {
			if (mutation.type === 'childList') {
				mutation.addedNodes.forEach((node) => {
					if (node.nodeType === Node.ELEMENT_NODE) {
						inspectAddedNode(/** @type {HTMLElement} */ (node));
					}
				});
			} else if (mutation.type === 'attributes') {
				inspectAttributeMutation(mutation);
			}
		}

		// Phase 4: re-scan for new overlays/images after significant DOM updates
		if (_p4_rescanOnMutation) {
			_p4_rescanOnMutation();
		}
	}

	function queueMutations(mutations) {
		for (const m of mutations) {
			if (!isExtensionUI(m.target)) {
				pendingMutations.push(m);
			}
		}

		if (!batchTimer && pendingMutations.length > 0) {
			batchTimer = setTimeout(processMutationBatch, CONFIG.BATCH_DELAY_MS);
		}
	}

	/* ==========================================================================
	   OBSERVER INITIALIZATION
	   ========================================================================== */

	function initObserver() {
		document.querySelectorAll('form').forEach((form) => {
			trackedForms.set(form, {
				action: form.getAttribute('action') || form.action || '',
				method: (form.getAttribute('method') || 'GET').toUpperCase()
			});
		});

		const observer = new MutationObserver(queueMutations);
		const targetNode = document.documentElement || document;
		observer.observe(targetNode, {
			childList: true,
			subtree: true,
			attributes: true,
			attributeFilter: ['action', 'method', 'style', 'class', 'hidden', 'type']
		});
	}

	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', initObserver, { once: true });
	} else {
		initObserver();
	}

	/* ==========================================================================
	   PHASE 4: VISUAL THREAT DETECTION (inlined from detectors/visual-threat-detector.js)
	   ========================================================================== */

	// --- Shared state & utilities ---
	const _reportedVisualHashes = new Set();
	const OVERLAY_MIN_OVERLAP_FRACTION = 0.25;
	const OVERLAY_HIGH_Z_THRESHOLD = 50;
	const BRAND_KEYWORDS = [
		'paypal', 'amazon', 'apple', 'google', 'microsoft', 'facebook', 'instagram',
		'netflix', 'bank of america', 'wellsfargo', 'chase', 'citibank', 'hsbc',
		'barclays', 'twitter', 'x.com', 'dropbox', 'linkedin', 'whatsapp',
		'docusign', 'adobe', 'salesforce', 'coinbase', 'binance', 'kraken'
	];
	const CREDENTIAL_PROMPT_KEYWORDS = [
		'sign in', 'sign-in', 'signin', 'log in', 'log-in', 'login', 'password',
		'verify identity', 'verify your account', 'account verification', 'confirm your identity',
		'secure login', 'authentication required', 'enter credentials', 'update password',
		'your session has expired', 'account suspended', 'verify your email',
		'click here to verify', 'confirm payment', 'verify payment'
	];
	const BENIGN_OVERLAY_PATTERNS = [
		/cookie/i, /consent/i, /gdpr/i, /banner/i, /toast/i, /notification/i,
		/snackbar/i, /tooltip/i, /dropdown/i, /autocomplete/i, /navbar/i,
		/header/i, /nav/i, /sticky/i, /fixed-top/i, /skip-to/i
	];

	function _emitVisualSignal(signal) {
		const hash = `VISUAL_${signal.type}_${JSON.stringify(signal.details).slice(0, 180)}`;
		if (_reportedVisualHashes.has(hash)) return;
		_reportedVisualHashes.add(hash);
		emitBehavioralSignal(signal);
	}

	function _overlapFraction(a, b) {
		const ix = Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left));
		const iy = Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
		const bArea = b.width * b.height;
		return bArea > 0 ? (ix * iy) / bArea : 0;
	}

	function _isBenignOverlay(el) {
		const combined = `${el.id || ''} ${el.className || ''}`;
		return BENIGN_OVERLAY_PATTERNS.some(p => p.test(combined));
	}

	function _isVisibleEl(el) {
		if (!el || !(el instanceof HTMLElement)) return false;
		if (el.hidden) return false;
		const s = window.getComputedStyle(el);
		if (s.display === 'none' || s.visibility === 'hidden' || s.opacity === '0') return false;
		return el.offsetWidth > 0 || el.offsetHeight > 0;
	}

	// --- Detector A: Clickjacking ---
	function _detectClickjackingOverlays() {
		const targets = Array.from(document.querySelectorAll(
			'input[type="submit"],button[type="submit"],button:not([type]),input[type="password"],input[type="email"],a[href]'
		)).filter(_isVisibleEl).slice(0, 40);
		if (!targets.length) return;

		const candidates = Array.from(document.querySelectorAll('*')).filter(el => {
			if (el.closest('[data-phishlens-ui]') || !_isVisibleEl(el) || _isBenignOverlay(el)) return false;
			const s = window.getComputedStyle(el);
			if (!['fixed', 'absolute', 'sticky'].includes(s.position)) return false;
			const z = parseInt(s.zIndex, 10);
			return !isNaN(z) && z >= OVERLAY_HIGH_Z_THRESHOLD;
		});

		for (const target of targets) {
			const tr = target.getBoundingClientRect();
			if (!tr.width || !tr.height) continue;
			for (const ov of candidates) {
				if (ov === target || ov.contains(target)) continue;
				const fraction = _overlapFraction(ov.getBoundingClientRect(), tr);
				if (fraction < OVERLAY_MIN_OVERLAP_FRACTION) continue;
				const s = window.getComputedStyle(ov);
				const opacity = parseFloat(s.opacity);
				const pointerEvents = s.pointerEvents;
				if (pointerEvents === 'none' && opacity >= 0.15) continue;
				_emitVisualSignal({
					type: 'CLICKJACKING_OVERLAY_DETECTED',
					severity: opacity < 0.15 ? 'high' : 'medium',
					details: {
						targetTag: target.tagName.toLowerCase(),
						targetId: target.id || null,
						overlayTag: ov.tagName.toLowerCase(),
						overlayId: ov.id || null,
						overlayClass: (ov.className || '').toString().slice(0, 60),
						overlayZIndex: parseInt(s.zIndex, 10),
						overlayOpacity: opacity,
						overlayPosition: s.position,
						overlapPercent: Math.round(fraction * 100),
						isTransparent: opacity < 0.15,
						isPointerActive: pointerEvents !== 'none'
					}
				});
			}
		}
	}

	function _checkClickRedressing(e) {
		const clicked = /** @type {HTMLElement} */ (e.target);
		if (!clicked || clicked.closest('[data-phishlens-ui]')) return;
		const top = document.elementFromPoint(e.clientX, e.clientY);
		if (!top || top === clicked || clicked.contains(top)) return;
		const s = window.getComputedStyle(top);
		const z = parseInt(s.zIndex, 10);
		const op = parseFloat(s.opacity);
		if (z >= OVERLAY_HIGH_Z_THRESHOLD && op < 0.15) {
			_emitVisualSignal({
				type: 'CLICK_REDRESSING_DETECTED',
				severity: 'high',
				details: {
					clickedTag: clicked.tagName.toLowerCase(),
					clickedId: clicked.id || null,
					topElementTag: top.tagName.toLowerCase(),
					topElementId: top.id || null,
					topZIndex: z,
					topOpacity: op
				}
			});
		}
	}

	// --- Detector B: QR-Code Phishing ---
	function _redactUrl(u) {
		try {
			const p = new URL(u);
			const sk = ['token','password','key','secret','auth','session','code','sig','access_token','id_token','bearer','api_key'];
			for (const k of Array.from(p.searchParams.keys())) {
				if (sk.some(s => k.toLowerCase().includes(s))) p.searchParams.set(k, '[REDACTED]');
			}
			if (p.hash && (p.hash.includes('=') || p.hash.length > 20)) p.hash = '#[REDACTED]';
			return p.toString();
		} catch { return u.split('?')[0]; }
	}

	function _decodeQRFromImageData(imageData) {
		const jsQR = window.__phishLens_jsQR;
		if (typeof jsQR !== 'function') return { data: null, error: 'qr-decoder-not-available' };
		try {
			const r = jsQR(imageData.data, imageData.width, imageData.height);
			return r && r.data ? { data: r.data } : { data: null, error: 'no-qr-found' };
		} catch (e) { return { data: null, error: `jsqr-error:${e.message}` }; }
	}

	function _tryDecodeFromImg(img) {
		if (!img.complete || !img.naturalWidth) return { data: null, error: 'not-loaded' };
		try {
			const c = document.createElement('canvas');
			c.width = img.naturalWidth; c.height = img.naturalHeight;
			const ctx = c.getContext('2d');
			if (!ctx) return { data: null, error: 'no-ctx' };
			ctx.drawImage(img, 0, 0, c.width, c.height);
			return _decodeQRFromImageData(ctx.getImageData(0, 0, c.width, c.height));
		} catch (e) {
			return { data: null, error: e instanceof DOMException && e.name === 'SecurityError' ? 'cors-tainted-canvas' : `err:${e.message}` };
		}
	}

	function _tryDecodeFromCanvas(canvas) {
		try {
			const ctx = canvas.getContext('2d');
			if (!ctx) return { data: null, error: 'no-ctx' };
			return _decodeQRFromImageData(ctx.getImageData(0, 0, canvas.width, canvas.height));
		} catch (e) {
			return { data: null, error: e instanceof DOMException && e.name === 'SecurityError' ? 'cors-tainted-canvas' : `err:${e.message}` };
		}
	}

	function _detectQRCodePhishing() {
		const candidates = [];
		for (const img of document.querySelectorAll('img')) {
			const meta = `${img.alt||''} ${img.title||''} ${img.className||''} ${img.id||''}`.toLowerCase();
			const isQRKw = /(qr|q\.r\.|quick.?response|scan.?code|scan.?me|scan.?to)/i.test(meta);
			const sq = img.naturalWidth > 0 && img.naturalHeight > 0 && Math.abs(img.naturalWidth/img.naturalHeight - 1) < 0.1;
			const big = img.naturalWidth >= 80 || (img.width >= 80 && img.height >= 80);
			if (isQRKw && big) candidates.push({ element: img, reason: 'qr-keyword', sq });
			else if (sq && big && img.naturalWidth <= 400) candidates.push({ element: img, reason: 'square-heuristic', sq });
		}
		for (const cv of document.querySelectorAll('canvas')) {
			const meta = `${cv.id||''} ${cv.className||''}`.toLowerCase();
			const isQRKw = /(qr|q\.r\.|quick.?response|scan.?code)/i.test(meta);
			const sq = cv.width > 0 && cv.height > 0 && Math.abs(cv.width/cv.height - 1) < 0.1;
			if ((isQRKw || sq) && cv.width >= 80) candidates.push({ element: cv, reason: isQRKw ? 'qr-keyword-canvas' : 'square-canvas', sq });
		}
		for (const { element, reason } of candidates) {
			const res = element.tagName === 'IMG' ? _tryDecodeFromImg(element) : _tryDecodeFromCanvas(element);
			if (res.data) {
				let isUrl = false, sanitized = null;
				try { new URL(res.data); isUrl = true; sanitized = _redactUrl(res.data); } catch {}
				_emitVisualSignal({
					type: isUrl ? 'QR_CODE_URL_DETECTED' : 'QR_CODE_DATA_DETECTED',
					severity: isUrl ? 'high' : 'medium',
					details: {
						reason, sanitizedUrl: sanitized,
						rawDataLength: res.data.length,
						tag: element.tagName.toLowerCase(),
						alt: element instanceof HTMLImageElement ? (element.alt || null) : null
					}
				});
				if (isUrl && sanitized) {
					try {
						chrome.runtime.sendMessage({ action: 'evaluateQRUrl',
							payload: { sanitizedUrl: sanitized, pageUrl: window.location.href, pageOrigin: window.location.origin }
						}, () => { if (chrome.runtime.lastError) {} });
					} catch {}
				}
			} else {
				_emitVisualSignal({
					type: 'QR_CODE_CANDIDATE_UNVERIFIED',
					severity: 'low',
					details: {
						reason, decodeError: res.error,
						isCORSBlocked: res.error === 'cors-tainted-canvas',
						tag: element.tagName.toLowerCase(),
						note: 'QR decode failed or decoder unavailable. Status: UNVERIFIED — not assumed safe or malicious.'
					}
				});
			}
		}
	}

	// --- Detector C: Image-based Impersonation ---
	function _detectImageImpersonation() {
		const host = window.location.hostname.toLowerCase();
		for (const img of document.querySelectorAll('img')) {
			if ((img.offsetWidth || img.width) < 150 || (img.offsetHeight || img.height) < 60) continue;
			const alt = (img.alt || '').toLowerCase();
			const ariaLabel = (img.getAttribute('aria-label') || '').toLowerCase();
			const fig = img.closest('figure');
			const cap = fig ? (fig.querySelector('figcaption') || {}).textContent || '' : '';
			const parent = img.parentElement;
			const surrounding = parent ? (parent.textContent || '').toLowerCase().slice(0, 200) : '';
			const allMeta = `${alt} ${ariaLabel} ${cap.toLowerCase()} ${surrounding}`;

			const brands = BRAND_KEYWORDS.filter(b => allMeta.includes(b));
			const prompts = CREDENTIAL_PROMPT_KEYWORDS.filter(k => allMeta.includes(k));
			if (!brands.length && !prompts.length) continue;

			const brandOnOwnDomain = brands.some(b => host.includes(b.split(' ')[0].replace(/[^a-z0-9]/g, '')));
			const isBrandImpersonation = brands.length > 0 && !brandOnOwnDomain;
			if (!isBrandImpersonation && !prompts.length) continue;

			_emitVisualSignal({
				type: isBrandImpersonation ? 'IMAGE_BRAND_IMPERSONATION_DETECTED' : 'IMAGE_CREDENTIAL_PROMPT_DETECTED',
				severity: isBrandImpersonation ? 'high' : 'medium',
				details: {
					alt: alt.slice(0, 80) || null,
					detectedBrands: brands.slice(0, 5),
					detectedPrompts: prompts.slice(0, 5),
					brandOnOwnDomain,
					pageHostname: host,
					imgSrc: img.src ? img.src.split('?')[0].slice(0, 100) : null
				}
			});
		}
	}

	// --- Wire up Phase 4 functions ---
	_p4_runClickRedressingCheck = _checkClickRedressing;

	let _p4_lastRescan = 0;
	_p4_rescanOnMutation = () => {
		const now = Date.now();
		if (now - _p4_lastRescan < 2000) return;
		_p4_lastRescan = now;
		if (typeof requestIdleCallback === 'function') {
			requestIdleCallback(() => { _detectClickjackingOverlays(); _detectImageImpersonation(); }, { timeout: 3000 });
		}
	};

	_p4_runVisualThreatDetection = () => {
		const run = () => {
			_detectClickjackingOverlays();
			_detectQRCodePhishing();
			_detectImageImpersonation();
		};
		if (typeof requestIdleCallback === 'function') {
			requestIdleCallback(run, { timeout: 4000 });
		} else {
			setTimeout(run, 1000);
		}
	};

	// Phase 5: Client-side Interstitial & Bot Challenge Detector
	function _checkClientInterstitial() {
		const title = (document.title || '').toLowerCase();
		const bodyText = (document.body ? document.body.innerText || '' : '').toLowerCase().slice(0, 3000);

		const botKeywords = [
			'just a moment...',
			'attention required! | cloudflare',
			'security check',
			'verify you are human',
			'ddos-guard',
			'hcaptcha challenge',
			'recaptcha',
			'checking your browser before accessing',
			'cf-browser-verification'
		];

		const matched = botKeywords.find(kw => title.includes(kw) || bodyText.includes(kw));
		if (matched) {
			emitBehavioralSignal({
				type: 'INTERSTITIAL_CAPTCHA_DETECTED',
				severity: 'medium',
				confidence: 0.95,
				details: {
					matchedKeyword: matched,
					title: document.title,
					reason: "We couldn't verify the destination page because access is blocked by a security check. Treat this destination as unverified and proceed cautiously."
				}
			});
		}
	}

	/**
	 * Pre-emptively lock all forms, inputs, and interactive fields across the entire page
	 * when the site is verified as phishing.
	 * Prevents any credential entry before submission is even attempted.
	 */
	function lockEntirePageFormsDueToPhishing() {
		isPageFlaggedAsPhishing = true;

		// 1. Lock all form tags with accessible warning and override options
		const forms = document.querySelectorAll('form');
		forms.forEach((f) => {
			FormLockGuard.block(
				f,
				'This website has been identified as a dangerous phishing threat. All input fields have been locked to protect your data.',
				window.location.origin
			);
		});

		// 2. Lock ALL inputs, textareas, selects, editable areas, and buttons on the entire page
		// (including standalone inputs, frameless login boxes, and custom components)
		enforceInputLockdown();

		// 3. Ensure a persistent page-wide banner is rendered at the top of the viewport
		ensureGlobalPhishingBanner();

		// 4. Start interval enforcement to defeat dynamic mutation / script re-enablement
		if (!phishingLockInterval) {
			phishingLockInterval = setInterval(() => {
				if (!isPageFlaggedAsPhishing) {
					clearInterval(phishingLockInterval);
					phishingLockInterval = null;
					return;
				}
				enforceInputLockdown();
			}, 350);
		}
	}

	function enforceInputLockdown() {
		if (!isPageFlaggedAsPhishing) return;
		const allControls = document.querySelectorAll('input:not([type="hidden"]), select, textarea, [contenteditable="true"], button');
		allControls.forEach((control) => {
			if (isExtensionUI(control)) return;

			const htmlEl = /** @type {HTMLElement} */ (control);
			htmlEl.setAttribute('data-phishlens-disabled', 'true');
			htmlEl.setAttribute('aria-disabled', 'true');
			htmlEl.setAttribute('disabled', 'true');
			htmlEl.setAttribute('readonly', 'true');
			htmlEl.setAttribute('tabindex', '-1');

			if ('disabled' in htmlEl) {
				/** @type {HTMLInputElement} */ (htmlEl).disabled = true;
			}
			if ('readOnly' in htmlEl) {
				/** @type {HTMLInputElement} */ (htmlEl).readOnly = true;
			}

			htmlEl.style.setProperty('pointer-events', 'none', 'important');
			htmlEl.style.setProperty('opacity', '0.45', 'important');
			htmlEl.style.setProperty('cursor', 'not-allowed', 'important');
			htmlEl.style.setProperty('user-select', 'none', 'important');

			// If any element is currently focused, blur it immediately
			if (document.activeElement === htmlEl) {
				htmlEl.blur();
			}
		});
	}

	/**
	 * Intercept ALL keyboard typing, pasting, dropping, and input events at the capture phase.
	 * This guarantees that even if an input element lacks disabled styling or was focused,
	 * NOT A SINGLE KEYSTROKE OR CLIPBOARD CHARACTER can be entered into any form field.
	 */
	function interceptAllInputsWhenPhishing(e) {
		if (!isPageFlaggedAsPhishing) return;
		if (e.target && isExtensionUI(e.target)) return;

		const target = /** @type {HTMLElement} */ (e.target);
		const tag = (target && target.tagName ? target.tagName.toLowerCase() : '');
		const isInputTarget = tag === 'input' || tag === 'textarea' || tag === 'select' || (target && target.isContentEditable);

		if (isInputTarget || e.type === 'paste' || e.type === 'drop') {
			e.preventDefault();
			e.stopPropagation();
			e.stopImmediatePropagation();
			if (target && typeof target.blur === 'function') {
				target.blur();
			}
			return false;
		}
	}

	const CAPTURE_INTERCEPT_EVENTS = [
		'keydown', 'keypress', 'keyup', 'beforeinput', 'input',
		'compositionstart', 'compositionupdate', 'compositionend',
		'paste', 'drop', 'cut'
	];
	CAPTURE_INTERCEPT_EVENTS.forEach((evtName) => {
		window.addEventListener(evtName, interceptAllInputsWhenPhishing, { capture: true, passive: false });
		document.addEventListener(evtName, interceptAllInputsWhenPhishing, { capture: true, passive: false });
	});

	function ensureGlobalPhishingBanner() {
		if (document.getElementById('phishlens-global-phishing-banner')) return;
		const banner = document.createElement('div');
		banner.id = 'phishlens-global-phishing-banner';
		banner.setAttribute('data-phishlens-ui', 'global-banner');
		banner.setAttribute('role', 'alert');
		banner.setAttribute('aria-live', 'assertive');
		banner.style.cssText = `
			position: fixed !important;
			top: 0 !important;
			left: 0 !important;
			width: 100% !important;
			z-index: 2147483647 !important;
			background: linear-gradient(90deg, #991b1b, #7f1d1d) !important;
			color: #ffffff !important;
			padding: 12px 20px !important;
			font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
			font-size: 14px !important;
			line-height: 1.4 !important;
			box-shadow: 0 4px 15px rgba(0,0,0,0.5) !important;
			display: flex !important;
			align-items: center !important;
			justify-content: space-between !important;
			box-sizing: border-box !important;
			gap: 16px !important;
		`;
		banner.innerHTML = `
			<div style="display: flex; align-items: center; gap: 12px;">
				<span style="font-size: 22px;">🛡️</span>
				<div>
					<strong style="font-size: 15px; color: #fecaca;">PhishLens Security Alert: Phishing Site Detected</strong>
					<div style="color: #fee2e2; font-size: 13px; margin-top: 2px;">
						This site is flagged as dangerous phishing. All input fields and forms have been locked to protect your data.
					</div>
				</div>
			</div>
			<div style="display: flex; gap: 10px; align-items: center; flex-shrink: 0;">
				<button type="button" id="phishlens-global-goback" style="background: #374151; color: #fff; border: 1px solid #4b5563; padding: 6px 14px; border-radius: 6px; font-size: 13px; font-weight: 500; cursor: pointer;">
					Go Back
				</button>
				<button type="button" id="phishlens-global-closetab" style="background: #dc2626; color: #fff; border: 1px solid #b91c1c; padding: 6px 14px; border-radius: 6px; font-size: 13px; font-weight: 600; cursor: pointer;">
					Close Tab
				</button>
				<button type="button" id="phishlens-global-override" style="background: transparent; color: #fca5a5; border: none; text-decoration: underline; padding: 4px 8px; font-size: 12px; cursor: pointer;">
					Proceed Anyway (Unsafe)
				</button>
			</div>
		`;
		(document.body || document.documentElement).prepend(banner);

		const goBackBtn = banner.querySelector('#phishlens-global-goback');
		if (goBackBtn) {
			goBackBtn.addEventListener('click', () => {
				if (window.history.length > 1) {
					window.history.back();
				} else {
					chrome.runtime.sendMessage({ action: 'closeCurrentTab' });
				}
			});
		}

		const closeTabBtn = banner.querySelector('#phishlens-global-closetab');
		if (closeTabBtn) {
			closeTabBtn.addEventListener('click', () => {
				chrome.runtime.sendMessage({ action: 'closeCurrentTab' });
			});
		}

		const overrideBtn = banner.querySelector('#phishlens-global-override');
		if (overrideBtn) {
			overrideBtn.addEventListener('click', () => {
				unlockEntirePageAfterUserOverride();
			});
		}
	}

	function unlockEntirePageAfterUserOverride() {
		isPageFlaggedAsPhishing = false;
		if (phishingLockInterval) {
			clearInterval(phishingLockInterval);
			phishingLockInterval = null;
		}
		const banner = document.getElementById('phishlens-global-phishing-banner');
		if (banner) banner.remove();

		// Unlock all form elements
		const lockedControls = document.querySelectorAll('[data-phishlens-disabled="true"]');
		lockedControls.forEach((control) => {
			const htmlControl = /** @type {HTMLElement} */ (control);
			htmlControl.removeAttribute('data-phishlens-disabled');
			htmlControl.removeAttribute('aria-disabled');
			htmlControl.removeAttribute('disabled');
			htmlControl.removeAttribute('readonly');
			htmlControl.removeAttribute('tabindex');
			if ('disabled' in htmlControl) /** @type {HTMLInputElement} */ (htmlControl).disabled = false;
			if ('readOnly' in htmlControl) /** @type {HTMLInputElement} */ (htmlControl).readOnly = false;
			htmlControl.style.removeProperty('pointer-events');
			htmlControl.style.removeProperty('opacity');
			htmlControl.style.removeProperty('cursor');
			htmlControl.style.removeProperty('user-select');
		});

		const forms = document.querySelectorAll('form[data-phishlens-blocked="true"]');
		forms.forEach(f => FormLockGuard.unlock(f));
	}

	// Listen for immediate lock notification from background worker
	chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
		if (msg.action === 'lockAllFormsDueToPhishing') {
			lockEntirePageFormsDueToPhishing();
			sendResponse({ status: 'locked' });
		}
	});

	// Check on page load if this domain is already confirmed as phishing
	function checkAndEnforceDomainPhishState() {
		try {
			// 1. Direct local storage check for instant zero-latency lockdown
			chrome.storage.local.get([window.location.hostname], (res) => {
				if (res && res[window.location.hostname] && res[window.location.hostname].status === 'phishing') {
					lockEntirePageFormsDueToPhishing();
				}
			});
		} catch (e) {}

		// 2. Background service worker query with retries
		let retryCount = 0;
		const maxRetries = 6;
		function queryWorker() {
			try {
				chrome.runtime.sendMessage({
					action: 'getCheckResult',
					domain: window.location.hostname,
					fullUrl: window.location.href
				}, (resp) => {
					if (resp && resp.phish === 'phishing') {
						lockEntirePageFormsDueToPhishing();
					} else if ((!resp || !resp.phish) && retryCount < maxRetries) {
						retryCount++;
						setTimeout(queryWorker, retryCount * 400);
					}
				});
			} catch (e) {}
		}
		queryWorker();
	}

	// Launch Phase 4, Phase 5 & Proactive Phishing Form Locking
	if (document.readyState === 'loading') {
		document.addEventListener('DOMContentLoaded', () => {
			_checkPageTestScenarioMeta();
			checkAndEnforceDomainPhishState();
			_checkClientInterstitial();
			_p4_runVisualThreatDetection();
		}, { once: true });
	} else {
		_checkPageTestScenarioMeta();
		checkAndEnforceDomainPhishState();
		_checkClientInterstitial();
		_p4_runVisualThreatDetection();
	}

	/**
	 * Developer test-mode meta tag detection.
	 *
	 * Pages under test can embed a <meta> tag that explicitly declares their scenario type.
	 * This bypasses URL-based classification (which would whitelist trusted hosts like github.io).
	 *
	 * Usage in a test/mock HTML page:
	 *   <meta name="x-phishlens-scenario" content="phishing">
	 *   <meta name="x-phishlens-scenario" content="suspicious">
	 *   <meta name="x-phishlens-scenario" content="unverified">
	 *   <meta name="x-phishlens-scenario" content="benign">
	 *
	 * The extension reads this ONLY on page load and treats it as an authoritative
	 * developer-declared ground-truth for the page's threat type.
	 */
	function _checkPageTestScenarioMeta() {
		const metaTag = document.querySelector('meta[name="x-phishlens-scenario"]');
		if (!metaTag) return;

		const scenario = (metaTag.getAttribute('content') || '').trim().toLowerCase();
		if (!scenario) return;

		console.log('[PhishLens Test Mode] Meta scenario declared:', scenario, 'on', window.location.href);

		if (scenario === 'phishing') {
			lockEntirePageFormsDueToPhishing();
			// Store an explicit test verdict so the popup agrees with the page lockdown.
			try {
				chrome.runtime.sendMessage({
					action: 'forcePhishVerdict',
					domain: window.location.hostname
				});
			} catch (e) {}
			// Also record the scenario as a behavioral signal for the report panel.
			try {
				chrome.runtime.sendMessage({
					action: 'behavioralThreatSignal',
					payload: {
						type: 'TEST_SCENARIO_PHISHING_DECLARED',
						severity: 'critical',
						confidence: 1.0,
						url: window.location.href,
						details: {
							source: 'x-phishlens-scenario meta tag',
							scenarioFile: window.location.pathname
						}
					}
				});
			} catch (e) {}
		} else if (scenario === 'suspicious') {
			emitBehavioralSignal({
				type: 'TEST_SCENARIO_SUSPICIOUS_DECLARED',
				severity: 'high',
				confidence: 0.9,
				details: { source: 'x-phishlens-scenario meta tag', scenarioFile: window.location.pathname }
			});
		} else if (scenario === 'unverified') {
			emitBehavioralSignal({
				type: 'INTERSTITIAL_CAPTCHA_DETECTED',
				severity: 'medium',
				confidence: 0.95,
				details: {
					matchedKeyword: 'test-scenario',
					title: document.title,
					reason: "We couldn't verify the destination page because access is blocked by a security check. Treat this destination as unverified and proceed cautiously."
				}
			});
		} else if (scenario === 'benign') {
			// No action — benign pages should not be flagged
			console.log('[PhishLens Test Mode] Benign scenario — no threat signals emitted');
		}
	}

})();
