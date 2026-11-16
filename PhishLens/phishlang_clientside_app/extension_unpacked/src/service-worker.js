/**
 * PhishLens Service Worker (Manifest V3)
 *
 * Includes:
 * Phase 1: Ingestion & Tab-level indexing of Behavioral Threat Signals
 * Phase 2: Form submission risk evaluation & IdP verification
 * Phase 3: Manifest V3 Network & Redirect Monitoring (webNavigation, webRequest correlation, DNR dynamic blocking)
 *
 * ============================================================================
 * MANIFEST V3 SECURITY ARCHITECTURE & LIMITATIONS:
 * ============================================================================
 * 1. Blocking Limitations:
 *    - In Manifest V3, `chrome.webRequestBlocking` is deprecated and unavailable for standard extensions.
 *    - Network-level blocking is strictly declarative via `chrome.declarativeNetRequest`.
 *    - To protect users before data leaves the browser, PhishLens employs a two-tier strategy:
 *      a) Content-Script Pre-Submission Interception (Phase 2): Intercepts the DOM submit event
 *         in the capture phase to cancel malicious form submissions at the renderer level before transmission.
 *      b) Declarative Net Request (DNR) Rules (Phase 3): Automatically registers dynamic redirect
 *         rules to steer navigations to confirmed phishing domains directly to `public/phishing.html`.
 *
 * 2. Observational Telemetry:
 *    - `chrome.webNavigation`: Observes navigation lifecycles, redirect chains, transition qualifiers,
 *      and multi-hop domain jumps across external origins.
 *    - `chrome.webRequest`: Non-blocking observation of subresource requests (fetch/XHR/beacons)
 *      correlated with user interaction timestamps to detect out-of-band credential exfiltration.
 *
 * 3. Privacy & Sanitization:
 *    - All observed URLs have query secrets (tokens, passwords, signatures, auth codes) redacted
 *      before logging, storage, or telemetry.
 * ============================================================================
 */

import { logGroupEventAsync, logResponse, onPhishStatusAsync } from './utils.js';
import { whitelist } from './whitelist.js';
import {
	computeRiskScore,
	computeUnifiedRiskScore,
	toSubmissionGuardResponse,
	derivePageStatusFromSignals,
	isKnownLegitimateDestination,
	detectInterstitialOrCaptcha,
	createTypedEvidence,
} from './risk-engine.js';

/** @type {Record<string,string>} */
const urlCheckResults = {};
/** @type {Map<string,boolean>} */
const whitelistMap = new Map();
/** @type {Record<number, Array<object>>} */
const tabBehavioralSignals = {};
/** @type {Record<number, { chain: Array<string>, startTime: number, lastCommittedUrl: string }>} */
const navigationChains = {};

class PhishResult {
	/**
	 * @param {boolean} isUserWhitelisted
	 * @param {boolean} isGloballyWhitelisted
	 * @param {'safe'|'suspicious'|'phishing'} status
	 */
	constructor(isUserWhitelisted, isGloballyWhitelisted, status) {
		this.isUserWhitelisted = isUserWhitelisted;
		this.isGloballyWhitelisted = isGloballyWhitelisted;
		this.status = status;
	}

	get isWhitelisted() {
		return this.isUserWhitelisted || this.isGloballyWhitelisted;
	}

	static asUserWhitelisted = new PhishResult(true, false, 'safe');
	static asGloballyWhitelisted = new PhishResult(false, true, 'safe');
	static asSafe = new PhishResult(false, false, 'safe');
	static asSuspicious = new PhishResult(false, false, 'suspicious');
	static asPhishing = new PhishResult(false, false, 'phishing');
	static asUnverified = new PhishResult(false, false, 'unverified');
}

/* ==========================================================================
   PRIVACY: QUERY PARAMETER & TOKEN REDACTION
   ========================================================================== */

/**
 * Redact sensitive query parameters and URL fragments to protect user privacy.
 * @param {string} urlString
 * @returns {string}
 */
function sanitizeAndRedactUrl(urlString) {
	if (!urlString) return '';
	try {
		const parsed = new URL(urlString);
		const sensitiveKeys = ['token', 'password', 'passwd', 'pwd', 'key', 'secret', 'auth', 'session', 'code', 'sig', 'signature', 'credential', 'access_token', 'id_token', 'bearer', 'api_key', 'apikey'];

		for (const key of Array.from(parsed.searchParams.keys())) {
			const lowerKey = key.toLowerCase();
			const isSensitive = sensitiveKeys.some(sk => lowerKey.includes(sk));
			if (isSensitive) {
				parsed.searchParams.set(key, '[REDACTED]');
			}
		}

		if (parsed.hash && (parsed.hash.includes('=') || parsed.hash.length > 20)) {
			parsed.hash = '#[REDACTED]';
		}

		return parsed.toString();
	} catch {
		return urlString.split('?')[0];
	}
}

/* ==========================================================================
   DECLARATIVE NET REQUEST (DNR) DYNAMIC BLOCKING
   ========================================================================== */

/**
 * Register a dynamic DNR rule to block navigation to a confirmed phishing domain in MV3
 * @param {string} domain
 */
async function blockDomainWithDNR(domain) {
	if (!chrome.declarativeNetRequest) return;
	try {
		let hash = 0;
		for (let i = 0; i < domain.length; i++) {
			hash = ((hash << 5) - hash) + domain.charCodeAt(i);
			hash |= 0;
		}
		const ruleId = Math.abs(hash) % 50000 + 100;

		await chrome.declarativeNetRequest.updateDynamicRules({
			addRules: [{
				id: ruleId,
				priority: 1,
				action: {
					type: 'redirect',
					redirect: {
						extensionPath: '/public/phishing.html'
					}
				},
				condition: {
					urlFilter: `||${domain}^`,
					resourceTypes: ['main_frame']
				}
			}],
			removeRuleIds: [ruleId]
		});
		console.log(`[PhishLens DNR] Dynamic rule registered for ${domain} (Rule #${ruleId})`);
	} catch (e) {
		console.error('[PhishLens DNR] Error updating dynamic rules:', e);
	}
}

/**
 * Record a behavioral signal for a specific tab
 * @param {number} tabId
 * @param {object} signal
 */
function recordBehavioralSignalForTab(tabId, signal) {
	if (!tabId || tabId <= 0) return;
	if (!tabBehavioralSignals[tabId]) {
		tabBehavioralSignals[tabId] = [];
	}
	tabBehavioralSignals[tabId].push({
		...signal,
		timestamp: Date.now()
	});
	if (tabBehavioralSignals[tabId].length > 50) {
		tabBehavioralSignals[tabId].shift();
	}
}

/* ==========================================================================
   EXTENSION LIFECYCLE & STORAGE
   ========================================================================== */

chrome.runtime.onInstalled.addListener(async (_details) => {
	await logGroupEventAsync('event-oninstalled-chrome.storage.local-user-settings', async () => {
		await chrome.storage.local.set({ showBlocklist: false });
	});

	await logGroupEventAsync('event-oninstalled-chrome.storage.local-whitelist', async () => {
		let i = 0;
		for (const whitelistedDomain of whitelist) {
			whitelistMap.set(whitelistedDomain, true);
			chrome.storage.local.set({
				[whitelistedDomain]: PhishResult.asGloballyWhitelisted,
			});
			i++;
		}
		console.log('chrome.storage.local: loaded %i whitelisted domains', i);
	});
});

/* ==========================================================================
   PHASE 3: REDIRECT CHAIN MONITORING (chrome.webNavigation)
   ========================================================================== */

if (chrome.webNavigation) {
	chrome.webNavigation.onBeforeNavigate.addListener((details) => {
		// Only track top-level navigation
		if (details.frameId !== 0) return;

		const sanitized = sanitizeAndRedactUrl(details.url);
		navigationChains[details.tabId] = {
			chain: [sanitized],
			startTime: Date.now(),
			lastCommittedUrl: sanitized
		};
	});

	chrome.webNavigation.onCommitted.addListener((details) => {
		if (details.frameId !== 0) return;

		const nav = navigationChains[details.tabId];
		if (!nav) return;

		const sanitized = sanitizeAndRedactUrl(details.url);
		if (!nav.chain.includes(sanitized)) {
			nav.chain.push(sanitized);
		}
		nav.lastCommittedUrl = sanitized;

		// Detect multi-hop redirect chains across distinct origins
		if (nav.chain.length >= 3) {
			const origins = nav.chain.map(u => {
				try { return new URL(u).origin; } catch { return ''; }
			}).filter(Boolean);
			const uniqueOrigins = Array.from(new Set(origins));

			if (uniqueOrigins.length >= 3) {
				const finalOrigin = uniqueOrigins[uniqueOrigins.length - 1];
				console.warn('[PhishLens Multi-Hop Redirect Detected]', nav.chain);

				recordBehavioralSignalForTab(details.tabId, {
					type: 'SUSPICIOUS_MULTI_HOP_REDIRECT_CHAIN',
					severity: 'medium',
					details: {
						hopCount: nav.chain.length,
						uniqueOriginCount: uniqueOrigins.length,
						initialOrigin: uniqueOrigins[0],
						finalOrigin: finalOrigin,
						redirectChain: nav.chain
					}
				});
			}
		}
	});
}

/* ==========================================================================
   PHASE 3: OUT-OF-BAND REQUEST CORRELATION (chrome.webRequest)
   ========================================================================== */

/**
 * Extract the registrable "eTLD+1" from a hostname.
 * e.g. "mail.google.com" → "google.com", "accounts.google.co.uk" → "google.co.uk"
 * This is a best-effort heuristic sufficient for same-org detection.
 * @param {string} hostname
 * @returns {string}
 */
function getRegistrableDomain(hostname) {
	if (!hostname) return '';
	const parts = hostname.split('.');
	// Most TLDs: take last 2 parts; known second-level TLDs (co.uk, com.au, etc.): take last 3
	const knownSLD = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'sch']);
	if (parts.length >= 3 && knownSLD.has(parts[parts.length - 2])) {
		return parts.slice(-3).join('.');
	}
	return parts.slice(-2).join('.');
}

/**
 * Map of trusted cross-organization domain pairs.
 * Key = registrable domain of initiator; Value = Set of trusted destination registrable domains.
 * These represent known first-party CDN / API infrastructures.
 * @type {Map<string, Set<string>>}
 */
const TRUSTED_CROSS_ORG_PAIRS = new Map([
	// Google properties
	['google.com',      new Set(['googleapis.com', 'gstatic.com', 'googleusercontent.com', 'googlevideo.com', 'google.com', 'doubleclick.net', 'youtube.com', 'ggpht.com', 'googletagmanager.com', 'accounts.google.com'])],
	['gmail.com',       new Set(['googleapis.com', 'gstatic.com', 'google.com', 'googleusercontent.com'])],
	['youtube.com',     new Set(['googlevideo.com', 'gstatic.com', 'googleapis.com', 'ggpht.com', 'google.com'])],
	// Microsoft properties
	['microsoft.com',   new Set(['office.com', 'live.com', 'microsoftonline.com', 'azureedge.net', 'azure.com', 'office365.com', 'sharepoint.com', 'outlook.com', 'msftauth.net', 'msauth.net', 'msecnd.net'])],
	['outlook.com',     new Set(['microsoft.com', 'live.com', 'microsoftonline.com', 'office.com', 'msftauth.net'])],
	['office.com',      new Set(['microsoft.com', 'microsoftonline.com', 'sharepoint.com', 'msftauth.net', 'azureedge.net'])],
	// Apple
	['apple.com',       new Set(['icloud.com', 'mzstatic.com', 'apple-cloudkit.com', 'appattest.apple.com'])],
	['icloud.com',      new Set(['apple.com', 'mzstatic.com'])],
	// Meta
	['facebook.com',    new Set(['fbcdn.net', 'instagram.com', 'whatsapp.com', 'facebook.net', 'cdninstagram.com'])],
	['instagram.com',   new Set(['fbcdn.net', 'facebook.com', 'cdninstagram.com'])],
	// Amazon / AWS
	['amazon.com',      new Set(['amazonaws.com', 'cloudfront.net', 'ssl-images-amazon.com', 'media-amazon.com'])],
	['amazonaws.com',   new Set(['amazon.com', 'cloudfront.net'])],
	// Twitter / X
	['twitter.com',     new Set(['twimg.com', 't.co', 'abs.twimg.com'])],
	['x.com',           new Set(['twimg.com', 'twitter.com', 't.co'])],
	// GitHub
	['github.com',      new Set(['githubusercontent.com', 'githubassets.com', 'github.io'])],
	// LinkedIn
	['linkedin.com',    new Set(['licdn.com', 'linkedin.cn'])],
	// Cloudflare
	['cloudflare.com',  new Set(['cloudflareinsights.com', 'cloudflare-dns.com'])],
]);

/**
 * Returns true if a cross-origin request between the two registrable domains
 * is considered trusted (same org infrastructure).
 * @param {string} initiatorRegDomain
 * @param {string} destRegDomain
 * @returns {boolean}
 */
function isTrustedCrossOrgPair(initiatorRegDomain, destRegDomain) {
	if (!initiatorRegDomain || !destRegDomain) return false;
	if (initiatorRegDomain === destRegDomain) return true;
	const trusted = TRUSTED_CROSS_ORG_PAIRS.get(initiatorRegDomain);
	if (trusted && trusted.has(destRegDomain)) return true;
	// Also check reverse direction (CDN initiating back to origin)
	for (const [org, trustedSet] of TRUSTED_CROSS_ORG_PAIRS) {
		if (trustedSet.has(initiatorRegDomain) && (org === destRegDomain || trustedSet.has(destRegDomain))) {
			return true;
		}
	}
	return false;
}

// 1. Observe subresource requests and correlate with user interaction
chrome.webRequest.onBeforeRequest.addListener(
	(details) => {
		if (details.type === 'main_frame' || !details.initiator) return;

		let initiatorHostname = '';
		try {
			initiatorHostname = new URL(details.initiator).hostname;
		} catch { return; }

		// Skip entirely if the initiator domain is in the global whitelist —
		// we already trust this site, so cross-origin API calls are expected.
		if (whitelistMap.has(initiatorHostname)) return;

		const initiatorRegDomain = getRegistrableDomain(initiatorHostname);

		let requestOrigin = '';
		let destHostname = '';
		try {
			const destUrl = new URL(details.url);
			requestOrigin = destUrl.origin;
			destHostname = destUrl.hostname;
		} catch { return; }

		if (!requestOrigin || requestOrigin === details.initiator) return;

		const destRegDomain = getRegistrableDomain(destHostname);

		// Skip same registrable domain (e.g. sub1.example.com → sub2.example.com)
		if (initiatorRegDomain && initiatorRegDomain === destRegDomain) return;

		// Skip known trusted cross-org pairs (Google APIs, Microsoft CDN, etc.)
		if (isTrustedCrossOrgPair(initiatorRegDomain, destRegDomain)) return;

		const tabId = details.tabId;
		if (tabId <= 0) return;

		// Only flag if a sensitive interaction occurred on this tab recently (within 3500ms)
		const signals = tabBehavioralSignals[tabId] || [];
		const now = Date.now();
		const recentSensitiveSignal = signals.slice().reverse().find(s =>
			(now - (s.timestamp || 0) < 3500) &&
			(s.type === 'DYNAMIC_SENSITIVE_INPUT_INSERTED' ||
			 s.type === 'FORM_ACTION_MODIFIED' ||
			 s.type === 'DYNAMIC_FORM_INSERTED')
		);

		if (recentSensitiveSignal) {
			const sanitizedUrl = sanitizeAndRedactUrl(details.url);
			console.warn('[PhishLens Out-of-band Subresource Exfiltration Signal]', {
				initiator: details.initiator,
				destination: requestOrigin,
				requestType: details.type
			});

			recordBehavioralSignalForTab(tabId, {
				type: 'OUT_OF_BAND_CROSS_ORIGIN_REQUEST',
				severity: 'high',
				details: {
					initiatorOrigin: details.initiator,
					destinationOrigin: requestOrigin,
					requestType: details.type,
					sanitizedUrl,
					correlatedSignal: recentSensitiveSignal.type
				}
			});
		}
	},
	{ urls: ['<all_urls>'] }
);


// 2. Main-frame page inspection listener (PhishLang MobileBERT inference)
chrome.webRequest.onCompleted.addListener(
	async (details) => {
		if (details.type !== 'main_frame') {
			return;
		}

		const url = new URL(details.url);
		const domain = url.hostname;
		const tabId = details.tabId;

		if (url.protocol === 'chrome:' || url.protocol === 'chrome-extension:') {
			urlCheckResults[domain] = 'safe';
			return;
		}

		if (whitelistMap.has(domain) || Object.hasOwn(urlCheckResults, domain)) {
			await logGroupEventAsync(`event-oncompleted-visited-whitelisted-domain:${domain}`, async () => {
				console.log(url);
			});
			return;
		}

		let phishHtmlText = '';
		await logGroupEventAsync('event-oncompleted-fetch-public/phishing.html', async () => {
			try {
				const response = await getPagePhishing();
				phishHtmlText = await response.text();
				logResponse(response);
			} catch (e) {
				console.error(e);
			}
		});

		await logGroupEventAsync(`event-oncompleted-freephish-scan:${url}`, async () => {
			try {
				const response = await getFreePhishCheckUrl(url);
				const data = await response.json();
				const nowSeconds = Date.now();
				const nowDate = new Date(nowSeconds);

				console.log({
					timestampRaw: nowSeconds,
					timestampIso: nowDate.toISOString(),
					tabId: tabId,
					site: url,
					httpResponse: response,
					httpResponseJson: data,
				});

				await onPhishResultEvent({
					phishResult: data.result,
					phishHtmlText: phishHtmlText,
					domain: domain,
					url: url.toString(),
					tabId: tabId,
				});
			} catch (e) {
				// Backend is unreachable — run the client-side heuristic engine as a fallback.
				console.warn('[PhishLens] Backend unreachable, running heuristic fallback for:', domain, e.message);
				const heuristicResult = runHeuristicCheck(url);
				console.log('[PhishLens] Heuristic result:', heuristicResult);
				if (!Object.hasOwn(urlCheckResults, domain)) {
					urlCheckResults[domain] = heuristicResult.verdict;
					if (heuristicResult.verdict === 'phishing' && tabId) {
						chrome.tabs.sendMessage(tabId, { action: 'lockAllFormsDueToPhishing' }).catch(() => {});
					}
				}
			}
		});
	},
	{ urls: ['<all_urls>'] }
);

/* ==========================================================================
   MESSAGE ROUTING & RISK EVALUATION
   ========================================================================== */

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
	switch (message.action) {
		case 'closeTab':
			{
				chrome.tabs.remove(message.tabId);
			}
			break;

		case 'closeCurrentTab':
			{
				if (sender.tab && sender.tab.id) {
					chrome.tabs.remove(sender.tab.id);
				}
				sendResponse({ status: 'closed' });
			}
			break;

		case 'getCheckResult':
			{
				let result = urlCheckResults[message.domain];
				if (!result && message.fullUrl) {
					try {
						const heuristic = runHeuristicCheck(new URL(message.fullUrl));
						result = heuristic.verdict;
						urlCheckResults[message.domain] = result;
					} catch (e) {
						// URL parsing error
					}
				}
				sendResponse({
					phish: result,
				});
			}
			break;

		case 'markSafe':
			{
				urlCheckResults[message.domain] = 'safe';
				whitelistMap[message.domain] = true;
				sendResponse({
					phish: urlCheckResults[message.domain],
				});
			}
			break;

		case 'behavioralThreatSignal':
			{
				const tabId = sender.tab ? sender.tab.id : (message.tabId || null);
				if (tabId) {
					recordBehavioralSignalForTab(tabId, message.payload);
				}

				console.log('[PhishLens Behavioral Signal]', message.payload);

				// Re-evaluate page risk using the correlated risk engine every time a
				// new signal arrives.  Policy:
				//   - Signals are deduplicated by type before scoring.
				//   - A single high-severity signal does NOT automatically mark the page suspicious.
				//   - Multiple independent signals are required to cross the threshold.
				//   - Legitimate-destination signals are discounted to 0 by the engine.
				if (message.payload && message.payload.url) {
					try {
						const domain = new URL(message.payload.url).hostname;
						if (domain && !whitelistMap.has(domain)) {
							const allSignals = tabId && tabBehavioralSignals[tabId]
								? tabBehavioralSignals[tabId]
								: [];
							const currentStatus = urlCheckResults[domain] ?? null;
							const aiVerdict = currentStatus === 'phishing' ? 'phishing'
								: currentStatus === 'suspicious' ? 'suspicious'
								: currentStatus === 'unverified' ? 'unverified'
								: null;

							const newStatus = derivePageStatusFromSignals(allSignals, currentStatus, aiVerdict);
							if (newStatus) {
								urlCheckResults[domain] = newStatus;
								console.log(`[PhishLens Risk Engine] ${domain} → ${newStatus} (from ${allSignals.length} signals)`);

								// If newly flagged as phishing, notify the tab immediately to lock all forms
								if (newStatus === 'phishing' && tabId) {
									chrome.tabs.sendMessage(tabId, { action: 'lockAllFormsDueToPhishing' }).catch(() => {});
								}
							}
						}
					} catch (e) {
						// Ignore invalid URLs
					}
				}

				sendResponse({ status: 'received' });
			}
			break;

		case 'getBehavioralSignals':
			{
				const tabId = message.tabId;
				sendResponse({
					signals: tabId && tabBehavioralSignals[tabId] ? tabBehavioralSignals[tabId] : []
				});
			}
			break;

		case 'evaluateSubmissionRisk':
			{
				const {
					pageUrl,
					pageOrigin,
					destinationUrl,
					destinationOrigin,
					isCrossOrigin,
					isKnownIdP,
					sensitiveCategories
				} = message.payload || {};

				let guardResponse = {
					verdict: 'ALLOW',
					reason: 'Destination verified as legitimate.',
					score: 0,
					contributors: [],
				};

				try {
					const pageDomain = new URL(pageUrl).hostname;

					// Gather all behavioral signals accumulated for this tab
					const tabId = sender.tab ? sender.tab.id : null;
					const tabSignals = tabId && tabBehavioralSignals[tabId]
						? tabBehavioralSignals[tabId]
						: [];

					// Current AI-derived page status
					const pageStatus = urlCheckResults[pageDomain] ?? null;
					const aiVerdict  = pageStatus === 'phishing'   ? 'phishing'
						: pageStatus === 'suspicious' ? 'suspicious'
						: pageStatus === 'unverified' ? 'unverified'
						: null;

					// Run the correlated unified risk engine (Phase 5)
					const riskResult = computeUnifiedRiskScore(tabSignals, {
						aiVerdict,
						isCrossOriginSubmit: !!isCrossOrigin,
						isKnownIdP:          !!isKnownIdP,
						destinationOrigin:   destinationOrigin || null,
						pageStatus,
					});

					guardResponse = toSubmissionGuardResponse(riskResult, destinationOrigin);

					console.log('[PhishLens Unified Risk Engine] evaluateSubmissionRisk', {
						pageDomain,
						score: riskResult.score,
						level: riskResult.level,
						verdict: guardResponse.verdict,
						contributors: riskResult.contributors,
					});

					// State handling based on unified level
					if (guardResponse.verdict === 'BLOCK') {
						if (aiVerdict === 'phishing' || pageStatus === 'phishing') {
							blockDomainWithDNR(pageDomain);
							urlCheckResults[pageDomain] = 'phishing';
						} else {
							urlCheckResults[pageDomain] = 'suspicious';
						}
					} else if (guardResponse.verdict === 'UNVERIFIED') {
						if (urlCheckResults[pageDomain] !== 'phishing') {
							urlCheckResults[pageDomain] = 'unverified';
						}
					}
				} catch (e) {
					console.error('[PhishLens] Error in evaluateSubmissionRisk:', e);
				}

				sendResponse(guardResponse);
			}
			break;

		// Phase 4: Handle a QR-decoded URL — run it through the same URL risk pipeline.
		// No image pixel data is ever transmitted; only the sanitized decoded string is received.
		case 'evaluateQRUrl':
			{
				const { sanitizedUrl, pageUrl } = message.payload || {};
				if (!sanitizedUrl) { sendResponse({ status: 'ignored' }); break; }

				let qrDomain = null;
				try { qrDomain = new URL(sanitizedUrl).hostname; } catch { /* non-URL data */ }
				let pageDomain = null;
				try { pageDomain = new URL(pageUrl).hostname; } catch {}

				if (!qrDomain) { sendResponse({ status: 'invalid-url' }); break; }

				// If already flagged, propagate to page domain
				if (urlCheckResults[qrDomain] === 'phishing') {
					if (pageDomain) urlCheckResults[pageDomain] = 'suspicious';
					sendResponse({ status: 'already-flagged', qrDomain });
					break;
				}

				// Record as a behavioral signal for this tab
				const qrTabId = sender.tab ? sender.tab.id : null;
				if (qrTabId) {
					recordBehavioralSignalForTab(qrTabId, {
						type: 'QR_CODE_URL_EVALUATED',
						severity: 'medium',
						sanitizedQrUrl: sanitizedUrl,
						qrDomain,
						timestamp: Date.now()
					});
				}

				// Asynchronously check the QR URL via the backend AI model (fire-and-forget)
				(async () => {
					try {
						const resp = await fetch(
							`http://localhost:5000/predict?url=${encodeURIComponent(sanitizedUrl)}`,
							{ method: 'GET', signal: AbortSignal.timeout(5000) }
						);
						if (resp.ok) {
							const result = await resp.json();
							if (result && result.phishing === true) {
								urlCheckResults[qrDomain] = 'phishing';
								if (pageDomain) urlCheckResults[pageDomain] = 'suspicious';
								blockDomainWithDNR(qrDomain);
								console.warn('[PhishLens] QR code points to phishing domain:', qrDomain);
							}
						}
					} catch (e) {
						console.debug('[PhishLens] QR URL backend check skipped:', e.message);
					}
				})();

				sendResponse({ status: 'queued', qrDomain });
			}
			break;
	}
});

chrome.tabs.onRemoved.addListener((tabId) => {
	delete tabBehavioralSignals[tabId];
	delete navigationChains[tabId];
});

/* ==========================================================================
   HEURISTIC URL CHECK (FALLBACK WHEN BACKEND IS OFFLINE)
   ========================================================================== */

/**
 * Perform client-side heuristic phishing risk evaluation on a URL
 * Useful when the local Python backend server is offline or unreachable.
 * @param {URL} url
 * @returns {{ verdict: 'safe'|'suspicious'|'phishing', score: number, reasons: string[] }}
 */
function runHeuristicCheck(url) {
	const domain = url.hostname.toLowerCase();
	const fullUrl = url.href.toLowerCase();
	const search = url.search.toLowerCase();
	const pathname = url.pathname.toLowerCase();
	const reasons = [];
	let score = 0;

	// Check if in known global whitelist
	if (whitelistMap.has(domain)) {
		return { verdict: 'safe', score: 0, reasons: ['Whitelisted domain'] };
	}

	// 1. Brand name impersonation in subdomain or path/query on non-brand domain
	const majorBrands = ['facebook', 'meta', 'google', 'gmail', 'apple', 'icloud', 'microsoft', 'office', 'netflix', 'paypal', 'amazon', 'chase', 'wellsfargo', 'bankofamerica', 'instagram', 'whatsapp', 'twitter', 'linkedin'];
	for (const brand of majorBrands) {
		const isBrandDomain = domain === `${brand}.com` || domain.endsWith(`.${brand}.com`);
		if (!isBrandDomain) {
			if (domain.includes(brand)) {
				score += 35;
				reasons.push(`Brand '${brand}' used in non-brand domain (${domain})`);
			} else if (search.includes(`${brand}-login`) || search.includes(`${brand}_login`) || pathname.includes(`${brand}-login`)) {
				score += 45;
				reasons.push(`Brand login targeting '${brand}' in query/path`);
			}
		}
	}

	// 2. Suspicious keywords in hostname or path
	const suspiciousKeywords = ['alerting-services', 'account-verify', 'security-update', 'login-verify', 'secure-login', 'wallet-connect', 'auth-check', 'session-update', 'signin-alert'];
	for (const kw of suspiciousKeywords) {
		if (domain.includes(kw) || pathname.includes(kw)) {
			score += 30;
			reasons.push(`Suspicious phishing pattern keyword '${kw}'`);
		}
	}

	// 3. Excess subdomains or random hex/hash prefixes
	const subdomains = domain.split('.');
	if (subdomains.length >= 4) {
		score += 15;
		reasons.push(`Excessive subdomain nesting (${subdomains.length} levels)`);
	}
	if (/^[a-f0-9]{5,}/.test(subdomains[0])) {
		score += 20;
		reasons.push('Random hex/hash prefix in subdomain');
	}

	// 4. Free/suspicious TLDs or Dynamic DNS
	const highRiskTLDs = ['.xyz', '.top', '.buzz', '.monster', '.work', '.click', '.tk', '.ml', '.ga', '.cf', '.gq', '.rest', '.quest'];
	if (highRiskTLDs.some(tld => domain.endsWith(tld))) {
		score += 25;
		reasons.push('High-risk top level domain');
	}

	// 5. IP address hostname
	if (/^(\d{1,3}\.){3}\d{1,3}$/.test(domain)) {
		score += 35;
		reasons.push('Direct IP address used as hostname');
	}

	let verdict = 'safe';
	if (score >= 45) {
		verdict = 'phishing';
	} else if (score >= 25) {
		verdict = 'suspicious';
	}

	return { verdict, score, reasons };
}

/* ==========================================================================
   AI MODEL PREDICTION & INJECTION
   ========================================================================== */

/**
 * @returns {Promise<Response>}
 */
async function getPagePhishing() {
	return await fetch(chrome.runtime.getURL('/public/phishing.html'), {
		method: 'GET',
		headers: {
			Accept: 'text/html',
		},
	});
}

/**
 * @param {URL} url
 * @returns {Promise<Response>}
 */
async function getFreePhishCheckUrl(url) {
	// Primary port 5000 with fallback to 5024
	try {
		return await fetch('http://localhost:5000/check_url', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ url: url.href }),
		});
	} catch {
		return await fetch('http://localhost:5024/check_url', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
			},
			body: JSON.stringify({ url: url.href }),
		});
	}
}

/**
 * Handle AI prediction results and inject warning page if malicious
 * @param {Object} context
 */
async function onPhishResultEvent(context) {
	onPhishStatusAsync(context.phishResult, {
		onPhishing: async () => {
			urlCheckResults[context.domain] = 'phishing';
			chrome.storage.local.set({
				[context.domain]: PhishResult.asPhishing,
			});

			// Register dynamic DNR rule to block future navigations natively
			blockDomainWithDNR(context.domain);

			// Immediately broadcast form lockdown to all tabs matching this phishing domain
			if (context.tabId) {
				chrome.tabs.sendMessage(context.tabId, { action: 'lockAllFormsDueToPhishing', domain: context.domain }).catch(() => {});
			}
			chrome.tabs.query({}, (tabs) => {
				for (const tab of tabs) {
					if (tab.url && tab.url.includes(context.domain) && tab.id && tab.id !== context.tabId) {
						chrome.tabs.sendMessage(tab.id, { action: 'lockAllFormsDueToPhishing', domain: context.domain }).catch(() => {});
					}
				}
			});

			await chrome.scripting.executeScript({
				target: { tabId: context.tabId },
				func: (phishHtmlText, url, tabId) => {
					if (phishHtmlText !== '') {
						let oldDocument = document.documentElement.outerHTML;
						document.write(phishHtmlText);

						let styles = document.createElement('link');
						styles.setAttribute('rel', 'stylesheet');
						styles.setAttribute('type', 'text/css');
						styles.setAttribute('href', `chrome-extension://${chrome.runtime.id}/public/dist.css`);
						document.head.appendChild(styles);

						chrome.storage.local.get(['showBlocklist', 'openaiApiKey'], async (result) => {
							if (!result.showBlocklist) {
								let blocklistReasons = document.getElementById('blocklist-reasons');
								if (blocklistReasons) blocklistReasons.style.display = 'none';
							}

							// If OpenAI API key is configured, generate dynamic explanation on block page
							if (result.openaiApiKey) {
								const insightBox = document.getElementById('openai-phishing-insight');
								const insightText = document.getElementById('openai-phishing-text');
								if (insightBox && insightText) {
									insightBox.classList.remove('hidden');
									insightText.textContent = 'Generating real-time AI security breakdown...';
									try {
										const resp = await fetch('https://api.openai.com/v1/chat/completions', {
											method: 'POST',
											headers: {
												'Content-Type': 'application/json',
												'Authorization': `Bearer ${result.openaiApiKey}`
											},
											body: JSON.stringify({
												model: 'gpt-3.5-turbo',
												messages: [
													{ role: 'system', content: 'You are a cybersecurity analyst explaining a blocked phishing site in 2 clear sentences.' },
													{ role: 'user', content: `Explain concisely why the site "${url}" is dangerous to visit and what threat it poses to users.` }
												],
												max_tokens: 150
											})
										});
										if (resp.ok) {
											const data = await resp.json();
											const reply = data.choices?.[0]?.message?.content?.trim();
											if (reply) insightText.textContent = reply;
										} else {
											insightBox.classList.add('hidden');
										}
									} catch (e) {
										insightBox.classList.add('hidden');
									}
								}
							}
						});

						const reportedUrl = document.getElementById('reported-url');
						if (reportedUrl) reportedUrl.textContent = url.toString();

						const closeBtn = document.getElementById('close-tab');
						if (closeBtn) {
							closeBtn.addEventListener('click', () => {
								chrome.runtime.sendMessage({ action: 'closeTab', tabId: tabId });
							});
						}

						const goBackBtn = document.getElementById('go-back-btn');
						if (goBackBtn) {
							goBackBtn.addEventListener('click', () => {
								if (window.history.length > 1) {
									window.history.back();
								} else {
									chrome.runtime.sendMessage({ action: 'closeTab', tabId: tabId });
								}
							});
						}

						const markSafeBtn = document.getElementById('mark-safe');
						if (markSafeBtn) {
							markSafeBtn.addEventListener('click', () => {
								chrome.runtime.sendMessage({ action: 'markSafe', tabId: tabId });
								const page = document.getElementById('freephishing-warning-page');
								if (page) page.remove();
								document.write(oldDocument);
							});
						}
					}
				},
				args: [
					context.phishHtmlText,
					context.url,
					context.tabId,
				],
			});
		},
		onSafe: async () => {
			urlCheckResults[context.domain] = 'safe';
			chrome.storage.local.set({
				[context.domain]: PhishResult.asSafe,
			});
		},
		onSuspicious: async () => {
			urlCheckResults[context.domain] = 'suspicious';
			chrome.storage.local.set({
				[context.domain]: PhishResult.asSuspicious,
			});
		},
		onUnverified: async () => {
			urlCheckResults[context.domain] = 'unverified';
			chrome.storage.local.set({
				[context.domain]: PhishResult.asUnverified,
			});
		},
	});
}
