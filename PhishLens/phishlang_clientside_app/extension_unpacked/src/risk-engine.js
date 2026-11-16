/**
 * PhishLens Correlated Risk Engine  (service-worker context)
 *
 * Design principles:
 *  1. ANY cross-origin request alone is NOT high-risk — context is required.
 *  2. Identical signals are deduplicated; each unique signal TYPE contributes once per evaluation.
 *  3. Destination legitimacy is evaluated before assigning risk weight.
 *  4. Unknown domains are weak evidence (low weight), not automatic suspicion.
 *  5. A single signal CANNOT trigger blocking — multiple independent indicators required.
 *
 * Risk is accumulated as a numeric score.  Verdict thresholds:
 *   score < THRESHOLD_SUSPICIOUS  → safe / unchecked (no action)
 *   score < THRESHOLD_BLOCK       → suspicious (warn user, do NOT block)
 *   score >= THRESHOLD_BLOCK      → phishing   (block submission, DNR if confirmed by AI)
 */

/* ==========================================================================
   CONSTANTS & WEIGHTS
   ========================================================================== */

/** Minimum score before the UI shows the "Suspicious" badge. */
const THRESHOLD_SUSPICIOUS = 40;

/** Minimum score before form submission is blocked and DNR activated. */
const THRESHOLD_BLOCK = 75;

/**
 * Point weights for each signal type.
 * Signals that cannot occur without attacker intent score higher.
 * Infra signals (CDN loads, embedded iframes) are discounted when the
 * destination is a known-legitimate service.
 */
const SIGNAL_WEIGHTS = {
	// ── High-confidence attack indicators ──────────────────────────────────
	AI_MODEL_PHISHING:                   60,
	FORM_ACTION_MODIFIED:                45,
	SUSPICIOUS_CROSS_ORIGIN_SUBMIT:      50,
	CLICKJACKING_OVERLAY_DETECTED:       50,
	QR_CODE_PHISHING_CONFIRMED:          55,
	IMAGE_BRAND_IMPERSONATION:           40,

	// ── Medium-confidence indicators ───────────────────────────────────────
	AI_MODEL_SUSPICIOUS:                 30,
	DYNAMIC_SENSITIVE_INPUT_INSERTED:    20,
	DYNAMIC_FORM_INSERTED:               15,
	DYNAMIC_LOGIN_MODAL_OVERLAY:         20,
	HIDDEN_FORM_REVEALED:                15,
	HIDDEN_SENSITIVE_INPUT_REVEALED:     10,
	SUSPICIOUS_MULTI_HOP_REDIRECT_CHAIN: 25,
	OUT_OF_BAND_CROSS_ORIGIN_REQUEST:    20,

	// ── Low-confidence / contextual indicators ─────────────────────────────
	DYNAMIC_EXTERNAL_SCRIPT_INJECTED:     8,
	DYNAMIC_IFRAME_INJECTED:              8,
	QR_CODE_UNVERIFIED:                   5,
	CLICK_TARGET_MISMATCH:               15,
};

/**
 * Signals whose weight drops to 0 when the destination is a known-legitimate service.
 * These are infrastructure events that are completely normal for major platforms.
 */
const DESTINATION_DISCOUNTED_SIGNALS = new Set([
	'OUT_OF_BAND_CROSS_ORIGIN_REQUEST',
	'DYNAMIC_EXTERNAL_SCRIPT_INJECTED',
	'DYNAMIC_IFRAME_INJECTED',
	'SUSPICIOUS_CROSS_ORIGIN_SUBMIT',
]);

/* ==========================================================================
   DESTINATION REPUTATION HELPERS
   ========================================================================== */

/** Best-effort eTLD+1 extractor */
function regDomain(hostname) {
	if (!hostname) return '';
	const parts = hostname.split('.');
	const knownSLD = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'sch']);
	if (parts.length >= 3 && knownSLD.has(parts[parts.length - 2])) return parts.slice(-3).join('.');
	return parts.slice(-2).join('.');
}

/**
 * Registrable domains of well-known legitimate services / CDNs / Identity Providers.
 * Requests TO these destinations are not suspicious in isolation.
 */
const KNOWN_LEGITIMATE_DOMAINS = new Set([
	// Google
	'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com',
	'googlevideo.com', 'ggpht.com', 'doubleclick.net', 'googletagmanager.com',
	'youtube.com', 'gmail.com', 'google-analytics.com',
	// Microsoft
	'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com',
	'outlook.com', 'sharepoint.com', 'azureedge.net', 'azure.com',
	'msftauth.net', 'msauth.net', 'msecnd.net', 'office365.com',
	// Apple
	'apple.com', 'icloud.com', 'mzstatic.com', 'aaplimg.com',
	// Meta
	'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com',
	'facebook.net', 'cdninstagram.com',
	// Amazon / AWS
	'amazon.com', 'amazonaws.com', 'cloudfront.net',
	// Twitter / X
	'twitter.com', 'x.com', 'twimg.com', 't.co',
	// GitHub
	'github.com', 'githubusercontent.com', 'githubassets.com',
	// Auth providers / SSO
	'okta.com', 'auth0.com', 'pingidentity.com', 'onelogin.com',
	'duosecurity.com', 'salesforce.com', 'slack.com',
	// Payment processors — legitimate cross-origin submit targets
	'stripe.com', 'paypal.com', 'braintreegateway.com', 'adyen.com', 'checkout.com',
	// CDNs
	'cloudflare.com', 'fastly.net', 'akamaized.net', 'akamai.net',
	'bootstrapcdn.com', 'jquery.com', 'jsdelivr.net', 'unpkg.com',
	'cloudflareinsights.com',
	// Analytics (not credential-stealing)
	'segment.com', 'mixpanel.com', 'hotjar.com', 'clarity.ms',
	// Media / streaming
	'netflix.com', 'nflxso.net', 'nflxext.com', 'nflximg.net', 'nflxvideo.net',
	'netflix.net', 'nflximg.com',
	'spotify.com', 'scdn.co', 'twitch.tv', 'jtvnw.net',
	'reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com',
	'linkedin.com', 'licdn.com',
]);

/**
 * Returns true when the destination is a well-known legitimate service.
 * @param {string|null|undefined} destinationOrigin
 * @returns {boolean}
 */
function isKnownLegitimateDestination(destinationOrigin) {
	if (!destinationOrigin) return false;
	try {
		const host = new URL(destinationOrigin).hostname.toLowerCase();
		return KNOWN_LEGITIMATE_DOMAINS.has(regDomain(host)) || KNOWN_LEGITIMATE_DOMAINS.has(host);
	} catch { return false; }
}

/* ==========================================================================
   CORRELATED RISK SCORER
   ========================================================================== */

/**
 * Compute a composite risk score from an array of behavioral signals.
 *
 * Rules enforced here:
 *  R1 — Each unique signal TYPE contributes at most once (deduplication).
 *  R2 — Signals targeting a known-legitimate destination are discounted to 0.
 *  R3 — Unknown destinations get their base weight (weak evidence), not elevated weight.
 *  R4 — THRESHOLD_BLOCK requires at least 2 independent signal types (enforced implicitly
 *       by the numeric thresholds — no single signal weight reaches 75 alone).
 *
 * @param {Array<{type:string, severity?:string, details?:object}>} signals
 * @param {object}       context
 * @param {string|null}  context.aiVerdict            'phishing'|'suspicious'|'safe'|null
 * @param {boolean}      context.isCrossOriginSubmit   form is submitting cross-origin
 * @param {boolean}      context.isKnownIdP            destination is a recognised IdP/OAuth provider
 * @param {string|null}  context.destinationOrigin     form or request destination origin string
 * @param {string|null}  context.pageStatus            current cached status for the page domain
 * @returns {{ score: number, verdict: 'safe'|'suspicious'|'phishing', contributors: string[] }}
 */
function computeRiskScore(signals = [], context = {}) {
	const {
		aiVerdict        = null,
		isCrossOriginSubmit = false,
		isKnownIdP       = false,
		destinationOrigin = null,
		pageStatus       = null,
	} = context;

	let score = 0;
	const contributors = [];
	const seenTypes = new Set();   // R1: deduplication

	// ── A. AI model verdict (highest confidence — always applied) ────────────
	if (aiVerdict === 'phishing') {
		score += SIGNAL_WEIGHTS.AI_MODEL_PHISHING;
		contributors.push('AI: phishing');
	} else if (aiVerdict === 'suspicious') {
		score += SIGNAL_WEIGHTS.AI_MODEL_SUSPICIOUS;
		contributors.push('AI: suspicious');
	}
	// aiVerdict === 'safe' actively suppresses the score (trust the model)
	if (aiVerdict === 'safe') {
		return { score: 0, verdict: 'safe', contributors: ['AI: safe'] };
	}

	// ── B. Cross-origin form submission ─────────────────────────────────────
	//    R2: if the destination is a legitimate service, this is NOT suspicious.
	if (isCrossOriginSubmit && !isKnownIdP) {
		if (!isKnownLegitimateDestination(destinationOrigin)) {
			score += SIGNAL_WEIGHTS.SUSPICIOUS_CROSS_ORIGIN_SUBMIT;
			contributors.push(`Cross-origin submit → ${destinationOrigin || 'unknown'}`);
		}
	}

	// ── C. Behavioral signals (content script + service worker) ─────────────
	for (const signal of signals) {
		const type = signal.type;
		if (!type || seenTypes.has(type)) continue;   // R1
		seenTypes.add(type);

		const baseWeight = SIGNAL_WEIGHTS[type] ?? 0;
		if (baseWeight === 0) continue;

		// R2: discount infra signals when destination is legitimate
		if (DESTINATION_DISCOUNTED_SIGNALS.has(type)) {
			const dest =
				signal.details?.destinationOrigin ??
				signal.details?.iframeOrigin ??
				signal.details?.scriptOrigin ??
				destinationOrigin;
			if (isKnownLegitimateDestination(dest)) continue;
		}

		score += baseWeight;
		contributors.push(`${type} (+${baseWeight})`);
	}

	// ── D. Page-level status bias ────────────────────────────────────────────
	//    A page ALREADY confirmed as phishing by AI should block any new submissions.
	if (pageStatus === 'phishing') {
		score = Math.max(score, THRESHOLD_BLOCK);
		contributors.push('Page previously flagged as phishing');
	}

	// ── E. Verdict ───────────────────────────────────────────────────────────
	let verdict;
	if (score >= THRESHOLD_BLOCK)      verdict = 'phishing';
	else if (score >= THRESHOLD_SUSPICIOUS) verdict = 'suspicious';
	else                                verdict = 'safe';

	return { score, verdict, contributors };
}

/**
 * Translate a risk result into a form-submission guard response object.
 * Maps 'phishing' → BLOCK, 'suspicious' → WARN (do NOT block on suspicion alone),
 * 'safe' → ALLOW.
 *
 * @param {{ score:number, verdict:string, contributors:string[] }} riskResult
 * @param {string|null} destinationOrigin
 * @returns {{ verdict:'ALLOW'|'WARN'|'BLOCK', reason:string, score:number, contributors:string[] }}
 */
function toSubmissionGuardResponse(riskResult, destinationOrigin) {
	const { score, verdict, contributors } = riskResult;

	if (verdict === 'phishing') {
		return {
			verdict: 'BLOCK',
			reason: `Blocked: correlated risk score ${score} — ${contributors.slice(0, 3).join('; ')}.`,
			score,
			contributors,
		};
	}
	if (verdict === 'suspicious') {
		return {
			verdict: 'WARN',
			reason: `Caution: suspicious indicators detected (score ${score}) — ${contributors.join('; ')}.`,
			score,
			contributors,
		};
	}
	return {
		verdict: 'ALLOW',
		reason: 'Destination verified as legitimate.',
		score,
		contributors,
	};
}

/**
 * Given all behavioral signals accumulated for a tab, decide whether the page-level
 * cached status should be updated.
 *
 * Policy:
 *  - Signals are deduplicated per type before scoring.
 *  - A page can move from safe → suspicious → phishing, but NEVER downgrade.
 *  - Behavioral signals alone cannot mark a page 'phishing' unless the AI also agrees
 *    (AI_MODEL_PHISHING weight = 60; we still need 15+ from other signals to reach 75).
 *
 * @param {Array<object>} allSignalsForTab
 * @param {string|null}   currentPageStatus
 * @param {string|null}   aiVerdict
 * @returns {'suspicious'|'phishing'|null}  null = no change
 */
function derivePageStatusFromSignals(allSignalsForTab, currentPageStatus, aiVerdict = null) {
	if (currentPageStatus === 'phishing') return null;  // never downgrade

	const { verdict } = computeRiskScore(allSignalsForTab, {
		aiVerdict,
		pageStatus: currentPageStatus,
	});

	if (verdict === 'phishing' && currentPageStatus !== 'phishing') return 'phishing';
	if (verdict === 'suspicious' && currentPageStatus !== 'suspicious' && currentPageStatus !== 'phishing') return 'suspicious';
	return null;
}

export {
	computeRiskScore,
	toSubmissionGuardResponse,
	derivePageStatusFromSignals,
	isKnownLegitimateDestination,
	THRESHOLD_SUSPICIOUS,
	THRESHOLD_BLOCK,
};
