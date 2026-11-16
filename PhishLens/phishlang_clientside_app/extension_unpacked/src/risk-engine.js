/**
 * PhishLens Phase 5: Unified Evidence Correlation Engine (risk-engine.js)
 *
 * Implements:
 * 1. Typed Evidence Schema:
 *    {
 *      signalId: string,
 *      category: 'DOM_INTEGRITY' | 'NAVIGATION_REDIRECT' | 'FORM_SECURITY' | 'VISUAL_SPOOF' | 'NETWORK_TELEMETRY' | 'MODEL_PREDICTION' | 'BOT_CHALLENGE',
 *      severity: 'low' | 'medium' | 'high' | 'critical',
 *      confidence: number (0.0 to 1.0),
 *      details: object,
 *      timestamp: number,
 *      state: 'ACTIVE' | 'EXPIRED' | 'DISCOUNTED' | 'SUPPRESSED'
 *    }
 *
 * 2. Sliding Correlation Window & Time Decay (15,000ms window; signals older than that expire).
 * 3. Type-level Deduplication (no score inflation from mutation repetition).
 * 4. Multi-Indicator Risk Categorization:
 *    - LOW: Allow normal interaction (score < 40)
 *    - MEDIUM: Warn user with specific context (40 <= score < 75)
 *    - HIGH: Lock form & block sensitive submission (score >= 75)
 *    - UNVERIFIED: Page/destination is blocked by bot challenge / interstitial / CAPTCHA / 401/403.
 *
 * 5. Strict Safe-Guard: Under no circumstances attempt to automate, bypass, or solve CAPTCHAs.
 */

/* ==========================================================================
   CONSTANTS, THRESHOLDS & EVIDENCE CONFIGURATION
   ========================================================================== */

export const CORRELATION_WINDOW_MS = 15000; // 15-second sliding window

export const THRESHOLDS = {
	LOW: 0,
	MEDIUM: 40,
	HIGH: 75,
};

export const THRESHOLD_SUSPICIOUS = THRESHOLDS.MEDIUM;
export const THRESHOLD_BLOCK = THRESHOLDS.HIGH;

/**
 * Signal Category mapping
 */
export const SIGNAL_CATEGORIES = {
	// DOM Integrity
	DYNAMIC_SENSITIVE_INPUT_INSERTED: 'DOM_INTEGRITY',
	DYNAMIC_FORM_INSERTED: 'DOM_INTEGRITY',
	DYNAMIC_LOGIN_MODAL_OVERLAY: 'DOM_INTEGRITY',
	HIDDEN_FORM_REVEALED: 'DOM_INTEGRITY',
	HIDDEN_SENSITIVE_INPUT_REVEALED: 'DOM_INTEGRITY',

	// Navigation & Redirection
	SUSPICIOUS_MULTI_HOP_REDIRECT_CHAIN: 'NAVIGATION_REDIRECT',

	// Form & Destination Security
	FORM_ACTION_MODIFIED: 'FORM_SECURITY',
	SUSPICIOUS_CROSS_ORIGIN_SUBMIT: 'FORM_SECURITY',

	// Visual Spoof & Redressing
	CLICKJACKING_OVERLAY_DETECTED: 'VISUAL_SPOOF',
	CLICK_TARGET_MISMATCH: 'VISUAL_SPOOF',
	IMAGE_BRAND_IMPERSONATION: 'VISUAL_SPOOF',
	IMAGE_CREDENTIAL_PROMPT_DETECTED: 'VISUAL_SPOOF',
	QR_CODE_PHISHING_CONFIRMED: 'VISUAL_SPOOF',
	QR_CODE_UNVERIFIED: 'VISUAL_SPOOF',

	// Network & Subresources
	OUT_OF_BAND_CROSS_ORIGIN_REQUEST: 'NETWORK_TELEMETRY',
	DYNAMIC_EXTERNAL_SCRIPT_INJECTED: 'NETWORK_TELEMETRY',
	DYNAMIC_IFRAME_INJECTED: 'NETWORK_TELEMETRY',

	// AI & Model Predictions
	AI_MODEL_PHISHING: 'MODEL_PREDICTION',
	AI_MODEL_SUSPICIOUS: 'MODEL_PREDICTION',

	// Bot Challenge & Interstitials (Phase 5)
	INTERSTITIAL_CAPTCHA_DETECTED: 'BOT_CHALLENGE',
	ACCESS_DENIED_STATE: 'BOT_CHALLENGE',
};

/**
 * Point weights for typed signals
 */
export const SIGNAL_WEIGHTS = {
	// Critical & High
	AI_MODEL_PHISHING: 60,
	QR_CODE_PHISHING_CONFIRMED: 55,
	SUSPICIOUS_CROSS_ORIGIN_SUBMIT: 50,
	CLICKJACKING_OVERLAY_DETECTED: 50,
	FORM_ACTION_MODIFIED: 45,
	IMAGE_BRAND_IMPERSONATION: 45,
	IMAGE_CREDENTIAL_PROMPT_DETECTED: 30,

	// Medium
	AI_MODEL_SUSPICIOUS: 30,
	SUSPICIOUS_MULTI_HOP_REDIRECT_CHAIN: 25,
	DYNAMIC_SENSITIVE_INPUT_INSERTED: 20,
	DYNAMIC_LOGIN_MODAL_OVERLAY: 20,
	OUT_OF_BAND_CROSS_ORIGIN_REQUEST: 20,
	CLICK_TARGET_MISMATCH: 15,
	DYNAMIC_FORM_INSERTED: 15,
	HIDDEN_FORM_REVEALED: 15,
	HIDDEN_SENSITIVE_INPUT_REVEALED: 10,

	// Low / Informational
	DYNAMIC_EXTERNAL_SCRIPT_INJECTED: 8,
	DYNAMIC_IFRAME_INJECTED: 8,
	QR_CODE_UNVERIFIED: 5,

	// Interstitial / Bot Challenges
	INTERSTITIAL_CAPTCHA_DETECTED: 0,
	ACCESS_DENIED_STATE: 0,
};

/**
 * Infrastructure signals that discount to 0 if the destination is a recognized service
 */
export const DESTINATION_DISCOUNTED_SIGNALS = new Set([
	'OUT_OF_BAND_CROSS_ORIGIN_REQUEST',
	'DYNAMIC_EXTERNAL_SCRIPT_INJECTED',
	'DYNAMIC_IFRAME_INJECTED',
	'SUSPICIOUS_CROSS_ORIGIN_SUBMIT',
]);

/* ==========================================================================
   DESTINATION REPUTATION & eTLD+1 HELPERS
   ========================================================================== */

export function regDomain(hostname) {
	if (!hostname) return '';
	const parts = hostname.split('.');
	const knownSLD = new Set(['co', 'com', 'org', 'net', 'gov', 'edu', 'ac', 'sch']);
	if (parts.length >= 3 && knownSLD.has(parts[parts.length - 2])) return parts.slice(-3).join('.');
	return parts.slice(-2).join('.');
}

export const KNOWN_LEGITIMATE_DOMAINS = new Set([
	'google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'googlevideo.com',
	'youtube.com', 'gmail.com', 'google-analytics.com', 'googletagmanager.com',
	'microsoft.com', 'microsoftonline.com', 'live.com', 'office.com', 'outlook.com',
	'sharepoint.com', 'azureedge.net', 'azure.com', 'msftauth.net', 'msauth.net',
	'apple.com', 'icloud.com', 'mzstatic.com', 'aaplimg.com',
	'facebook.com', 'fbcdn.net', 'instagram.com', 'whatsapp.com', 'facebook.net',
	'amazon.com', 'amazonaws.com', 'cloudfront.net',
	'twitter.com', 'x.com', 'twimg.com', 't.co',
	'github.com', 'githubusercontent.com', 'githubassets.com',
	'okta.com', 'auth0.com', 'pingidentity.com', 'onelogin.com', 'duosecurity.com',
	'stripe.com', 'paypal.com', 'braintreegateway.com', 'adyen.com', 'checkout.com',
	'cloudflare.com', 'fastly.net', 'akamaized.net', 'akamai.net', 'bootstrapcdn.com',
	'jsdelivr.net', 'unpkg.com', 'cloudflareinsights.com',
	'netflix.com', 'nflxso.net', 'nflxext.com', 'nflximg.net', 'nflxvideo.net',
	'spotify.com', 'scdn.co', 'twitch.tv', 'jtvnw.net',
	'reddit.com', 'redd.it', 'redditmedia.com', 'redditstatic.com',
	'linkedin.com', 'licdn.com'
]);

export function isKnownLegitimateDestination(destinationOrigin) {
	if (!destinationOrigin) return false;
	try {
		const host = new URL(destinationOrigin).hostname.toLowerCase();
		return KNOWN_LEGITIMATE_DOMAINS.has(regDomain(host)) || KNOWN_LEGITIMATE_DOMAINS.has(host);
	} catch {
		return false;
	}
}

/* ==========================================================================
   INTERSTITIAL, CAPTCHA & ACCESS DENIED DETECTORS
   ========================================================================== */

export const BOT_CHALLENGE_PATTERNS = {
	titleKeywords: [
		'just a moment...',
		'attention required! | cloudflare',
		'security check',
		'verify you are human',
		'ddos-guard',
		'hcaptcha challenge',
		'recaptcha',
		'bot verification',
		'access denied',
		'403 forbidden',
		'401 unauthorized'
	],
	bodyKeywords: [
		'checking your browser before accessing',
		'please complete the security check to access',
		'cf-browser-verification',
		'ray id:',
		'turnstile.render',
		'challenges.cloudflare.com',
		'g-recaptcha',
		'h-captcha',
		'geetest',
		'arkoselabs'
	]
};

/**
 * Analyze a document representation to see if it is stuck on a CAPTCHA / bot challenge / 403
 * @param {object} params
 * @param {string} params.title
 * @param {string} params.text
 * @param {number} [params.httpStatus]
 * @returns {{ isBlocked: boolean, reason?: string, challengeType?: string }}
 */
export function detectInterstitialOrCaptcha({ title = '', text = '', httpStatus = 200 }) {
	const lowerTitle = (title || '').toLowerCase();
	const lowerText = (text || '').toLowerCase();

	if (httpStatus === 403 || httpStatus === 401) {
		return {
			isBlocked: true,
			challengeType: 'HTTP_ACCESS_DENIED',
			reason: `HTTP ${httpStatus} Access Denied state`
		};
	}

	for (const kw of BOT_CHALLENGE_PATTERNS.titleKeywords) {
		if (lowerTitle.includes(kw)) {
			return {
				isBlocked: true,
				challengeType: 'TITLE_BOT_CHALLENGE',
				reason: `Matched bot challenge title pattern: "${kw}"`
			};
		}
	}

	for (const kw of BOT_CHALLENGE_PATTERNS.bodyKeywords) {
		if (lowerText.includes(kw)) {
			return {
				isBlocked: true,
				challengeType: 'BODY_BOT_CHALLENGE',
				reason: `Matched interstitial verification pattern: "${kw}"`
			};
		}
	}

	return { isBlocked: false };
}

/* ==========================================================================
   TYPED EVIDENCE FACTORY & NORMALIZER
   ========================================================================== */

let _signalCounter = 0;

export function createTypedEvidence(raw) {
	_signalCounter++;
	const type = raw.type || 'UNKNOWN';
	const category = SIGNAL_CATEGORIES[type] || 'NETWORK_TELEMETRY';
	const baseSeverity = raw.severity || (SIGNAL_WEIGHTS[type] >= 40 ? 'high' : SIGNAL_WEIGHTS[type] >= 15 ? 'medium' : 'low');
	const confidence = typeof raw.confidence === 'number' ? Math.max(0, Math.min(1, raw.confidence)) : 0.85;

	return {
		signalId: `sig_${Date.now()}_${_signalCounter}`,
		type,
		category,
		severity: baseSeverity,
		confidence,
		details: raw.details || {},
		timestamp: raw.timestamp || Date.now(),
		state: 'ACTIVE'
	};
}

/* ==========================================================================
   UNIFIED CORRELATED RISK SCORER (PHASE 5)
   ========================================================================== */

export function computeUnifiedRiskScore(rawSignals = [], context = {}) {
	const {
		aiVerdict = null,
		isCrossOriginSubmit = false,
		isKnownIdP = false,
		destinationOrigin = null,
		pageStatus = null,
		isInterstitialBlocked = false,
		interstitialReason = ''
	} = context;

	// Check if this evaluation is blocked by a bot challenge / CAPTCHA / 403
	if (isInterstitialBlocked || aiVerdict === 'unverified') {
		return {
			score: 0,
			level: 'UNVERIFIED',
			verdict: 'unverified',
			contributors: ['Access blocked by bot challenge/interstitial security check'],
			activeSignals: [],
			unverifiedReason: interstitialReason || "We couldn't verify the destination page because access is blocked by a security check. Treat this destination as unverified and proceed cautiously."
		};
	}

	const now = Date.now();
	let score = 0;
	const contributors = [];
	const seenTypes = new Set();
	const activeSignals = [];

	// 1. AI model prediction verdict
	if (aiVerdict === 'phishing') {
		score += SIGNAL_WEIGHTS.AI_MODEL_PHISHING;
		contributors.push('AI Model: Confirmed Phishing (+60)');
	} else if (aiVerdict === 'suspicious') {
		score += SIGNAL_WEIGHTS.AI_MODEL_SUSPICIOUS;
		contributors.push('AI Model: Suspicious (+30)');
	} else if (aiVerdict === 'safe') {
		score = 0;
	}

	// 2. Cross-origin sensitive form destination
	if (isCrossOriginSubmit && !isKnownIdP) {
		if (!isKnownLegitimateDestination(destinationOrigin)) {
			score += SIGNAL_WEIGHTS.SUSPICIOUS_CROSS_ORIGIN_SUBMIT;
			contributors.push(`Cross-origin submit to unverified domain: ${destinationOrigin || 'unknown'} (+50)`);
		}
	}

	// 3. Process dynamic signals using Sliding Correlation Window (expire > 15s)
	for (const raw of rawSignals) {
		const sig = raw.category ? raw : createTypedEvidence(raw);

		// Sliding window check: expire stale signals
		if (now - sig.timestamp > CORRELATION_WINDOW_MS) {
			sig.state = 'EXPIRED';
			continue;
		}

		// Check for interstitial signal embedded in signals
		if (sig.type === 'INTERSTITIAL_CAPTCHA_DETECTED' || sig.type === 'ACCESS_DENIED_STATE') {
			return {
				score: 0,
				level: 'UNVERIFIED',
				verdict: 'unverified',
				contributors: ['Bot challenge/interstitial detected on tab'],
				activeSignals: [sig],
				unverifiedReason: sig.details?.reason || "We couldn't verify the destination page because access is blocked by a security check. Treat this destination as unverified and proceed cautiously."
			};
		}

		// Deduplication by signal type
		if (seenTypes.has(sig.type)) {
			continue;
		}
		seenTypes.add(sig.type);

		const baseWeight = SIGNAL_WEIGHTS[sig.type] ?? 0;
		if (baseWeight === 0) continue;

		// Suppress infrastructure signals when destination is legitimate
		if (DESTINATION_DISCOUNTED_SIGNALS.has(sig.type)) {
			const dest = sig.details?.destinationOrigin || sig.details?.iframeOrigin || sig.details?.scriptOrigin || destinationOrigin;
			if (isKnownLegitimateDestination(dest)) {
				sig.state = 'DISCOUNTED';
				continue;
			}
		}

		// Apply confidence scaling
		const effectiveWeight = Math.round(baseWeight * sig.confidence);
		score += effectiveWeight;
		sig.state = 'ACTIVE';
		activeSignals.push(sig);
		contributors.push(`${sig.type} (+${effectiveWeight})`);
	}

	// 4. Page status bias
	if (pageStatus === 'phishing') {
		score = Math.max(score, THRESHOLDS.HIGH);
		if (!contributors.includes('Page previously flagged as phishing')) {
			contributors.push('Page previously flagged as phishing');
		}
	}

	// 5. Categorize output levels
	let level;
	let verdict;

	if (score >= THRESHOLDS.HIGH) {
		level = 'HIGH';
		verdict = 'phishing';
	} else if (score >= THRESHOLDS.MEDIUM) {
		level = 'MEDIUM';
		verdict = 'suspicious';
	} else {
		level = 'LOW';
		verdict = 'safe';
	}

	return {
		score,
		level,
		verdict,
		contributors,
		activeSignals
	};
}

export function toSubmissionGuardResponse(riskResult, destinationOrigin) {
	const { score, level, verdict, contributors, unverifiedReason } = riskResult;

	if (level === 'UNVERIFIED') {
		return {
			verdict: 'UNVERIFIED',
			level: 'UNVERIFIED',
			reason: unverifiedReason || "We couldn't verify the destination page because access is blocked by a security check. Treat this destination as unverified and proceed cautiously.",
			score: 0,
			contributors
		};
	}

	if (level === 'HIGH') {
		return {
			verdict: 'BLOCK',
			level: 'HIGH',
			reason: `Submission blocked: Correlated threat score ${score}/100 — ${contributors.slice(0, 3).join('; ')}.`,
			score,
			contributors
		};
	}

	if (level === 'MEDIUM') {
		return {
			verdict: 'WARN',
			level: 'MEDIUM',
			reason: `Caution: Suspicious indicators detected on this form (score ${score}/100) — ${contributors.join('; ')}.`,
			score,
			contributors
		};
	}

	return {
		verdict: 'ALLOW',
		level: 'LOW',
		reason: 'Destination verified as legitimate.',
		score,
		contributors
	};
}

export function computeRiskScore(signals, context) {
	const res = computeUnifiedRiskScore(signals, context);
	return {
		score: res.score,
		level: res.level,
		verdict: res.verdict,
		contributors: res.contributors,
		unverifiedReason: res.unverifiedReason
	};
}

export function derivePageStatusFromSignals(allSignalsForTab, currentPageStatus, aiVerdict = null) {
	if (currentPageStatus === 'phishing') return null;

	const res = computeUnifiedRiskScore(allSignalsForTab, {
		aiVerdict,
		pageStatus: currentPageStatus
	});

	if (res.level === 'UNVERIFIED') return 'unverified';
	if (res.level === 'HIGH' && currentPageStatus !== 'phishing') return 'phishing';
	if (res.level === 'MEDIUM' && currentPageStatus !== 'suspicious' && currentPageStatus !== 'phishing') return 'suspicious';
	return null;
}
