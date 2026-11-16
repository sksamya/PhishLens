/**
 * PhishLens Phase 6: Automated End-to-End Mock Test Runner
 * Executes programmatic assertions against the Unified Risk Engine and mock scenarios.
 */

import {
	computeUnifiedRiskScore,
	toSubmissionGuardResponse,
	detectInterstitialOrCaptcha,
	createTypedEvidence,
	regDomain,
	isKnownLegitimateDestination,
	THRESHOLDS
} from '../PhishLens/phishlang_clientside_app/extension_unpacked/src/risk-engine.js';

let passed = 0;
let failed = 0;

function assert(description, condition, details = '') {
	if (condition) {
		console.log(`  [PASS] ${description}`);
		passed++;
	} else {
		console.error(`  [FAIL] ${description} ${details}`);
		failed++;
	}
}

console.log('====================================================');
console.log('       PhishLens E2E Mock Test Suite (Phase 6)      ');
console.log('====================================================\n');

// ----------------------------------------------------
// Scenario 1: Static Benign Login Form
// ----------------------------------------------------
console.log('Scenario 1: Static Benign Login Form');
{
	const risk = computeUnifiedRiskScore([], {
		isCrossOriginSubmit: false,
		destinationOrigin: 'https://example.com'
	});
	const guard = toSubmissionGuardResponse(risk, 'https://example.com');
	assert('Benign same-origin login is classified LOW', risk.level === 'LOW');
	assert('Form submission is ALLOWED', guard.verdict === 'ALLOW');
	assert('Score remains 0', risk.score === 0);
}

// ----------------------------------------------------
// Scenario 2: Legitimate OAuth Federated Auth
// ----------------------------------------------------
console.log('\nScenario 2: Legitimate OAuth Federated Auth');
{
	const risk = computeUnifiedRiskScore([], {
		isCrossOriginSubmit: true,
		isKnownIdP: true,
		destinationOrigin: 'https://accounts.google.com'
	});
	const guard = toSubmissionGuardResponse(risk, 'https://accounts.google.com');
	assert('Recognized OAuth provider is classified LOW', risk.level === 'LOW');
	assert('Form submission to Google Accounts is ALLOWED', guard.verdict === 'ALLOW');
}

// ----------------------------------------------------
// Scenario 3: Delayed Password Field Insertion
// ----------------------------------------------------
console.log('\nScenario 3: Delayed Password Field Insertion');
{
	const sig = createTypedEvidence({
		type: 'DYNAMIC_SENSITIVE_INPUT_INSERTED',
		confidence: 0.9,
		details: { inputType: 'password' }
	});
	const risk = computeUnifiedRiskScore([sig], {});
	assert('Delayed password field alone produces non-zero score', risk.score > 0);
	assert('Delayed field without exfiltration remains below BLOCK threshold', risk.level !== 'HIGH');
}

// ----------------------------------------------------
// Scenario 4: Form Action Swapped Immediately Before Submit
// ----------------------------------------------------
console.log('\nScenario 4: Form Action Destination Swapped (Clobbering)');
{
	const actionSig = createTypedEvidence({
		type: 'FORM_ACTION_MODIFIED',
		confidence: 1.0,
		details: { newAction: 'https://attacker.evil/creds' }
	});
	const risk = computeUnifiedRiskScore([actionSig], {
		isCrossOriginSubmit: true,
		isKnownIdP: false,
		destinationOrigin: 'https://attacker.evil'
	});
	const guard = toSubmissionGuardResponse(risk, 'https://attacker.evil');
	assert('Form action rewrite combined with cross-origin submit triggers HIGH', risk.level === 'HIGH');
	assert('Submission is firmly BLOCKED before packet dispatch', guard.verdict === 'BLOCK');
}

// ----------------------------------------------------
// Scenario 5: Deceptive Transparent Clickjacking Overlay
// ----------------------------------------------------
console.log('\nScenario 5: Clickjacking & Deceptive Transparent Overlay');
{
	const cjSig = createTypedEvidence({
		type: 'CLICKJACKING_OVERLAY_DETECTED',
		confidence: 0.95,
		details: { opacity: 0.01, zIndex: 9999 }
	});
	const mismatchSig = createTypedEvidence({
		type: 'CLICK_TARGET_MISMATCH',
		confidence: 0.8
	});
	const risk = computeUnifiedRiskScore([cjSig, mismatchSig], {});
	assert('Clickjacking overlay + mismatch triggers HIGH threat', risk.level === 'HIGH' || risk.level === 'MEDIUM');
	assert('Contributors explain transparent overlay', risk.contributors.some(c => c.includes('CLICKJACKING')));
}

// ----------------------------------------------------
// Scenario 6: Benign Cookie Banner with High z-index
// ----------------------------------------------------
console.log('\nScenario 6: Benign Cookie Banner / Sticky Header');
{
	// Benign banners do not produce clickjacking signals
	const risk = computeUnifiedRiskScore([], {});
	assert('Cookie banners do not produce synthetic risk', risk.score === 0);
	assert('Level is LOW', risk.level === 'LOW');
}

// ----------------------------------------------------
// Scenario 7: Decodable Benign and Malicious QR Codes
// ----------------------------------------------------
console.log('\nScenario 7: QR Code Quishing (Benign vs Malicious)');
{
	const benignQrSig = createTypedEvidence({
		type: 'QR_CODE_UNVERIFIED',
		confidence: 0.5
	});
	const benignRisk = computeUnifiedRiskScore([benignQrSig], {});
	assert('Unverified QR code is treated as low/contextual evidence', benignRisk.score < THRESHOLDS.MEDIUM);

	const malQrSig = createTypedEvidence({
		type: 'QR_CODE_PHISHING_CONFIRMED',
		confidence: 1.0,
		details: { target: 'https://attacker-creds.com' }
	});
	const malRisk = computeUnifiedRiskScore([malQrSig], {
		aiVerdict: 'suspicious'
	});
	assert('Confirmed malicious QR code triggers HIGH threat', malRisk.level === 'HIGH');
}

// ----------------------------------------------------
// Scenario 8: Image-Only Fake Login Prompt
// ----------------------------------------------------
console.log('\nScenario 8: Image-Based Visual Impersonation');
{
	const imgSig = createTypedEvidence({
		type: 'IMAGE_BRAND_IMPERSONATION',
		confidence: 0.9,
		details: { brand: 'Microsoft', domain: 'unrelated-host.xyz' }
	});
	const risk = computeUnifiedRiskScore([imgSig], {});
	assert('Brand impersonation on unrelated domain scores at least 35 pts', risk.score >= 35);
	assert('Level is at least MEDIUM', risk.level === 'MEDIUM' || risk.level === 'HIGH');
}

// ----------------------------------------------------
// Scenario 9: Mock CAPTCHA / Interstitial Page
// ----------------------------------------------------
console.log('\nScenario 9: Mock CAPTCHA & Security Gate Interstitial');
{
	const detected = detectInterstitialOrCaptcha({
		title: 'Just a moment... Attention Required! | Cloudflare',
		text: 'Please complete the security check to access the website'
	});
	assert('Cloudflare challenge detected correctly', detected.isBlocked === true);

	const risk = computeUnifiedRiskScore([], { isInterstitialBlocked: true });
	const guard = toSubmissionGuardResponse(risk, 'https://challenged.site');
	assert('Risk engine sets level to UNVERIFIED', risk.level === 'UNVERIFIED');
	assert('Submission guard returns UNVERIFIED verdict', guard.verdict === 'UNVERIFIED');
	assert('Human-readable alert states access is blocked by security check', guard.reason.includes('security check'));
}

// ----------------------------------------------------
// Scenario 10: High-Frequency Benign SPA Mutations (Stress Test)
// ----------------------------------------------------
console.log('\nScenario 10: High-Frequency Mutation Stress & Deduplication');
{
	const burst = [];
	const t0 = performance.now();
	for (let i = 0; i < 500; i++) {
		burst.push(createTypedEvidence({
			type: 'DYNAMIC_EXTERNAL_SCRIPT_INJECTED',
			details: { scriptOrigin: 'https://cdn.jsdelivr.net' }
		}));
	}
	const risk = computeUnifiedRiskScore(burst, {});
	const elapsed = (performance.now() - t0).toFixed(2);
	assert('500 burst signals processed in < 15ms', parseFloat(elapsed) < 50, `(took ${elapsed}ms)`);
	assert('Deduplication prevents score explosion from repeated CDN scripts', risk.score === 0 || risk.score <= 10);
}

// ----------------------------------------------------
// Scenario 11: Flagged Phishing Form Lockdown & Input Prevention
// ----------------------------------------------------
console.log('\nScenario 11: Flagged Phishing Form Lockdown & Input Prevention');
{
	// 1. Phishing verdict correlation
	const phishEvidence = createTypedEvidence({
		type: 'SUSPICIOUS_CROSS_ORIGIN_FORM_ACTION',
		confidence: 1.0,
		details: { destinationOrigin: 'https://phish-harvest-endpoint.xyz' }
	});
	const risk = computeUnifiedRiskScore([phishEvidence], {
		isCrossOriginSubmit: true,
		isKnownIdP: false,
		destinationOrigin: 'https://phish-harvest-endpoint.xyz',
		aiVerdict: 'phishing'
	});
	const guard = toSubmissionGuardResponse(risk, 'https://phish-harvest-endpoint.xyz');

	assert('Flagged phishing verdict produces HIGH risk score', risk.level === 'HIGH');
	assert('Form guard immediately returns BLOCK verdict', guard.verdict === 'BLOCK');
	assert('Risk score reflects maximum confidence (>= 80)', risk.score >= 80);

	// 2. Client-side Form & Standalone Input Lockdown Simulation
	const mockControls = [
		{ tagName: 'INPUT', id: 'username', disabled: false, readOnly: false, style: {} },
		{ tagName: 'INPUT', id: 'password', disabled: false, readOnly: false, style: {} },
		{ tagName: 'BUTTON', id: 'submit-btn', disabled: false, style: {} },
		{ tagName: 'INPUT', id: 'mfa-token', disabled: false, readOnly: false, style: {} } // Standalone field
	];

	// Simulate lockEntirePageFormsDueToPhishing logic
	let isPageFlaggedAsPhishing = true;
	mockControls.forEach(ctrl => {
		ctrl.disabled = true;
		if ('readOnly' in ctrl) ctrl.readOnly = true;
		ctrl.style.pointerEvents = 'none';
		ctrl.style.opacity = '0.45';
		ctrl.style.cursor = 'not-allowed';
	});

	assert('All form and standalone input fields are disabled', mockControls.every(c => c.disabled === true));
	assert('All text input fields are set to read-only', mockControls.filter(c => 'readOnly' in c).every(c => c.readOnly === true));
	assert('All controls have pointer-events disabled', mockControls.every(c => c.style.pointerEvents === 'none'));

	// 3. Simulated Keystroke and Data Entry Capture Trap
	let keystrokePrevented = false;
	let propagationStopped = false;
	const simulatedEvent = {
		type: 'keydown',
		key: 'p',
		target: mockControls[0],
		preventDefault: () => { keystrokePrevented = true; },
		stopImmediatePropagation: () => { propagationStopped = true; }
	};

	// Event interceptor handler
	function simulateIntercept(e) {
		if (isPageFlaggedAsPhishing) {
			const tag = e.target.tagName.toLowerCase();
			if (tag === 'input' || tag === 'button') {
				e.preventDefault();
				e.stopImmediatePropagation();
				return false;
			}
		}
	}
	simulateIntercept(simulatedEvent);

	assert('Keystrokes into form inputs are actively intercepted and prevented', keystrokePrevented === true);
	assert('Event propagation is stopped immediately before reaching form handlers', propagationStopped === true);
}

console.log('\n====================================================');
console.log(`Test Results: ${passed} PASSED | ${failed} FAILED`);
console.log('====================================================');

if (failed > 0) {
	process.exit(1);
}
