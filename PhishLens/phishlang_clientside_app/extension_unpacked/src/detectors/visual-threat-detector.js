/**
 * PhishLens - Phase 4: Visual Threat Detection Module
 *
 * Detectors:
 *   A. Clickjacking & Deceptive Overlay Detector
 *   B. QR-Code Phishing (Quishing) Detector — fully local, zero external calls
 *   C. Image-based Phishing & Visual Impersonation Detector
 *
 * STRICT PRIVACY: No user input values, keystrokes, or credentials are read.
 * STRICT CORS: Canvas data extraction respects tainted-canvas security boundaries.
 *              No images are uploaded to any external service.
 */

/* ==========================================================================
   CONSTANTS & CONFIGURATION
   ========================================================================== */

/** @type {Set<string>} - Deduplication of reported visual signals */
const _reportedVisualHashes = new Set();

/** Minimum overlap fraction for overlay detection to be triggered */
const OVERLAY_MIN_OVERLAP_FRACTION = 0.25;

/** z-index above which floating elements are considered "elevated" */
const OVERLAY_HIGH_Z_THRESHOLD = 50;

/**
 * Known brand keywords whose login/security prompts on unrelated domains signal impersonation.
 * These are matched against accessible metadata only (alt text, aria-label, surrounding text).
 */
const BRAND_KEYWORDS = [
	'paypal', 'amazon', 'apple', 'google', 'microsoft', 'facebook', 'instagram',
	'netflix', 'bank of america', 'wellsfargo', 'chase', 'citibank', 'hsbc',
	'barclays', 'twitter', 'x.com', 'dropbox', 'linkedin', 'whatsapp',
	'docusign', 'adobe', 'salesforce', 'coinbase', 'binance', 'kraken'
];

/** Login/credential UI prompt keywords for image-based impersonation detection */
const CREDENTIAL_PROMPT_KEYWORDS = [
	'sign in', 'sign-in', 'signin', 'log in', 'log-in', 'login', 'password',
	'verify identity', 'verify your account', 'account verification', 'confirm your identity',
	'secure login', 'authentication required', 'enter credentials', 'update password',
	'your session has expired', 'account suspended', 'verify your email',
	'click here to verify', 'confirm payment', 'verify payment'
];

/** CSS classes / id patterns hinting at legitimate modals/banners (not clickjacking) */
const BENIGN_OVERLAY_PATTERNS = [
	/cookie/i, /consent/i, /gdpr/i, /banner/i, /toast/i, /notification/i,
	/snackbar/i, /tooltip/i, /dropdown/i, /autocomplete/i, /navbar/i,
	/header/i, /nav/i, /sticky/i, /fixed-top/i, /skip-to/i
];

/* ==========================================================================
   SHARED UTILITY
   ========================================================================== */

/**
 * Emit a de-duplicated visual threat signal via the extension messaging channel.
 * @param {object} signal
 * @param {function} emitFn - The emitBehavioralSignal function from content-script scope
 */
function emitVisualSignal(signal, emitFn) {
	const hash = `VISUAL_${signal.type}_${JSON.stringify(signal.details).slice(0, 180)}`;
	if (_reportedVisualHashes.has(hash)) return;
	_reportedVisualHashes.add(hash);
	emitFn(signal);
}

/**
 * Compute axis-aligned bounding rectangle intersection area fraction
 * @param {DOMRect} a
 * @param {DOMRect} b
 * @returns {number} fraction of rect `b` that is covered by rect `a`
 */
function overlapFraction(a, b) {
	const ix = Math.max(0, Math.min(a.right, b.right) - Math.max(a.left, b.left));
	const iy = Math.max(0, Math.min(a.bottom, b.bottom) - Math.max(a.top, b.top));
	const intersection = ix * iy;
	const bArea = b.width * b.height;
	return bArea > 0 ? intersection / bArea : 0;
}

/**
 * Returns true if the element's id/class name matches a known benign overlay pattern
 * @param {Element} el
 * @returns {boolean}
 */
function isBenignOverlayByPattern(el) {
	const combined = `${el.id || ''} ${el.className || ''}`;
	return BENIGN_OVERLAY_PATTERNS.some(p => p.test(combined));
}

/* ==========================================================================
   DETECTOR A: CLICKJACKING & DECEPTIVE OVERLAY DETECTION
   ========================================================================== */

/**
 * Scan all sensitive form controls and buttons on the page for deceptive overlapping elements.
 * Runs once on idle after page load and can be triggered again on significant DOM mutations.
 * @param {function} emitFn
 */
function detectClickjackingOverlays(emitFn) {
	// Collect sensitive interaction targets
	const sensitiveSelectors = [
		'input[type="submit"]',
		'button[type="submit"]',
		'button:not([type])',
		'input[type="password"]',
		'input[type="email"]',
		'a[href]'
	];

	const sensitiveElements = /** @type {HTMLElement[]} */ (
		Array.from(document.querySelectorAll(sensitiveSelectors.join(',')))
			.filter(el => isVisibleElement(el))
			.slice(0, 40) // Limit scan scope for performance
	);

	if (sensitiveElements.length === 0) return;

	// Gather all elevated floating elements on the page
	const allElements = Array.from(document.querySelectorAll('*'));
	const overlayRatio = window.innerWidth > 0 ? 1 / window.innerWidth : 0;

	/** @type {HTMLElement[]} */
	const candidateOverlays = allElements.filter(el => {
		if (el.closest('[data-phishlens-ui]')) return false;
		if (!isVisibleElement(el)) return false;
		if (isBenignOverlayByPattern(el)) return false;

		const style = window.getComputedStyle(el);
		const position = style.position;
		if (position !== 'fixed' && position !== 'absolute' && position !== 'sticky') return false;

		const zIndex = parseInt(style.zIndex, 10);
		if (isNaN(zIndex) || zIndex < OVERLAY_HIGH_Z_THRESHOLD) return false;

		return true;
	});

	for (const target of sensitiveElements) {
		const targetRect = target.getBoundingClientRect();
		if (targetRect.width === 0 || targetRect.height === 0) continue;

		for (const overlay of candidateOverlays) {
			if (overlay === target || overlay.contains(target)) continue;

			const overlayRect = overlay.getBoundingClientRect();
			const fraction = overlapFraction(overlayRect, targetRect);
			if (fraction < OVERLAY_MIN_OVERLAP_FRACTION) continue;

			const style = window.getComputedStyle(overlay);
			const opacity = parseFloat(style.opacity);
			const pointerEvents = style.pointerEvents;
			const zIndex = parseInt(style.zIndex, 10);

			// Transparent or near-transparent overlapping element is a strong clickjacking signal
			const isLowOpacity = opacity < 0.15;
			const isPointerActive = pointerEvents !== 'none';

			if (!isPointerActive && !isLowOpacity) continue; // Purely decorative & non-interactive

			emitVisualSignal({
				type: 'CLICKJACKING_OVERLAY_DETECTED',
				severity: isLowOpacity ? 'high' : 'medium',
				details: {
					targetTag: target.tagName.toLowerCase(),
					targetId: target.id || null,
					targetType: target.getAttribute('type') || null,
					overlayTag: overlay.tagName.toLowerCase(),
					overlayId: overlay.id || null,
					overlayClass: (overlay.className || '').toString().slice(0, 60),
					overlayZIndex: zIndex,
					overlayOpacity: opacity,
					overlayPosition: style.position,
					overlapFraction: Math.round(fraction * 100),
					isTransparent: isLowOpacity,
					isPointerActive
				}
			}, emitFn);
		}
	}
}

/**
 * Compare the event's target with the visually top-most element at that point.
 * This detects UI redressing where a hidden element captures a user's click on an apparently safe button.
 * Called from the click capture listener in content-script.js
 * @param {MouseEvent} e
 * @param {function} emitFn
 */
function checkClickRedressing(e, emitFn) {
	const clickedElement = /** @type {HTMLElement} */ (e.target);
	if (!clickedElement || clickedElement.closest('[data-phishlens-ui]')) return;

	// elementFromPoint returns the top-most element at the click coordinates
	const topElement = document.elementFromPoint(e.clientX, e.clientY);
	if (!topElement || topElement === clickedElement || clickedElement.contains(topElement)) return;

	// If click target != top element, something is visually above it intercepting the click
	const topStyle = window.getComputedStyle(topElement);
	const topZIndex = parseInt(topStyle.zIndex, 10);
	const topOpacity = parseFloat(topStyle.opacity);

	if (topZIndex >= OVERLAY_HIGH_Z_THRESHOLD && topOpacity < 0.15) {
		emitVisualSignal({
			type: 'CLICK_REDRESSING_DETECTED',
			severity: 'high',
			details: {
				clickedTag: clickedElement.tagName.toLowerCase(),
				clickedId: clickedElement.id || null,
				topElementTag: topElement.tagName.toLowerCase(),
				topElementId: topElement.id || null,
				topZIndex,
				topOpacity,
				clickX: Math.round(e.clientX),
				clickY: Math.round(e.clientY)
			}
		}, emitFn);
	}
}

/* ==========================================================================
   DETECTOR B: QR-CODE PHISHING (QUISHING) DETECTOR
   ========================================================================== */

/**
 * Detect candidate QR code images by visual and semantic heuristics.
 * Returns array of candidate elements with metadata (never raw pixel data).
 * @returns {{ element: HTMLImageElement|HTMLCanvasElement, reason: string }[]}
 */
function findQRCandidates() {
	const candidates = [];

	// 1. Scan <img> elements
	for (const img of document.querySelectorAll('img')) {
		const alt = (img.alt || '').toLowerCase();
		const title = (img.title || '').toLowerCase();
		const className = (img.className || '').toLowerCase();
		const id = (img.id || '').toLowerCase();
		const combined = `${alt} ${title} ${className} ${id}`;

		const isQRKeyword = /(qr|q\.r\.|quick.?response|scan.?code|scan.?me|scan.?to|scan.?with)/i.test(combined);

		// Aspect ratio close to 1:1 (QR codes are square)
		const isSquare = img.naturalWidth > 0 && img.naturalHeight > 0 &&
			Math.abs(img.naturalWidth / img.naturalHeight - 1) < 0.1;

		// Minimum size to represent a scannable QR code
		const isSufficientSize = img.naturalWidth >= 80 || (img.width >= 80 && img.height >= 80);

		if (isQRKeyword && isSufficientSize) {
			candidates.push({ element: img, reason: 'qr-keyword-match', isSquare });
		} else if (isSquare && isSufficientSize && img.naturalWidth <= 400) {
			// Square image in a reasonable size range — lower confidence candidate
			candidates.push({ element: img, reason: 'square-image-heuristic', isSquare });
		}
	}

	// 2. Scan <canvas> elements
	for (const canvas of document.querySelectorAll('canvas')) {
		const id = (canvas.id || '').toLowerCase();
		const className = (canvas.className || '').toLowerCase();
		const combined = `${id} ${className}`;
		const isQRKeyword = /(qr|q\.r\.|quick.?response|scan.?code|scan.?me)/i.test(combined);
		const isSquare = canvas.width > 0 && canvas.height > 0 &&
			Math.abs(canvas.width / canvas.height - 1) < 0.1;
		const isSufficientSize = canvas.width >= 80;

		if ((isQRKeyword || isSquare) && isSufficientSize) {
			candidates.push({ element: canvas, reason: isQRKeyword ? 'qr-keyword-canvas' : 'square-canvas-heuristic', isSquare });
		}
	}

	return candidates;
}

/**
 * Attempt to decode a QR code from a canvas element.
 * Respects the canvas tainted-security boundary — returns null if canvas is tainted.
 * NEVER uploads pixel data externally.
 * @param {HTMLCanvasElement} canvas
 * @returns {{ data: string|null, error?: string }}
 */
function tryDecodeQRFromCanvas(canvas) {
	try {
		// getImageData throws SecurityError for tainted canvases (cross-origin images)
		const ctx = canvas.getContext('2d');
		if (!ctx) return { data: null, error: 'no-2d-context' };
		const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
		return decodeQRFromImageData(imageData);
	} catch (e) {
		if (e instanceof DOMException && e.name === 'SecurityError') {
			return { data: null, error: 'cors-tainted-canvas' };
		}
		return { data: null, error: `decode-error: ${e.message}` };
	}
}

/**
 * Attempt to draw an image to a same-origin canvas and decode from it.
 * Returns null if the image is cross-origin (tainted canvas will throw SecurityError).
 * @param {HTMLImageElement} img
 * @returns {{ data: string|null, error?: string }}
 */
function tryDecodeQRFromImage(img) {
	if (!img.complete || img.naturalWidth === 0) {
		return { data: null, error: 'image-not-loaded' };
	}
	try {
		const offscreen = document.createElement('canvas');
		offscreen.width = img.naturalWidth || img.width;
		offscreen.height = img.naturalHeight || img.height;
		const ctx = offscreen.getContext('2d');
		if (!ctx) return { data: null, error: 'no-2d-context' };
		ctx.drawImage(img, 0, 0, offscreen.width, offscreen.height);
		// Will throw SecurityError if cross-origin (CORS-unsafe)
		const imageData = ctx.getImageData(0, 0, offscreen.width, offscreen.height);
		return decodeQRFromImageData(imageData);
	} catch (e) {
		if (e instanceof DOMException && e.name === 'SecurityError') {
			return { data: null, error: 'cors-tainted-canvas' };
		}
		return { data: null, error: `decode-error: ${e.message}` };
	}
}

/**
 * Lightweight QR code decoder — zero external dependencies, pure client-side.
 * Implements a simplified local version using jsQR's algorithm pattern.
 * Returns decoded string or null if decoding fails.
 *
 * NOTE: This embedded decoder is a stub placeholder. The actual jsQR library
 * must be bundled as a local file at `src/lib/jsqr.min.js` and loaded via
 * the manifest's `web_accessible_resources` or directly in the content script.
 * No network requests to any CDN or external endpoint are made.
 *
 * @param {ImageData} imageData
 * @returns {{ data: string|null, error?: string }}
 */
function decodeQRFromImageData(imageData) {
	// Attempt to use the bundled jsQR if available (injected by manifest content_scripts)
	const jsQR = window.__phishLens_jsQR;
	if (typeof jsQR !== 'function') {
		return { data: null, error: 'qr-decoder-not-available' };
	}
	try {
		const result = jsQR(imageData.data, imageData.width, imageData.height);
		if (result && result.data) {
			return { data: result.data };
		}
		return { data: null, error: 'no-qr-found' };
	} catch (e) {
		return { data: null, error: `jsqr-error: ${e.message}` };
	}
}

/**
 * Redact known sensitive query params from a URL string before passing for analysis.
 * Mirrors the sanitizeAndRedactUrl function in service-worker.js (no import available from CS).
 * @param {string} urlString
 * @returns {string}
 */
function redactUrlParams(urlString) {
	try {
		const parsed = new URL(urlString);
		const sensitiveKeys = ['token', 'password', 'key', 'secret', 'auth', 'session', 'code', 'sig', 'access_token', 'id_token', 'bearer', 'api_key'];
		for (const key of Array.from(parsed.searchParams.keys())) {
			if (sensitiveKeys.some(sk => key.toLowerCase().includes(sk))) {
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

/**
 * Run the QR detection scan across all candidate elements on the page.
 * @param {function} emitFn
 */
function detectQRCodePhishing(emitFn) {
	const candidates = findQRCandidates();
	if (candidates.length === 0) return;

	for (const { element, reason, isSquare } of candidates) {
		let decodeResult = { data: null, error: 'not-attempted' };

		if (element.tagName === 'IMG') {
			decodeResult = tryDecodeQRFromImage(/** @type {HTMLImageElement} */ (element));
		} else if (element.tagName === 'CANVAS') {
			decodeResult = tryDecodeQRFromCanvas(/** @type {HTMLCanvasElement} */ (element));
		}

		if (decodeResult.data) {
			// Successfully decoded a QR code
			let qrStatus = 'unknown';
			let sanitizedQrUrl = null;
			let isUrl = false;

			try {
				const parsed = new URL(decodeResult.data);
				isUrl = true;
				sanitizedQrUrl = redactUrlParams(decodeResult.data);
				qrStatus = 'decoded-url';
			} catch {
				qrStatus = 'decoded-non-url';
			}

			emitVisualSignal({
				type: isUrl ? 'QR_CODE_URL_DETECTED' : 'QR_CODE_DATA_DETECTED',
				severity: isUrl ? 'high' : 'medium',
				details: {
					detectionReason: reason,
					decodedType: qrStatus,
					sanitizedUrl: sanitizedQrUrl,
					rawDataLength: decodeResult.data.length,
					elementTag: element.tagName.toLowerCase(),
					elementId: element.id || null,
					elementAlt: element instanceof HTMLImageElement ? (element.alt || null) : null
				}
			}, emitFn);

			// Forward decoded URL into the existing URL risk pipeline via background worker
			if (isUrl && sanitizedQrUrl) {
				try {
					chrome.runtime.sendMessage({
						action: 'evaluateQRUrl',
						payload: {
							sanitizedUrl: sanitizedQrUrl,
							pageUrl: window.location.href,
							pageOrigin: window.location.origin
						}
					}, () => {
						if (chrome.runtime.lastError) {/* Background may be reloading */}
					});
				} catch { /* Context may be invalidated */ }
			}
		} else {
			// Could not decode — mark as unverified (never assume safe or malicious)
			const error = decodeResult.error;
			const isCORSBlocked = error === 'cors-tainted-canvas';
			const isDecoderAbsent = error === 'qr-decoder-not-available';

			emitVisualSignal({
				type: 'QR_CODE_CANDIDATE_UNVERIFIED',
				severity: 'low',
				details: {
					detectionReason: reason,
					decodeError: error,
					isCORSBlocked,
					isDecoderAbsent,
					elementTag: element.tagName.toLowerCase(),
					elementId: element.id || null,
					elementAlt: element instanceof HTMLImageElement ? (element.alt || null) : null,
					note: isCORSBlocked
						? 'CORS security boundary prevented QR decode — image is cross-origin. Status: UNVERIFIED.'
						: 'QR decode failed or decoder unavailable. Status: UNVERIFIED.'
				}
			}, emitFn);
		}
	}
}

/* ==========================================================================
   DETECTOR C: IMAGE-BASED PHISHING & VISUAL IMPERSONATION
   ========================================================================== */

/**
 * Scan large images on the page for accessible metadata suggesting credential/login prompts.
 * Checks for brand impersonation on unrelated base domains.
 * @param {function} emitFn
 */
function detectImageBasedImpersonation(emitFn) {
	const pageHostname = window.location.hostname.toLowerCase();
	const images = Array.from(document.querySelectorAll('img'));

	for (const img of images) {
		// Only inspect sufficiently large images (login panels are typically large)
		const displayWidth = img.offsetWidth || img.width;
		const displayHeight = img.offsetHeight || img.height;
		if (displayWidth < 150 || displayHeight < 60) continue;

		const alt = (img.alt || '').toLowerCase().trim();
		const title = (img.title || '').toLowerCase().trim();
		const ariaLabel = (img.getAttribute('aria-label') || '').toLowerCase();
		const figCaption = (() => {
			const fig = img.closest('figure');
			if (!fig) return '';
			const cap = fig.querySelector('figcaption');
			return cap ? (cap.textContent || '').toLowerCase() : '';
		})();

		// Also check up to 2 levels of surrounding container text for context
		const surroundingText = (() => {
			const parent = img.parentElement;
			if (!parent) return '';
			return (parent.textContent || '').toLowerCase().replace(/\s+/g, ' ').slice(0, 200);
		})();

		const allMeta = `${alt} ${title} ${ariaLabel} ${figCaption} ${surroundingText}`;

		// 1. Detect brand names in metadata
		const detectedBrands = BRAND_KEYWORDS.filter(b => allMeta.includes(b));

		// 2. Detect credential/login prompts
		const detectedPrompts = CREDENTIAL_PROMPT_KEYWORDS.filter(k => allMeta.includes(k));

		if (detectedBrands.length === 0 && detectedPrompts.length === 0) continue;

		// 3. Check if the detected brand matches the current domain
		const isBrandOnOwnDomain = detectedBrands.some(brand => {
			const brandCore = brand.split(' ')[0].replace(/[^a-z0-9]/g, '');
			return pageHostname.includes(brandCore);
		});

		// Brand present but NOT on the brand's own domain → impersonation signal
		const isBrandImpersonation = detectedBrands.length > 0 && !isBrandOnOwnDomain;

		// Image with credential prompt keywords is suspicious regardless of brand
		const hasCredentialPrompt = detectedPrompts.length > 0;

		if (!isBrandImpersonation && !hasCredentialPrompt) continue;

		emitVisualSignal({
			type: isBrandImpersonation ? 'IMAGE_BRAND_IMPERSONATION_DETECTED' : 'IMAGE_CREDENTIAL_PROMPT_DETECTED',
			severity: isBrandImpersonation ? 'high' : 'medium',
			details: {
				elementId: img.id || null,
				elementSrc: img.src ? img.src.split('?')[0].slice(0, 100) : null,
				altText: alt.slice(0, 80) || null,
				detectedBrands: detectedBrands.slice(0, 5),
				detectedPrompts: detectedPrompts.slice(0, 5),
				isBrandOnOwnDomain,
				pageHostname,
				displayWidth,
				displayHeight,
				note: isBrandImpersonation
					? `Brand "${detectedBrands[0]}" detected on unrelated domain "${pageHostname}".`
					: `Image appears to present a credential/login prompt ("${detectedPrompts[0]}").`
			}
		}, emitFn);
	}
}

/* ==========================================================================
   INTERNAL HELPERS
   ========================================================================== */

/**
 * Check if element is visible (non-zero size, not hidden)
 * @param {Element} el
 * @returns {boolean}
 */
function isVisibleElement(el) {
	if (!el || !(el instanceof HTMLElement)) return false;
	if (el.hidden) return false;
	const style = window.getComputedStyle(el);
	if (style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0') return false;
	return el.offsetWidth > 0 || el.offsetHeight > 0;
}

/* ==========================================================================
   PUBLIC API — called from content-script.js
   ========================================================================== */

/**
 * Run all three Phase 4 visual detectors once per page-load (on requestIdleCallback).
 * @param {function} emitBehavioralSignal - Signal emitter from content-script.js scope
 */
function runVisualThreatDetection(emitBehavioralSignal) {
	const run = () => {
		detectClickjackingOverlays(emitBehavioralSignal);
		detectQRCodePhishing(emitBehavioralSignal);
		detectImageBasedImpersonation(emitBehavioralSignal);
	};

	if (typeof requestIdleCallback === 'function') {
		requestIdleCallback(run, { timeout: 4000 });
	} else {
		setTimeout(run, 1000);
	}
}

/**
 * Run only the click-redressing check on a MouseEvent.
 * Call this from the existing click capture listener.
 * @param {MouseEvent} e
 * @param {function} emitBehavioralSignal
 */
function runClickRedressingCheck(e, emitBehavioralSignal) {
	checkClickRedressing(e, emitBehavioralSignal);
}

/**
 * Re-run overlay and image detectors on significant DOM mutations.
 * Rate-limited: at most once per 2 seconds.
 * @param {function} emitBehavioralSignal
 */
let _lastMutationRescan = 0;
function rescanOnMutation(emitBehavioralSignal) {
	const now = Date.now();
	if (now - _lastMutationRescan < 2000) return;
	_lastMutationRescan = now;

	if (typeof requestIdleCallback === 'function') {
		requestIdleCallback(() => {
			detectClickjackingOverlays(emitBehavioralSignal);
			detectImageBasedImpersonation(emitBehavioralSignal);
		}, { timeout: 3000 });
	}
}
