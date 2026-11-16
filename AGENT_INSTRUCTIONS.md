# Agent Instructions: Dynamic Behavioural Threat Detection for the Phishing-Protection Browser Extension

## Goal

Inspect the existing repository and implement the features below in its
current architecture. Do not merely provide suggestions, mockups, or a
mock risk score: make the code changes, test them, and report the
results. Preserve existing functionality and coding conventions. First
inspect `manifest.json`, the extension architecture, permissions,
content scripts, service worker, risk engine, UI, and tests. Reuse
existing components rather than creating duplicate systems.

The feature should continuously assess webpage behaviour after initial
page load and protect users before sensitive information is submitted.

## 1. Dynamic DOM monitoring

Use `MutationObserver` in the content script to monitor relevant
changes: - New password, email, OTP, or payment-related fields. - Hidden
forms or fields becoming visible. - New forms being inserted. - Form
`action` or `method` attributes changing. - New scripts, iframes, login
overlays, and relevant links being added or changed.

Batch/debounce mutation processing. Ignore irrelevant mutations and the
extension's own UI. Re-check current DOM state rather than assuming a
mutation is malicious. Never read or store values typed into fields.

## 2. Continuous user-interaction monitoring

Monitor relevant interactions throughout the page lifetime, not only at
initial load: - Clicks on links, buttons, submit controls, and
image-based controls. - `pointerdown`, `auxclick`, and keyboard
activation where relevant. - `focusin` and `change` on sensitive fields,
without reading their values. - Form submission attempts. -
Navigation/new-window attempts where observable. - DOM and form changes
caused by interactions.

Correlate an interaction with subsequent DOM mutations, requests, and
redirects using short-lived metadata. Example: a click causes a hidden
form to appear, its action changes to an unrelated origin, and a request
follows.

Do not record keystrokes, typed text, passwords, OTPs, clipboard
contents, cookies, or authentication data. Track only safe metadata such
as event type, element type, timestamp, and relevant origin. Use
delegated listeners where appropriate, support single-page applications,
prevent listener accumulation, debounce repeated events, and avoid
blocking normal interactions without sufficient evidence.

## 3. Form and submission monitoring

Inspect sensitive forms and their current: - `action`, `method`, and
destination origin. - Field types, labels, and autocomplete metadata. -
Visibility and changes after page load. - Submission path, including
submit buttons and programmatic submission where supported.

A destination on another origin is a signal to investigate, not proof of
phishing. Account for legitimate identity providers, payment processors,
CDNs, and federated login.

Re-check the destination immediately before submission. Detect
suspicious changes that occur after initial scanning or user
interaction.

## 4. Network and redirect monitoring

Use APIs compatible with the repository's Chrome extension manifest
version to observe relevant requests and navigation: - Unexpected
cross-origin requests around sensitive form submission. - Form
submissions to unrelated or suspicious origins. - Redirect chains
leading to suspicious destinations. - Dynamically loaded scripts or
frames from suspicious origins, where observable.

Manifest V3 requirements: - Inspect the current manifest before choosing
APIs. - `chrome.webRequest` has important MV3 blocking limitations; do
not assume it can arbitrarily cancel requests. - Use
`chrome.declarativeNetRequest` for supported blocking rules when
appropriate. - Use supported `chrome.webNavigation` and request events
for observation where permitted. - Request minimum permissions and host
access. Do not add broad permissions without explaining why they are
required. - Document what cannot be observed or blocked. Do not claim
complete coverage.

Redact likely secrets and sensitive query parameters from
logged/displayed URLs.

## 5. JavaScript behaviour monitoring

Where useful, detect suspicious behaviour involving: - `fetch()`,
`XMLHttpRequest`, and `navigator.sendBeacon()` around sensitive form
submission. - Dynamic script/iframe loading. - Form destination
changes. - Programmatic form submission.

Content scripts run in an isolated world. If page-world instrumentation
is needed, use a narrowly scoped MAIN-world script compatible with the
current manifest. Treat messages from the page as untrusted; validate
their shape, origin, tab/frame context, and data types. Never expose
privileged extension APIs to page scripts. Do not capture credentials,
cookies, tokens, or arbitrary page contents. Do not use `eval()` or
unsafe dynamic code execution.

If an API cannot be monitored reliably under browser security rules,
document the limitation and implement the strongest supported
alternative.

## 6. QR-code phishing (quishing) monitoring

Identify likely QR-code images and canvases, including those inserted or
replaced dynamically.

-   Use image `alt` text, accessible labels, nearby text, and associated
    link destinations as contextual signals.
-   Where feasible, decode QR codes in a safe environment using a
    reputable maintained library. Do not upload page images or QR
    contents to an external service by default.
-   Respect cross-origin/CORS restrictions and tainted-canvas
    limitations; never bypass browser security.
-   If a QR code resolves to a URL, pass that URL through the existing
    URL/domain reputation and risk pipeline.
-   Check suspicious URL patterns, lookalike domains, raw IP hosts,
    misleading brand/domain combinations, risky schemes, and redirect
    destinations.
-   Never automatically open a QR destination.
-   If decoding fails or the destination cannot be inspected, report it
    as **unverified**, not safe or malicious.
-   If the QR destination is high risk, warn before the user follows it.
    If it is merely displayed, do not claim a credential-theft attempt
    occurred.
-   Avoid rescanning every image: use mutation-driven processing,
    caching, size/visibility heuristics, and resource limits.

Test benign, suspicious mock, malformed, low-resolution, rotated, and
dynamically inserted QR codes using harmless local URLs.

## 7. Clickjacking and deceptive overlay detection

Detect possible UI-redressing patterns: - Transparent or nearly
transparent overlays over important controls. - Large fixed-position
elements intercepting pointer events. - Invisible/obscured iframes
layered over visible buttons or links. - Mismatch between the apparent
control and the actual event target. - Overlays appearing around
sensitive actions. - Visible labels that do not reasonably match the
actual destination/action.

Inspect relevant computed styles, bounding rectangles, stacking order
(`z-index`), opacity, visibility, pointer-event behaviour, and iframe
placement where accessible. On interaction, compare apparent and actual
targets where technically possible.

Treat these as signals, not proof: legitimate sites use modals, menus,
cookie banners, and embedded frames. Do not inspect cross-origin iframe
internals. Do not silently remove page elements or break layout. Warn
and block the associated sensitive submission only when combined
evidence reaches the high-risk threshold.

Test benign modals, cookie banners, transparent overlays, deceptive mock
overlays, and cross-origin iframe cases. Ensure legitimate overlays are
not routinely flagged.

## 8. Image-based phishing and visual impersonation

Support detection of phishing pages that use images to imitate login
screens, brand pages, buttons, or security prompts.

-   Identify large images, background images, and image regions near
    login/credential-entry areas.
-   Use image metadata, accessible text, nearby page text, form fields,
    and destination-domain information as initial signals.
-   Where feasible, use local OCR to detect text embedded in images. An
    external OCR/image service must not be enabled by default; require
    explicit privacy review and user awareness before any upload.
-   Compare detected brand names/login phrases with the actual page
    domain and form destination.
-   Flag combinations such as a recognizable brand/login prompt on an
    unrelated domain with a sensitive form.
-   Check image-based clickable controls for unexpected destinations.
-   Treat logos alone as weak evidence; legitimate articles,
    advertisements, and support pages may contain brand imagery.
-   If OCR is unavailable or confidence is low, mark the signal
    unknown/unverified.
-   Respect cross-origin image/canvas restrictions. Do not bypass CORS.

Test mock image-based login pages, background-image prompts, image
buttons, legitimate brand illustrations, and unrelated editorial images.

## 9. CAPTCHA and inaccessible forwarding-page alerts

If a forwarding/destination page cannot be inspected because of a
CAPTCHA, bot challenge, access-denied response, authentication wall, or
similar interstitial, show a clear alert.

Suggested message:

> We couldn't verify the forwarding page because access is blocked by a
> CAPTCHA or security check. Treat this destination as unverified and
> proceed cautiously.

Requirements: - Detect only observable challenge/interstitial
indicators, such as known CAPTCHA elements, challenge-page text,
access-denied messages, or navigation that remains on a challenge
page. - Never solve, bypass, automate, or evade CAPTCHAs, bot checks,
rate limits, or access controls. - Do not repeatedly reload or retry in
a way that worsens blocking. - Distinguish **unverified** from
**confirmed phishing**. A CAPTCHA alone is not proof of maliciousness. -
Preserve the observable redirect chain where permitted, but redact
likely secrets from URLs. - Offer safe actions such as returning to the
previous page or closing the tab. Do not automatically continue through
an unverified destination. - If the page later becomes inspectable
through normal user access, rerun ordinary checks. - Never store CAPTCHA
responses, challenge tokens, cookies, or authentication data.

Test using local mock CAPTCHA/interstitial and forwarding pages. Do not
automate access to real CAPTCHA-protected services.

## 10. Sensitive form locking

Implement robust form locking while assessment is pending and when
high-risk behaviour is detected.

-   Identify sensitive controls using field type, labels, autocomplete
    metadata, and form context; never inspect field values.
-   During assessment, optionally show a clear temporary protected state
    on relevant sensitive controls, consistent with the existing product
    design.
-   Prevent high-risk sensitive form submission before it is
    transmitted.
-   Re-check form destination, method, and risk evidence immediately
    before allowing submission.
-   Scope locking to the affected form/control; do not unnecessarily
    disable the whole page.
-   Explain why the field/form is locked. Make the status accessible to
    keyboard and screen-reader users.
-   Do not unlock merely because a timer elapsed.
-   Unlock only when assessment completes and the risk policy permits
    it.
-   On timeout or service-worker failure, show **Unable to verify**; do
    not label the page safe. Keep high-risk submission blocked until a
    safe choice is available.
-   Ensure exceptions or lost messages do not leave benign pages
    permanently locked.
-   Make lock/unlock operations idempotent and synchronise state using
    validated messages.
-   Do not rely on a CSS overlay as the security boundary.
-   Handle `submit`, submit buttons, and `requestSubmit()` carefully.
    Test programmatic submission paths and document limitations.
-   Never capture, copy, store, log, or transmit sensitive field values.

Test low-risk unlock, high-risk blocking, last-second action changes,
programmatic submissions, assessment timeout, extension errors, and
keyboard/screen-reader behaviour.

## 11. Unified risk scoring and event correlation

Integrate all evidence into the existing risk engine. Do not create
competing risk systems.

Signals may include: - Initial URL/domain/page checks. - Delayed or
interaction-triggered sensitive fields. - Form action/destination
changes. - Unexpected requests and redirect chains. - Suspicious QR-code
destinations. - Clickjacking/overlay indicators. - Image/OCR brand
impersonation. - CAPTCHA/inaccessible forwarding state. - Sensitive form
submission attempts.

Use a common typed evidence format containing only safe metadata: signal
identifier/category, origin and redacted destination, event type/time,
confidence/severity, short explanation, and state (confirmed,
suspicious, or unverified).

Deduplicate repeated evidence, expire stale signals, and use a bounded
correlation window. Do not inflate risk from repeated identical events.
Weak signals must not independently trigger a definitive phishing
verdict. CAPTCHA or unavailable inspection means **unverified**, not
phishing. Keep thresholds configurable and consistent with the current
project.

Suggested outcomes: - **Low:** allow normal interaction. - **Medium:**
warn and explain the concern. - **High:** block sensitive submission and
explain why. - **Unverified:** explain that inspection could not be
completed; do not claim safe or malicious without evidence.

## 12. User-facing alerts and protection

Warnings must state the actual reason, for example: - "This login form
sends information to an unexpected domain." - "This QR code points to a
suspicious destination." - "A transparent overlay may be intercepting
this click." - "This image appears to imitate a login page on an
unrelated domain." - "We couldn't verify the forwarding page because
access is blocked by a CAPTCHA or security check."

Show the suspicious destination when safe to do so. Provide safe exit
options. Do not silently redirect users. Ensure the extension UI is
distinguishable from page content and does not trigger its own observer.
Do not claim a page is safe solely because no suspicious behaviour was
observed.

## 13. Architecture and engineering requirements

Adapt to the existing codebase. A typical separation is: - **Content
script:** DOM observation, interaction events, form inspection, QR/image
candidate discovery, and form-lock UI. - **Background service worker:**
permitted request/navigation observation, coordination, and risk
updates. - **MAIN-world instrumentation:** only if required, narrowly
scoped and without credential capture. - **Risk engine:** combines
static and behavioural evidence. - **Extension UI:** risk state,
reasons, and safe user actions.

Keep messages small, typed, validated, and free of sensitive values.
Handle single-page navigation, cleanup observers/listeners, bounded
queues, and performance. Fail safely without falsely labelling
uninspected pages as safe.

## 14. Testing requirements

Use local mock pages/servers and dummy data only. Never use real
credentials or live phishing infrastructure.

Test at least: 1. Normal static login form submitting to its own origin.
2. Legitimate third-party identity-provider login. 3. Harmless dynamic
input insertion. 4. Delayed and click-triggered password-field
insertion. 5. Form action changed after page load and immediately before
submission. 6. Redirect and external request after a mock interaction.
7. Hidden form later made visible. 8. Frequent benign single-page-app
DOM changes. 9. Benign and suspicious QR destinations; malformed and
undecodable QR codes. 10. Dynamically inserted QR codes. 11. Benign
modal/cookie banner and deceptive transparent overlay. 12. Cross-origin
iframe that cannot be inspected internally. 13. Image-based fake login
and legitimate unrelated brand imagery. 14. CAPTCHA/access-denied
forwarding interstitial. 15. Destination that remains unverified. 16.
Low-risk form unlock after completed assessment. 17. High-risk form
blocked before transmission. 18. Assessment timeout does not silently
unlock a sensitive form. 19. Programmatic form submission paths to the
extent supported. 20. Repeated mutations/events do not inflate risk or
degrade performance.

For every test, record expected and observed behaviour, risk outcome,
whether submission was prevented before transmission, false-positive
considerations, and browser/API limitations.

## 15. Privacy and performance

-   Never collect or log passwords, OTPs, payment details, cookies,
    session tokens, authentication headers, clipboard contents, or full
    keystroke sequences.
-   Do not transmit browsing history, page contents, images, or QR data
    to an external service by default.
-   Debounce mutation processing and avoid full-page scans on every
    event.
-   Bound queues, caches, observers, and timers; clean up when no longer
    needed.
-   Use minimum permissions and host access.
-   Do not bypass CORS, cross-origin isolation, CAPTCHA, bot checks, or
    access controls.
-   Do not break benign sites. Document false-positive risks and
    unsupported cases.

## 16. Deliverables

After implementation: 1. List every file created or modified. 2. Explain
the role of each changed file. 3. Describe the flow from page load
through continuous monitoring, risk assessment, alerting, and
prevention. 4. Document manifest/API limitations and anything that
cannot be reliably observed. 5. Provide setup, build, and run
instructions. 6. Provide tests run and their results. 7. Identify
remaining limitations honestly.

## 17. Definition of done

The work is complete only when: - Dynamic DOM changes and continuous
user interactions are monitored. - Delayed and interaction-triggered
form changes are detected. - Relevant form destinations, requests, and
redirects are assessed within browser API limits. - QR-code destinations
are decoded and checked where feasible. - Clickjacking/deceptive overlay
indicators are assessed without routinely flagging legitimate UI. -
Image-based phishing/visual impersonation is assessed with confidence
limits. - CAPTCHA/access-challenge forwarding pages produce an
**unverified** alert without bypassing controls. - Sensitive forms are
locked during assessment according to policy and high-risk submissions
are blocked before transmission. - All signals feed one consistent risk
engine. - Benign dynamic websites remain usable. - No sensitive values
are captured, logged, stored, or transmitted. - Tests and limitations
are documented.

**Do not fake coverage or merely add UI labels. Implement and test the
real detection and protection flow. Where browser security restrictions
prevent reliable observation or blocking, state the limitation and
implement the strongest supported alternative.**
