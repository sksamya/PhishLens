/**
 * PhishLens Gemini Client Service
 * Generates dynamic, AI-powered site security reports and explanation of threats.
 */

/**
 * Call Gemini generateContent API to explain why a website was flagged or evaluate its threat profile.
 * @param {string} apiKey
 * @param {object} params
 * @param {string} params.url
 * @param {string} params.domain
 * @param {string} params.verdict
 * @param {Array<object>} [params.signals]
 * @returns {Promise<{ explanation: string, threatSummary: string, recommendations: string[] }>}
 */
export async function generateSiteExplanationWithGemini(apiKey, { url, domain, verdict, signals = [] }) {
	const trimmedKey = (apiKey || '').trim();
	if (!trimmedKey) {
		throw new Error('Please enter your Gemini API key in User Settings above.');
	}

	const signalsSummary = signals.length > 0
		? signals.map(s => `- ${s.type} (${s.severity || 'medium'}): ${JSON.stringify(s.details || {})}`).join('\n')
		: 'No behavioral DOM signals recorded.';

	const prompt = `You are a web security analyst for PhishLens browser security.
Analyze the following website and behavioral threat signals, and provide an in-depth, user-friendly security report:

URL: ${url}
Domain: ${domain}
System Verdict: ${verdict}

Observed Behavioral/Structural Signals:
${signalsSummary}

Please reply in valid JSON format matching this exact schema:
{
  "threatSummary": "A concise 1-2 sentence overview of why this site is safe, suspicious, or dangerous.",
  "explanation": "A detailed 2-3 paragraph explanation of the technical indicators (e.g. deceptive domain names, suspicious query parameters, cross-origin credential harvesting, hidden forms).",
  "recommendations": [
    "Actionable tip 1 for the user",
    "Actionable tip 2 for the user",
    "Actionable tip 3 for the user"
  ]
}
Return only JSON with no markdown wrapping or markdown codeblocks.`;

	const controller = new AbortController();
	const timeout = setTimeout(() => controller.abort(), 30000);
	let response;
	try {
		response = await fetch('https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent', {
			method: 'POST',
			headers: {
				'Content-Type': 'application/json',
				'x-goog-api-key': trimmedKey
			},
			body: JSON.stringify({
				systemInstruction: { parts: [{ text: 'You are a cybersecurity expert specializing in phishing detection.' }] },
				contents: [{ role: 'user', parts: [{ text: prompt }] }],
				generationConfig: { temperature: 0.2, maxOutputTokens: 500, responseMimeType: 'application/json' }
			}),
			signal: controller.signal
		});
	} catch (error) {
		if (error.name === 'AbortError') {
			throw new Error('Gemini did not respond within 30 seconds. Check your connection and API key, then try again.');
		}
		throw error;
	} finally {
		clearTimeout(timeout);
	}

	if (!response.ok) {
		const errData = await response.json().catch(() => ({}));
		const errMsg = errData.error?.message || `HTTP ${response.status} ${response.statusText}`;
		throw new Error(`Gemini API error: ${errMsg}`);
	}

	const data = await response.json();
	const text = data.candidates?.[0]?.content?.parts?.map(part => part.text || '').join('').trim();
	if (!text) {
		throw new Error('Received empty response from Gemini.');
	}

	try {
		// Clean any accidental markdown codeblock wrapper
		const cleaned = text.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```$/i, '').trim();
		return JSON.parse(cleaned);
	} catch (e) {
		return {
			threatSummary: 'Security Report for ' + domain,
			explanation: text,
			recommendations: ['Verify the domain address carefully before entering any information.']
		};
	}
}
