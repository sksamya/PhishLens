/**
 * PhishLens OpenAI Client Service
 * Generates dynamic, AI-powered site security reports and explanation of threats.
 */

/**
 * Call OpenAI Chat Completion API to explain why a website was flagged or evaluate its threat profile.
 * @param {string} apiKey
 * @param {object} params
 * @param {string} params.url
 * @param {string} params.domain
 * @param {string} params.verdict
 * @param {Array<object>} [params.signals]
 * @returns {Promise<{ explanation: string, threatSummary: string, recommendations: string[] }>}
 */
export async function generateSiteExplanationWithOpenAI(apiKey, { url, domain, verdict, signals = [] }) {
	if (!apiKey || typeof apiKey !== 'string' || !apiKey.startsWith('sk-')) {
		throw new Error('Please provide a valid OpenAI API key starting with "sk-".');
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

	const response = await fetch('https://api.openai.com/v1/chat/completions', {
		method: 'POST',
		headers: {
			'Content-Type': 'application/json',
			'Authorization': `Bearer ${apiKey}`
		},
		body: JSON.stringify({
			model: 'gpt-3.5-turbo',
			messages: [
				{ role: 'system', content: 'You are a cybersecurity expert specializing in phishing detection.' },
				{ role: 'user', content: prompt }
			],
			temperature: 0.2,
			max_tokens: 500
		})
	});

	if (!response.ok) {
		const errData = await response.json().catch(() => ({}));
		const errMsg = errData.error?.message || `HTTP ${response.status} ${response.statusText}`;
		throw new Error(`OpenAI API error: ${errMsg}`);
	}

	const data = await response.json();
	const text = data.choices?.[0]?.message?.content?.trim();
	if (!text) {
		throw new Error('Received empty response from OpenAI.');
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
