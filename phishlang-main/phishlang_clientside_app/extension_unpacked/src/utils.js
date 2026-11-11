/**
 * @param {('phishing'|'suspicious'|'safe')|string} event
 * @param {object} callbacks
 * @param {() => Promise<void>} callbacks.onPhishing
 * @param {() => Promise<void>} callbacks.onSuspicious
 * @param {() => Promise<void>} callbacks.onSafe
 * @param {(() => Promise<void>)|undefined} [callbacks.onDefault]
 * @returns void
 */
async function onPhishStatusAsync(event, callbacks) {
	switch (event) {
		case 'phishing':
			await callbacks.onPhishing();
			break
		case 'suspicious':
			await callbacks.onSuspicious();
			break
		case 'safe':
			await callbacks.onSafe();
			break
		default:
			if (callbacks.onDefault === undefined) {
				await callbacks.onSafe();
			}
			else {
				await callbacks.onDefault();
			}
			break
	}
}

/**
 * @param {string} message
 * @param {...any} optionalParams
 * @returns {void}
 */
function logEvent(message, ...optionalParams) {
	console.log(...logMessage(message), ...optionalParams);
}

/**
 * @param {string} message
 * @param {...any} optionalParams
 * @returns {void}
 */
function logGroup(message, ...optionalParams) {
	console.groupCollapsed(...logMessage(message), ...optionalParams);
}

/**
 * Attempt some asynchronous action, and log the event to the console within a group
 * @param {string} event
 * @param {() => Promise<void>} action
 * @returns {Promise<void>}
 */
async function logGroupEventAsync(event, action) {
	console.groupCollapsed(...logMessage(event));
	try {
		await action();
	}
	catch (e) {
		console.error(e);
	}
	console.groupEnd();
}

/**
 * @param {Response} response
 * @returns {void}
 */
function logResponse(response) {
	console.log('HTTP response status', response.status, response.statusText);
}

/**
 * @param {string} message
 * @returns {string[]}
 */
function logMessage(message) {
	return [
		`%c [${getDateISOString()}] %cDEBUG %c${message}`,
		'color: gray;',
		'color: blue;',
		'color: black; font-weight: 400;',
	]
}

/**
 * @returns {string}
 */
function getDateISOString() {
	return new Date(Date.now()).toISOString()
}

export { logEvent, logGroup, logGroupEventAsync, logResponse, onPhishStatusAsync };
