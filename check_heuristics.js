const fs = require('fs');
const content = fs.readFileSync('PhishLens/phishlang_clientside_app/extension_unpacked/src/service-worker.js', 'utf8');
const start = content.indexOf('function runHeuristicCheck');
const end = content.indexOf('/* ==========================================================================\n   AI MODEL PREDICTION') !== -1 ?
  content.indexOf('/* ==========================================================================\n   AI MODEL PREDICTION') :
  content.indexOf('/* ==========================================================================\r\n   AI MODEL PREDICTION');

const fnCode = content.substring(start, end);
const fn = new Function('url', 'whitelistMap', fnCode + '\nreturn runHeuristicCheck(url);');
console.log('Mock 4:', fn(new URL('https://myuser.github.io/PhishLens/test/mocks/04_form_action_swapped.html'), new Map()));
console.log('Mock 11:', fn(new URL('https://myuser.github.io/PhishLens/test/mocks/11_phishing_locked_form.html'), new Map()));
