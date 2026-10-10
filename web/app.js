import * as api from './api.js';
import {verdictView, source, label, errorView, loading} from './views.js';
import {practiceView} from './practice.js';
import {timelineView} from './timeline.js';

const $ = selector => document.querySelector(selector);
const defaults = {health_records: 30, bank_records: 25, government_docs: 50, login_session: 0};
let scanBusy = false;
let lastResult = null;
$('#mock-banner').hidden = !api.mock;

function renderResult(target, result) {
  target.innerHTML = verdictView(result);
  target.querySelector('.timeline-slot').innerHTML = timelineView(result);
}
function focusScanResult() {
  const result = $('#scan-result .result');
  result.tabIndex = -1;
  result.focus({preventScroll: true});
  result.scrollIntoView({block: 'start'});
}
window.addEventListener('scanner-rate-limit', () => {
  if (scanBusy) $('#scan-status').innerHTML = loading('Too many requests. Waiting a few seconds, then retrying');
});
const flipPanel = practiceView(renderResult);

async function offerSaved() {
  const target = $('#saved-results');
  try {
    const results = await api.cached();
    target.innerHTML = results.length ? '<section class="saved"><h3>Saved results</h3><p>These describe a previous scan, not the current connection.</p><div></div></section>' : '<p>No saved results are available.</p>';
    for (const result of results) {
      const button = document.createElement('button');
      button.className = 'secondary';
      button.textContent = `${result.host}: ${source(result)}`;
      button.addEventListener('click', () => {
        lastResult = result;
        renderResult($('#scan-result'), result);
        focusScanResult();
        $('#scan-status').textContent = `${label(result)}. ${source(result)}.`;
        $('#empty-note').hidden = true;
      });
      target.querySelector('.saved div').append(button);
    }
  } catch { target.replaceChildren(); }   // the scanner message above already explains
}

async function runScan() {
  if (scanBusy || !$('#scan-form').reportValidity()) return;
  scanBusy = true;
  $('#scan-button').disabled = true;
  $('#scan-result').setAttribute('aria-busy', 'true');
  $('#scan-status').innerHTML = loading();
  $('#saved-results').replaceChildren();
  $('#empty-note').hidden = true;
  // Clear the old verdict so it cannot be mistaken for this request's result.
  $('#scan-result').replaceChildren();
  const host = api.normalizeHost($('#host').value);
  $('#host').value = host;
  try {
    lastResult = await api.scan(host, $('#data').value, $('#years').value);
    // Keep the address bar in step, so the link can be shared to repeat this scan.
    const link = new URLSearchParams({host, data: $('#data').value, years: $('#years').value});
    if (api.mock) link.set('mock', '1');
    history.replaceState(null, '', `?${link}${location.hash}`);
    renderResult($('#scan-result'), lastResult);
    focusScanResult();
    $('#scan-status').textContent = `${host}: ${label(lastResult)}, ${lastResult.verdict.score} out of 100. ${source(lastResult)}.`;
  } catch (error) {
    $('#scan-status').innerHTML = errorView(error);
    $('#scan-status').querySelector('[data-retry]').addEventListener('click', runScan);
    if (error.code === 'unreachable') await offerSaved();
  } finally {
    scanBusy = false;
    $('#scan-button').disabled = false;
    $('#scan-result').setAttribute('aria-busy', 'false');
  }
}
$('#scan-form').addEventListener('submit', event => { event.preventDefault(); runScan(); });
$('#data').addEventListener('change', () => { $('#years').value = defaults[$('#data').value]; });
async function loadExamples() {
  try {
    const {sites} = await api.demoSites();
    const priority = ['cloudflare.com', 'github.com', 'static-rsa.badssl.com'];
    const featured = [...priority.filter(host => sites.includes(host)), ...sites.filter(host => !priority.includes(host))].slice(0, 3);
    const ordered = [...featured, ...sites.filter(host => !featured.includes(host))];
    for (const [index, host] of ordered.entries()) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'chip'; button.textContent = host;
      button.addEventListener('click', () => {
        if (scanBusy) return;
        $('#host').value = host;
        runScan();   // one click is enough for an example
      });
      $(index < 3 ? '#demo-sites' : '#demo-more').append(button);
    }
    $('#more-examples').hidden = ordered.length <= 3;
  } catch { $('#demo-sites').textContent = 'Examples are unavailable. Enter any public hostname.'; }
}
function route() {
  const flip = location.hash === '#flip';
  $('#scan-view').hidden = flip;
  $('#flip-view').hidden = !flip;
  if (flip && !flipPanel.isInitialized()) flipPanel.load();
  document.querySelectorAll('nav a').forEach(a => {
    if (a.hash === (flip ? '#flip' : '#scan')) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  });
}
// Skipping to the content must not change the page the visitor is on.
document.querySelector('.skip').addEventListener('click', event => {
  event.preventDefault();
  $('#main').focus();
});
window.addEventListener('hashchange', route);
route(); loadExamples();

// A link like /?host=github.com&data=bank_records&years=25 runs that scan on arrival.
(function scanFromLink() {
  const params = new URLSearchParams(location.search);
  const host = params.get('host');
  if (!host || location.hash === '#flip') return;
  $('#host').value = api.normalizeHost(host);
  if (defaults[params.get('data')] !== undefined) {
    $('#data').value = params.get('data');
    $('#years').value = defaults[params.get('data')];
  }
  const years = params.get('years');
  if (years !== null && /^\d{1,3}$/.test(years)) $('#years').value = years;
  runScan();
})();
