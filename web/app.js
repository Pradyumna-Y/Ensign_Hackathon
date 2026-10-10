import * as api from './api.js';
import {escape, verdictView, source, label, errorView, loading} from './views.js';
import {practiceView} from './practice.js';

const $ = selector => document.querySelector(selector);
const defaults = {health_records: 30, bank_records: 25, government_docs: 50, login_session: 0};
let scanBusy = false;
let lastResult = null;
$('#mock-banner').hidden = !api.mock;

function renderResult(target, result) {
  target.innerHTML = verdictView(result);
}
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
        $('#scan-status').textContent = `${label(result)}. ${source(result)}.`;
        $('#empty-note').hidden = true;
      });
      target.querySelector('.saved div').append(button);
    }
  } catch { target.textContent = 'Saved results could not be loaded. Check the backend connection and try again.'; }
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
    renderResult($('#scan-result'), lastResult);
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
    for (const host of sites) {
      const button = document.createElement('button');
      button.type = 'button'; button.className = 'chip'; button.textContent = host;
      button.addEventListener('click', () => {
        $('#host').value = host; $('#host').focus();
      });
      $('#demo-sites').append(button);
    }
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
window.addEventListener('hashchange', route);
route(); loadExamples();
