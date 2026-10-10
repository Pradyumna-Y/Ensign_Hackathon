import * as api from './api.js';
import {label, errorView, loading, escape} from './views.js';

export function practiceView(renderResult) {
  const root = document.querySelector('#flip-view');
  root.innerHTML = `<div class="intro flip-intro"><p class="eyebrow"><span aria-hidden="true"></span>See the difference, one switch at a time</p><h1 id="flip-title">Same server.<br><span class="muted-title">A different lock.</span></h1><p class="intro-description">The practice server is ours, and this switch really changes how it agrees on keys.</p><p id="practice-mock" ${api.mock ? '' : 'hidden'}>In this mock demo, the switch alternates sample results instead of restarting a server.</p></div>
    <div class="flip-controls"><div><p class="control-caption">Practice server key exchange</p><div class="mode-labels"><span data-mode="classical">Old lock</span><span class="mode-track" aria-hidden="true"><i></i></span><span data-mode="hybrid">New lock</span></div></div><button id="flip-button" class="primary" type="button" role="switch" aria-label="New lock" aria-checked="false" disabled>Load practice server</button></div>
    <p class="reset-row"><button id="reset-button" class="secondary" type="button">Reset to the old lock</button></p>
    <div id="flip-status" class="status" role="status" aria-live="polite"></div><div id="comparison" class="compare single"></div>`;
  const status = root.querySelector('#flip-status');
  const button = root.querySelector('#flip-button');
  const comparison = root.querySelector('#comparison');
  const reset = root.querySelector('#reset-button');
  let mode = null;
  let current = null;
  let busy = false;
  let initialized = false;
  window.addEventListener('scanner-rate-limit', () => {
    if (busy) status.innerHTML = loading('Too many requests. Waiting a few seconds, then retrying');
  });

  function updateMode() {
    root.querySelectorAll('[data-mode]').forEach(el => el.classList.toggle('active', el.dataset.mode === mode));
    button.setAttribute('aria-checked', String(mode === 'hybrid'));
    root.querySelector('.mode-track').classList.toggle('hybrid', mode === 'hybrid');
    button.textContent = mode === 'hybrid' ? 'Switch to the old lock' : 'Switch to the new lock';
  }
  function show(before, after, animate = false) {
    comparison.className = `compare ${before ? '' : 'single'}`;
    const tone = r => r.verdict.label === 'ready' ? 'good' : 'bad';
    const banner = before ? `<div class="flip-banner"><div class="fb-side"><span class="fb-num ${tone(before)}">${escape(before.verdict.score)}</span><span class="fb-cap">Before: ${escape(label(before))}</span></div><span class="fb-arrow" aria-hidden="true">→</span><div class="fb-side"><span class="fb-num ${tone(after)}">${escape(after.verdict.score)}</span><span class="fb-cap">After: ${escape(label(after))}</span></div><p class="fb-text">${api.mock ? 'Mock demo: this sample result changed. Nothing was restarted.' : 'Same server. It was really stopped and restarted with a different key exchange.'}</p></div>` : '';
    comparison.innerHTML = `${banner}${before ? '<section><h2>Before</h2><div id="before-result"></div></section>' : ''}<section><h2>${before ? 'After' : 'Current connection'}</h2><div id="after-result"></div></section>`;
    if (before) renderResult(root.querySelector('#before-result'), before);
    const target = root.querySelector('#after-result');
    renderResult(target, after);
    if (animate) {
      target.style.setProperty('--before-score', `${before.verdict.score}%`);
      target.classList.add('flip-moment');
    }
  }
  function recover(error, retry) {
    status.innerHTML = errorView(error, true);
    status.querySelector('[data-retry]').addEventListener('click', retry);
  }
  async function load() {
    if (busy) return;
    busy = true; button.disabled = true; reset.disabled = true;
    status.innerHTML = loading('Loading the practice server');
    try {
      const state = await api.practice();
      mode = state.mode; updateMode();
      status.innerHTML = loading();
      current = await api.scan(state.scanHost);
      // Read the mode again after the scan, so another judge's flip cannot leave the
      // switch showing the wrong side. If it is empty, fall back to what the scan saw.
      const after = await api.practice().catch(() => state);
      mode = after.mode || (current.handshake.keyExchange === 'hybrid_pq' ? 'hybrid' : 'classical');
      updateMode();
      show(null, current);
      initialized = true;
      status.textContent = `Current connection: ${label(current)}, ${current.verdict.score} out of 100.`
        + (mode === 'hybrid' ? ' It is on the new lock. Use Reset to start from the old lock.' : '');
    } catch (error) { recover(error, load); }
    finally { busy = false; button.disabled = !initialized; reset.disabled = false; }
  }
  async function flip() {
    if (busy || !current) return;
    busy = true; button.disabled = true; reset.disabled = true;
    status.innerHTML = loading(api.mock ? 'Switching the mock practice result' : 'Restarting the practice server');
    const before = current;
    try {
      const state = await api.setPracticeMode(mode === 'classical' ? 'hybrid' : 'classical');
      mode = state.mode; updateMode();
      status.innerHTML = loading();
      current = await api.scan('practice');
      show(before, current, true);
      if (matchMedia('(max-width: 760px)').matches) {
        root.querySelector('.flip-banner').scrollIntoView({block: 'start'});
      }
      status.textContent = `Before: ${label(before)}, ${before.verdict.score}. After: ${label(current)}, ${current.verdict.score}.`;
    } catch (error) {
      // A restart may have succeeded even if its response was lost. Reload the
      // actual mode on retry rather than guessing from the previous switch.
      comparison.replaceChildren();   // never leave an old result beside an error
      recover(error, load);
      initialized = false;
    } finally {
      busy = false; button.disabled = !initialized; reset.disabled = false;
      if (initialized) button.focus({preventScroll: true});
    }
  }
  async function resetDemo() {
    if (busy) return;
    busy = true; button.disabled = true; reset.disabled = true;
    status.innerHTML = loading(api.mock ? 'Resetting the mock practice result' : 'Resetting the practice server');
    try {
      const state = await api.setPracticeMode('classical');
      mode = state.mode; updateMode();
      status.innerHTML = loading();
      current = await api.scan('practice');
      show(null, current);
      initialized = true;
      status.textContent = `Reset: ${label(current)}, ${current.verdict.score} out of 100. Ready to flip.`;
    } catch (error) {
      comparison.replaceChildren();
      recover(error, load);
      initialized = false;
    } finally {
      busy = false; button.disabled = !initialized; reset.disabled = false;
      if (initialized) button.focus({preventScroll: true});
    }
  }
  reset.addEventListener('click', resetDemo);
  button.addEventListener('click', flip);
  // Clicking a label picks that mode; clicking the track flips it.
  root.querySelectorAll('[data-mode]').forEach(el =>
    el.addEventListener('click', () => { if (el.dataset.mode !== mode) flip(); }));
  root.querySelector('.mode-track').addEventListener('click', flip);
  return {load, isInitialized: () => initialized || busy};
}
