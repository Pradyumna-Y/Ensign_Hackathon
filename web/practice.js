import * as api from './api.js';
import {escape, label, errorView, loading} from './views.js';

export function practiceView(renderResult) {
  const root = document.querySelector('#flip-view');
  root.innerHTML = `<div class="intro"><p class="eyebrow">One connection. Two ways to agree on a key.</p><h1 id="flip-title">Flip the lock.</h1><p>The practice server is ours, and this switch really changes how it agrees on keys.</p><p id="practice-mock" ${api.mock ? '' : 'hidden'}>In this mock demo, the switch alternates sample results instead of restarting a server.</p></div>
    <div class="flip-controls"><div class="mode-labels"><span data-mode="classical">Old lock</span><span aria-hidden="true">↔</span><span data-mode="hybrid">New lock</span></div><button id="flip-button" class="primary" type="button" role="switch" aria-label="New lock" aria-checked="false" disabled>Load practice server</button></div>
    <div id="flip-status" class="status" role="status" aria-live="polite"></div><div id="comparison" class="compare single"></div>`;
  const status = root.querySelector('#flip-status');
  const button = root.querySelector('#flip-button');
  const comparison = root.querySelector('#comparison');
  let mode = null;
  let current = null;
  let busy = false;
  let initialized = false;

  function updateMode() {
    root.querySelectorAll('[data-mode]').forEach(el => el.classList.toggle('active', el.dataset.mode === mode));
    button.setAttribute('aria-checked', String(mode === 'hybrid'));
    button.textContent = mode === 'hybrid' ? 'Switch to the old lock' : 'Switch to the new lock';
  }
  function show(before, after, animate = false) {
    comparison.className = `compare ${before ? '' : 'single'}`;
    comparison.innerHTML = `${before ? '<section><h2>Before</h2><div id="before-result"></div></section>' : ''}<section><h2>${before ? 'After' : 'Current connection'}</h2><div id="after-result"></div></section>`;
    if (before) renderResult(root.querySelector('#before-result'), before);
    const target = root.querySelector('#after-result');
    renderResult(target, after);
    if (animate) {
      target.style.setProperty('--before-score', `${before.verdict.score}%`);
      target.classList.add('flip-moment');
    }
  }
  function recover(error, retry) {
    status.innerHTML = errorView(error);
    status.querySelector('[data-retry]').addEventListener('click', retry);
  }
  async function load() {
    if (busy) return;
    busy = true; button.disabled = true;
    status.innerHTML = loading('Loading the practice server');
    try {
      const state = await api.practice();
      mode = state.mode; updateMode();
      status.innerHTML = loading();
      current = await api.scan(state.scanHost);
      show(null, current);
      initialized = true;
      status.textContent = `Current connection: ${label(current)}, ${current.verdict.score} out of 100.`;
    } catch (error) { recover(error, load); }
    finally { busy = false; button.disabled = !initialized; }
  }
  async function flip() {
    if (busy || !current) return;
    busy = true; button.disabled = true;
    status.innerHTML = loading(api.mock ? 'Switching the mock practice result' : 'Restarting the practice server');
    const before = current;
    try {
      const state = await api.setPracticeMode(mode === 'classical' ? 'hybrid' : 'classical');
      mode = state.mode; updateMode();
      status.innerHTML = loading();
      current = await api.scan('practice');
      show(before, current, true);
      status.textContent = `Before: ${label(before)}, ${before.verdict.score}. After: ${label(current)}, ${current.verdict.score}.`;
    } catch (error) {
      // A restart may have succeeded even if its response was lost. Reload the
      // actual mode on retry rather than guessing from the previous switch.
      recover(error, load);
      initialized = false;
    } finally { busy = false; button.disabled = !initialized; }
  }
  button.addEventListener('click', flip);
  return {load, isInitialized: () => initialized || busy};
}
