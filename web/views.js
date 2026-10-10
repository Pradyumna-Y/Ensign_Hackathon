// API strings are escaped before entering markup, including hostnames and fixes.
export function escape(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;', '<':'&lt;', '>':'&gt;', '"':'&quot;', "'":'&#39;'}[c]));
}
export const label = result => result.verdict.label === 'ready' ? 'Ready' : 'Not ready yet';
export const source = result => result.source === 'cached'
  ? `Saved result from ${new Date(result.scannedAt).toLocaleString()}`
  : result.source === 'sample' ? 'Sample data, not a live scan' : 'Live scan';
const isNew = group => /MLKEM|ML-KEM/i.test(group);
function evidenceView(h) {
  const e = h.evidence;
  if (!e) return '<p class="tech-label">This is a saved result from before evidence was kept.</p>';
  return `<p class="tech-label">Our scanner ran (shortened: the real run connects to the address it checked)</p><pre><code>${escape(e.command)}</code></pre><p class="tech-label">and OpenSSL printed</p><pre><code>${(e.lines || []).map(escape).join('\n')}</code></pre>`;
}
function chip(group, picked = false) {
  const method = isNew(group) ? 'new method' : 'old method';
  return `<span class="protocol ${picked ? 'picked' : ''}"><code>${escape(group)}</code><small>${method}</small></span>`;
}
export function verdictView(result) {
  const {handshake: h, verdict: v, certificate: c} = result;
  const ready = v.label === 'ready';
  return `<article class="result ${ready ? 'ready' : ''}" aria-label="${escape(result.host)} result">
    <div class="result-meta"><span class="host">${escape(result.host)}</span><span class="badge">${escape(source(result))}</span></div>
    <div class="verdict-summary"><div><h2 class="verdict-label"><span class="verdict-icon" aria-hidden="true">${ready ? '✓' : '!'}</span>${label(result)}</h2><p class="headline">${escape(v.headline)}</p><p class="reason">${escape(v.reason)}</p></div><div class="score-number" aria-hidden="true"><strong>${escape(v.score)}</strong><span>out of 100</span></div></div>
    <div class="meter-label"><span>Connection readiness</span><span>Ready at 80</span></div>
    <div class="meter" role="meter" aria-label="Connection readiness" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${Number(v.score)}" style="--score:${Number(v.score)}%"><div class="meter-fill"></div><span class="threshold" aria-hidden="true"></span></div>
    <p class="meter-caption">Our own 0 to 100 rubric. It scores key exchange and TLS only.</p>
    <div class="handshake-summary"><p>The site picked</p><div class="protocols">${h.serverPicked ? chip(h.serverPicked, true) : `<span class="protocol picked">No named group<small>${h.keyExchange === 'static_rsa' ? 'old method: RSA key exchange' : 'method not identified'}</small></span>`}</div><p class="offered-note">Our scanner offered ${h.weOffered.length} key exchange methods (${h.weOffered.filter(isNew).length} new, ${h.weOffered.filter(g => !isNew(g)).length} old).</p></div>
    <details class="tech"><summary>See the evidence and technical details</summary><p class="tech-label">Our scanner offered</p><div class="protocols">${h.weOffered.map(g => chip(g)).join('')}</div>${evidenceView(h)}</details>
    <p class="tls"><code>${escape(h.tlsVersion)}</code> · ${!h.supportsTls13 ? 'TLS 1.3 not observed in this scan' : h.acceptsTls12 ? 'TLS 1.2 also accepted' : 'TLS 1.2 not accepted'}</p>${(h.limits || []).map(l => `<p class="limits">${escape(l)}</p>`).join('')}
    <div class="timeline-slot"></div>
    ${v.fixes.length ? `<section class="fixes"><h3>What to change</h3><ul>${v.fixes.map(f => `<li><strong>${escape(f.title)}</strong><p>${escape(f.detail)}</p></li>`).join('')}</ul></section>` : ''}
    <details class="notes"><summary>Notes: what this does not tell you</summary><p>We check one thing: how the connection agrees on its secret key, plus the TLS version.</p><p>Not ready today is normal and not a sign of carelessness. Ordinary computers cannot break these connections today.</p><p>We cannot see databases, passwords, or anything behind the connection.</p><h3>Certificate (not scored)</h3>${c ? `<dl><dt>Key</dt><dd><code>${escape(c.keyType)} ${escape(c.keyBits)}</code></dd><dt>Signature</dt><dd><code>${escape(c.signature)}</code></dd><dt>Expires</dt><dd>${escape(c.expires)}</dd><dt>Identity check</dt><dd>${c.verifyNote ? escape(c.verifyNote) : 'Not checked'}</dd></dl>` : '<p>No certificate details returned.</p>'}<p>Certificate signatures are not scored. With an ephemeral key exchange, a stolen certificate key alone cannot decrypt past traffic. Static RSA key exchange is the exception. The identity check is shown for context and does not change the score.</p><p>The year quantum computers arrive is an assumption. We use ${escape(result.shelfLife.quantumArrivalYear)} and say so on screen. Estimates vary.</p></details>
  </article>`;
}

const errors = {
  invalid_host: 'Enter a public hostname such as github.com. IP addresses and ports are not supported.',
  invalid_input: 'Choose a data type and a whole number of years from 0 to 100.',
  blocked_target: 'This address is not a public scan target. Choose a public website.',
  dns_failed: 'We could not find that hostname. Check the spelling and try again.',
  timeout: 'The site took too long to respond. Try again or scan another site.',
  no_tls: 'The site did not answer with a TLS connection. Check the address or try another site.',
  rate_limited: 'Too many requests. Wait a few seconds, then try again.',
  internal: 'The scanner could not finish this request. Try again.',
  unreachable: 'The scanner cannot be reached right now. Ask the team to restart it.'
};
export function errorView(error, practice = false) {
  const message = practice && error.code === 'unreachable'
    ? 'The practice server cannot be reached right now. Ask the team to restart it, then try again.'
    : practice && error.code === 'no_tls' && error.message ? error.message
    : errors[error.code] || 'This request could not be completed. Try again.';
  return `<p>${escape(message)}</p><button class="secondary" type="button" data-retry>Try again</button>`;
}
export function loading(text = 'Scanning') { return `<span class="spinner" aria-hidden="true"></span>${escape(text)}`; }
