import {escape} from './views.js';

export function timelineView(result) {
  const s = result.shelfLife;
  const now = new Date().getFullYear();
  // Grow the axis for the longest permitted shelf life rather than clipping it.
  const start = Math.min(now, s.secretUntilYear, s.quantumArrivalYear);
  const end = Math.max(2060, s.secretUntilYear + 3, s.quantumArrivalYear + 3, now + 10);
  const x = year => 18 + (year - start) / (end - start) * 604;
  const hybrid = result.handshake.keyExchange === 'hybrid_pq';
  const overlap = s.secretUntilYear > s.quantumArrivalYear && !hybrid;
  const color = hybrid ? '#12805C' : s.urgency === 'medium' ? '#9A6700' : s.urgency === 'high' ? '#C23B32' : '#0F1B2D';
  const text = hybrid
    ? `This data must stay secret until ${s.secretUntilYear}. A connection that uses the hybrid key exchange resists a future quantum computer reading recorded traffic.`
    : overlap
      ? `This data must stay secret until ${s.secretUntilYear}. Recorded traffic today could be read from ${s.quantumArrivalYear}.`
      : `This data must stay secret until ${s.secretUntilYear}, no later than the assumed quantum arrival in ${s.quantumArrivalYear}. This connection still uses ${result.handshake.keyExchange === 'unknown' ? 'an unidentified' : 'an old'} key method.`;
  // Labels stay in HTML so they remain readable at 390 px and under zoom.
  return `<section class="timeline" aria-label="Data shelf life"><h3>How long does the secret need to last?</h3>
    <div class="timeline-legend"><span><i style="background:${color}"></i>Data must stay secret${hybrid ? ' · protected' : ''}</span><span><i style="background:#5B4BDB"></i>Quantum computers arrive (our assumption): ${escape(s.quantumArrivalYear)}</span></div>
    <svg viewBox="0 0 640 122" aria-hidden="true">
      <rect x="${x(s.quantumArrivalYear)}" y="6" width="${622-x(s.quantumArrivalYear)}" height="82" fill="#5B4BDB" opacity=".13"/>
      <line x1="${x(s.quantumArrivalYear)}" x2="${x(s.quantumArrivalYear)}" y1="6" y2="88" stroke="#5B4BDB" stroke-width="2"/>
      <text x="${x(s.quantumArrivalYear)}" y="23" font-size="19" text-anchor="middle" fill="#5B4BDB" stroke="#fff" stroke-width="6" paint-order="stroke">${s.quantumArrivalYear}</text>
      <rect x="${x(now)}" y="31" width="${Math.max(3,x(s.secretUntilYear)-x(now))}" height="24" rx="2" fill="${color}"/>
      <circle cx="${x(s.secretUntilYear)}" cy="43" r="4" fill="${color}"/>
      <text x="${x(s.secretUntilYear)}" y="82" font-size="19" text-anchor="${x(s.secretUntilYear) < 100 ? 'start' : x(s.secretUntilYear) > 540 ? 'end' : 'middle'}" fill="${color}">Until ${s.secretUntilYear}</text>
      <line x1="18" x2="622" y1="88" y2="88" stroke="#7F8DA0"/>
      <text x="18" y="112" font-size="19" fill="#0F1B2D">${start}${start === now ? ' · now' : ''}</text>
      <text x="622" y="112" font-size="19" text-anchor="end" fill="#0F1B2D">${end}</text>
    </svg><p class="timeline-sentence">${escape(text)}</p><p class="timeline-assumption">${escape(s.quantumArrivalYear)} is an assumption, not a forecast. Estimates vary. Shelf life does not change the readiness score.</p></section>`;
}
