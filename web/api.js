export const mock = new URLSearchParams(location.search).get('mock') === '1';
let practiceMode = 'classical';
const delay = () => new Promise(resolve => setTimeout(resolve, 600 + Math.random() * 600));

// Parse error JSON even for 4xx and 5xx responses.
async function request(url, options = {}, retries = 0) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 40000);
  try {
    const response = await fetch(url, {...options, signal: controller.signal});
    let body;
    try { body = await response.json(); }
    catch { throw Object.assign(new Error('The scanner returned an unreadable response.'), {code: 'unreachable'}); }
    // Retry a rate-limited read once. Never repeat a server restart implicitly.
    if (response.status === 429 && retries === 0 && !options.method) {
      window.dispatchEvent(new Event('scanner-rate-limit'));
      await new Promise(resolve => setTimeout(resolve, 3000));
      return await request(url, options, retries + 1);
    }
    if (body.error || body.status === 'error') {
      throw Object.assign(new Error(body.error?.message || 'The scan failed.'), {
        code: body.error?.code || 'internal', httpStatus: response.status
      });
    }
    if (!response.ok) throw Object.assign(new Error('The scanner could not complete the request.'), {code: 'internal'});
    return body;
  } catch (error) {
    if (error.code) throw error;
    throw Object.assign(new Error('The scanner is not running or cannot be reached.'), {code: 'unreachable'});
  } finally { clearTimeout(timeout); }
}

async function fixture(name) {
  await delay();
  return request(`fixtures/${name}.json`);
}

export function normalizeHost(value) {
  return value.trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, '').split(/[/?#]/)[0]
    .replace(/^.*@/, '').toLowerCase();
}

export async function scan(host, data = 'health_records', years = 30) {
  if (!mock) return request(`/api/scan?${new URLSearchParams({host, data, years})}`);
  const name = host === 'practice' ? `practice-${practiceMode}`
    : host === 'cloudflare.com' ? 'ready'
    : host === 'static-rsa.badssl.com' ? 'not-ready-legacy'
    : host === 'timeout.example' ? 'error-timeout'
    : host === 'cached.example' ? 'cached-ready' : 'not-ready';
  const result = await fixture(name);
  result.host = host;
  result.source = 'sample';   // never shown as a live scan
  // Only mock data is adapted. Live results are never rescored or rewritten.
  const now = new Date().getFullYear();
  result.shelfLife = {...result.shelfLife, dataType: data, years: Number(years), secretUntilYear: now + Number(years)};
  if (result.handshake.keyExchange !== 'hybrid_pq') {
    result.shelfLife.urgency = now + Number(years) > result.shelfLife.quantumArrivalYear ? 'high'
      : now + Number(years) > 2030 ? 'medium' : 'low';
  }
  return result;
}

export async function demoSites() {
  return mock ? {sites: ['cloudflare.com', 'github.com', 'static-rsa.badssl.com', 'timeout.example', 'cached.example']}
    : request('/api/demo-sites');
}
export async function cached() {
  return mock ? [await fixture('cached-ready')] : request('/api/cached');
}
export async function practice() {
  return mock ? {mode: practiceMode, scanHost: 'practice'} : request('/api/practice');
}
export async function setPracticeMode(mode) {
  if (!mock) return request('/api/practice/mode', {
    method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({mode})
  });
  await delay();
  practiceMode = mode;
  return {mode};
}
