# Frontend guide

Plain HTML, CSS, and JavaScript modules. No build step or runtime dependencies.

## Preview

From this folder, run `python -m http.server 5500`, then open
http://localhost:5500/?mock=1. Always use a server, because browsers block module
and fixture requests from a page opened directly from disk.

For live mode, run the backend as described in the repository README and open
http://127.0.0.1:8000/. API requests use the same origin as the page.

- `#scan`: scan a public hostname and choose data retention.
- `#flip`: change the practice server's key exchange and compare results.
- The scoreboard stretch is not implemented.

Mock mode has a visible banner and never runs automatically when live requests
fail. Its example sites demonstrate ready, classical, static RSA, timeout, and
cached results. The practice switch alternates the two practice fixtures.

## Explain it to judges

- `api.js` chooses mock fixtures only when the URL contains `?mock=1`. Live
  requests parse JSON even when the HTTP status is an error. Rate-limited reads
  wait three seconds and retry once. Server restarts require an explicit click.
- `views.js` escapes API text and renders verdicts without recalculating scores.
  Saved results display their original scan time.
- `app.js` handles form submission, examples, saved results, and hash navigation.
  Changing the data type fills its default retention period.
- `practice.js` reads the current mode, restarts the practice server, rescans,
  and preserves the previous result. A failed restart requires reading the
  actual server mode again, because it might already have changed.
- `timeline.js` compares the result's retention year with its assumed quantum
  arrival year. Long retention periods extend the axis. The adjacent sentence
  gives the same information without relying on the graphic or its colors.

Keyboard focus moves to a completed scan. Result status is announced politely.
Touch controls are at least 44 pixels tall. Reduced-motion preferences remove
loading rotation and the practice verdict animation.

## Suggested LEARNED.md entries

Add these to the shared learning log with your own event timestamps:

1. I learned to keep mock data separate from live results and parse error JSON
   regardless of HTTP status.
2. I learned to reload the server's actual mode after a failed toggle because
   the restart may already have succeeded.
3. I learned that data retention and connection readiness answer different
   questions, so the timeline explains risk without changing the score.
4. I learned to test errors, keyboard focus, reduced motion, and phone layouts
   alongside the successful demo path.
