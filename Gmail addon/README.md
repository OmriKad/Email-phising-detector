# Gmail Add-on (ngrok -> local backend)

This folder contains Google Apps Script files to deploy a Gmail add-on that sends
current-message payloads to your phishing API:

- Endpoint: `POST /api/v1/detect`
- Request source: `gmail_addon`
- Payload strategy: compact text + extracted links + attachment names only

## Files

- `Code.gs`: add-on logic and UI cards
- `appsscript.json`: manifest/scopes/triggers

## Setup steps (Google Apps Script)

1. Start backend locally:
   ```bash
   docker compose up --build
   ```

2. Expose backend with ngrok:
   ```bash
   ngrok http 8000
   ```

3. Copy ngrok HTTPS URL, for example:
   - `https://abc123.ngrok-free.app`

4. In Google Apps Script project:
   - Add `Code.gs` and `appsscript.json` from this folder.
   - Enable Advanced Google service: `Gmail API`.
   - In `Code.gs`, set:
     - `const BACKEND_BASE_URL = 'https://your-ngrok-url.ngrok-free.app';`

5. Deploy the add-on:
   - Test deployment in Apps Script.
   - Open Gmail and the add-on panel on a message.

## Notes

- Gmail add-ons require HTTPS. Do not use `http://localhost` directly.
- If ngrok URL rotates, update `BACKEND_BASE_URL` in `Code.gs`.
- If backend returns error envelope, add-on displays API `error.code` and `error.message`.
- Add-on now strips heavy MIME content and sends:
  - selected headers (`From`, `Reply-To`, `Subject`, `To`)
  - compact body text (plain + HTML-derived text)
  - extracted links
  - attachment filenames only

## Quick troubleshooting

- `Addon Error: BACKEND_BASE_URL is not set`
  - Set `BACKEND_BASE_URL` constant in `Code.gs`.

- `Backend Error HTTP 502 MODEL_PROVIDER_ERROR`
  - Backend cannot reach model runner. Check `/api/v1/health` and backend logs.

- `Backend Error HTTP 504 MODEL_TIMEOUT`
  - Usually model inference is still too slow for current timeout.
  - Compact mode should reduce this significantly; if needed, raise backend `REQUEST_TIMEOUT_SECONDS`.

- `Missing Gmail context`
  - Run from an opened Gmail message (not standalone execution).
