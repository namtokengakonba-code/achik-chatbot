# Achik Chatbot

## Shared correction memory

Anyone can use **Correct this answer** below a chatbot response to submit a correction. Each correction is saved immediately in Cloudflare KV and can guide future answers for everyone. There is no admin token or approval step.

Community submissions are reference context, not automatic model retraining: the model's weights do not change. Because submissions are public and immediate, corrections may be inaccurate or misleading; the chatbot is instructed to treat them as community guidance rather than verified facts.

The `ACHIK_CORRECTIONS` KV namespace is configured in `wrangler.jsonc`. For local development, add `GEMINI_API_KEY` to `.dev.vars` (which is ignored by Git), then run `npm run dev`.

## File analysis and dashboards

Signed-in users can attach up to five PDF, Excel (`.xlsx`/`.xls`), Word (`.docx`), image (JPEG, PNG, WebP, GIF), CSV/TSV, or plain-text files and ask a prompt about them. Files are limited to 10 MB each and 12 MB total; extracted text is limited to 500,000 characters per file and 1,000,000 characters per request. PDF/image files are sent to Gemini as file data; spreadsheets and Word documents are extracted in the browser before their text is sent. The chatbot can analyze the provided data and return an interactive dashboard with metrics and switchable charts when requested or useful. Attachments are sent to Google Gemini for processing and are not stored by this app.

## User accounts

Chat and correction submissions require signing in with Google. The Worker uses Google's OpenID Connect user-info endpoint to verify the account email. Sign-in uses OAuth state validation, PKCE, and secure, HTTP-only session cookies.

### Deployment setup

1. In Google Cloud Console, configure the OAuth consent screen and create an OAuth client ID for a Web application.
2. Add this exact Authorized redirect URI to the Google OAuth client: `https://achik-chatbot.namtokengakonba.workers.dev/api/auth/google/callback`. For local testing, also authorize `http://localhost:8787/api/auth/google/callback`.
3. Add `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `GEMINI_API_KEY`, and `GOOGLE_CLIENT_SECRET` as GitHub Actions secrets. `GOOGLE_CLIENT_ID` can be an Actions secret or repository variable. The API token must be scoped to the Cloudflare account that owns this Worker.
4. To enable the AdSense banner, create a responsive ad unit and add `ADSENSE_CLIENT_ID` (`ca-pub-...`) and `ADSENSE_SLOT_ID` (the numeric ad-unit ID) as GitHub Actions repository variables. Leave both unset to keep ads disabled. The deployment workflow validates the pair and inserts them into the public page; these IDs are public and must not be treated as credentials.
5. Push/deploy the app. The workflow applies D1 migrations before deploying the Worker. If deploying directly with Wrangler instead, set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as Worker secrets and replace the AdSense placeholders in `public/index.html` with the publisher and ad-unit IDs.

The D1 database binding and migrations are in `wrangler.jsonc` and `migrations/`. For local development, use a Google OAuth client configured with `http://localhost:8787/api/auth/google/callback`, add `GEMINI_API_KEY`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET` to `.dev.vars`, run `npx wrangler d1 migrations apply achik-chatbot-users --local`, and then run `npm run dev`. The former Resend email-verification configuration is no longer used.  
