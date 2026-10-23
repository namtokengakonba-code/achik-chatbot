# Achik Chatbot

## Shared correction memory

Anyone can use **Correct this answer** below a chatbot response to submit a correction. Each correction is saved immediately in Cloudflare KV and can guide future answers for everyone. There is no admin token or approval step.

Community submissions are reference context, not automatic model retraining: the model's weights do not change. Because submissions are public and immediate, corrections may be inaccurate or misleading; the chatbot is instructed to treat them as community guidance rather than verified facts.

The chatbot is designed for natural Garo-English conversation, with a separate translation mode. In Quick Translator mode, the Worker searches the web for both Garo-English and English-Garo dictionary entries for up to twelve key terms and retrieves the main text from up to five results per direction. The model uses those results as unverified lexical evidence while translating sentence by sentence. This searches available web results, not every online source. Source links are shown with the translation, which preserves order and line breaks; the original text is shown alongside for comparison. The input's extracted terms are sent to Firecrawl for web search. Configure `FIRECRAWL_API_KEY` as a Cloudflare Worker secret and a GitHub Actions secret for deployment. It uses Gemini 3.6 Flash first for faster replies and retries with Gemini 3.8 Flash when needed. If Gemini is unavailable or rate-limited, the Worker can use Groq's `qwen/qwen3.8-27b` as a fallback. Groq is optional: create an API key in GroqCloud and set it as the `GROQ_API_KEY` Worker secret (`npx wrangler secret put GROQ_API_KEY`). For local development, add `GEMINI_API_KEY`, `FIRECRAWL_API_KEY`, and, if using the fallback, `GROQ_API_KEY` to `.dev.vars` (which is ignored by Git), then run `npm run dev`. Groq's free usage and rate limits depend on its current account terms. Text and up to three images can use the fallback; PDF requests still require Gemini.

Song lyrics can be translated when they are user-authored, public domain, or the user confirms they have permission. For other songs, the chatbot can discuss themes or provide a high-level summary instead of translating or reproducing lyrics. Authorized lyric translations aim to preserve line structure, meaning, and tone.

## File analysis and dashboards

Signed-in users can attach up to five PDF, Excel (`.xlsx`/`.xls`), Word (`.docx`), image (JPEG, PNG, WebP, GIF), CSV/TSV, or plain-text files and ask a prompt about them. Files are limited to 10 MB each and 12 MB total; extracted text is limited to 500,000 characters per file and 1,000,000 characters per request. PDF/image files are sent to Gemini as file data; spreadsheets and Word documents are extracted in the browser before their text is sent. If Gemini is unavailable, Groq can be used for text and up to three images; PDF analysis requires Gemini. The chatbot can analyze the provided data and return an interactive dashboard with metrics and switchable charts when requested or useful. Attachments are sent to the selected AI provider for processing and are not stored by this app.

## User accounts

Chat and correction submissions require signing in with Google. The Worker uses Google's OpenID Connect user-info endpoint to verify the account email. Sign-in uses OAuth state validation, PKCE, and secure, HTTP-only session cookies.

### Deployment setup

1. In Google Cloud Console, configure the OAuth consent screen and create an OAuth client ID for a Web application.
2. Add this exact Authorized redirect URI to the Google OAuth client: `https://achik-chatbot.namtokengakonba.workers.dev/api/auth/google/callback`. For local testing, also authorize `http://localhost:8787/api/auth/google/callback`.
3. Add `CLOUDFLARE_ACCOUNT_ID`, `CLOUDFLARE_API_TOKEN`, `GEMINI_API_KEY`, `FIRECRAWL_API_KEY`, and `GOOGLE_CLIENT_SECRET` as GitHub Actions secrets. `GOOGLE_CLIENT_ID` can be an Actions secret or repository variable. The API token must be scoped to the Cloudflare account that owns this Worker.
   To enable the optional Groq fallback in production, set the `GROQ_API_KEY` Worker secret with `npx wrangler secret put GROQ_API_KEY`.
4. To enable AdSense Auto ads, turn on Auto ads for the approved site in AdSense and add `ADSENSE_CLIENT_ID` as a GitHub Actions secret or repository variable. Enter the publisher ID as shown (`pub-...` or `ca-pub-...`); the workflow normalizes `pub-...` for the AdSense script. Auto ads do not require an ad-unit slot ID. The publisher ID is public and must not be treated as a credential.
5. Push/deploy the app. The workflow applies D1 migrations before deploying the Worker. If deploying directly with Wrangler instead, set `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `FIRECRAWL_API_KEY` as Worker secrets (for example, `npx wrangler secret put FIRECRAWL_API_KEY`) and replace the AdSense publisher ID placeholder in `public/index.html`.

The D1 database binding and migrations are in `wrangler.jsonc` and `migrations/`. For local development, use a Google OAuth client configured with `http://localhost:8787/api/auth/google/callback`, add `GEMINI_API_KEY`, `FIRECRAWL_API_KEY`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET` to `.dev.vars`, run `npx wrangler d1 migrations apply achik-chatbot-users --local`, and then run `npm run dev`. The former Resend email-verification configuration is no longer used.
