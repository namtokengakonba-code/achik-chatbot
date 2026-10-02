# Achik Chatbot

## Shared correction memory

Anyone can use **Correct this answer** below a chatbot response to submit a correction. Each correction is saved immediately in Cloudflare KV and can guide future answers for everyone. There is no admin token or approval step.

Community submissions are reference context, not automatic model retraining: the model's weights do not change. Because submissions are public and immediate, corrections may be inaccurate or misleading; the chatbot is instructed to treat them as community guidance rather than verified facts.

The `ACHIK_CORRECTIONS` KV namespace is configured in `wrangler.jsonc`. For local development, add `GEMINI_API_KEY` to `.dev.vars` (which is ignored by Git), then run `npm run dev`.

## User accounts

Chat and correction submissions require signing in with Google. The Worker uses Google's OpenID Connect user-info endpoint to verify the account email. Sign-in uses OAuth state validation, PKCE, and secure, HTTP-only session cookies.

### Deployment setup

1. In Google Cloud Console, configure the OAuth consent screen and create an OAuth client ID for a Web application.
2. Add this exact Authorized redirect URI to the Google OAuth client: `https://achik-chatbot.namtokengakonba.workers.dev/api/auth/google/callback`. For local testing, also authorize `http://localhost:8787/api/auth/google/callback`.
3. Add `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as GitHub Actions secrets. Keep `GEMINI_API_KEY` and a valid `CLOUDFLARE_API_TOKEN`.
4. Push/deploy the app. The workflow applies D1 migrations before deploying the Worker. If deploying directly with Wrangler instead, set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` as Worker secrets.

The D1 database binding and migrations are in `wrangler.jsonc` and `migrations/`. For local development, use a Google OAuth client configured with `http://localhost:8787/api/auth/google/callback`, add `GEMINI_API_KEY`, `GOOGLE_CLIENT_ID`, and `GOOGLE_CLIENT_SECRET` to `.dev.vars`, run `npx wrangler d1 migrations apply achik-chatbot-users --local`, and then run `npm run dev`. The former Resend email-verification configuration is no longer used.  
