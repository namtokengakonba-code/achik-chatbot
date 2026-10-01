/**
 * Cloudflare Worker: A·chik Ku·sik Language Gateway & Gemini Secure Proxy
 */

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const GARO_SYSTEM_PROMPT = `You are a specialist linguist and conversational assistant fluent in Garo (A·chik ku·sik) and English.
The Garo language is a Sino-Tibetan language of the Bodo-Garo branch spoken predominantly in the Garo Hills of Meghalaya, Assam, and northern Bangladesh.

CRITICAL LINGUISTIC RULES:
1. ORTHOGRAPHY: Write Garo in the standard Roman/Latin script. You MUST use the glottal stop character ra-khe ('·' / middle dot, U+00B7), such as in: A·chik, ku·sik, na·a, anga, re·baa, cha·a, ring·a, song·jinma. Never omit the ra-khe.
2. SYNTAX: Garo follows an agglutinative SOV (Subject-Object-Verb) sentence structure with standard case suffixes (-ko accusative, -na dative, -chin instrumental, -oni ablative, -o locative).
3. DIALECT BASE: Prioritize standard A·chik/A·beng dialect vocabulary.

You must respond ONLY with a valid, raw JSON object matching this exact schema:
{
  "garo": "Authentic A·chik ku·sik text translated or answering the query",
  "english": "Fluent English counterpart or explanation",
  "pronunciation": "Phonetic pronunciation guide for English speakers",
  "vocabulary": [
    {"garo": "Garo word/root with ra-khe", "english": "English meaning"}
  ],
  "cultural_note": "Brief cultural context or grammar insight (optional, keep short)"
}`;

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 1. Handle CORS Preflight
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // 2. Health check route
    if (url.pathname === "/api/health") {
      return new Response(
        JSON.stringify({ status: "healthy", service: "achik-chatbot", model: "gemini-2.5-flash", timestamp: new Date().toISOString() }),
        { headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
      );
    }

    // 3. AI Chat & Translation API Route
    if (url.pathname === "/api/chat" && request.method === "POST") {
      if (!env.GEMINI_API_KEY) {
        return new Response(
          JSON.stringify({
            error: "GEMINI_API_KEY secret is not set in Cloudflare Worker environment variables.",
          }),
          { status: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
        );
      }

      try {
        const reqData = await request.json();
        const userPrompt = reqData.message?.trim();
        const mode = reqData.mode || "dual";

        if (!userPrompt) {
          return new Response(
            JSON.stringify({ error: "Missing 'message' field in request body." }),
            { status: 400, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
          );
        }

        let contextPrefix = "";
        if (mode === "translate") {
          contextPrefix = "Directly translate the following text into natural Garo (A·chik ku·sik) and provide vocabulary breakdowns: ";
        } else if (mode === "pure") {
          contextPrefix = "Answer naturally as an A·chik conversational partner with native Garo as the primary focus: ";
        } else {
          contextPrefix = "Provide a comprehensive bilingual response in Garo (A·chik ku·sik) and English: ";
        }

        const geminiEndpoint = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${env.GEMINI_API_KEY}`;

        const payload = {
          contents: [
            {
              role: "user",
              parts: [{ text: `${contextPrefix}"${userPrompt}"` }],
            },
          ],
          systemInstruction: {
            parts: [{ text: GARO_SYSTEM_PROMPT }],
          },
          generationConfig: {
            responseMimeType: "application/json",
            temperature: 0.3,
            maxOutputTokens: 2048,
          },
        };

        const geminiRes = await fetch(geminiEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(payload),
        });

        if (!geminiRes.ok) {
          const errorData = await geminiRes.text();
          return new Response(
            JSON.stringify({ error: "Upstream Gemini API error", details: errorData }),
            { status: geminiRes.status, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
          );
        }

        const data = await geminiRes.json();
        const rawJsonString = data.candidates?.[0]?.content?.parts?.[0]?.text;

        if (!rawJsonString) {
          return new Response(
            JSON.stringify({ error: "Received empty response from AI engine." }),
            { status: 502, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
          );
        }

        return new Response(rawJsonString, {
          status: 200,
          headers: { ...CORS_HEADERS, "Content-Type": "application/json" },
        });
      } catch (err) {
        return new Response(
          JSON.stringify({ error: "Worker processing error: " + err.message }),
          { status: 500, headers: { ...CORS_HEADERS, "Content-Type": "application/json" } }
        );
      }
    }

    // 4. Fallback to Cloudflare Static Assets
    if (env.ASSETS) {
      return env.ASSETS.fetch(request);
    }

    return new Response("Not Found", { status: 404, headers: CORS_HEADERS });
  },
};