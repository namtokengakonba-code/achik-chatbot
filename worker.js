// 1. Google Gemini Provider Attempt
      for (const model of GEMINI_MODELS) {
        // Must use backticks (`) and clean URL without markdown brackets
        const endpoint = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent?key=${encodeURIComponent(geminiKey)}`;

        try {
          const response = await fetch(endpoint, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(payload),
          });

          const responseText = await response.text();
          let data;
          try {
            data = JSON.parse(responseText);
          } catch {
            data = null;
          }

          const rawText = data?.candidates?.[0]?.content?.parts?.[0]?.text;
          const parsed = parseModelJson(rawText);

          if (response.ok && parsed) {
            return jsonResponse(parsed, 200, { "X-Served-By-Model": model });
          }

          const details = data?.error?.message ||
            data?.promptFeedback?.blockReason ||
            (response.ok ? "Gemini returned non-parseable text." : response.statusText);

          failedAttempts.push({
            model,
            status: response.status,
            details: String(details || "No response details provided.").slice(0, 300),
          });
        } catch (networkError) {
          // Mask sensitive key if caught in network errors
          const safeMessage = networkError.message.replace(geminiKey, "[REDACTED_KEY]");
          failedAttempts.push({ model, status: "NetworkError", details: safeMessage });
        }
      }

      // 2. Groq Fallback Provider
      const groqKey = env.GROQ_API_KEY ? env.GROQ_API_KEY.trim() : "";
      if (groqKey) {
        const groqMessages = [
          { role: "system", content: GARO_SYSTEM_PROMPT + correctionContext(approvedCorrections) },
        ];
        let groqImageCount = 0;
        let groqUnsupportedAttachment = "";

        for (const message of payload.contents) {
          const content = [];
          for (const part of message.parts) {
            if (typeof part.text === "string") {
              content.push({ type: "text", text: part.text });
            } else if (part.inline_data?.mime_type?.startsWith("image/")) {
              groqImageCount += 1;
              content.push({
                type: "image_url",
                image_url: {
                  url: `data:${part.inline_data.mime_type};base64,${part.inline_data.data}`,
                },
              });
            } else if (part.inline_data) {
              groqUnsupportedAttachment = "Groq fallback does not support PDF attachments.";
            }
          }

          if (content.length) {
            groqMessages.push({
              role: message.role === "model" ? "assistant" : message.role,
              content: content.length === 1 && content[0].type === "text" ? content[0].text : content,
            });
          }
        }

        if (groqImageCount > 3) {
          groqUnsupportedAttachment = "Groq fallback supports up to three images per request.";
        }

        if (groqUnsupportedAttachment) {
          failedAttempts.push({
            model: GROQ_MODEL,
            status: "UnsupportedAttachment",
            details: groqUnsupportedAttachment,
          });
        } else {
          try {
            // Clean direct URL string (no markdown braces or brackets)
            const groqEndpoint = "https://api.groq.com/openai/v1/chat/completions";
            const response = await fetch(groqEndpoint, {
              method: "POST",
              headers: {
                Authorization: `Bearer ${groqKey}`,
                "Content-Type": "application/json",
              },
              body: JSON.stringify({
                model: GROQ_MODEL,
                messages: groqMessages,
                temperature: 0.7,
                max_completion_tokens: attachments.length ? 6144 : 2048,
                response_format: { type: "json_object" },
              }),
            });

            const responseText = await response.text();
            let data;
            try {
              data = JSON.parse(responseText);
            } catch {
              data = null;
            }

            const rawText = data?.choices?.[0]?.message?.content;
            const parsed = parseModelJson(rawText);

            if (response.ok && parsed) {
              return jsonResponse(parsed, 200, { "X-Served-By-Model": GROQ_MODEL });
            }

            failedAttempts.push({
              model: GROQ_MODEL,
              status: response.status,
              details: String(
                data?.error?.message ||
                (response.ok ? "Groq returned non-parseable content." : response.statusText) ||
                "No details provided."
              ).slice(0, 300),
            });
          } catch (networkError) {
            const safeMessage = networkError.message.replace(groqKey, "[REDACTED_KEY]");
            failedAttempts.push({ model: GROQ_MODEL, status: "NetworkError", details: safeMessage });
          }
        }
      }