import http from "node:http";

const port = Number.parseInt(process.env.OPENCLAW_CAPTURE_PORT ?? "18765", 10);

const server = http.createServer((request, response) => {
  const chunks = [];
  request.on("data", (chunk) => chunks.push(chunk));
  request.on("end", () => {
    let body;
    try {
      body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      body = null;
    }

    const input = Array.isArray(body?.input) ? body.input : null;
    const summary = {
      method: request.method,
      path: request.url,
      bodyKeys: body && typeof body === "object" ? Object.keys(body).sort() : null,
      model: body?.model,
      store: body?.store,
      stream: body?.stream,
      instructionsType: typeof body?.instructions,
      instructionsLength:
        typeof body?.instructions === "string" ? body.instructions.length : null,
      inputIsArray: input !== null,
      inputItems: input?.map((item) => ({
        keys: item && typeof item === "object" ? Object.keys(item).sort() : null,
        type: item?.type,
        role: item?.role,
        contentIsArray: Array.isArray(item?.content),
        contentTypes: Array.isArray(item?.content)
          ? item.content.map((part) => part?.type ?? null)
          : null,
      })),
      toolsCount: Array.isArray(body?.tools) ? body.tools.length : null,
      toolChoice: body?.tool_choice,
      parallelToolCalls: body?.parallel_tool_calls,
      reasoning: body?.reasoning,
      include: body?.include,
      text: body?.text,
      maxOutputTokens: body?.max_output_tokens,
      promptCacheKeyType: typeof body?.prompt_cache_key,
      promptCacheRetention: body?.prompt_cache_retention,
    };

    process.stdout.write(`${JSON.stringify(summary, null, 2)}\n`);
    response.writeHead(400, { "content-type": "application/json" });
    response.end('{"error":{"message":"schema capture complete"}}');
    server.close();
  });
});

server.listen(port, "127.0.0.1");
