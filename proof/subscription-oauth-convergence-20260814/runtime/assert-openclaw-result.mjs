import fs from "node:fs";

const [resultPath, expectedProvider, expectedModel] = process.argv.slice(2);

if (!resultPath || !expectedProvider || !expectedModel) {
  process.stderr.write(
    "usage: node assert-openclaw-result.mjs <result.json> <provider> <model>\n",
  );
  process.exit(64);
}

const result = JSON.parse(fs.readFileSync(resultPath, "utf8"));
const payloadTexts = Array.isArray(result.payloads)
  ? result.payloads.map((payload) => payload?.text ?? null)
  : [];
const tools = result.meta?.systemPromptReport?.tools;
const trace = result.meta?.executionTrace;
const summary = {
  payloadTexts,
  finalAssistantVisibleText: result.meta?.finalAssistantVisibleText ?? null,
  stopReason: result.meta?.stopReason ?? null,
  completionStopReason: result.meta?.completion?.stopReason ?? null,
  winnerProvider: trace?.winnerProvider ?? null,
  winnerModel: trace?.winnerModel ?? null,
  fallbackUsed: trace?.fallbackUsed ?? null,
  toolEntryCount: Array.isArray(tools?.entries) ? tools.entries.length : null,
  toolSchemaChars: tools?.schemaChars ?? null,
};

const expectedText = "OPENSHELL_OAUTH_ROUTE_OK";
const passed =
  payloadTexts.length === 1 &&
  payloadTexts[0] === expectedText &&
  summary.finalAssistantVisibleText === expectedText &&
  summary.stopReason === "stop" &&
  summary.completionStopReason === "stop" &&
  summary.winnerProvider === expectedProvider &&
  summary.winnerModel === expectedModel &&
  summary.fallbackUsed === false &&
  summary.toolEntryCount === 0 &&
  summary.toolSchemaChars === 0;

process.stdout.write(`${JSON.stringify({ passed, ...summary })}\n`);
if (!passed) {
  process.exit(71);
}
