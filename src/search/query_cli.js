#!/usr/bin/env node

const fs = require("node:fs");
const query = require("./query.js");

function main() {
  const raw = fs.readFileSync(0, "utf8");
  const payload = raw.trim() ? JSON.parse(raw) : {};
  const value = payload.query || "";
  const cursor = Number.isInteger(payload.cursor) ? payload.cursor : value.length;
  const options = payload.options || {};
  const mode = payload.mode || "suggest";

  if (mode === "analyze") {
    return {
      context: query.analyzeQueryContext(value, cursor),
      continuation: query.continuationStateAfterSpace(value, cursor, options),
    };
  }

  if (mode === "apply") {
    return query.applySuggestion(value, cursor, payload.item || {}, options);
  }

  return query.suggestQueryCompletions(value, cursor, options);
}

process.stdout.write(`${JSON.stringify(main(), null, 2)}\n`);
