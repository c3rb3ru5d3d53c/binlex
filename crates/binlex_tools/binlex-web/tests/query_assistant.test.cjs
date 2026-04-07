const test = require("node:test");
const assert = require("node:assert/strict");

const {
  analyzeQueryContext,
  applySuggestion,
  continuationStateAfterSpace,
  fieldSuggestions,
  fieldStageSuggestions,
  filterQuerySuggestions,
  isClauseComplete,
  operatorSuggestions,
  suggestQueryCompletions,
  valueSuggestions,
} = require("../../../../src/search/query.js");

const SHA256 =
  "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";

const OPTIONS = {
  architectures: ["amd64", "i386", "cil"],
  collections: ["functions", "blocks", "instructions"],
};

function labels(items) {
  return items.map((item) => item.label);
}

function continuationFor(value, cursor = value.length, options = OPTIONS) {
  return continuationStateAfterSpace(value, cursor, options);
}

test("query assistant symbolic matrix", async (t) => {
  await t.test("empty query suggests sample first", () => {
    const continuation = continuationFor(" ");
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.deepEqual(suggested.slice(0, 4), ["sample:", "embedding:", "embeddings:", "vector:"]);
    assert.ok(suggested.includes("("));
    assert.ok(suggested.includes("!"));
  });

  await t.test("pipe continuation prefers fields", () => {
    const continuation = continuationFor(`sample:${SHA256} | `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldStageSuggestions(continuation.context));
    assert.equal(suggested[0], "sample:");
    assert.ok(suggested.includes("!"));
    assert.ok(suggested.includes("ascending"));
    assert.ok(suggested.includes("descending"));
  });

  await t.test("negation before field keeps field completion active", () => {
    const context = analyzeQueryContext(`sample:${SHA256} | !sy`);
    assert.equal(context.stage, "field");
    assert.equal(context.token, "sy");
    const suggestions = filterQuerySuggestions(fieldSuggestions(context), context.partial);
    assert.equal(labels(suggestions)[0], "symbol:");
  });

  await t.test("operator suggestions include symbolic operators and close paren", () => {
    const continuation = continuationFor(`sample:${SHA256} | ( collection:functions `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "operator");
    const suggested = labels(operatorSuggestions(continuation.context));
    assert.ok(suggested.includes("|"));
    assert.ok(suggested.includes("||"));
    assert.ok(suggested.includes("->"));
    assert.ok(suggested.includes("<-"));
    assert.ok(suggested.includes(")"));
  });

  await t.test("choosing group open inserts spaced closing paren", () => {
    const state = applySuggestion(`sample:${SHA256} | !`, `sample:${SHA256} | !`.length, {
      label: "(",
      insert: "(",
      kind: "group",
    });
    assert.equal(state.value, `sample:${SHA256} | !(  )`);
    assert.equal(state.cursor, `sample:${SHA256} | !( `.length);
  });

  await t.test("complete sample term followed by space expects operators next", () => {
    const continuation = continuationFor(`sample:${SHA256} `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "operator");
  });

  await t.test("directional compare continuation expects a field on the right side", () => {
    const continuation = continuationFor(`sample:${SHA256} | collection:functions -> `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    assert.equal(labels(fieldSuggestions(continuation.context))[0], "sample:");
  });

  await t.test("field suggestion filtering prefers sample over unrelated fields", () => {
    const suggestions = filterQuerySuggestions(fieldSuggestions({ previousKind: "operator" }), "sa");
    assert.equal(labels(suggestions)[0], "sample:");
  });

  await t.test("operator suggestion filtering prefers exact symbolic matches", () => {
    const suggestions = filterQuerySuggestions(operatorSuggestions({ depth: 0 }), "||");
    assert.equal(labels(suggestions)[0], "||");
  });

  await t.test("sample completeness matches sha256 syntax", () => {
    assert.equal(isClauseComplete({ stage: "value", field: "sample", partial: SHA256 }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "sample", partial: "bogus" }, OPTIONS), false);
  });

  await t.test("address, embeddings, score, date, limit, and drop completeness stay valid", () => {
    assert.equal(isClauseComplete({ stage: "value", field: "address", partial: "0x401000" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "embeddings", partial: ">=1.5k" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "score", partial: ">0.95" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "date", partial: "2026-03-30" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "limit", partial: "10" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "drop", partial: "rhs" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "number_of_blocks", partial: ">=4" }, OPTIONS), true);
  });

  await t.test("architecture, collection, and drop value suggestions still work", () => {
    assert.deepEqual(
      labels(valueSuggestions({ stage: "value", field: "architecture", partial: "a" }, OPTIONS)),
      ["amd64", "i386", "cil"]
    );
    assert.deepEqual(
      labels(valueSuggestions({ stage: "value", field: "collection", partial: "f" }, OPTIONS)),
      ["functions", "blocks", "instructions"]
    );
    assert.deepEqual(
      labels(valueSuggestions({ stage: "value", field: "drop", partial: "r" }, OPTIONS)),
      ["lhs", "rhs"]
    );
  });

  await t.test("drop completion suggests lhs and rhs", () => {
    const completion = suggestQueryCompletions("drop:", "drop:".length, OPTIONS);
    assert.equal(completion.kind, "value");
    assert.deepEqual(labels(completion.suggestions), ["lhs", "rhs"]);
  });

  await t.test("keyword stream operators appear after pipe filtering", () => {
    const completion = suggestQueryCompletions(
      `sample:${SHA256} | limit:10 | a`,
      `sample:${SHA256} | limit:10 | a`.length,
      OPTIONS
    );
    assert.equal(completion.kind, "field");
    assert.ok(labels(completion.suggestions).includes("ascending"));
  });

  await t.test("suggestQueryCompletions works for symbolic operators", () => {
    let completion = suggestQueryCompletions("sample:", "sample:".length, OPTIONS);
    assert.equal(completion.kind, "value");

    completion = suggestQueryCompletions(`sample:${SHA256} |`, `sample:${SHA256} |`.length, OPTIONS);
    assert.equal(completion.kind, "operator");

    completion = suggestQueryCompletions(`sample:${SHA256} | `, `sample:${SHA256} | `.length, OPTIONS);
    assert.equal(completion.kind, "field");

    completion = suggestQueryCompletions(`sample:${SHA256} | collection:f`, `sample:${SHA256} | collection:f`.length, OPTIONS);
    assert.equal(completion.kind, "value");
    assert.deepEqual(labels(completion.suggestions), ["functions"]);
  });
});
