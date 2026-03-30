const test = require("node:test");
const assert = require("node:assert/strict");

const {
  analyzeQueryContext,
  applySuggestion,
  continuationStateAfterSpace,
  fieldSuggestions,
  filterQuerySuggestions,
  isClauseComplete,
  isDelimitedValueContext,
  operatorSuggestions,
  suggestQueryCompletions,
  valueSuggestions,
} = require("../../../../src/search/query.js");

const SHA256 =
  "d60f9eaa4f62f0ee84531d9aa633c5bb390ea0056953e58d80b9a62277dbe5c5";

const OPTIONS = {
  architectures: ["amd64", "i386", "cil"],
  collections: ["function", "block", "instruction"],
};

function labels(items) {
  return items.map((item) => item.label);
}

function continuationFor(value, cursor = value.length, options = OPTIONS) {
  return continuationStateAfterSpace(value, cursor, options);
}

test("query assistant matrix", async (t) => {
  await t.test("empty query with trailing space suggests fields first", () => {
    const continuation = continuationFor(" ");
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.deepEqual(suggested.slice(0, 4), ["sha256:", "embedding:", "embeddings:", "vector:"]);
    assert.equal(suggested.at(-2), "(");
    assert.equal(suggested.at(-1), "NOT");
  });

  await t.test("AND continuation prefers fields first, then group open, then NOT", () => {
    const continuation = continuationFor(`sha256:${SHA256} AND `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.deepEqual(suggested.slice(0, 4), ["sha256:", "embedding:", "embeddings:", "vector:"]);
    assert.equal(suggested.at(-2), "(");
    assert.equal(suggested.at(-1), "NOT");
  });

  await t.test("AND NOT continuation suggests fields and group open, but not NOT", () => {
    const continuation = continuationFor(`sha256:${SHA256} AND NOT `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.deepEqual(suggested.slice(0, 4), ["sha256:", "embedding:", "embeddings:", "vector:"]);
    assert.ok(suggested.includes("("));
    assert.ok(!suggested.includes("NOT"));
  });

  await t.test("NOT at query start suggests fields and group open, but not nested NOT", () => {
    const continuation = continuationFor("NOT ");
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.equal(suggested[0], "sha256:");
    assert.ok(suggested.includes("("));
    assert.ok(!suggested.includes("NOT"));
  });

  await t.test("open paren followed by space suggests fields and allows NOT", () => {
    const continuation = continuationFor("( ");
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.equal(suggested[0], "sha256:");
    assert.ok(suggested.includes("("));
    assert.equal(suggested.at(-1), "NOT");
  });

  await t.test("nested group after AND keeps close operator available later", () => {
    const continuation = continuationFor(`sha256:${SHA256} AND ( `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.ok(suggested.includes("("));
    assert.ok(suggested.includes("NOT"));

    const afterTerm = continuationFor(`sha256:${SHA256} AND ( collection:function `);
    assert.ok(afterTerm);
    assert.equal(afterTerm.kind, "operator");
    assert.ok(labels(operatorSuggestions(afterTerm.context)).includes(")"));
  });

  await t.test("typing a field after AND NOT ( keeps field completion active", () => {
    const context = analyzeQueryContext(`sha256:${SHA256} AND NOT ( sh`);
    assert.equal(context.stage, "field");
    assert.equal(context.token, "sh");
    const suggestions = filterQuerySuggestions(fieldSuggestions(context), context.partial);
    assert.equal(labels(suggestions)[0], "sha256:");
  });

  await t.test("choosing group open auto-inserts spaced closing paren and leaves cursor inside", () => {
    const state = applySuggestion(`sha256:${SHA256} AND NOT `, `sha256:${SHA256} AND NOT `.length, {
      label: "(",
      insert: "(",
      kind: "group",
    });
    assert.equal(state.value, `sha256:${SHA256} AND NOT (  )`);
    assert.equal(state.cursor, `sha256:${SHA256} AND NOT ( `.length);
  });

  await t.test("NOT followed immediately by group open is parsed as unary NOT, not a field", () => {
    const context = analyzeQueryContext(`sha256:${SHA256} AND NOT (`);
    assert.equal(context.stage, "field");
    assert.equal(context.previousKind, "group-open");
    assert.equal(context.depth, 1);
  });

  await t.test("partial operator NO stays in operator mode before trailing space", () => {
    const context = analyzeQueryContext(`sha256:${SHA256} NO`);
    assert.equal(context.stage, "operator");
    assert.equal(context.token, "NO");
  });

  await t.test("partial field prefix stays in field mode", () => {
    const context = analyzeQueryContext("sh");
    assert.equal(context.stage, "field");
    assert.equal(context.token, "sh");
  });

  await t.test("field suggestion filtering keeps matching fields ahead of punctuation", () => {
    const suggestions = filterQuerySuggestions(fieldSuggestions({ previousKind: "operator" }), "sha");
    assert.equal(labels(suggestions)[0], "sha256:");
  });

  await t.test("operator suggestion filtering prefers exact operator match", () => {
    const suggestions = filterQuerySuggestions(operatorSuggestions({ depth: 0 }), "OR");
    assert.equal(labels(suggestions)[0], "OR");
  });

  await t.test("complete sha256 term followed by space expects operators next", () => {
    const continuation = continuationFor(`sha256:${SHA256} `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "operator");
  });

  await t.test("closed group with trailing space expects operators next", () => {
    const continuation = continuationFor(`( sha256:${SHA256} ) `);
    assert.ok(continuation);
    assert.equal(continuation.kind, "operator");
  });

  await t.test("mid-string cursor after AND NOT still offers field continuation", () => {
    const query = `sha256:${SHA256} AND NOT corpus:demo`;
    const cursor = query.indexOf("corpus:");
    const continuation = continuationFor(query, cursor);
    assert.ok(continuation);
    assert.equal(continuation.kind, "field");
    const suggested = labels(fieldSuggestions(continuation.context));
    assert.ok(suggested.includes("sha256:"));
    assert.ok(suggested.includes("("));
    assert.ok(!suggested.includes("NOT"));
  });

  await t.test("complete vector is recognized as complete value", () => {
    assert.equal(
      isClauseComplete({ stage: "value", field: "vector", partial: "[0.1, -0.2, 0.3]" }, OPTIONS),
      true
    );
  });

  await t.test("incomplete vector remains incomplete", () => {
    assert.equal(
      isClauseComplete({ stage: "value", field: "vector", partial: "[0.1, -0.2" }, OPTIONS),
      false
    );
  });

  await t.test("complete quoted symbol is recognized as complete value", () => {
    assert.equal(
      isClauseComplete({ stage: "value", field: "symbol", partial: "\"kernel32:CreateFileW\"" }, OPTIONS),
      true
    );
  });

  await t.test("unterminated symbol remains incomplete", () => {
    assert.equal(
      isClauseComplete({ stage: "value", field: "symbol", partial: "\"kernel32:CreateFileW" }, OPTIONS),
      false
    );
  });

  await t.test("address and embeddings completeness match accepted syntax", () => {
    assert.equal(isClauseComplete({ stage: "value", field: "address", partial: "0x401000" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "address", partial: "bogus" }, OPTIONS), false);
    assert.equal(isClauseComplete({ stage: "value", field: "embeddings", partial: ">=1.5k" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "embeddings", partial: ">>1k" }, OPTIONS), false);
    assert.equal(isClauseComplete({ stage: "value", field: "date", partial: "2026-03-30" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "date", partial: ">=2026-03-01" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "date", partial: "2026-3-1" }, OPTIONS), false);
  });

  await t.test("architecture and collection completion uses configured datasets", () => {
    assert.equal(isClauseComplete({ stage: "value", field: "architecture", partial: "amd64" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "architecture", partial: "arm64" }, OPTIONS), false);
    assert.equal(isClauseComplete({ stage: "value", field: "collection", partial: "function" }, OPTIONS), true);
    assert.equal(isClauseComplete({ stage: "value", field: "collection", partial: "symbol" }, OPTIONS), false);
  });

  await t.test("architecture and collection value suggestions come from configured datasets", () => {
    assert.deepEqual(
      labels(valueSuggestions({ stage: "value", field: "architecture", partial: "a" }, OPTIONS)),
      ["amd64", "i386", "cil"]
    );
    assert.deepEqual(
      labels(valueSuggestions({ stage: "value", field: "collection", partial: "f" }, OPTIONS)),
      ["function", "block", "instruction"]
    );
  });

  await t.test("value-stage completion filters architecture and collection suggestions", () => {
    let completion = suggestQueryCompletions("architecture:a", "architecture:a".length, OPTIONS);
    assert.equal(completion.kind, "value");
    assert.deepEqual(labels(completion.suggestions), ["amd64"]);

    completion = suggestQueryCompletions("collection:f", "collection:f".length, OPTIONS);
    assert.equal(completion.kind, "value");
    assert.deepEqual(labels(completion.suggestions), ["function"]);
  });

  await t.test("corpus values are treated as delimited but never complete", () => {
    const context = analyzeQueryContext("corpus:demo");
    assert.equal(context.stage, "value");
    assert.equal(isClauseComplete(context, OPTIONS), false);
    assert.equal(isDelimitedValueContext(context), true);
  });

  await t.test("collection trailing space returns value continuation for dropdown suggestions", () => {
    const continuation = continuationFor("collection: ");
    assert.ok(continuation);
    assert.equal(continuation.kind, "value");
    assert.equal(continuation.context.field, "collection");
    const completion = suggestQueryCompletions("collection: ", "collection: ".length, OPTIONS);
    assert.equal(completion.kind, "value");
    assert.deepEqual(labels(completion.suggestions), ["function", "block", "instruction"]);
  });

  await t.test("committed corpus clause transitions cleanly to operator suggestions", () => {
    const continuation = continuationFor("corpus:demo ", "corpus:demo ".length, {
      ...OPTIONS,
      committedClause: { field: "corpus", value: "demo" },
    });
    assert.ok(continuation);
    assert.equal(continuation.kind, "operator");
  });

  await t.test("NOT without space before group is treated as unary NOT followed by group", () => {
    const context = analyzeQueryContext("NOT(");
    assert.equal(context.stage, "field");
    assert.equal(context.previousKind, "group-open");
    assert.equal(context.depth, 1);
  });

  await t.test("bare opening paren does not re-suggest opening paren", () => {
    const suggestions = fieldSuggestions(analyzeQueryContext("("));
    assert.ok(!labels(suggestions).includes("("));
  });

  await t.test("NOT followed by opening paren does not re-suggest opening paren", () => {
    const suggestions = fieldSuggestions(analyzeQueryContext("NOT("));
    assert.ok(!labels(suggestions).includes("("));
  });

  await t.test("vector and symbol contexts preserve in-progress value stage", () => {
    let context = analyzeQueryContext("vector:[0.1, ");
    assert.equal(context.stage, "value");
    assert.equal(context.field, "vector");

    context = analyzeQueryContext("symbol:\"kernel32");
    assert.equal(context.stage, "value");
    assert.equal(context.field, "symbol");
  });
});
