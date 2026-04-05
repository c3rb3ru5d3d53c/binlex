(function (root, factory) {
  const api = factory();
  if (typeof module !== "undefined" && module.exports) {
    module.exports = api;
  }
  root.BinlexQuery = api;
})(typeof globalThis !== "undefined" ? globalThis : this, function () {
  const QUERY_FIELD_SUGGESTIONS = [
    { label: "sample:", insert: "sample:", kind: "field" },
    { label: "embedding:", insert: "embedding:", kind: "field" },
    { label: "embeddings:", insert: "embeddings:", kind: "field" },
    { label: "vector:", insert: "vector:", kind: "field" },
    { label: "score:", insert: "score:", kind: "field" },
    { label: "limit:", insert: "limit:", kind: "field" },
    { label: "drop:", insert: "drop:", kind: "field" },
    { label: "corpus:", insert: "corpus:", kind: "field" },
    { label: "collection:", insert: "collection:", kind: "field" },
    { label: "architecture:", insert: "architecture:", kind: "field" },
    { label: "address:", insert: "address:", kind: "field" },
    { label: "date:", insert: "date:", kind: "field" },
    { label: "size:", insert: "size:", kind: "field" },
    { label: "symbol:", insert: "symbol:", kind: "field" },
    { label: "cyclomatic_complexity:", insert: "cyclomatic_complexity:", kind: "field" },
    { label: "average_instructions_per_block:", insert: "average_instructions_per_block:", kind: "field" },
    { label: "number_of_instructions:", insert: "number_of_instructions:", kind: "field" },
    { label: "number_of_blocks:", insert: "number_of_blocks:", kind: "field" },
    { label: "entropy:", insert: "entropy:", kind: "field" },
    { label: "contiguous:", insert: "contiguous:", kind: "field" },
    { label: "chromosome.entropy:", insert: "chromosome.entropy:", kind: "field" },
    { label: "|", insert: " | ", kind: "operator" },
    { label: "||", insert: " || ", kind: "operator" },
    { label: "!", insert: "!", kind: "operator" },
    { label: "->", insert: " -> ", kind: "operator" },
    { label: "<-", insert: " <- ", kind: "operator" },
    { label: "ascending", insert: " | ascending", kind: "operator" },
    { label: "descending", insert: " | descending", kind: "operator" },
    { label: "(", insert: "(", kind: "group" },
    { label: ")", insert: ")", kind: "group" },
  ];

  function normalizeOptions(options = {}) {
    return {
      architectures: options.architectures || [],
      collections: options.collections || [],
      committedClause: options.committedClause || null,
    };
  }

  function queryGroupDepth(value, cursor) {
    const prefix = value.slice(0, cursor);
    let depth = 0;
    for (const ch of prefix) {
      if (ch === "(") depth += 1;
      else if (ch === ")" && depth > 0) depth -= 1;
    }
    return depth;
  }

  function symbolicOperatorAt(value, index) {
    if ((value || "").startsWith("||", index)) return "||";
    if ((value || "").startsWith("->", index)) return "->";
    if ((value || "").startsWith("<-", index)) return "<-";
    if ((value || "")[index] === "|") return "|";
    return null;
  }

  function analyzeQueryContext(value, cursor = value.length) {
    value = value || "";
    let index = 0;
    let depth = 0;
    let previousKind = "start";
    while (index < cursor) {
      while (index < cursor && /\s/.test(value[index])) index += 1;
      if (index >= cursor) {
        if (previousKind === "term" || previousKind === "group-close") {
          return { stage: "operator", partial: "", token: "", previousKind, depth, value, cursor };
        }
        return { stage: "field", partial: "", token: "", previousKind, depth, value, cursor };
      }

      if (value[index] === "(") {
        depth += 1;
        index += 1;
        previousKind = "group-open";
        if (index >= cursor) {
          return { stage: "field", partial: "(", token: "(", previousKind, depth, value, cursor };
        }
        continue;
      }

      if (value[index] === ")") {
        depth = Math.max(0, depth - 1);
        index += 1;
        previousKind = "group-close";
        if (index >= cursor) {
          return { stage: "operator", partial: ")", token: ")", previousKind, depth, value, cursor };
        }
        continue;
      }

      if (previousKind === "term" || previousKind === "group-close") {
        const operator = symbolicOperatorAt(value, index);
        if (!operator) {
          return {
            stage: "operator",
            partial: value.slice(index, cursor),
            token: value.slice(index, cursor),
            previousKind,
            depth,
            value,
            cursor,
          };
        }
        const operatorEnd = index + operator.length;
        if (cursor <= operatorEnd) {
          const partial = value.slice(index, cursor);
          return { stage: "operator", partial, token: partial, previousKind, depth, value, cursor };
        }
        index = operatorEnd;
        previousKind = "operator";
        continue;
      }

      if (value[index] === "!") {
        index += 1;
        previousKind = "not";
        if (index >= cursor) {
          return { stage: "field", partial: "", token: "", previousKind, depth, value, cursor };
        }
        continue;
      }

      const fieldStart = index;
      while (index < cursor && /[A-Za-z0-9_.]/.test(value[index])) index += 1;
      const field = value.slice(fieldStart, index).toLowerCase();
      if (index >= cursor) {
        return { stage: "field", partial: field, token: field, previousKind, depth, value, cursor };
      }
      if (value[index] !== ":") {
        return { stage: "field", partial: field, token: field, previousKind, depth, value, cursor };
      }

      index += 1;
      while (index < cursor && /\s/.test(value[index])) index += 1;
      const valueStart = index;
      if (index >= cursor) {
        return { stage: "value", field, partial: "", token: "", previousKind, depth, value, cursor };
      }

      if (field === "vector") {
        if (value[index] !== "[") {
          const token = value.slice(valueStart, cursor);
          return { stage: "value", field, partial: token, token, previousKind, depth, value, cursor };
        }
        let vectorDepth = 0;
        while (index < cursor) {
          if (value[index] === "[") vectorDepth += 1;
          if (value[index] === "]") {
            vectorDepth -= 1;
            if (vectorDepth === 0) {
              index += 1;
              break;
            }
          }
          index += 1;
        }
        if (index >= cursor) {
          const token = value.slice(valueStart, cursor);
          return { stage: completedValueContext(field, token, normalizeOptions()) ? "complete" : "value", field, partial: token, token, previousKind, depth, value, cursor };
        }
      } else if (field === "symbol") {
        if (value[index] !== "\"") {
          const token = value.slice(valueStart, cursor);
          return { stage: "value", field, partial: token, token, previousKind, depth, value, cursor };
        }
        index += 1;
        let escaped = false;
        while (index < cursor) {
          const ch = value[index];
          index += 1;
          if (escaped) escaped = false;
          else if (ch === "\\") escaped = true;
          else if (ch === "\"") break;
        }
        if (index >= cursor) {
          const token = value.slice(valueStart, cursor);
          return { stage: completedValueContext(field, token, normalizeOptions()) ? "complete" : "value", field, partial: token, token, previousKind, depth, value, cursor };
        }
      } else {
        while (index < cursor && !/\s|\(|\)|\|/.test(value[index])) index += 1;
        if (index >= cursor) {
          const token = value.slice(valueStart, cursor);
          return { stage: completedValueContext(field, token, normalizeOptions()) ? "complete" : "value", field, partial: token, token, previousKind, depth, value, cursor };
        }
      }

      previousKind = "term";
    }

    return { stage: "field", partial: "", token: "", previousKind, depth, value, cursor };
  }

  function completedValueContext(field, rawValue, options) {
    return isClauseComplete({ stage: "value", field, partial: rawValue }, options);
  }

  function terminalQueryContext(value, cursor) {
    const prefix = (value || "").slice(0, cursor);
    const trimmed = prefix.replace(/\s+$/, "");
    if (!trimmed) return { hasTrailingSpace: /\s$/.test(prefix), context: null, prefix };
    return {
      hasTrailingSpace: trimmed.length < prefix.length,
      context: analyzeQueryContext(trimmed, trimmed.length),
      prefix,
    };
  }

  function operatorContinuationContext(prefix, depth = null) {
    const cursor = prefix.length;
    return {
      stage: "operator",
      partial: "",
      token: "",
      previousKind: "term",
      depth: depth ?? queryGroupDepth(prefix, cursor),
      value: prefix,
      cursor,
    };
  }

  function committedSuggestionState(value, cursor, options) {
    const committed = normalizeOptions(options).committedClause;
    if (!committed?.field || !committed?.value) return null;
    const prefix = (value || "").slice(0, cursor);
    const context = analyzeQueryContext(value, cursor);
    if (context?.stage === "value" && context.field === committed.field) {
      const partial = (context.partial || "").trim();
      if (partial === committed.value) {
        return {
          kind: "none",
          context: {
            stage: "complete",
            field: committed.field,
            partial: committed.value,
            token: committed.value,
            previousKind: "term",
            depth: context.depth,
            value: prefix,
            cursor: prefix.length,
          },
        };
      }
      if (partial.startsWith(committed.value)) return null;
    }
    const clauseText = `${committed.field}:${committed.value}`;
    if (prefix.endsWith(`${clauseText} `)) {
      return { kind: "operator", context: operatorContinuationContext(prefix, queryGroupDepth(prefix, prefix.length)) };
    }
    if (prefix.endsWith(clauseText)) {
      return {
        kind: "none",
        context: {
          stage: "complete",
          field: committed.field,
          partial: committed.value,
          token: committed.value,
          previousKind: "term",
          depth: queryGroupDepth(prefix, prefix.length),
          value: prefix,
          cursor: prefix.length,
        },
      };
    }
    return null;
  }

  function continuationStateAfterSpace(value, cursor = value.length, options = {}) {
    const committed = committedSuggestionState(value, cursor, options);
    if (committed) return committed;
    const terminal = terminalQueryContext(value, cursor);
    if (!terminal.hasTrailingSpace) return null;
    const prefix = terminal.prefix || "";
    const context = terminal.context;
    if (!context) {
      return { kind: "field", context: { stage: "field", partial: "", token: "", previousKind: "start", depth: queryGroupDepth(prefix, prefix.length), value: prefix, cursor: prefix.length } };
    }
    if (/\(\s+$/i.test(prefix)) {
      return { kind: "field", context: { stage: "field", partial: "", token: "", previousKind: "group-open", depth: queryGroupDepth(prefix, prefix.length), value: prefix, cursor: prefix.length } };
    }
    if (/!\s+$/i.test(prefix)) {
      return { kind: "field", context: { stage: "field", partial: "", token: "", previousKind: "not", depth: queryGroupDepth(prefix, prefix.length), value: prefix, cursor: prefix.length } };
    }
    if (context.stage === "complete") return { kind: "operator", context: operatorContinuationContext(prefix, context.depth) };
    if (context.stage === "operator") {
      const token = context.token || "";
      if (["|", "||", "->", "<-"].includes(token)) {
        return { kind: "field", context: { ...context, stage: "field", partial: "", token: "", previousKind: "operator", value: prefix, cursor: prefix.length } };
      }
      return { kind: "operator", context: operatorContinuationContext(prefix, context.depth) };
    }
    if (context.stage === "field") {
      return { kind: "field", context: { ...context, partial: "", token: "", value: prefix, cursor: prefix.length } };
    }
    if (context.stage === "value") {
      if (isClauseComplete(context, options) || isDelimitedValueContext(context)) {
        return { kind: "operator", context: operatorContinuationContext(prefix, context.depth) };
      }
      if (["corpus", "architecture", "collection"].includes(context.field)) {
        return { kind: "value", context: { ...context, partial: "", token: "", value: prefix, cursor: prefix.length } };
      }
    }
    return { kind: "none", context };
  }

  function continuationSuggestions() {
    return QUERY_FIELD_SUGGESTIONS.map((item) => ({ ...item }));
  }

  function operatorSuggestions(context) {
    const items = continuationSuggestions().filter((item) => item.kind === "operator" && item.label !== "!");
    if ((context.depth || 0) > 0) {
      const close = continuationSuggestions().find((item) => item.label === ")");
      if (close) items.push(close);
    }
    return items;
  }

  function fieldSuggestions(context) {
    const open = context?.token === "(" || context?.partial === "(" ? null : continuationSuggestions().find((item) => item.label === "(");
    const negate = continuationSuggestions().find((item) => item.label === "!");
    const fields = continuationSuggestions().filter((item) => item.kind === "field");
    const items = [...fields];
    if (open) items.push(open);
    if (negate && context?.previousKind !== "term" && context?.previousKind !== "group-close" && context?.previousKind !== "not") {
      items.push(negate);
    }
    return items;
  }

  function fieldStageSuggestions(context) {
    const items = [...fieldSuggestions(context)];
    continuationSuggestions()
      .filter(
        (item) =>
          item.kind === "operator" &&
          ["ascending", "descending"].includes((item.label || "").toLowerCase())
      )
      .forEach((item) => items.push(item));
    return items;
  }

  function valueSuggestions(context, options = {}) {
    if (!context || context.stage !== "value") return [];
    const normalized = normalizeOptions(options);
    if (context.field === "architecture") {
      return normalized.architectures.map((value) => ({ label: value, insert: value, kind: "value" }));
    }
    if (context.field === "collection") {
      return normalized.collections.map((value) => ({ label: value, insert: value, kind: "value" }));
    }
    if (context.field === "drop") {
      return ["lhs", "rhs"].map((value) => ({ label: value, insert: value, kind: "value" }));
    }
    if (context.field === "contiguous") {
      return ["true", "false"].map((value) => ({ label: value, insert: value, kind: "value" }));
    }
    return [];
  }

  function fuzzyMenuScore(query, label) {
    const rawQuery = (query || "").toLowerCase().trim();
    const rawLabel = (label || "").toLowerCase().trim();
    if (!rawQuery) return 0;
    if (rawLabel === rawQuery) return 5000;
    if (rawLabel.startsWith(rawQuery)) return 4000 - (rawLabel.length - rawQuery.length);
    if (rawLabel.includes(rawQuery)) return 3000 - (rawLabel.length - rawQuery.length);
    const q = rawQuery.replace(/[^a-z0-9]/g, "");
    const l = rawLabel.replace(/[^a-z0-9]/g, "");
    if (!q) return -1;
    if (l.includes(q)) return 1000 - (l.length - q.length);
    let score = 0;
    let position = 0;
    for (const ch of q) {
      const found = l.indexOf(ch, position);
      if (found === -1) return -1;
      score += 10;
      if (found === position) score += 4;
      position = found + 1;
    }
    return score - (l.length - q.length);
  }

  function filterQuerySuggestions(items, query) {
    const needle = (query || "").trim();
    return items
      .map((item, index) => ({ item, index, score: needle ? fuzzyMenuScore(needle, item.label || "") : 0 }))
      .filter((entry) => !needle || entry.score >= 0)
      .sort((lhs, rhs) => {
        if (!needle) return lhs.index - rhs.index;
        if (rhs.score !== lhs.score) return rhs.score - lhs.score;
        return lhs.index - rhs.index;
      })
      .map((entry) => entry.item);
  }

  function isDelimitedValueContext(context) {
    if (!context || context.stage !== "value") return false;
    const value = (context.partial || "").trim();
    if (!value) return false;
    return context.field !== "vector" && context.field !== "symbol";
  }

  function isClauseComplete(context, options = {}) {
    if (!context || context.stage !== "value") return false;
    const value = (context.partial || "").trim();
    if (!value) return false;
    const normalized = normalizeOptions(options);
    if (context.field === "sample") return /^[0-9a-fA-F]{64}$/.test(value);
    if (context.field === "embedding") return /^[0-9a-fA-F]{64}$/.test(value);
    if (context.field === "embeddings") return /^(>=|<=|>|<|=)?\s*\d+(?:\.\d+)?\s*[kKmMbB]?$/.test(value);
    if (context.field === "score") return /^(>=|<=|>|<|=)?\s*-?\d+(?:\.\d+)?$/.test(value);
    if (context.field === "limit") return /^\d+$/.test(value) && Number(value) > 0;
    if (context.field === "drop") return /^(lhs|rhs)$/i.test(value);
    if (context.field === "date") return /^(>=|<=|>|<|=)?\s*\d{4}(?:-\d{2}(?:-\d{2})?)?$/.test(value);
    if (context.field === "vector") {
      try {
        const parsed = JSON.parse(value);
        return Array.isArray(parsed) && parsed.length >= 2;
      } catch (_) {
        return false;
      }
    }
    if (context.field === "symbol") return /^"(?:[^"\\]|\\.)+"$/.test(value);
    if (context.field === "architecture") return normalized.architectures.some((item) => item.toLowerCase() === value.toLowerCase());
    if (context.field === "collection") return normalized.collections.some((item) => item.toLowerCase() === value.toLowerCase());
    if (context.field === "drop") return ["lhs", "rhs"].some((item) => item === value.toLowerCase());
    if (["cyclomatic_complexity", "number_of_instructions", "number_of_blocks", "embeddings", "limit", "size"].includes(context.field)) {
      return /^(>=|<=|>|<|=)?\s*\d+(?:\.\d+)?\s*[kKmMbB]?$/.test(value);
    }
    if (["average_instructions_per_block", "entropy", "chromosome.entropy", "score"].includes(context.field)) {
      return /^(>=|<=|>|<|=)?\s*-?\d+(?:\.\d+)?$/.test(value);
    }
    if (context.field === "contiguous") return /^(true|false)$/i.test(value);
    if (context.field === "corpus") return false;
    if (context.field === "address") return /^(0x[0-9a-fA-F]+|\d+)$/.test(value);
    return false;
  }

  function replacementStateForContext(context, replacement, cursorOffset = replacement.length) {
    const partialLength = (context.partial || "").length;
    const before = (context.value || "").slice(0, (context.cursor || 0) - partialLength);
    const after = (context.value || "").slice(context.cursor || 0);
    return { value: `${before}${replacement}${after}`, cursor: before.length + cursorOffset };
  }

  function applySuggestion(value, cursor, item, options = {}) {
    const context = analyzeQueryContext(value, cursor);
    const replacement = item.insert || item.label || "";
    const current = (context.partial || "").trim();
    if (item.kind === "group" && replacement === "(") {
      const nextChar = (context.value || "").slice(context.cursor || 0, (context.cursor || 0) + 1);
      return nextChar === ")" ? replacementStateForContext(context, "(", 1) : replacementStateForContext(context, "(  )", 2);
    }
    if (item.kind === "group" && current === replacement.trim()) {
      if (cursor >= value.length || !/\s/.test(value[cursor] || "")) return { value: `${value.slice(0, cursor)} ${value.slice(cursor)}`, cursor: cursor + 1 };
      return { value, cursor };
    }
    const state = replacementStateForContext(context, replacement);
    if (item.kind === "value" && context.field === "corpus") {
      state.committedClause = { field: "corpus", value: replacement.trim() };
    }
    return state;
  }

  function suggestQueryCompletions(value, cursor = value.length, options = {}) {
    const continuation = continuationStateAfterSpace(value, cursor, options);
    if (continuation) {
      if (continuation.kind === "operator") return { kind: "operator", context: continuation.context, suggestions: operatorSuggestions(continuation.context) };
      if (continuation.kind === "field") return { kind: "field", context: continuation.context, suggestions: fieldStageSuggestions(continuation.context) };
      if (continuation.kind === "value") return { kind: "value", context: continuation.context, suggestions: valueSuggestions(continuation.context, options) };
      return { kind: continuation.kind, context: continuation.context, suggestions: [] };
    }

    const clause = analyzeQueryContext(value, cursor);
    if (clause.stage === "complete" || clause.stage === "none") return { kind: "none", context: clause, suggestions: [] };
    if (!clause.token && clause.stage === "field") {
      return clause.previousKind === "term" || clause.previousKind === "group-close"
        ? { kind: "operator", context: clause, suggestions: operatorSuggestions(clause) }
        : { kind: "field", context: clause, suggestions: fieldStageSuggestions(clause) };
    }
    if (clause.stage === "value") {
      return { kind: "value", context: clause, suggestions: filterQuerySuggestions(valueSuggestions(clause, options), clause.partial) };
    }
    const baseSuggestions = clause.stage === "operator" ? operatorSuggestions(clause) : fieldStageSuggestions(clause);
    return { kind: clause.stage, context: clause, suggestions: filterQuerySuggestions(baseSuggestions, clause.partial) };
  }

  return {
    QUERY_FIELD_SUGGESTIONS,
    analyzeQueryContext,
    applySuggestion,
    continuationStateAfterSpace,
    continuationSuggestions,
    fieldSuggestions,
    fieldStageSuggestions,
    filterQuerySuggestions,
    isClauseComplete,
    isDelimitedValueContext,
    operatorSuggestions,
    queryGroupDepth,
    replacementStateForContext,
    suggestQueryCompletions,
    valueSuggestions,
  };
});
