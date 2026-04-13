function parseQueryDataset(name) {
  const form = getSearchForm();
  if (!form) return [];
  try {
    return JSON.parse(form.dataset[name] || "[]");
  } catch (_) {
    return [];
  }
}

function queryCompletionCatalog() {
  const items = parseQueryDataset("queryCompletions");
  if (Array.isArray(items) && items.length > 0) {
    return items.map((item) => ({ ...item }));
  }
  return QUERY_FIELD_SUGGESTIONS.map((item) => ({ ...item }));
}

function queryGroupDepth(value, cursor) {
  const prefix = value.slice(0, cursor);
  let depth = 0;
  for (const ch of prefix) {
    if (ch === "(") {
      depth += 1;
    } else if (ch === ")" && depth > 0) {
      depth -= 1;
    }
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

function analyzeQueryContext(input) {
  const value = input?.value || "";
  const cursor = input?.selectionStart ?? value.length;
  let index = 0;
  let depth = 0;
  let previousKind = "start";
  while (index < cursor) {
    while (index < cursor && /\s/.test(value[index])) {
      index += 1;
    }
    if (index >= cursor) {
      if (previousKind === "term" || previousKind === "group-close") {
        return {
          stage: "operator",
          partial: "",
          token: "",
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      return {
        stage: "field",
        partial: "",
        token: "",
        previousKind,
        depth,
        value,
        cursor,
      };
    }

    if (value[index] === "(") {
      depth += 1;
      index += 1;
      previousKind = "group-open";
      if (index >= cursor) {
        return {
          stage: "field",
          partial: "(",
          token: "(",
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      continue;
    }

    if (value[index] === ")") {
      depth = Math.max(0, depth - 1);
      index += 1;
      previousKind = "group-close";
      if (index >= cursor) {
        return {
          stage: "operator",
          partial: ")",
          token: ")",
          previousKind,
          depth,
          value,
          cursor,
        };
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
        return {
          stage: "operator",
          partial,
          token: partial,
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      index = operatorEnd;
      previousKind = "operator";
      continue;
    }

    if (value[index] === "!") {
      index += 1;
      previousKind = "not";
      if (index >= cursor) {
        return {
          stage: "field",
          partial: "",
          token: "",
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      continue;
    }

    const fieldStart = index;
    while (index < cursor && /[A-Za-z0-9_.]/.test(value[index])) {
      index += 1;
    }
    const field = value.slice(fieldStart, index).toLowerCase();
    if (index >= cursor) {
      return {
        stage: "field",
        partial: field,
        token: field,
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    if (value[index] !== ":") {
      return {
        stage: "field",
        partial: field,
        token: field,
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    index += 1;
    if (index >= cursor) {
      return {
        stage: "value",
        field,
        partial: "",
        token: "",
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    while (index < cursor && /\s/.test(value[index])) {
      index += 1;
    }
    const valueStart = index;
    if (index >= cursor) {
      return {
        stage: "value",
        field,
        partial: "",
        token: "",
        previousKind,
        depth,
        value,
        cursor,
      };
    }
    if (field === "vector") {
      if (value[index] !== "[") {
        return {
          stage: "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
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
        return {
          stage: completedValueContext(field, value.slice(valueStart, cursor)) ? "complete" : "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
    } else if (field === "symbol") {
      if (value[index] !== "\"") {
        return {
          stage: "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      index += 1;
      let escaped = false;
      while (index < cursor) {
        const ch = value[index];
        index += 1;
        if (escaped) {
          escaped = false;
          continue;
        }
        if (ch === "\\") {
          escaped = true;
          continue;
        }
        if (ch === "\"") {
          break;
        }
      }
      if (index >= cursor) {
        return {
          stage: completedValueContext(field, value.slice(valueStart, cursor)) ? "complete" : "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
    } else {
        while (index < cursor && !/\s|\(|\)|\|/.test(value[index])) {
          index += 1;
        }
      if (index >= cursor) {
        return {
          stage: completedValueContext(field, value.slice(valueStart, cursor)) ? "complete" : "value",
          field,
          partial: value.slice(valueStart, cursor),
          token: value.slice(valueStart, cursor),
          previousKind,
          depth,
          value,
          cursor,
        };
      }
    }

    previousKind = "term";
  }

  return {
    stage: "field",
    partial: "",
    token: "",
    previousKind,
    depth,
    value,
    cursor,
  };
}

function completedValueContext(field, rawValue) {
  return isClauseComplete({
    stage: "value",
    field,
    partial: rawValue,
  });
}

function terminalQueryContext(input) {
  const rawValue = input?.value || "";
  const cursor = input?.selectionStart ?? rawValue.length;
  const prefix = rawValue.slice(0, cursor);
  const trimmed = prefix.replace(/\s+$/, "");
  if (!trimmed) {
    return {
      hasTrailingSpace: /\s$/.test(prefix),
      context: null,
      prefix,
    };
  }
  return {
    hasTrailingSpace: trimmed.length < prefix.length,
    context: analyzeQueryContext({
      value: trimmed,
      selectionStart: trimmed.length,
    }),
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

function continuationStateAfterSpace(input) {
  const committed = committedSuggestionState(input);
  if (committed) return committed;
  const terminal = terminalQueryContext(input);
  if (!terminal.hasTrailingSpace) return null;
  const prefix = terminal.prefix || "";
  const context = terminal.context;
  if (!context) {
    return {
      kind: "field",
      context: {
        stage: "field",
        partial: "",
        token: "",
        previousKind: "start",
        depth: queryGroupDepth(prefix, prefix.length),
        value: prefix,
        cursor: prefix.length,
      },
    };
  }
  if (/\(\s+$/i.test(prefix)) {
    return {
      kind: "field",
      context: {
        stage: "field",
        partial: "",
        token: "",
        previousKind: "group-open",
        depth: queryGroupDepth(prefix, prefix.length),
        value: prefix,
        cursor: prefix.length,
      },
    };
  }
  if (/!\s+$/i.test(prefix)) {
    return {
      kind: "field",
      context: {
        stage: "field",
        partial: "",
        token: "",
        previousKind: "not",
        depth: queryGroupDepth(prefix, prefix.length),
        value: prefix,
        cursor: prefix.length,
      },
    };
  }
  if (context.stage === "complete") {
    return {
      kind: "operator",
      context: operatorContinuationContext(prefix, context.depth),
    };
  }
  if (context.stage === "operator") {
    const token = context.token || "";
      if (["|", "||", "->", "<-"].includes(token)) {
      return {
        kind: "field",
        context: {
          ...context,
          stage: "field",
          partial: "",
          token: "",
          previousKind: "operator",
          value: prefix,
          cursor: prefix.length,
        },
      };
    }
    return {
      kind: "operator",
      context: operatorContinuationContext(prefix, context.depth),
    };
  }
  if (context.stage === "field") {
    return {
      kind: "field",
      context: {
        ...context,
        partial: "",
        token: "",
        value: prefix,
        cursor: prefix.length,
      },
    };
  }
  if (context.stage === "value") {
    if (isClauseComplete(context) || isDelimitedValueContext(context)) {
      return {
        kind: "operator",
        context: operatorContinuationContext(prefix, context.depth),
      };
    }
    if (["corpus", "tag", "architecture", "collection"].includes(context.field)) {
      return {
        kind: "value",
        context: {
          ...context,
          partial: "",
          token: "",
          value: prefix,
          cursor: prefix.length,
        },
      };
    }
  }
  return {
    kind: "none",
    context,
  };
}

function committedSuggestionState(input) {
  const committed = getCommittedQueryClause(input);
  if (!committed?.field || !committed?.value) return null;
  const prefix = (input?.value || "").slice(0, input?.selectionStart ?? (input?.value || "").length);
  const context = analyzeQueryContext(input);
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
    if (partial.startsWith(committed.value)) {
      clearCommittedQueryClause(input);
      return null;
    }
  }
  const clauseText = `${committed.field}:${committed.value}`;
  if (prefix.endsWith(`${clauseText} `)) {
    return {
      kind: "operator",
      context: operatorContinuationContext(prefix, queryGroupDepth(prefix, prefix.length)),
    };
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
  clearCommittedQueryClause(input);
  return null;
}

function isDelimitedValueContext(context) {
  if (!context || context.stage !== "value") return false;
  const value = (context.partial || "").trim();
  if (!value) return false;
  return context.field !== "vector" && context.field !== "symbol";
}

function isClauseComplete(context) {
  if (!context) return false;
  if (context.stage !== "value") return false;
  const value = (context.partial || "").trim();
  if (!value) return false;
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
  if (context.field === "symbol") {
    return /^"(?:[^"\\]|\\.)+"$/.test(value);
  }
  if (context.field === "architecture") {
    return parseQueryDataset("architectures").some((item) => item.toLowerCase() === value.toLowerCase());
  }
  if (context.field === "username") {
    return value.length > 0;
  }
  if (context.field === "collection") {
    return parseQueryDataset("collections").some((item) => item.toLowerCase() === value.toLowerCase());
  }
  if (context.field === "expand") {
    return ["blocks", "instructions"].some((item) => item === value.toLowerCase());
  }
  if (context.field === "ascending" || context.field === "descending") {
    return QUERY_SORT_KEYS.some((item) => item === value.toLowerCase());
  }
  if (["symbols", "tags", "comments", "cyclomatic_complexity", "instructions", "blocks"].includes(context.field)) {
    return /^(>=|<=|>|<|=)?\s*\d+$/.test(value);
  }
  if (["average_instructions_per_block", "markov", "entropy", "chromosome.entropy"].includes(context.field)) {
    return /^(>=|<=|>|<|=)?\s*-?\d+(?:\.\d+)?$/.test(value);
  }
  if (context.field === "contiguous") {
    return /^(true|false)$/i.test(value);
  }
  if (context.field === "drop") {
    return ["lhs", "rhs"].some((item) => item === value.toLowerCase());
  }
  if (context.field === "corpus") {
    return false;
  }
  if (context.field === "address") {
    return /^(0x[0-9a-fA-F]+|\d+)$/.test(value);
  }
  return false;
}

function continuationSuggestions() {
  return queryCompletionCatalog();
}

function operatorSuggestions(context) {
  const items = continuationSuggestions().filter((item) => item.kind === "operator" && item.label !== "!");
  if ((context.depth || 0) > 0) {
    const close = continuationSuggestions().find((item) => item.label === ")");
    if (close) {
      items.push(close);
    }
  }
  return items;
}

function fieldSuggestions(context) {
  const open = continuationSuggestions().find((item) => item.label === "(");
  const negate = continuationSuggestions().find((item) => item.label === "!");
  const fields = continuationSuggestions().filter((item) => item.kind === "field");
  const items = [];
  items.push(...fields);
  if (open) {
    items.push(open);
  }
  if (
    negate &&
    context?.previousKind !== "term" &&
    context?.previousKind !== "group-close" &&
    context?.previousKind !== "not"
  ) {
    items.push(negate);
  }
  return items;
}

function fieldStageSuggestions(context) {
  return [...fieldSuggestions(context)];
}

function helpTextForClause(clause) {
  if (!clause || !clause.token) {
    return "Use explicit fields like sample:, embedding:, embeddings:, vector:, score:, limit:, corpus:, collection:, architecture:, username:, address:, date:, size:, symbol:, tag:, symbols:, tags:, comments:, cyclomatic_complexity:, average_instructions_per_block:, instructions:, blocks:, markov:, entropy:, contiguous:, and chromosome.entropy:, plus pipe utilities like expand:blocks, expand:instructions, and drop:rhs.";
  }
  if (clause.stage === "field") {
    return "Use explicit fields like sample:, embedding:, embeddings:, vector:, score:, limit:, corpus:, collection:, architecture:, username:, address:, date:, size:, symbol:, tag:, symbols:, tags:, comments:, cyclomatic_complexity:, average_instructions_per_block:, instructions:, blocks:, markov:, entropy:, contiguous:, and chromosome.entropy:, plus pipe utilities like expand:blocks, expand:instructions, and drop:rhs.";
  }
  if (clause.field === "vector") {
    return "vector expects a JSON array like vector:[0.1, -0.2, 0.3]";
  }
  if (clause.field === "sample") {
    return "sample expects 64 hexadecimal characters.";
  }
  if (clause.field === "embedding") {
    return "embedding expects 64 hexadecimal characters.";
  }
  if (clause.field === "embeddings") {
    return "embeddings accepts counts with optional comparisons like embeddings:>1k or embeddings:<=12m";
  }
  if (clause.field === "address") {
    return "address accepts decimal or hexadecimal values like address:0x401000";
  }
  if (clause.field === "date") {
    return "date accepts YYYY, YYYY-MM, YYYY-MM-DD, or comparisons like date:>=2026-03-01";
  }
  if (clause.field === "size") {
    return "size accepts bytes with optional comparisons like size:>64 or size:>=1mb";
  }
  if (clause.field === "tag") {
    return "Select or search for an exact entity tag value.";
  }
  if (clause.field === "symbols") {
    return "symbols accepts integer comparisons like symbols:>0 or symbols:>=2";
  }
  if (clause.field === "tags") {
    return "tags accepts integer comparisons like tags:>0 or tags:>=3";
  }
  if (clause.field === "comments") {
    return "comments accepts integer comparisons like comments:>0 or comments:>=5";
  }
  if (clause.field === "corpus") {
    return "Select or search for a corpus value.";
  }
  if (clause.field === "architecture") {
    return "Select an architecture like amd64, i386, or cil.";
  }
  if (clause.field === "username") {
    return "Filter by the exact indexing username, for example username:alice";
  }
  if (clause.field === "collection") {
    return "Select functions, blocks, or instructions.";
  }
  if (clause.field === "ascending" || clause.field === "descending") {
    return "Select a sort field like score, markov, entropy, or blocks.";
  }
  if (clause.field === "symbol") {
    return "symbol expects a quoted string like symbol:\"kernel32:CreateFileW\"";
  }
  return "Use |, ||, !, parentheses, and directional compares like -> and <- to combine fielded terms.";
}

function replaceActiveQueryClause(input, replacement) {
  const context = analyzeQueryContext(input);
  return replacementStateForContext(context, replacement);
}

function replacementStateForContext(context, replacement, cursorOffset = replacement.length) {
  const partialLength = (context.partial || "").length;
  const before = (context.value || "").slice(0, (context.cursor || 0) - partialLength);
  const after = (context.value || "").slice(context.cursor || 0);
  return {
    value: `${before}${replacement}${after}`,
    cursor: before.length + cursorOffset,
  };
}

function syncQueryInputCaret(input, cursor) {
  input.focus();
  input.setSelectionRange(cursor, cursor);
  if (typeof input.scrollLeft === "number" && typeof input.scrollWidth === "number") {
    input.scrollLeft = input.scrollWidth;
  }
  if (typeof window !== "undefined" && typeof window.requestAnimationFrame === "function") {
    window.requestAnimationFrame(() => {
      input.focus();
      input.setSelectionRange(cursor, cursor);
      if (typeof input.scrollLeft === "number" && typeof input.scrollWidth === "number") {
        input.scrollLeft = input.scrollWidth;
      }
    });
  }
}

function applyReplacementState(input, state) {
  clearCommittedQueryClause(input);
  input.value = state.value;
  syncQueryInputCaret(input, state.cursor);
  scheduleQueryAssistantUpdate();
}

function applyQuerySuggestion(item) {
  const input = getQueryInput();
  if (!input) return;
  const context = analyzeQueryContext(input);
  const replacement = item.insert || item.label || "";
  const current = (context.partial || "").trim();
  if (item.kind === "group" && replacement === "(") {
    const nextChar = (context.value || "").slice(context.cursor || 0, (context.cursor || 0) + 1);
    const state = nextChar === ")"
      ? replacementStateForContext(context, "(", 1)
      : replacementStateForContext(context, "(  )", 2);
    applyReplacementState(input, state);
    return;
  }
  if (item.kind === "group" && current === replacement.trim()) {
    const cursor = input.selectionStart ?? input.value.length;
    if (cursor >= input.value.length || !/\s/.test(input.value[cursor] || "")) {
      input.value = `${input.value.slice(0, cursor)} ${input.value.slice(cursor)}`;
      syncQueryInputCaret(input, cursor + 1);
    }
    scheduleQueryAssistantUpdate();
    return;
  }
  applyReplacementState(input, replaceActiveQueryClause(input, replacement));
  if (item.kind === "value" && ["corpus", "tag"].includes(context.field)) {
    setCommittedQueryClause(input, {
      field: context.field,
      value: replacement.trim(),
    });
    scheduleQueryAssistantUpdate();
  }
}

function hideQueryAssistantMenu() {
  const assistant = getQueryAssistant();
  const menu = getQueryAssistantMenu();
  if (!menu || !assistant) return;
  querySuggestionItems = [];
  querySuggestionIndex = 0;
  assistant.hidden = true;
  assistant.parentElement?.classList.remove("assistant-open");
  menu.remove();
}

function renderQuerySuggestions(items) {
  const assistant = getQueryAssistant();
  const menu = ensureQueryAssistantMenu();
  if (!menu || !assistant) return;
  if (!items.length) {
    hideQueryAssistantMenu();
    return;
  }
  querySuggestionItems = items.slice(0, 8);
  querySuggestionIndex = 0;
  assistant.hidden = false;
  assistant.parentElement?.classList.add("assistant-open");
  menu.hidden = false;
  menu.innerHTML = "";
  querySuggestionItems.forEach((item, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "query-suggestion";
    if (index === querySuggestionIndex) button.classList.add("active");
    const label = document.createElement("span");
    label.className = "query-suggestion-label";
    label.textContent = item.label;
    button.appendChild(label);
    const metaParts = [item.usage, item.description].filter(Boolean);
    if (metaParts.length > 0) {
      const meta = document.createElement("span");
      meta.className = "query-suggestion-meta";
      meta.textContent = metaParts.join("  ");
      button.appendChild(meta);
    }
    button.onmouseenter = () => {
      querySuggestionIndex = index;
      refreshActiveQuerySuggestion();
    };
    button.onfocus = () => {
      querySuggestionIndex = index;
      refreshActiveQuerySuggestion();
    };
    button.onclick = () => applyQuerySuggestion(item);
    menu.appendChild(button);
  });
}

function refreshActiveQuerySuggestion() {
  const menu = getQueryAssistantMenu();
  if (!menu) return;
  Array.from(menu.querySelectorAll(".query-suggestion")).forEach((button, index) => {
    button.classList.toggle("active", index === querySuggestionIndex);
    if (index === querySuggestionIndex) {
      button.scrollIntoView({ block: "nearest" });
    }
  });
}

function filterQuerySuggestions(items, query) {
  const needle = (query || "").trim();
  return items
    .map((item, index) => ({
      item,
      index,
      score: needle ? fuzzyMenuScore(needle, item.label || "") : 0,
    }))
    .filter((entry) => !needle || entry.score >= 0)
    .sort((lhs, rhs) => {
      if (!needle) return lhs.index - rhs.index;
      if (rhs.score !== lhs.score) return rhs.score - lhs.score;
      return lhs.index - rhs.index;
    })
    .map((entry) => entry.item);
}

function suggestionItemsForValueField(field, partial) {
  if (field === "architecture") {
    return Promise.resolve(
      filterQuerySuggestions(
        parseQueryDataset("architectures").map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field === "collection") {
    return Promise.resolve(
      filterQuerySuggestions(
        parseQueryDataset("collections").map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field === "drop") {
    return Promise.resolve(
      filterQuerySuggestions(
        ["lhs", "rhs"].map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field === "contiguous") {
    return Promise.resolve(
      filterQuerySuggestions(
        ["true", "false"].map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field === "expand") {
    return Promise.resolve(
      filterQuerySuggestions(
        ["blocks", "instructions"].map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field === "ascending" || field === "descending") {
    return Promise.resolve(
      filterQuerySuggestions(
        QUERY_SORT_KEYS.map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
        partial
      )
    );
  }
  if (field === "tag") {
    if (tagSuggestionAbort) tagSuggestionAbort.abort();
    tagSuggestionAbort = new AbortController();
    const url = `/api/v1/tags/search?q=${encodeURIComponent(partial || "")}`;
    return fetch(url, { signal: tagSuggestionAbort.signal })
      .then((response) => response.json())
      .then((payload) =>
        filterQuerySuggestions(
          (Array.isArray(payload?.tags) ? payload.tags : []).map((item) => {
            const value = metadataItemName(item);
            return {
              label: value,
              insert: value,
              kind: "value",
            };
          }),
          partial
        )
      )
      .catch(() => []);
  }
  if (field !== "corpus") {
    return Promise.resolve([]);
  }
  if (corpusSuggestionAbort) corpusSuggestionAbort.abort();
  corpusSuggestionAbort = new AbortController();
  const url = `/api/v1/corpora?q=${encodeURIComponent(partial || "")}`;
  return fetch(url, { signal: corpusSuggestionAbort.signal })
    .then((response) => response.json())
    .then((payload) =>
      filterQuerySuggestions(
        (Array.isArray(payload?.corpora) ? payload.corpora : []).map((item) => {
          const value = metadataItemName(item);
          return {
          label: value,
          insert: value,
          kind: "value",
        };
        }),
        partial
      )
    )
    .catch(() => []);
}

async function updateQueryAssistant() {
  const assistant = getQueryAssistant();
  const input = getQueryInput();
  if (!assistant || !input) return;
  if (document.activeElement !== input) {
    hideQueryAssistantMenu();
    return;
  }
  assistant.hidden = false;
  const continuation = continuationStateAfterSpace(input);
  if (continuation) {
    if (continuation.kind === "operator") {
      renderQuerySuggestions(operatorSuggestions(continuation.context));
      return;
    }
    if (continuation.kind === "field") {
      renderQuerySuggestions(fieldStageSuggestions(continuation.context));
      return;
    }
    if (continuation.kind === "value") {
      const items = await suggestionItemsForValueField(
        continuation.context.field,
        continuation.context.partial
      );
      renderQuerySuggestions(items);
      return;
    }
    hideQueryAssistantMenu();
    return;
  }

  const clause = analyzeQueryContext(input);
  const token = (clause.token || "").trim();
  if (clause.stage === "complete") {
    hideQueryAssistantMenu();
    return;
  }

  if (!token && clause.stage === "field") {
    if (clause.previousKind === "term" || clause.previousKind === "group-close") {
      renderQuerySuggestions(operatorSuggestions(clause));
      return;
    }
    renderQuerySuggestions(fieldStageSuggestions(clause));
    return;
  }

  if (clause.stage === "value") {
    if (isClauseComplete(clause)) {
      hideQueryAssistantMenu();
      return;
    }
    if (["corpus", "tag", "architecture", "collection", "drop", "contiguous", "expand", "ascending", "descending"].includes(clause.field)) {
      const items = await suggestionItemsForValueField(clause.field, clause.partial);
      renderQuerySuggestions(items);
      return;
    }
    querySuggestionItems = [];
    querySuggestionIndex = 0;
    const menu = getQueryAssistantMenu();
    if (menu) {
      menu.remove();
    }
    return;
  }

  if (clause.stage === "none") {
    hideQueryAssistantMenu();
    return;
  }
  const baseSuggestions =
    clause.stage === "operator"
      ? operatorSuggestions(clause)
      : fieldStageSuggestions(clause);
  const suggestions = filterQuerySuggestions(baseSuggestions, clause.partial);
  renderQuerySuggestions(suggestions);
}

function handleQueryInputKeydown(event) {
  const menu = getQueryAssistantMenu();
  const hasSuggestions = !!menu && !menu.hidden && querySuggestionItems.length > 0;
  if (event.key === "ArrowDown" && hasSuggestions) {
    event.preventDefault();
    querySuggestionIndex = (querySuggestionIndex + 1) % querySuggestionItems.length;
    refreshActiveQuerySuggestion();
    return;
  }
  if (event.key === "ArrowUp" && hasSuggestions) {
    event.preventDefault();
    querySuggestionIndex =
      (querySuggestionIndex - 1 + querySuggestionItems.length) % querySuggestionItems.length;
    refreshActiveQuerySuggestion();
    return;
  }
  if (event.key === "Enter" && hasSuggestions) {
    event.preventDefault();
    applyQuerySuggestion(querySuggestionItems[querySuggestionIndex]);
  }
}

function handleQueryInputKeyup(event) {
  if (["ArrowDown", "ArrowUp", "Enter"].includes(event.key)) {
    return;
  }
  scheduleQueryAssistantUpdate();
}
