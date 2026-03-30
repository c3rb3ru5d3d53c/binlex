const QUERY_FIELD_SUGGESTIONS = [
  { label: "sha256:", insert: "sha256:", kind: "field", usage: "sha256:<64-hex-hash>", description: "Exact lookup by sample SHA-256" },
  { label: "embedding:", insert: "embedding:", kind: "field", usage: "embedding:<64-hex-hash>", description: "Nearest-neighbor search from an existing embedding" },
  { label: "embeddings:", insert: "embeddings:", kind: "field", usage: "embeddings:>1k", description: "Filter by embedding count with comparisons" },
  { label: "vector:", insert: "vector:", kind: "field", usage: "vector:[0.1, -0.2, 0.3]", description: "Nearest-neighbor search from an explicit vector" },
  { label: "corpus:", insert: "corpus:", kind: "field", usage: "corpus:<name>", description: "Filter by corpus name" },
  { label: "collection:", insert: "collection:", kind: "field", usage: "collection:function", description: "Filter by indexed entity type" },
  { label: "architecture:", insert: "architecture:", kind: "field", usage: "architecture:amd64", description: "Filter by architecture" },
  { label: "address:", insert: "address:", kind: "field", usage: "address:0x401000", description: "Filter by exact address" },
  { label: "date:", insert: "date:", kind: "field", usage: "date:>=2026-03-01", description: "Filter by indexed UTC date or date range bounds" },
  { label: "size:", insert: "size:", kind: "field", usage: "size:>1mb", description: "Filter by instruction, block, or function byte size" },
  { label: "symbol:", insert: "symbol:", kind: "field", usage: "symbol:\"kernel32:CreateFileW\"", description: "Filter by exact quoted symbol name" },
  { label: "AND", insert: "AND ", kind: "operator", usage: "term AND term", description: "Combine clauses that must all match" },
  { label: "OR", insert: "OR ", kind: "operator", usage: "term OR term", description: "Match either clause" },
  { label: "NOT", insert: "NOT ", kind: "operator", usage: "NOT term", description: "Negate the next clause" },
  { label: "(", insert: "(", kind: "group", usage: "( term )", description: "Start a grouped sub-expression" },
  { label: ")", insert: ")", kind: "group", usage: "( term )", description: "Close the current grouped sub-expression" },
];

let corpusSuggestionAbort = null;
let querySuggestionItems = [];
let querySuggestionIndex = 0;
const THEME_STORAGE_KEY = "binlex-web-theme";
let activeRowActionTrigger = null;
const QUERY_COMMIT_DATASET_KEY = "committedQueryClause";
let queryAssistantUpdateHandle = null;

function getSearchForm() {
  return document.getElementById("search-form");
}

function getQueryInput() {
  return document.getElementById("query-input");
}

function clearCommittedQueryClause(input) {
  if (input?.dataset) {
    delete input.dataset[QUERY_COMMIT_DATASET_KEY];
  }
}

function setCommittedQueryClause(input, clause) {
  if (!input?.dataset) return;
  input.dataset[QUERY_COMMIT_DATASET_KEY] = JSON.stringify(clause);
}

function getCommittedQueryClause(input) {
  if (!input?.dataset?.[QUERY_COMMIT_DATASET_KEY]) return null;
  try {
    return JSON.parse(input.dataset[QUERY_COMMIT_DATASET_KEY]);
  } catch (_) {
    clearCommittedQueryClause(input);
    return null;
  }
}

function applyTheme(theme) {
  const normalized = theme === "light" ? "light" : "dark";
  document.body?.setAttribute("data-theme", normalized);
  document.getElementById("theme-dark")?.classList.toggle("active", normalized === "dark");
  document.getElementById("theme-light")?.classList.toggle("active", normalized === "light");
}

function setTheme(theme) {
  applyTheme(theme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme === "light" ? "light" : "dark");
  } catch (_) {}
}

function getQueryAssistantMenu() {
  return document.getElementById("query-assistant-menu");
}

function getQueryAssistant() {
  return document.getElementById("query-assistant");
}

function getTopKPopover() {
  return document.getElementById("top-k-popover");
}

function getTopKInput() {
  return document.getElementById("top-k-input");
}

function getPageInput() {
  return document.getElementById("page-input");
}

function scheduleQueryAssistantUpdate() {
  if (queryAssistantUpdateHandle !== null) {
    window.cancelAnimationFrame(queryAssistantUpdateHandle);
  }
  queryAssistantUpdateHandle = window.requestAnimationFrame(() => {
    queryAssistantUpdateHandle = null;
    updateQueryAssistant();
  });
}

function ensureQueryAssistantMenu() {
  const assistant = getQueryAssistant();
  if (!assistant) return null;
  let menu = getQueryAssistantMenu();
  if (menu) return menu;
  menu = document.createElement("div");
  menu.className = "query-assistant-menu";
  menu.id = "query-assistant-menu";
  menu.hidden = true;
  assistant.appendChild(menu);
  return menu;
}

function updateTopKValue(value) {
  const normalized = String(Math.max(1, Math.min(64, Number(value || 16) || 16)));
  const input = getTopKInput();
  const label = document.getElementById("top-k-label");
  const display = document.getElementById("top-k-value");
  const slider = document.getElementById("top-k-slider");
  if (input) input.value = normalized;
  if (label) label.textContent = normalized;
  if (display) display.textContent = normalized;
  if (slider && slider.value !== normalized) slider.value = normalized;
  syncFormState("upload-form");
}

function toggleTopKPopover() {
  const popover = getTopKPopover();
  const root = document.querySelector(".top-k-control");
  if (!popover) return;
  const next = popover.hidden;
  closeTopKPopover();
  if (!next) return;
  if (root) root.classList.add("open");
  popover.hidden = false;
}

function closeTopKPopover() {
  const popover = getTopKPopover();
  const root = document.querySelector(".top-k-control");
  if (root) root.classList.remove("open");
  if (popover) popover.hidden = true;
}

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
      const opStart = index;
      while (index < cursor && /[A-Za-z]/.test(value[index])) {
        index += 1;
      }
      const op = value.slice(opStart, index).toUpperCase();
      if (index >= cursor) {
        return {
          stage: "operator",
          partial: op,
          token: op,
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      if (!/\s/.test(value[index])) {
        return {
          stage: "operator",
          partial: op,
          token: op,
          previousKind,
          depth,
          value,
          cursor,
        };
      }
      if (["AND", "OR", "NOT"].includes(op)) {
        previousKind = "operator";
        continue;
      }
      return {
        stage: "operator",
        partial: op,
        token: op,
        previousKind,
        depth,
        value,
        cursor,
      };
    }

    const fieldStart = index;
    while (index < cursor && /[A-Za-z0-9_]/.test(value[index])) {
      index += 1;
    }
    const field = value.slice(fieldStart, index).toLowerCase();
    if (
      field === "not" &&
      index < cursor &&
      (/\s/.test(value[index]) || value[index] === "(")
    ) {
      previousKind = "operator";
      continue;
    }
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
      while (index < cursor && !/\s|\(|\)/.test(value[index])) {
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
  if (/\bNOT\s+$/i.test(prefix)) {
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
    const token = (context.token || "").toUpperCase();
    if (["AND", "OR", "NOT"].includes(token)) {
      return {
        kind: "field",
        context: {
          ...context,
          stage: "field",
          partial: "",
          token: "",
          previousKind: token === "NOT" ? "not" : "operator",
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
    if (["corpus", "architecture", "collection"].includes(context.field)) {
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
  if (context.field === "sha256") return /^[0-9a-fA-F]{64}$/.test(value);
  if (context.field === "embedding") return /^[0-9a-fA-F]{64}$/.test(value);
  if (context.field === "embeddings") return /^(>=|<=|>|<|=)?\s*\d+(?:\.\d+)?\s*[kKmMbB]?$/.test(value);
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
  if (context.field === "collection") {
    return parseQueryDataset("collections").some((item) => item.toLowerCase() === value.toLowerCase());
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
  const items = continuationSuggestions().filter((item) => item.kind === "operator");
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
  const not = continuationSuggestions().find((item) => item.label === "NOT");
  const fields = continuationSuggestions().filter((item) => item.kind === "field");
  const items = [];
  items.push(...fields);
  if (open) {
    items.push(open);
  }
  if (
    not &&
    context?.previousKind !== "term" &&
    context?.previousKind !== "group-close" &&
    context?.previousKind !== "not"
  ) {
    items.push(not);
  }
  return items;
}

function helpTextForClause(clause) {
  if (!clause || !clause.token) {
    return "Use explicit fields like sha256:, embedding:, embeddings:, vector:, corpus:, collection:, architecture:, address:, date:, size:, and symbol:.";
  }
  if (clause.stage === "field") {
    return "Use explicit fields like sha256:, embedding:, embeddings:, vector:, corpus:, collection:, architecture:, address:, date:, size:, and symbol:.";
  }
  if (clause.field === "vector") {
    return "vector expects a JSON array like vector:[0.1, -0.2, 0.3]";
  }
  if (clause.field === "sha256") {
    return "sha256 expects 64 hexadecimal characters.";
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
  if (clause.field === "corpus") {
    return "Select or search for a corpus value.";
  }
  if (clause.field === "architecture") {
    return "Select an architecture like amd64, i386, or cil.";
  }
  if (clause.field === "collection") {
    return "Select function, block, or instruction.";
  }
  if (clause.field === "symbol") {
    return "symbol expects a quoted string like symbol:\"kernel32:CreateFileW\"";
  }
  return "Use AND, OR, NOT, and parentheses to combine fielded terms.";
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
  if (item.kind === "value" && context.field === "corpus") {
    setCommittedQueryClause(input, {
      field: "corpus",
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
  const normalizedNeedle = needle.toUpperCase();
  return items
    .map((item, index) => ({
      item,
      index,
      score: needle
        ? (
            normalizedNeedle === "NOT" &&
            item.kind === "operator" &&
            item.label === "NOT"
              ? -1
              : fuzzyMenuScore(needle, item.label || "")
          )
        : 0,
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
  if (field !== "corpus") {
    return Promise.resolve([]);
  }
  if (corpusSuggestionAbort) corpusSuggestionAbort.abort();
  corpusSuggestionAbort = new AbortController();
  const url = `/api/corpora?q=${encodeURIComponent(partial || "")}`;
  return fetch(url, { signal: corpusSuggestionAbort.signal })
    .then((response) => response.json())
    .then((items) =>
      filterQuerySuggestions(
        items.map((value) => ({
          label: value,
          insert: value,
          kind: "value",
        })),
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
      renderQuerySuggestions(fieldSuggestions(continuation.context));
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
    renderQuerySuggestions(fieldSuggestions(clause));
    return;
  }

  if (clause.stage === "value") {
    if (isClauseComplete(clause)) {
      hideQueryAssistantMenu();
      return;
    }
    if (["corpus", "architecture", "collection"].includes(clause.field)) {
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
      : fieldSuggestions(clause);
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

function parseRowActions(shell) {
  try {
    return JSON.parse(shell?.dataset?.actions || "[]");
  } catch (_) {
    return [];
  }
}

function getRowActionItems(shell) {
  const tree = parseRowActions(shell);
  const path = (shell?.dataset?.path || "").split("/").filter(Boolean);
  let items = tree;
  for (const label of path) {
    const next = items.find((item) => item.label === label);
    if (!next || !Array.isArray(next.children)) return [];
    items = next.children;
  }
  return items;
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

function getRowActionPopover() {
  return document.getElementById("row-action-popover");
}

function renderRowActionMenu(shell) {
  if (!shell) return;
  const items = getRowActionItems(shell);
  const query = shell.querySelector(".menu-search")?.value?.trim() || "";
  const breadcrumb = shell.querySelector(".row-actions-breadcrumb");
  const back = shell.querySelector(".row-actions-back");
  const container = shell.querySelector(".row-action-options");
  if (!container || !breadcrumb || !back) return;

  const path = (shell.dataset.path || "").split("/").filter(Boolean);
  breadcrumb.textContent = ["Action", ...path].join(" / ");
  back.hidden = path.length === 0;

  const ranked = items
    .map((item, index) => ({
      item,
      index,
      score: query ? fuzzyMenuScore(query, item.label || "") : 0,
    }))
    .filter((entry) => !query || entry.score >= 0)
    .sort((lhs, rhs) => {
      if (!query) return lhs.index - rhs.index;
      if (rhs.score !== lhs.score) return rhs.score - lhs.score;
      return lhs.index - rhs.index;
    });

  container.innerHTML = "";
  ranked.forEach(({ item }) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "row-action-button";
    button.textContent = item.label || "";
    if (Array.isArray(item.children)) {
      button.classList.add("branch");
      button.onclick = (event) => {
        event.preventDefault();
        event.stopPropagation();
        navigateRowActions(button, item.label);
      };
    } else {
      button.onclick = async (event) => {
        event.preventDefault();
        event.stopPropagation();
        await runRowAction(button, item);
      };
    }
    container.appendChild(button);
  });
  if (shell.classList.contains("row-actions-popover")) {
    positionRowActionMenu(activeRowActionTrigger, shell);
  }
}

function positionRowActionMenu(trigger, menu) {
  if (!(trigger instanceof HTMLElement) || !(menu instanceof HTMLElement) || menu.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
  const menuRect = menu.getBoundingClientRect();
  const left = Math.max(
    12,
    Math.min(triggerRect.right - menuRect.width, viewportWidth - menuRect.width - 12)
  );
  let top = triggerRect.bottom + 6;
  if (top + menuRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - menuRect.height - 6);
  }
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
}

function closeRowActionMenu() {
  const popover = getRowActionPopover();
  if (popover) {
    popover.hidden = true;
    popover.dataset.actions = "[]";
    popover.dataset.path = "";
    const search = popover.querySelector(".menu-search");
    if (search) search.value = "";
  }
  if (activeRowActionTrigger instanceof HTMLElement) {
    activeRowActionTrigger.classList.remove("active");
  }
  activeRowActionTrigger = null;
}

function toggleRowActionMenu(button) {
  const popover = getRowActionPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  if (activeRowActionTrigger === button && !popover.hidden) {
    closeRowActionMenu();
    return;
  }
  if (activeRowActionTrigger instanceof HTMLElement) {
    activeRowActionTrigger.classList.remove("active");
  }
  activeRowActionTrigger = button;
  activeRowActionTrigger.classList.add("active");
  popover.dataset.actions = button.dataset.actions || "[]";
  popover.dataset.path = "";
  popover.hidden = false;
  const search = popover.querySelector(".menu-search");
  if (search) search.value = "";
  renderRowActionMenu(popover);
  positionRowActionMenu(button, popover);
  if (search instanceof HTMLElement) {
    setTimeout(() => search.focus(), 0);
  }
}

function navigateRowActions(button, label = null) {
  const shell = button.closest(".row-actions-popover");
  if (!shell) return;
  const path = (shell.dataset.path || "").split("/").filter(Boolean);
  if (label) {
    path.push(label);
  } else {
    path.pop();
  }
  shell.dataset.path = path.join("/");
  const search = shell.querySelector(".menu-search");
  if (search) search.value = "";
  renderRowActionMenu(shell);
}

async function runRowAction(button, item) {
  if (item?.action === "download_text") {
    const blob = new Blob([item?.payload || ""], {
      type: item?.content_type || "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = item?.filename || "download.txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    return;
  }
  if ((item?.action || "copy") === "download" || item?.action === "navigate") {
    if (item?.url) {
      closeRowActionMenu();
      window.location.assign(item.url);
    }
    return;
  }
  const payload = item?.payload || "";
  try {
    await navigator.clipboard.writeText(payload);
    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("action-feedback");
    }, 1200);
  } catch (_) {
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = "Copy";
    }, 1200);
  }
}

function dismissNotice(button) {
  button.closest(".notice")?.remove();
}

if (typeof document !== "undefined") {
  document.addEventListener("click", (event) => {
    const popover = getRowActionPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeRowActionTrigger && activeRowActionTrigger.contains(event.target)) return;
    closeRowActionMenu();
  });
}

if (typeof window !== "undefined") {
  window.addEventListener("resize", () => {
    const popover = getRowActionPopover();
    if (popover && !popover.hidden) {
      positionRowActionMenu(activeRowActionTrigger, popover);
    }
  });

  window.addEventListener("scroll", (event) => {
    const popover = getRowActionPopover();
    if (popover && !popover.hidden && popover.contains(event.target)) {
      return;
    }
    closeRowActionMenu();
  }, true);
}

function filterOptions(input, group) {
  const needle = input.value.toLowerCase();
  const root = input.closest('[data-group-root]');
  if (!root) return;
  if (root.dataset.remote === "true") {
    fetchRemoteOptions(root, group, needle);
    return;
  }
  root.querySelectorAll(`[data-group="${group}"]`).forEach((item) => {
    const text = item.innerText.toLowerCase();
    const visible = text.includes(needle);
    item.dataset.matchesSearch = visible ? "1" : "0";
    if (!root.querySelector('.menu-options').classList.contains('selected-only')) {
      item.style.display = visible ? "" : "none";
    }
  });
  applyVisibleLimit(root.querySelector('.menu-options'));
}

function clearGroup(button, group, defaults) {
  const root = button.closest('[data-group-root]');
  if (root) {
    const options = root.querySelector('.menu-options');
    root.querySelectorAll(`input[type="checkbox"][name="${group}"]`).forEach((item) => {
      item.checked = false;
    });
    if (options) {
      options.classList.remove('selected-only');
      if (root.dataset.remote === "true") {
        options.innerHTML = "";
      }
    }
    const selectedButton = Array.from(root.querySelectorAll('.menu-actions button'))
      .find((button) => button.textContent === 'View all');
    if (selectedButton) {
      selectedButton.textContent = 'View selected';
    }
    defaults.forEach((value) => {
      ensureCheckboxOption(root, group, value);
      const input = root.querySelector(`input[type="checkbox"][name="${group}"][value="${CSS.escape(value)}"]`);
      if (input) {
        input.checked = true;
      }
    });
    root.querySelectorAll(`[data-group="${group}"]`).forEach((item) => {
      const input = item.querySelector('input');
      const visible = !input || defaults.includes(input.value) || item.dataset.matchesSearch !== "0";
      item.style.display = visible ? "" : "none";
      item.classList.toggle('selected-match', !!input?.checked);
    });
    applyVisibleLimit(options);
  }
  syncFilterForms();
}

function toggleSelectedView(button, group) {
  const root = button.closest('[data-group-root]');
  if (!root) return;
  const options = root.querySelector('.menu-options');
  const selectedOnly = !options.classList.contains('selected-only');
  options.classList.toggle('selected-only', selectedOnly);
  root.querySelectorAll(`[data-group="${group}"]`).forEach((item) => {
    const checked = item.querySelector('input')?.checked;
    item.classList.toggle('selected-match', !!checked);
    if (selectedOnly) {
      item.style.display = checked ? "" : "none";
    } else {
      const matches = item.dataset.matchesSearch !== "0";
      item.style.display = matches ? "" : "none";
    }
  });
  applyVisibleLimit(options);
  button.textContent = selectedOnly ? "View all" : "View selected";
}

function syncFormState(formId) {
  const form = document.getElementById(formId);
  if (!form) return;
  const searchQuery = document.querySelector('#search-form input[name="query"]');
  const uploadQuery = document.querySelector('#upload-form input[name="query"]');
  if (searchQuery && uploadQuery) uploadQuery.value = searchQuery.value;
  const searchTopK = document.querySelector('#search-form input[name="top_k"]');
  const uploadTopK = document.querySelector('#upload-form input[name="top_k"]');
  if (searchTopK && uploadTopK) uploadTopK.value = searchTopK.value;
  const searchPage = document.querySelector('#search-form input[name="page"]');
  const uploadPage = document.querySelector('#upload-form input[name="page"]');
  if (searchPage && uploadPage) uploadPage.value = searchPage.value;
}

function syncFilterForms() {
  syncFormState("search-form");
  syncFormState("upload-form");
}

function syncUploadState() {
  syncFormState("upload-form");
}

function syncSearchState() {
  const pageInput = getPageInput();
  if (pageInput) pageInput.value = "1";
  syncFormState("search-form");
}

function openUploadModal() {
  const modal = document.getElementById("upload-modal");
  if (!modal) return;
  modal.hidden = false;
  installDropzone();
  updateUploadModalState();
}

function closeUploadModal() {
  const modal = document.getElementById("upload-modal");
  if (!modal) return;
  modal.hidden = true;
}

function openUploadStatusModal(state, payload = {}) {
  const modal = document.getElementById("upload-status-modal");
  const icon = document.getElementById("upload-status-icon");
  const title = document.getElementById("upload-status-title");
  const text = document.getElementById("upload-status-text");
  const extra = document.getElementById("upload-status-extra");
  const closeButton = document.getElementById("upload-status-close");
  if (!modal || !icon || !title || !text || !extra || !closeButton) return;

  icon.classList.remove("uploading", "success", "failed");
  icon.classList.add(state);
  modal.hidden = false;
  extra.innerHTML = "";
  closeButton.hidden = state === "uploading";

  if (state === "uploading") {
    title.textContent = "Uploading Sample";
    text.textContent = "Binlex Web is uploading and processing the sample.";
  } else if (state === "success") {
    title.textContent = "Upload Successful";
    text.textContent = "The sample upload completed successfully. Results may take a moment to appear.";
    if (payload.sha256) {
      extra.innerHTML = `<div class="upload-status-sha"><span>SHA256</span><div class="upload-status-sha-row"><code id="upload-status-sha-value">${escapeHtml(payload.sha256)}</code><button type="button" class="secondary" id="upload-status-copy" onclick="copyUploadSha(this)">Copy</button></div></div>`;
    }
  } else {
    title.textContent = "Upload Failed";
    text.textContent = payload.error || "The upload failed.";
  }
}

function closeUploadStatusModal() {
  const modal = document.getElementById("upload-status-modal");
  if (!modal) return;
  modal.hidden = true;
}

async function copyUploadSha(button) {
  const code = document.getElementById("upload-status-sha-value");
  const payload = code?.textContent || "";
  if (!payload) return;
  try {
    await navigator.clipboard.writeText(payload);
    const previous = button.textContent;
    button.textContent = "Copied";
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  } catch (_) {
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = "Copy";
    }, 1200);
  }
}

function escapeHtml(value) {
  return String(value || "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function setUploadedSha256State(sha256) {
  document.querySelectorAll('input[name="uploaded_sha256"]').forEach((item) => item.remove());
  if (!sha256) return;
  ["search-form", "upload-form"].forEach((id) => {
    const form = document.getElementById(id);
    if (!form) return;
    const hidden = document.createElement("input");
    hidden.type = "hidden";
    hidden.name = "uploaded_sha256";
    hidden.value = sha256;
    form.appendChild(hidden);
  });
}

function mirrorUploadFileList(files) {
  const target = document.getElementById("upload-input");
  const source = document.getElementById("upload-file-picker");
  const label = document.getElementById("upload-file-name");
  if (!target || !source || !files || !files.length) return;
  const dataTransfer = new DataTransfer();
  dataTransfer.items.add(files[0]);
  target.files = dataTransfer.files;
  source.files = dataTransfer.files;
  if (label) label.textContent = files[0].name;
  updateUploadModalState();
}

function updateUploadModalState() {
  const format = document.querySelector('input[name="upload-format"]:checked')?.value || "Auto";
  const shellcode = format === "Shellcode";
  setSingleOptionVisible("upload-architecture", "Auto", !shellcode);
  if (!shellcode) {
    setSingleSelectValue("upload-architecture", "Auto");
  } else if ((document.querySelector('input[name="upload-architecture"]:checked')?.value || "Auto") === "Auto") {
    clearSingleSelect("upload-architecture", "Architecture: Select");
  }
  setSingleSelectDisabled("upload-architecture", !shellcode);
  const arch = document.querySelector('input[name="upload-architecture"]:checked')?.value || "";
  const file = document.getElementById("upload-file-picker")?.files?.length || 0;
  const submit = document.getElementById("upload-submit");
  const tip = document.getElementById("upload-modal-tip");
  if (tip) tip.textContent = "";
  if (submit) {
    submit.disabled = file === 0 || (shellcode && !arch);
  }
}

async function submitUploadModal() {
  syncUploadState();
  const format = document.querySelector('input[name="upload-format"]:checked')?.value || "Auto";
  const arch = document.querySelector('input[name="upload-architecture"]:checked')?.value || "Auto";
  const formatTarget = document.getElementById("upload-format");
  const archTarget = document.getElementById("upload-architecture-override");
  if (formatTarget) formatTarget.value = format === "Auto" ? "" : format;
  if (archTarget) archTarget.value = arch === "Auto" ? "" : arch;
  const form = document.getElementById("upload-form");
  if (!(form instanceof HTMLFormElement)) return;
  const submit = document.getElementById("upload-submit");
  if (submit) submit.disabled = true;
  closeUploadModal();
  openUploadStatusModal("uploading");
  try {
    const response = await fetch("/upload", {
      method: "POST",
      body: new FormData(form),
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      openUploadStatusModal("failed", { error: payload.error || "The upload failed." });
      return;
    }
    setUploadedSha256State(payload.sha256 || "");
    openUploadStatusModal("success", { sha256: payload.sha256 || "" });
  } catch (_) {
    openUploadStatusModal("failed", { error: "The upload failed." });
  } finally {
    if (submit) submit.disabled = false;
  }
}

function filterSingleOptions(input, group) {
  const needle = input.value.toLowerCase();
  const root = input.closest('[data-single-select]');
  if (!root) return;
  root.querySelectorAll(`[data-single-group="${group}"]`).forEach((item) => {
    const text = item.innerText.toLowerCase();
    item.style.display = text.includes(needle) ? "" : "none";
  });
}

function selectSingleOption(group, value) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  if (root.classList.contains("disabled")) return;
  setSingleSelectSummary(group, value);
  root.open = false;
  updateUploadModalState();
}

function setSingleSelectValue(group, value) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  root.querySelectorAll(`input[name="${group}"]`).forEach((item) => {
    item.checked = item.value === value;
  });
  setSingleSelectSummary(group, value);
}

function setSingleSelectDisabled(group, disabled) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  root.classList.toggle("disabled", disabled);
  if (disabled) {
    root.open = false;
  }
}

function clearSingleSelect(group, summaryText) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  root.querySelectorAll(`input[name="${group}"]`).forEach((item) => {
    item.checked = false;
  });
  const summary = root.querySelector('summary');
  if (summary) {
    summary.textContent = summaryText;
  }
}

function setSingleSelectSummary(group, value) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  const summary = root.querySelector('summary');
  if (!summary) return;
  const label = group === "upload-format" ? "Format" : "Architecture";
  summary.textContent = `${label}: ${value}`;
}

function setSingleOptionVisible(group, value, visible) {
  const root = document.querySelector(`[data-single-select="${group}"]`);
  if (!root) return;
  const item = root.querySelector(`[data-option="${CSS.escape(value)}"]`);
  if (!item) return;
  item.style.display = visible ? "" : "none";
}

function installDropzone() {
  const input = document.getElementById("upload-file-picker");
  const zone = document.getElementById("upload-dropzone");
  if (!input || !zone || zone.dataset.installed === "1") return;
  zone.dataset.installed = "1";
  input.addEventListener("change", () => mirrorUploadFileList(input.files));
  ["dragenter", "dragover"].forEach((eventName) => {
    zone.addEventListener(eventName, (event) => {
      event.preventDefault();
      zone.classList.add("dragging");
    });
  });
  ["dragleave", "drop"].forEach((eventName) => {
    zone.addEventListener(eventName, (event) => {
      event.preventDefault();
      zone.classList.remove("dragging");
    });
  });
  zone.addEventListener("drop", (event) => {
    const files = event.dataTransfer?.files;
    if (files && files.length) {
      mirrorUploadFileList(files);
    }
  });
}

if (typeof document !== "undefined") {
  document.addEventListener("click", (event) => {
    const assistant = document.getElementById("query-assistant");
    const input = getQueryInput();
    if (assistant && !assistant.contains(event.target) && input && event.target !== input) {
      hideQueryAssistantMenu();
    }
    const topK = document.querySelector(".top-k-control");
    if (topK && !topK.contains(event.target)) {
      closeTopKPopover();
    }
  });

  document.addEventListener("DOMContentLoaded", () => {
    let savedTheme = "dark";
    try {
      savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || "dark";
    } catch (_) {}
    applyTheme(savedTheme);
    const input = getQueryInput();
    window.setTimeout(() => {
      if (input && document.activeElement === input) {
        input.blur();
      }
      if (document.body instanceof HTMLElement) {
        document.body.focus({ preventScroll: true });
      }
      hideQueryAssistantMenu();
    }, 0);
  });
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    analyzeQueryContext,
    continuationStateAfterSpace,
    fieldSuggestions,
    operatorSuggestions,
    isClauseComplete,
    isDelimitedValueContext,
    filterQuerySuggestions,
    continuationSuggestions,
    queryGroupDepth,
    applyQuerySuggestion,
    replacementStateForContext,
    syncQueryInputCaret,
  };
}
