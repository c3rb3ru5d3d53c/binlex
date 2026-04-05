const QUERY_FIELD_SUGGESTIONS = [
  { label: "sample:", insert: "sample:", kind: "field", usage: "sample:<64-hex-hash>", description: "Root a search from a specific sample" },
  { label: "embedding:", insert: "embedding:", kind: "field", usage: "embedding:<64-hex-hash>", description: "Nearest-neighbor search from an existing embedding" },
  { label: "embeddings:", insert: "embeddings:", kind: "field", usage: "embeddings:>1k", description: "Filter by embedding count with comparisons" },
  { label: "vector:", insert: "vector:", kind: "field", usage: "vector:[0.1, -0.2, 0.3]", description: "Nearest-neighbor search from an explicit vector" },
  { label: "score:", insert: "score:", kind: "field", usage: "score:>0.95", description: "Filter by similarity score with comparisons" },
  { label: "expand:", insert: "expand:", kind: "field", usage: "expand:blocks", description: "Expand rows downward to child blocks or instructions" },
  { label: "limit:", insert: "limit:", kind: "field", usage: "limit:10", description: "Cap the current result stream" },
  { label: "ascending:", insert: "ascending:", kind: "field", usage: "ascending:score", description: "Sort the current result stream in ascending order by a specific field" },
  { label: "descending:", insert: "descending:", kind: "field", usage: "descending:score", description: "Sort the current result stream in descending order by a specific field" },
  { label: "drop:", insert: "drop:", kind: "field", usage: "drop:rhs", description: "Project compare results onto one side" },
  { label: "corpus:", insert: "corpus:", kind: "field", usage: "corpus:<name>", description: "Filter by corpus name" },
  { label: "collection:", insert: "collection:", kind: "field", usage: "collection:function", description: "Filter by indexed entity type" },
  { label: "architecture:", insert: "architecture:", kind: "field", usage: "architecture:amd64", description: "Filter by architecture" },
  { label: "username:", insert: "username:", kind: "field", usage: "username:anonymous", description: "Filter by the indexing username" },
  { label: "address:", insert: "address:", kind: "field", usage: "address:0x401000", description: "Filter by exact address" },
  { label: "date:", insert: "date:", kind: "field", usage: "date:>=2026-03-01", description: "Filter by indexed UTC date or date range bounds" },
  { label: "size:", insert: "size:", kind: "field", usage: "size:>1mb", description: "Filter by instruction, block, or function byte size" },
  { label: "symbol:", insert: "symbol:", kind: "field", usage: "symbol:\"kernel32:CreateFileW\"", description: "Filter by exact quoted symbol name" },
  { label: "cyclomatic_complexity:", insert: "cyclomatic_complexity:", kind: "field", usage: "cyclomatic_complexity:>5", description: "Filter by cyclomatic complexity" },
  { label: "average_instructions_per_block:", insert: "average_instructions_per_block:", kind: "field", usage: "average_instructions_per_block:<10", description: "Filter by average instructions per block" },
  { label: "instructions:", insert: "instructions:", kind: "field", usage: "instructions:>=32", description: "Filter by the number of instructions" },
  { label: "blocks:", insert: "blocks:", kind: "field", usage: "blocks:>=4", description: "Filter by the number of blocks" },
  { label: "markov:", insert: "markov:", kind: "field", usage: "markov:>0.6", description: "Filter by block Markov score" },
  { label: "entropy:", insert: "entropy:", kind: "field", usage: "entropy:<6.5", description: "Filter by byte entropy" },
  { label: "contiguous:", insert: "contiguous:", kind: "field", usage: "contiguous:true", description: "Filter by contiguous layout" },
  { label: "chromosome.entropy:", insert: "chromosome.entropy:", kind: "field", usage: "chromosome.entropy:>3.0", description: "Filter by chromosome entropy" },
  { label: "|", insert: " | ", kind: "operator", usage: "term | term", description: "Pipe results through another narrowing filter" },
  { label: "||", insert: " || ", kind: "operator", usage: "term || term", description: "Match either clause" },
  { label: "!", insert: "!", kind: "operator", usage: "!term", description: "Negate the next term or group" },
  { label: "->", insert: " -> ", kind: "operator", usage: "left-query -> right-query", description: "Compare each left-side result to its best right-side match" },
  { label: "<-", insert: " <- ", kind: "operator", usage: "left-query <- right-query", description: "Compare each right-side result to its best left-side match" },
  { label: "(", insert: "(", kind: "group", usage: "( term )", description: "Start a grouped sub-expression" },
  { label: ")", insert: ")", kind: "group", usage: "( term )", description: "Close the current grouped sub-expression" },
];

const QUERY_SORT_KEYS = [
  "score",
  "size",
  "embeddings",
  "address",
  "timestamp",
  "cyclomatic_complexity",
  "average_instructions_per_block",
  "instructions",
  "blocks",
  "markov",
  "entropy",
  "chromosome.entropy",
];

let corpusSuggestionAbort = null;
let querySuggestionItems = [];
let querySuggestionIndex = 0;
const THEME_STORAGE_KEY = "binlex-web-theme";
let activeRowActionTrigger = null;
let activeCorporaTrigger = null;
let activeCorporaResultKey = null;
let activeTagTrigger = null;
let activeTagResultKey = null;
let activeSymbolTrigger = null;
let activeSymbolResultKey = null;
const QUERY_COMMIT_DATASET_KEY = "committedQueryClause";
let queryAssistantUpdateHandle = null;
const MODAL_SELECT_ACTIVE_Z_INDEX = "120";
const tagRowRequests = new Set();
const tagSearchRequests = new Set();
const symbolRowRequests = new Set();
const symbolSearchRequests = new Set();
const corporaRowRequests = new Set();
const corporaSearchRequests = new Set();
const uploadCorporaRequests = new Set();
let uploadCorporaSearchHandle = null;
const RESULT_COLUMNS_STORAGE_KEY = "binlex-web-result-columns-v2";
const TAGS_POPOVER_VISIBLE_LIMIT = 6;
let activeColumnsTrigger = null;

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
  const button = document.getElementById("theme-toggle-button");
  if (button) {
    const nextTheme = normalized === "dark" ? "light" : "dark";
    const icon = normalized === "dark" ? "☀️" : "🌙";
    const label = normalized === "dark" ? "Switch to light mode" : "Switch to dark mode";
    button.textContent = icon;
    button.setAttribute("aria-label", label);
    button.setAttribute("title", label);
    button.dataset.nextTheme = nextTheme;
  }
}

function setTheme(theme) {
  applyTheme(theme);
  try {
    localStorage.setItem(THEME_STORAGE_KEY, theme === "light" ? "light" : "dark");
  } catch (_) {}
}

function toggleTheme() {
  const current = document.body?.getAttribute("data-theme") === "light" ? "light" : "dark";
  setTheme(current === "dark" ? "light" : "dark");
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

function getCorporaPopover() {
  return document.getElementById("corpora-popover");
}

function getTagsPopover() {
  return document.getElementById("tags-popover");
}

function getSymbolPopover() {
  return document.getElementById("symbol-popover");
}

function getColumnsPopover() {
  return document.getElementById("columns-popover");
}

function getPageInput() {
  return document.getElementById("page-input");
}

function setSearchSubmitLoading(loading) {
  const button = document.getElementById("search-submit-button");
  if (!(button instanceof HTMLButtonElement)) return;
  const label = button.querySelector(".search-submit-label");
  const loader = button.querySelector(".search-submit-loader");
  button.disabled = !!loading;
  if (label instanceof HTMLElement) {
    label.hidden = !!loading;
  }
  if (loader instanceof HTMLElement) {
    loader.hidden = !loading;
  }
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

function toggleResultDetails(row) {
  if (!(row instanceof HTMLElement)) return;
  const detailRow = row.nextElementSibling;
  if (!(detailRow instanceof HTMLElement) || !detailRow.classList.contains("result-detail-row")) {
    return;
  }
  const willOpen = detailRow.hidden;
  row.classList.toggle("expanded", willOpen);
  detailRow.hidden = !willOpen;
  if (willOpen) {
    requestResultDetailByKey(row.dataset.resultKey || "").catch((error) => {
      console.error("binlex-web detail request failed", error);
    });
  }
  if (!willOpen) {
    row.classList.remove("expanded");
  }
}

function expandResultDetails(row) {
  if (!(row instanceof HTMLElement)) return;
  const detailRow = row.nextElementSibling;
  if (!(detailRow instanceof HTMLElement) || !detailRow.classList.contains("result-detail-row")) {
    return;
  }
  row.classList.add("expanded");
  detailRow.hidden = false;
  requestResultDetailByKey(row.dataset.resultKey || "").catch((error) => {
    console.error("binlex-web detail request failed", error);
  });
}

function collapseResultDetails(row) {
  if (!(row instanceof HTMLElement)) return;
  const detailRow = row.nextElementSibling;
  if (!(detailRow instanceof HTMLElement) || !detailRow.classList.contains("result-detail-row")) {
    return;
  }
  row.classList.remove("expanded");
  detailRow.hidden = true;
}

function expandResultDetailsByKey(resultKey) {
  if (!resultKey) return;
  const row = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"]`);
  if (row instanceof HTMLElement) {
    expandResultDetails(row);
  }
}

function collapseResultDetailsByKey(resultKey) {
  if (!resultKey) return;
  const row = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"]`);
  if (row instanceof HTMLElement) {
    collapseResultDetails(row);
  }
}

function expandAllResultDetails() {
  document.querySelectorAll(".result-row").forEach((row) => {
    if (row instanceof HTMLElement) {
      expandResultDetails(row);
    }
  });
}

function collapseAllResultDetails() {
  document.querySelectorAll(".result-row").forEach((row) => {
    if (row instanceof HTMLElement) {
      collapseResultDetails(row);
    }
  });
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
  if (["cyclomatic_complexity", "instructions", "blocks"].includes(context.field)) {
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
    return "Use explicit fields like sample:, embedding:, embeddings:, vector:, score:, limit:, corpus:, collection:, architecture:, username:, address:, date:, size:, symbol:, cyclomatic_complexity:, average_instructions_per_block:, instructions:, blocks:, markov:, entropy:, contiguous:, and chromosome.entropy:, plus pipe utilities like expand:blocks, expand:instructions, and drop:rhs.";
  }
  if (clause.stage === "field") {
    return "Use explicit fields like sample:, embedding:, embeddings:, vector:, score:, limit:, corpus:, collection:, architecture:, username:, address:, date:, size:, symbol:, cyclomatic_complexity:, average_instructions_per_block:, instructions:, blocks:, markov:, entropy:, contiguous:, and chromosome.entropy:, plus pipe utilities like expand:blocks, expand:instructions, and drop:rhs.";
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
  if (clause.field === "corpus") {
    return "Select or search for a corpus value.";
  }
  if (clause.field === "architecture") {
    return "Select an architecture like amd64, i386, or cil.";
  }
  if (clause.field === "username") {
    return "Filter by the exact indexing username, for example username:anonymous";
  }
  if (clause.field === "collection") {
    return "Select function, block, or instruction.";
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
  if (field !== "corpus") {
    return Promise.resolve([]);
  }
  if (corpusSuggestionAbort) corpusSuggestionAbort.abort();
  corpusSuggestionAbort = new AbortController();
  const url = `/api/v1/corpora?q=${encodeURIComponent(partial || "")}`;
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
    if (["corpus", "architecture", "collection", "drop", "contiguous", "expand", "ascending", "descending"].includes(clause.field)) {
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
  back.disabled = path.length === 0;

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
  ranked.forEach(({ item }, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "row-action-button";
    if (index === 0) {
      button.classList.add("active");
    }
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
  const search = shell.querySelector(".menu-search");
  if (search instanceof HTMLElement && document.activeElement !== search) {
    setTimeout(() => search.focus(), 0);
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

function updateCorporaCell(resultKey) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const cell = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"] .corpora-cell-td`);
  if (cell instanceof HTMLElement) {
    cell.innerHTML = renderCorporaCell(row);
    if (activeCorporaResultKey === resultKey) {
      activeCorporaTrigger = document.querySelector(`.corpora-popover-trigger[data-result-key="${CSS.escape(resultKey)}"]`);
      if (activeCorporaTrigger instanceof HTMLElement) {
        activeCorporaTrigger.classList.add("active");
      }
    }
  }
  refreshResultDetailRow(resultKey);
}

function currentCorporaPopoverTrigger() {
  if (!activeCorporaResultKey) return null;
  const trigger = document.querySelector(`.corpora-popover-trigger[data-result-key="${CSS.escape(activeCorporaResultKey)}"]`);
  return trigger instanceof HTMLElement ? trigger : null;
}

async function loadRowCorporaByKey(resultKey, force = false) {
  if (!resultKey || corporaRowRequests.has(resultKey)) return;
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  if (!force && row.corpora_loaded) return;
  row.collection_corpora = normalizeTagList(row.collection_corpora || row.corpora || []);
  row.corpora = normalizeTagList(row.corpora || row.collection_corpora || []);
  corporaRowRequests.add(resultKey);
  row.corpora_loading = true;
  row.corpora_error = null;
  try {
    const collectionUrl = `/api/v1/corpora/collection?${new URLSearchParams({
      sha256: row.sha256 || "",
      collection: row.collection || "",
      architecture: row.architecture || "",
      address: String(Number(row.address || 0)),
    }).toString()}`;
    const collection = await fetchJsonWithCredentials(collectionUrl);
    row.collection_corpora = normalizeTagList(collection?.corpora || []);
    row.corpora = normalizeTagList([...row.collection_corpora]);
    row.corpora_loaded = true;
    row.corpora_error = null;
  } catch (error) {
    row.collection_corpora = normalizeTagList(row.collection_corpora || row.corpora || []);
    row.corpora = normalizeTagList(row.corpora || row.collection_corpora || []);
    row.corpora_loaded = true;
    row.corpora_error = error instanceof Error ? error.message : "Unable to load corpora.";
  } finally {
    row.corpora_loading = false;
    corporaRowRequests.delete(resultKey);
    updateCorporaCell(resultKey);
    if (activeCorporaResultKey === resultKey) {
      renderCorporaPopover();
    }
  }
}

async function loadAvailableCorporaByKey(resultKey, query = "", force = false) {
  if (!resultKey) return;
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const normalizedQuery = String(query || "").trim();
  const requestKey = `${resultKey}\u0000${normalizedQuery.toLowerCase()}`;
  if (corporaSearchRequests.has(requestKey)) return;
  if (!force && row.available_corpora_loaded_query === normalizedQuery) return;
  corporaSearchRequests.add(requestKey);
  row.available_corpora_loading = true;
  row.available_corpora_error = null;
  try {
    const url = `/api/v1/corpora?q=${encodeURIComponent(normalizedQuery)}`;
    const payload = await fetchJsonWithCredentials(url);
    row.available_corpora = normalizeTagList([...(Array.isArray(payload) ? payload : []), ...(row.available_corpora_created || [])]);
    row.available_corpora_total_results = row.available_corpora.length;
    row.available_corpora_loaded_query = normalizedQuery;
  } catch (error) {
    row.available_corpora = normalizeTagList(row.available_corpora_created || []);
    row.available_corpora_total_results = row.available_corpora.length;
    row.available_corpora_loaded_query = normalizedQuery;
    row.available_corpora_error = error instanceof Error ? error.message : "Unable to search corpora.";
    row.corpora_error = row.available_corpora_error;
  } finally {
    row.available_corpora_loading = false;
    corporaSearchRequests.delete(requestKey);
    if (activeCorporaResultKey === resultKey) {
      renderCorporaPopover();
    }
  }
}

function corporaAvailableSearchValue() {
  return String(getCorporaPopover()?.querySelector?.('.corpora-manager-search[data-corpora-scope="available"]')?.value || "").trim();
}

function corporaCollectionSearchValue() {
  return String(getCorporaPopover()?.querySelector?.('.corpora-manager-search[data-corpora-scope="collection"]')?.value || "").trim();
}

function filteredCorporaForSearch(values, needle) {
  const lowered = String(needle || "").trim().toLowerCase();
  return normalizeTagList(values).filter((value) => !lowered || value.toLowerCase().includes(lowered));
}

function filteredAvailableCorpora(row) {
  const assigned = new Set([...(row?.collection_corpora || [])].map((value) => value.toLowerCase()));
  return filteredCorporaForSearch(row?.available_corpora || [], corporaAvailableSearchValue())
    .filter((value) => !assigned.has(value.toLowerCase()));
}

function filteredCollectionCorpora(row) {
  return filteredCorporaForSearch(row?.collection_corpora || row?.corpora || [], corporaCollectionSearchValue());
}

function canCreateCorpus(row) {
  const typed = corporaAvailableSearchValue();
  const lowered = typed.toLowerCase();
  if (!lowered) return false;
  const known = normalizeTagList([...(row?.available_corpora || []), ...(row?.collection_corpora || [])]);
  return !known.some((value) => value.toLowerCase() === lowered);
}

function corporaCollectionTitle(row) {
  return `Collection (${tagCollectionLabel(row)})`;
}

function corporaSummaryText(visible, total) {
  return total > visible ? `Showing ${compactCount(visible)} of ${compactCount(total)}` : "";
}

function renderAvailableCorpusItem(value, active, resultKey) {
  const activeClass = active ? " active" : "";
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(value)}">${escapeHtml(value)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button><button type="button" class="symbol-picker-move" data-corpora-action="apply" data-corpora-scope="collection" data-result-key="${escapeHtml(resultKey)}" data-corpus="${escapeHtml(encodeURIComponent(value))}">&rarr;</button></div></div>`;
}

function renderAssignedCorpusItem(value, scope, active, resultKey) {
  const activeClass = active ? " active" : "";
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(value)}">${escapeHtml(value)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button><button type="button" class="symbol-picker-move" data-corpora-action="remove" data-corpora-scope="${escapeHtml(scope)}" data-result-key="${escapeHtml(resultKey)}" data-corpus="${escapeHtml(encodeURIComponent(value))}">&larr;</button></div></div>`;
}

function renderCorporaManagerColumn(title, scope, items, resultKey, total, searchValue, create) {
  const visible = items.slice(0, TAGS_POPOVER_VISIBLE_LIMIT);
  const body = visible.length === 0
    ? `<div class="corpora-manager-empty">${scope === "available" ? "No corpora available." : "No corpora."}</div>`
    : visible
        .map((value, index) => scope === "available"
          ? renderAvailableCorpusItem(value, index === 0, resultKey)
          : renderAssignedCorpusItem(value, scope, index === 0, resultKey))
        .join("");
  const summary = corporaSummaryText(visible.length, total);
  return `<div class="corpora-manager-column"><div class="corpora-manager-header"><div class="corpora-manager-label">${escapeHtml(title)}</div>${summary ? `<div class="corpora-manager-summary">${escapeHtml(summary)}</div>` : ""}</div><div class="upload-corpus-search-wrap corpora-manager-search-wrap"><input type="search" class="menu-search corpora-manager-search${create ? " corpora-manager-search-has-action" : ""}" data-corpora-scope="${escapeHtml(scope)}" value="${escapeHtml(searchValue || "")}" placeholder="Search corpora" aria-label="Search corpora">${create || ""}</div><div class="corpora-manager-list">${body}</div></div>`;
}

function ensureCorporaPopover() {
  let popover = getCorporaPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "corpora-popover";
  popover.className = "corpora-popover corpora-manager-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="corpora-manager-title">Corpora</div>
    <div class="corpora-popover-body"></div>
  `;
  document.body.appendChild(popover);
  return popover;
}

function positionCorporaPopover(trigger, popover) {
  if (!(trigger instanceof HTMLElement) || !(popover instanceof HTMLElement) || popover.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
  const popoverRect = popover.getBoundingClientRect();
  const left = Math.max(12, Math.min(triggerRect.right - popoverRect.width, viewportWidth - popoverRect.width - 12));
  let top = triggerRect.bottom + 6;
  if (top + popoverRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - popoverRect.height - 6);
  }
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
}

function renderCorporaPopover() {
  const popover = ensureCorporaPopover();
  const body = popover?.querySelector?.(".corpora-popover-body");
  if (!(popover instanceof HTMLElement) || !(body instanceof HTMLElement)) return;
  const activeInput = document.activeElement instanceof HTMLInputElement
    && document.activeElement.classList.contains("corpora-manager-search")
    ? document.activeElement
    : null;
  const activeScope = String(activeInput?.dataset?.corporaScope || "");
  const selectionStart = activeInput?.selectionStart ?? null;
  const selectionEnd = activeInput?.selectionEnd ?? null;
  const currentTrigger = currentCorporaPopoverTrigger();
  if (currentTrigger) {
    activeCorporaTrigger = currentTrigger;
    activeCorporaTrigger.classList.add("active");
  }
  const row = activeCorporaResultKey ? findSearchRowByKey(activeCorporaResultKey) : null;
  if (!row) {
    closeCorporaPopover();
    return;
  }
  if (!row.corpora_loaded && !row.corpora_loading) {
    loadRowCorporaByKey(activeCorporaResultKey).catch((error) => console.error("binlex-web corpora load failed", error));
  }
  const availableQuery = corporaAvailableSearchValue();
  if (!row.corpora_loading && row.available_corpora_loaded_query !== availableQuery && !row.available_corpora_loading) {
    loadAvailableCorporaByKey(activeCorporaResultKey, availableQuery).catch((error) => console.error("binlex-web corpora search failed", error));
  }
  if (row.corpora_loading) {
    body.innerHTML = '<div class="tags-popover-status">Loading corpora...</div>';
  } else if (row.corpora_error) {
    body.innerHTML = `<div class="tags-popover-status error">${escapeHtml(row.corpora_error)}</div>`;
  } else {
    const available = filteredAvailableCorpora(row);
    const collection = filteredCollectionCorpora(row);
    const create = `<button type="button" class="upload-corpus-create-inline corpora-manager-create-inline" data-corpora-action="create"${canCreateCorpus(row) ? "" : " disabled"}>Create</button>`;
    body.innerHTML = `<div class="corpora-manager-grid">${
      renderCorporaManagerColumn("Available", "available", available, activeCorporaResultKey, Number(row.available_corpora_total_results || available.length), corporaAvailableSearchValue(), create)
    }${
      renderCorporaManagerColumn(corporaCollectionTitle(row), "collection", collection, activeCorporaResultKey, collection.length, corporaCollectionSearchValue(), "")
    }</div>`;
    body.querySelectorAll(".corpora-manager-search").forEach((input) => {
      input.addEventListener("input", () => renderCorporaPopover());
      input.addEventListener("keydown", (event) => handleCorporaPopoverKeydown(event));
    });
    body.querySelectorAll('[data-corpora-action="create"]').forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        createAvailableCorpus();
      });
    });
    body.querySelectorAll('[data-corpora-action="apply"]').forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const target = event.currentTarget;
        applyAvailableCorpus(
          String(target?.dataset?.resultKey || ""),
          String(target?.dataset?.corporaScope || ""),
          String(target?.dataset?.corpus || ""),
        );
      });
    });
    body.querySelectorAll('[data-corpora-action="remove"]').forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const target = event.currentTarget;
        removeAssignedCorpus(
          String(target?.dataset?.resultKey || ""),
          String(target?.dataset?.corporaScope || ""),
          String(target?.dataset?.corpus || ""),
        );
      });
    });
    if (activeScope) {
      const replacement = body.querySelector(`.corpora-manager-search[data-corpora-scope="${CSS.escape(activeScope)}"]`);
      if (replacement instanceof HTMLInputElement) {
        replacement.focus();
        if (selectionStart != null && selectionEnd != null) replacement.setSelectionRange(selectionStart, selectionEnd);
      }
    }
  }
  positionCorporaPopover(currentTrigger || activeCorporaTrigger, popover);
}

function closeCorporaPopover() {
  const popover = getCorporaPopover();
  if (popover) {
    popover.hidden = true;
    popover.querySelectorAll(".corpora-manager-search").forEach((input) => {
      if (input instanceof HTMLInputElement) input.value = "";
    });
  }
  if (activeCorporaTrigger instanceof HTMLElement) {
    activeCorporaTrigger.classList.remove("active");
  }
  activeCorporaTrigger = null;
  activeCorporaResultKey = null;
}

function toggleCorporaPopover(button) {
  const popover = ensureCorporaPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  const resultKey = String(button.dataset.resultKey || "");
  if (activeCorporaTrigger === button && activeCorporaResultKey === resultKey && !popover.hidden) {
    closeCorporaPopover();
    return;
  }
  closeRowActionMenu();
  closeTagsPopover();
  closeSymbolPopover();
  if (activeCorporaTrigger instanceof HTMLElement) {
    activeCorporaTrigger.classList.remove("active");
  }
  activeCorporaTrigger = button;
  activeCorporaResultKey = resultKey;
  activeCorporaTrigger.classList.add("active");
  popover.hidden = false;
  renderCorporaPopover();
  const search = popover.querySelector('.corpora-manager-search[data-corpora-scope="available"]');
  if (search instanceof HTMLElement) setTimeout(() => search.focus(), 0);
}

function handleCorporaPopoverKeydown(event) {
  if (event.key === "Escape") {
    event.preventDefault();
    closeCorporaPopover();
    return;
  }
  if (event.key !== "Enter") return;
  const row = activeCorporaResultKey ? findSearchRowByKey(activeCorporaResultKey) : null;
  if (!row) return;
  event.preventDefault();
  const scope = String(event.target?.dataset?.corporaScope || "available");
  if (scope === "available") {
    const available = filteredAvailableCorpora(row);
    if (available.length > 0) {
      applyAvailableCorpus(activeCorporaResultKey, "collection", encodeURIComponent(available[0]));
      return;
    }
    if (canCreateCorpus(row)) createAvailableCorpus();
    return;
  }
  const list = filteredCollectionCorpora(row);
  if (list.length > 0) {
    removeAssignedCorpus(activeCorporaResultKey, scope, encodeURIComponent(list[0]));
  }
}

async function createAvailableCorpus() {
  const row = activeCorporaResultKey ? findSearchRowByKey(activeCorporaResultKey) : null;
  const typed = corporaAvailableSearchValue();
  if (!row || !typed) return;
  const confirmed = await requestTagsConfirmation({
    title: "Create Corpus",
    message: `Create "${typed}" as a corpus?`,
    confirmLabel: "Create",
  });
  if (!confirmed) return;
  try {
    await postJsonWithCredentials("/api/v1/corpora/add", { corpus: typed });
    row.available_corpora_created = normalizeTagList([...(row.available_corpora_created || []), typed]);
    row.available_corpora = normalizeTagList([...(row.available_corpora || []), typed]);
    row.available_corpora_total_results = Math.max(
      Number(row.available_corpora_total_results || 0),
      row.available_corpora.length,
    );
    renderCorporaPopover();
    await loadAvailableCorporaByKey(activeCorporaResultKey, typed, true);
  } catch (error) {
    row.corpora_error = error instanceof Error ? error.message : "Unable to create corpus.";
    renderCorporaPopover();
  }
}

async function applyAvailableCorpus(resultKey, scope, encodedCorpus) {
  const row = findSearchRowByKey(resultKey);
  const corpus = decodeURIComponent(String(encodedCorpus || ""));
  if (!row || !corpus) return;
  try {
    await postJsonWithCredentials("/api/v1/corpora/collection/add", {
      sha256: row.sha256,
      collection: row.collection,
      architecture: row.architecture,
      address: Number(row.address || 0),
      corpus,
    });
    row.collection_corpora = normalizeTagList([...(row.collection_corpora || []), corpus]);
    row.corpora = normalizeTagList([...(row.collection_corpora || [])]);
    row.corpora_loaded = true;
    row.corpora_error = null;
    updateCorporaCell(resultKey);
    renderCorporaPopover();
    loadRowCorporaByKey(resultKey, true).catch((error) => console.error("binlex-web corpora load failed", error));
    loadAvailableCorporaByKey(resultKey, corporaAvailableSearchValue(), true).catch((error) => console.error("binlex-web corpora search failed", error));
  } catch (error) {
    row.corpora_error = error instanceof Error ? error.message : "Unable to apply corpus.";
    renderCorporaPopover();
  }
}

async function removeAssignedCorpus(resultKey, scope, encodedCorpus) {
  const row = findSearchRowByKey(resultKey);
  const corpus = decodeURIComponent(String(encodedCorpus || ""));
  if (!row || !corpus) return;
  try {
    await postJsonWithCredentials("/api/v1/corpora/collection/remove", {
      sha256: row.sha256,
      collection: row.collection,
      architecture: row.architecture,
      address: Number(row.address || 0),
      corpus,
    });
    row.collection_corpora = normalizeTagList((row.collection_corpora || []).filter((value) => value !== corpus));
    row.corpora = normalizeTagList([...(row.collection_corpora || [])]);
    row.corpora_loaded = true;
    row.corpora_error = null;
    updateCorporaCell(resultKey);
    renderCorporaPopover();
    loadRowCorporaByKey(resultKey, true).catch((error) => console.error("binlex-web corpora load failed", error));
    loadAvailableCorporaByKey(resultKey, corporaAvailableSearchValue(), true).catch((error) => console.error("binlex-web corpora search failed", error));
  } catch (error) {
    row.corpora_error = error instanceof Error ? error.message : "Unable to remove corpus.";
    renderCorporaPopover();
  }
}

function normalizeTagList(values) {
  return Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean))).sort((lhs, rhs) => lhs.localeCompare(rhs));
}

function tagCollectionLabel(row) {
  const text = String(row?.collection || "").trim().toLowerCase();
  if (!text) return "Collection";
  return text.charAt(0).toUpperCase() + text.slice(1);
}

function tagCollectionTitle(row) {
  return `Collection (${tagCollectionLabel(row)})`;
}

function tagAvailableSearchValue() {
  return String(getTagsPopover()?.querySelector?.('.tags-manager-search[data-tag-scope="available"]')?.value || "").trim();
}

function tagCollectionSearchValue() {
  return String(getTagsPopover()?.querySelector?.('.tags-manager-search[data-tag-scope="collection"]')?.value || "").trim();
}

function filterTagsForSearch(tags, needle) {
  const lowered = String(needle || "").trim().toLowerCase();
  return normalizeTagList(tags).filter((tag) => !lowered || tag.toLowerCase().includes(lowered));
}

function filteredAvailableTags(row) {
  const assigned = new Set((row?.collection_tags || []).map((tag) => tag.toLowerCase()));
  return filterTagsForSearch(row?.available_tags || [], tagAvailableSearchValue())
    .filter((tag) => !assigned.has(tag.toLowerCase()));
}

function filteredCollectionTags(row) {
  return filterTagsForSearch(row?.collection_tags || [], tagCollectionSearchValue());
}

function canCreateTag(row) {
  const typed = tagAvailableSearchValue();
  const lowered = typed.toLowerCase();
  if (!lowered) return false;
  const known = normalizeTagList([...(row?.available_tags || []), ...(row?.collection_tags || [])]);
  return !known.some((tag) => tag.toLowerCase() === lowered);
}

function updateTagsCell(resultKey) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const cell = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"] .tags-cell-td`);
  if (cell instanceof HTMLElement) {
    cell.innerHTML = renderTagsCell(row);
    if (activeTagResultKey === resultKey) {
      activeTagTrigger = document.querySelector(
        `.tags-popover-trigger[data-result-key="${CSS.escape(resultKey)}"]`
      );
      if (activeTagTrigger instanceof HTMLElement) {
        activeTagTrigger.classList.add("active");
      }
    }
  }
  refreshResultDetailRow(resultKey);
}

function currentTagsPopoverTrigger() {
  if (!activeTagResultKey) return null;
  const trigger = document.querySelector(
    `.tags-popover-trigger[data-result-key="${CSS.escape(activeTagResultKey)}"]`
  );
  return trigger instanceof HTMLElement ? trigger : null;
}

function rowSymbolsSearchValue() {
  const popover = getSymbolPopover();
  const input = popover?.querySelector?.(".symbol-popover-search");
  return String(input?.value || "").trim();
}

function filterSymbolsForSearch(symbols, needle) {
  const lowered = String(needle || "").trim().toLowerCase();
  const unique = Array.from(new Set((symbols || []).map((symbol) => String(symbol || "").trim()).filter(Boolean)));
  return unique.filter((symbol) => !lowered || symbol.toLowerCase().includes(lowered));
}

function updateSymbolCell(resultKey) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const cell = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"] .symbol-cell-td`);
  if (cell instanceof HTMLElement) {
    cell.innerHTML = renderSymbolCell(row);
    if (activeSymbolResultKey === resultKey) {
      activeSymbolTrigger = document.querySelector(
        `.symbol-popover-trigger[data-result-key="${CSS.escape(resultKey)}"]`
      );
      if (activeSymbolTrigger instanceof HTMLElement) {
        activeSymbolTrigger.classList.add("active");
      }
    }
  }
  refreshResultDetailRow(resultKey);
}

function refreshResultDetailRow(resultKey) {
  if (!resultKey) return;
  const row = findSearchRowByKey(resultKey);
  const summaryRow = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"]`);
  const detailRow = summaryRow instanceof HTMLElement ? summaryRow.nextElementSibling : null;
  if (!row || !(detailRow instanceof HTMLElement) || !detailRow.classList.contains("result-detail-row")) {
    return;
  }
  const wasHidden = detailRow.hidden;
  const columnCount = Math.max(1, enabledResultColumnIds().length);
  const wrapper = document.createElement("tbody");
  wrapper.innerHTML = renderResultDetails(row, resultKey, columnCount);
  const replacement = wrapper.firstElementChild;
  if (!(replacement instanceof HTMLElement)) return;
  replacement.hidden = wasHidden;
  detailRow.replaceWith(replacement);
}

function currentSymbolPopoverTrigger() {
  if (!activeSymbolResultKey) return null;
  const trigger = document.querySelector(
    `.symbol-popover-trigger[data-result-key="${CSS.escape(activeSymbolResultKey)}"]`
  );
  return trigger instanceof HTMLElement ? trigger : null;
}

async function fetchJsonWithCredentials(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: {
      "X-Requested-With": "binlex-web",
      "Accept": "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `request failed with status ${response.status}`);
  }
  return response.json();
}

async function postJsonWithCredentials(url, payload) {
  return fetchJsonWithCredentials(url, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

async function loadRowTagsByKey(resultKey, force = false) {
  if (!resultKey || tagRowRequests.has(resultKey)) return;
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  if (!force && row.tags_loaded) return;
  tagRowRequests.add(resultKey);
  row.tags_loading = true;
  row.tag_error = null;
  try {
    const collectionUrl = `/api/v1/tags/collection?${new URLSearchParams({
      sha256: row.sha256 || "",
      collection: row.collection || "",
      address: String(Number(row.address || 0)),
    }).toString()}`;
    const collection = await fetchJsonWithCredentials(collectionUrl);
    row.collection_tags = normalizeTagList(collection?.tags || []);
    row.collection_tag_count = row.collection_tags.length;
    row.tags_loaded = true;
    row.tag_error = null;
  } catch (error) {
    row.collection_tags = normalizeTagList(row.collection_tags || []);
    row.collection_tag_count = Number(row.collection_tag_count || row.collection_tags.length || 0);
    row.tags_loaded = true;
    row.tag_error = error instanceof Error ? error.message : "Unable to load tags.";
  } finally {
    row.tags_loading = false;
    tagRowRequests.delete(resultKey);
    updateTagsCell(resultKey);
    if (activeTagResultKey === resultKey) {
      renderTagsPopover();
    }
  }
}

async function loadAvailableTagsByKey(resultKey, query = "", force = false) {
  if (!resultKey) return;
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const normalizedQuery = String(query || "").trim();
  const requestKey = `${resultKey}\u0000${normalizedQuery.toLowerCase()}`;
  if (tagSearchRequests.has(requestKey)) return;
  if (!force && row.available_tags_loaded_query === normalizedQuery) return;
  tagSearchRequests.add(requestKey);
  row.available_tags_loading = true;
  row.available_tags_error = null;
  try {
    const url = `/api/v1/tags/search?${new URLSearchParams({
      q: normalizedQuery,
      limit: "64",
    }).toString()}`;
    const payload = await fetchJsonWithCredentials(url);
    row.available_tags = normalizeTagList(payload?.tags || []);
    row.available_tags_total_results = Number(payload?.total_results || 0);
    row.available_tags_has_next = !!payload?.has_next;
    row.available_tags_loaded_query = normalizedQuery;
    row.available_tags_error = null;
  } catch (error) {
    row.available_tags = [];
    row.available_tags_total_results = 0;
    row.available_tags_has_next = false;
    row.available_tags_loaded_query = normalizedQuery;
    row.available_tags_error = error instanceof Error ? error.message : "Unable to search tags.";
  } finally {
    row.available_tags_loading = false;
    tagSearchRequests.delete(requestKey);
    if (activeTagResultKey === resultKey) {
      renderTagsPopover();
    }
  }
}

async function loadRowSymbolsByKey(resultKey, force = false) {
  if (!resultKey || symbolRowRequests.has(resultKey)) return;
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  if (!force && row.symbols_loaded) return;
  symbolRowRequests.add(resultKey);
  row.symbols_loading = true;
  row.symbol_error = null;
  try {
    const url = `/api/v1/symbols/collection?${new URLSearchParams({
      sha256: row.sha256 || "",
      collection: row.collection || "",
      architecture: row.architecture || "",
      address: String(Number(row.address || 0)),
    }).toString()}`;
    const payload = await fetchJsonWithCredentials(url);
    row.symbols = filterSymbolsForSearch(payload?.symbols || [], "");
    row.symbols_loaded = true;
    row.symbol_error = null;
  } catch (error) {
    row.symbols = filterSymbolsForSearch(row.symbol ? [row.symbol] : [], "");
    row.symbols_loaded = true;
    row.symbol_error = error instanceof Error ? error.message : "Unable to load symbols.";
  } finally {
    row.symbols_loading = false;
    symbolRowRequests.delete(resultKey);
    updateSymbolCell(resultKey);
    if (activeSymbolResultKey === resultKey) {
      renderSymbolPopover();
    }
  }
}

async function loadAvailableSymbolsByKey(resultKey, query = "", force = false) {
  if (!resultKey) return;
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const normalizedQuery = String(query || "").trim();
  const requestKey = `${resultKey}\u0000${normalizedQuery.toLowerCase()}`;
  if (symbolSearchRequests.has(requestKey)) return;
  if (!force && row.available_symbols_loaded_query === normalizedQuery) return;
  symbolSearchRequests.add(requestKey);
  row.available_symbols_loading = true;
  row.available_symbols_error = null;
  try {
    const url = `/api/v1/symbols/search?${new URLSearchParams({
      q: normalizedQuery,
      limit: "64",
    }).toString()}`;
    const payload = await fetchJsonWithCredentials(url);
    row.available_symbols = filterSymbolsForSearch(payload?.symbols || [], "");
    row.available_symbols_total_results = Number(payload?.total_results || 0);
    row.available_symbols_has_next = !!payload?.has_next;
    row.available_symbols_loaded_query = normalizedQuery;
    row.available_symbols_error = null;
  } catch (error) {
    row.available_symbols = [];
    row.available_symbols_total_results = 0;
    row.available_symbols_has_next = false;
    row.available_symbols_loaded_query = normalizedQuery;
    row.available_symbols_error = error instanceof Error ? error.message : "Unable to search symbols.";
  } finally {
    row.available_symbols_loading = false;
    symbolSearchRequests.delete(requestKey);
    updateSymbolCell(resultKey);
    if (activeSymbolResultKey === resultKey) {
      renderSymbolPopover();
    }
  }
}

function primeVisibleRowTags() {
  const data = currentSearchData();
  if (!data || !Array.isArray(data.results)) return;
  data.results.forEach((row) => {
    const resultKey = resultRowKey(row);
    loadRowTagsByKey(resultKey).catch((error) => {
      console.error("binlex-web tag preload failed", error);
    });
  });
}

function ensureTagsConfirmModal() {
  let modal = document.getElementById("tags-confirm-modal");
  if (modal) return modal;
  modal = document.createElement("div");
  modal.id = "tags-confirm-modal";
  modal.className = "modal-backdrop";
  modal.hidden = true;
  modal.innerHTML = `
    <div class="modal-card tags-confirm-card" role="dialog" aria-modal="true" aria-label="Tag Action">
      <div class="modal-grid modal-grid-single">
        <div class="tags-confirm-title" id="tags-confirm-title"></div>
        <div class="tags-confirm-text" id="tags-confirm-text"></div>
      </div>
      <div class="modal-actions">
        <button type="button" class="secondary" id="tags-confirm-cancel">Cancel</button>
        <button type="button" class="primary" id="tags-confirm-confirm">Confirm</button>
      </div>
    </div>
  `;
  modal.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  modal.querySelector(".tags-confirm-card")?.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  document.body.appendChild(modal);
  return modal;
}

function requestTagsConfirmation({ title, message, confirmLabel }) {
  const modal = ensureTagsConfirmModal();
  const titleEl = document.getElementById("tags-confirm-title");
  const textEl = document.getElementById("tags-confirm-text");
  const cancel = document.getElementById("tags-confirm-cancel");
  const confirm = document.getElementById("tags-confirm-confirm");
  if (!(modal instanceof HTMLElement) || !(titleEl instanceof HTMLElement) || !(textEl instanceof HTMLElement) || !(cancel instanceof HTMLButtonElement) || !(confirm instanceof HTMLButtonElement)) {
    return Promise.resolve(false);
  }
  titleEl.textContent = title || "";
  textEl.textContent = message || "";
  confirm.textContent = confirmLabel || "Confirm";
  modal.hidden = false;
  setTimeout(() => confirm.focus(), 0);
  return new Promise((resolve) => {
    const cleanup = (value) => {
      modal.hidden = true;
      cancel.removeEventListener("click", onCancel);
      confirm.removeEventListener("click", onConfirm);
      modal.removeEventListener("keydown", onKeydown);
      resolve(value);
    };
    const onCancel = (event) => {
      event.stopPropagation();
      cleanup(false);
    };
    const onConfirm = (event) => {
      event.stopPropagation();
      cleanup(true);
    };
    const onKeydown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        cleanup(false);
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        event.stopPropagation();
        cleanup(true);
      }
    };
    cancel.addEventListener("click", onCancel);
    confirm.addEventListener("click", onConfirm);
    modal.addEventListener("keydown", onKeydown);
  });
}

function isInsideTagsConfirmModal(target) {
  const modal = document.getElementById("tags-confirm-modal");
  return modal instanceof HTMLElement && !modal.hidden && modal.contains(target);
}

function symbolAvailableSearchValue() {
  const popover = getSymbolPopover();
  const input = popover?.querySelector?.('.symbol-popover-search[data-symbol-scope="available"]');
  return String(input?.value || "").trim();
}

function symbolAppliedSearchValue() {
  const popover = getSymbolPopover();
  const input = popover?.querySelector?.('.symbol-popover-search[data-symbol-scope="applied"]');
  return String(input?.value || "").trim();
}

function filteredAvailableSymbols(row) {
  const applied = new Set(filterSymbolsForSearch(row?.symbols || [], "").map((symbol) => symbol.toLowerCase()));
  return filterSymbolsForSearch(row?.available_symbols || [], "")
    .filter((symbol) => !applied.has(symbol.toLowerCase()));
}

function filteredAppliedSymbols(row) {
  return filterSymbolsForSearch(row?.symbols || [], symbolAppliedSearchValue());
}

function symbolCanCreate(row) {
  const typed = symbolAvailableSearchValue();
  const lowered = typed.trim().toLowerCase();
  if (!lowered) return false;
  const known = [...filterSymbolsForSearch(row?.symbols || [], ""), ...filterSymbolsForSearch(row?.available_symbols || [], "")];
  return !known.some((symbol) => symbol.toLowerCase() === lowered);
}

async function copySymbolValue(button, encodedSymbol) {
  const symbol = decodeURIComponent(String(encodedSymbol || ""));
  if (!symbol) return;
  try {
    await navigator.clipboard.writeText(symbol);
    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("action-feedback");
    }, 1200);
  } catch (_) {
    const previous = button.textContent;
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  }
}

async function copyPickerValue(button, encodedValue) {
  const value = decodeURIComponent(String(encodedValue || ""));
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("action-feedback");
    }, 1200);
  } catch (_) {
    const previous = button.textContent;
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  }
}

function symbolPickerItemHtml(symbol, direction, active, resultKey) {
  const moveArrow = direction === "apply" ? "&rarr;" : "&larr;";
  const activeClass = active ? " active" : "";
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(symbol)}">${escapeHtml(symbol)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copySymbolValue(this,'${escapeHtml(encodeURIComponent(symbol))}')">Copy</button><button type="button" class="symbol-picker-move" onclick="event.stopPropagation(); ${direction === "apply" ? `applyAvailableSymbol('${escapeHtml(resultKey)}','${escapeHtml(encodeURIComponent(symbol))}')` : `unapplySymbol('${escapeHtml(resultKey)}','${escapeHtml(encodeURIComponent(symbol))}')`}">${moveArrow}</button></div></div>`;
}

function renderSymbolPickerColumn(title, scope, items, resultKey, searchValue) {
  const row = findSearchRowByKey(resultKey);
  const visible = items.slice(0, TAGS_POPOVER_VISIBLE_LIMIT);
  const hiddenCount = Math.max(0, items.length - visible.length);
  const body = visible.length === 0
    ? `<div class="symbol-popover-empty">No ${scope} symbols.</div>`
    : visible.map((symbol, index) => symbolPickerItemHtml(symbol, scope === "available" ? "apply" : "remove", index === 0, resultKey)).join("");
  let summary = "";
  if (scope === "available") {
    const total = Number(row?.available_symbols_total_results || 0);
    if (total > visible.length) {
      summary = `Showing ${compactCount(visible.length)} of ${compactCount(total)}`;
    }
  } else if (hiddenCount > 0) {
    summary = `Showing ${compactCount(visible.length)} of ${compactCount(items.length)}`;
  }
  const create = scope === "available"
    ? `<button type="button" class="upload-corpus-create-inline symbol-picker-create-inline" onclick="event.stopPropagation(); createAvailableSymbol()"${symbolCanCreate(findSearchRowByKey(resultKey)) ? "" : " disabled"}>Create</button>`
    : "";
  const header = `<div class="symbol-picker-header"><div class="symbol-picker-label">${escapeHtml(title)}</div>${summary ? `<div class="symbol-picker-summary">${escapeHtml(summary)}</div>` : ""}</div>`;
  return `<div class="symbol-picker-column">${header}<div class="upload-corpus-search-wrap symbol-picker-search-wrap"><input type="search" class="menu-search symbol-popover-search${scope === "available" ? " symbol-popover-search-has-action" : ""}" data-symbol-scope="${escapeHtml(scope)}" value="${escapeHtml(searchValue || "")}" placeholder="" aria-label="Search ${escapeHtml(title.toLowerCase())} symbols">${create}</div><div class="symbol-picker-list">${body}</div></div>`;
}

function symbolsPopoverContent(row) {
  const resultKey = resultRowKey(row);
  const availableSearch = symbolAvailableSearchValue();
  const appliedSearch = symbolAppliedSearchValue();
  return `<div class="symbol-picker-grid">${renderSymbolPickerColumn("Available", "available", filteredAvailableSymbols(row), resultKey, availableSearch)}${renderSymbolPickerColumn("Applied", "applied", filteredAppliedSymbols(row), resultKey, appliedSearch)}</div>`;
}

function ensureSymbolPopover() {
  let popover = getSymbolPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "symbol-popover";
  popover.className = "symbol-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="symbol-popover-header">
      <div class="symbol-popover-title">Symbols</div>
    </div>
    <div class="symbol-popover-body"></div>
  `;
  document.body.appendChild(popover);
  return popover;
}

function positionSymbolPopover(trigger, popover) {
  if (!(trigger instanceof HTMLElement) || !(popover instanceof HTMLElement) || popover.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
  const popoverRect = popover.getBoundingClientRect();
  const left = Math.max(12, Math.min(triggerRect.right - popoverRect.width, viewportWidth - popoverRect.width - 12));
  let top = triggerRect.bottom + 6;
  if (top + popoverRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - popoverRect.height - 6);
  }
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
}

function renderSymbolPopover() {
  const popover = ensureSymbolPopover();
  const body = popover?.querySelector?.(".symbol-popover-body");
  if (!(popover instanceof HTMLElement) || !(body instanceof HTMLElement)) return;
  const activeInput = document.activeElement instanceof HTMLInputElement
    && document.activeElement.classList.contains("symbol-popover-search")
    ? document.activeElement
    : null;
  const activeScope = String(activeInput?.dataset?.symbolScope || "");
  const selectionStart = activeInput?.selectionStart ?? null;
  const selectionEnd = activeInput?.selectionEnd ?? null;
  const currentTrigger = currentSymbolPopoverTrigger();
  if (currentTrigger) {
    activeSymbolTrigger = currentTrigger;
    activeSymbolTrigger.classList.add("active");
  }
  const row = activeSymbolResultKey ? findSearchRowByKey(activeSymbolResultKey) : null;
  if (!row) {
    closeSymbolPopover();
    return;
  }
  if (!row.symbols_loaded && !row.symbols_loading) {
    loadRowSymbolsByKey(activeSymbolResultKey).catch((error) => {
      console.error("binlex-web symbol load failed", error);
    });
  }
  const availableQuery = symbolAvailableSearchValue();
  if (!row.symbols_loading && row.available_symbols_loaded_query !== availableQuery && !row.available_symbols_loading) {
    loadAvailableSymbolsByKey(activeSymbolResultKey, availableQuery).catch((error) => {
      console.error("binlex-web symbol search failed", error);
    });
  }
  if (row.symbols_loading) {
    body.innerHTML = '<div class="tags-popover-status">Loading symbols...</div>';
  } else if (row.symbol_error) {
    body.innerHTML = `<div class="tags-popover-status error">${escapeHtml(row.symbol_error)}</div>`;
  } else {
    body.innerHTML = symbolsPopoverContent(row);
    body.querySelectorAll(".symbol-popover-search").forEach((input) => {
      input.addEventListener("input", () => renderSymbolPopover());
      input.addEventListener("keydown", (event) => handleSymbolPopoverKeydown(event));
    });
    if (activeScope) {
      const replacement = body.querySelector(`.symbol-popover-search[data-symbol-scope="${CSS.escape(activeScope)}"]`);
      if (replacement instanceof HTMLInputElement) {
        replacement.focus();
        if (selectionStart != null && selectionEnd != null) {
          replacement.setSelectionRange(selectionStart, selectionEnd);
        }
      }
    }
  }
  positionSymbolPopover(currentTrigger || activeSymbolTrigger, popover);
}

function closeSymbolPopover() {
  const popover = getSymbolPopover();
  if (popover) {
    popover.hidden = true;
    popover.querySelectorAll(".symbol-popover-search").forEach((input) => {
      if (input instanceof HTMLInputElement) input.value = "";
    });
  }
  if (activeSymbolTrigger instanceof HTMLElement) {
    activeSymbolTrigger.classList.remove("active");
  }
  activeSymbolTrigger = null;
  activeSymbolResultKey = null;
}

function toggleSymbolPopover(button) {
  const popover = ensureSymbolPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  const resultKey = String(button.dataset.resultKey || "");
  if (activeSymbolTrigger === button && activeSymbolResultKey === resultKey && !popover.hidden) {
    closeSymbolPopover();
    return;
  }
  closeRowActionMenu();
  closeCorporaPopover();
  closeTagsPopover();
  if (activeSymbolTrigger instanceof HTMLElement) {
    activeSymbolTrigger.classList.remove("active");
  }
  activeSymbolTrigger = button;
  activeSymbolResultKey = resultKey;
  activeSymbolTrigger.classList.add("active");
  popover.hidden = false;
  renderSymbolPopover();
  const search = popover.querySelector('.symbol-popover-search[data-symbol-scope="available"]');
  if (search instanceof HTMLElement) {
    setTimeout(() => search.focus(), 0);
  }
}

function handleSymbolPopoverKeydown(event) {
  if (event.key === "Escape") {
    event.preventDefault();
    closeSymbolPopover();
    return;
  }
  if (event.key !== "Enter") {
    return;
  }
  const row = activeSymbolResultKey ? findSearchRowByKey(activeSymbolResultKey) : null;
  if (!row) return;
  event.preventDefault();
  const scope = String(event.target?.dataset?.symbolScope || "available");
  if (scope === "available") {
    const available = filteredAvailableSymbols(row);
    if (available.length > 0) {
      applyAvailableSymbol(activeSymbolResultKey, encodeURIComponent(available[0]));
      return;
    }
    if (symbolCanCreate(row)) {
      createAvailableSymbol();
    }
    return;
  }
  const applied = filteredAppliedSymbols(row);
  if (applied.length > 0) {
    unapplySymbol(activeSymbolResultKey, encodeURIComponent(applied[0]));
  }
}

async function createAvailableSymbol() {
  const row = activeSymbolResultKey ? findSearchRowByKey(activeSymbolResultKey) : null;
  const typed = symbolAvailableSearchValue();
  if (!row || !typed || !activeSymbolResultKey) return;
  const confirmed = await requestTagsConfirmation({
    title: "Create Symbol",
    message: `Create "${typed}" for ${tagCollectionLabel(row)} symbols?`,
    confirmLabel: "Create",
  });
  if (!confirmed) return;
  try {
    await postJsonWithCredentials("/api/v1/symbols/add", { symbol: typed });
    await loadAvailableSymbolsByKey(activeSymbolResultKey, typed, true);
  } catch (error) {
    row.available_symbols_error = error instanceof Error ? error.message : "Unable to create symbol.";
    renderSymbolPopover();
  }
}

async function applyAvailableSymbol(resultKey, encodedSymbol) {
  const row = findSearchRowByKey(resultKey);
  const symbol = decodeURIComponent(String(encodedSymbol || ""));
  if (!row || !symbol) return;
  try {
    await postJsonWithCredentials("/api/v1/symbols/collection/add", {
      sha256: row.sha256,
      collection: row.collection,
      architecture: row.architecture,
      address: Number(row.address || 0),
      symbol,
    });
    await loadRowSymbolsByKey(resultKey, true);
    await loadAvailableSymbolsByKey(resultKey, symbolAvailableSearchValue(), true);
  } catch (error) {
    row.symbol_error = error instanceof Error ? error.message : "Unable to apply symbol.";
    renderSymbolPopover();
  }
}

async function unapplySymbol(resultKey, encodedSymbol) {
  const row = findSearchRowByKey(resultKey);
  const symbol = decodeURIComponent(String(encodedSymbol || ""));
  if (!row || !symbol) return;
  try {
    await postJsonWithCredentials("/api/v1/symbols/collection/remove", {
      sha256: row.sha256,
      collection: row.collection,
      architecture: row.architecture,
      address: Number(row.address || 0),
      symbol,
    });
    await loadRowSymbolsByKey(resultKey, true);
    await loadAvailableSymbolsByKey(resultKey, symbolAvailableSearchValue(), true);
  } catch (error) {
    row.symbol_error = error instanceof Error ? error.message : "Unable to unapply symbol.";
    renderSymbolPopover();
  }
}

function tagSummaryText(row, scope, visible, total) {
  if (scope === "available") {
    const totalResults = Number(row?.available_tags_total_results || 0);
    const hasNext = !!row?.available_tags_has_next;
    if (hasNext) {
      const lowerBound = Math.max(Number(total || 0), totalResults);
      return `Showing ${compactCount(visible)} of ${compactCount(lowerBound)}+`;
    }
    return totalResults > visible ? `Showing ${compactCount(visible)} of ${compactCount(totalResults)}` : "";
  }
  return total > visible ? `Showing ${compactCount(visible)} of ${compactCount(total)}` : "";
}

function renderAvailableTagItem(tag, active, resultKey) {
  const activeClass = active ? " active" : "";
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(tag)}">${escapeHtml(tag)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(tag))}')">Copy</button><button type="button" class="symbol-picker-move" data-tag-action="apply" data-result-key="${escapeHtml(resultKey)}" data-tag="${escapeHtml(encodeURIComponent(tag))}">&rarr;</button></div></div>`;
}

function renderAssignedTagItem(tag, active, resultKey) {
  const activeClass = active ? " active" : "";
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(tag)}">${escapeHtml(tag)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(tag))}')">Copy</button><button type="button" class="symbol-picker-move" data-tag-action="remove" data-result-key="${escapeHtml(resultKey)}" data-tag="${escapeHtml(encodeURIComponent(tag))}">&larr;</button></div></div>`;
}

function renderTagsManagerColumn(title, scope, items, row, resultKey, total, searchValue, create) {
  const visible = items.slice(0, TAGS_POPOVER_VISIBLE_LIMIT);
  const body = visible.length === 0
    ? `<div class="corpora-manager-empty">${scope === "available" ? "No tags available." : "No tags applied."}</div>`
    : visible
        .map((tag, index) => scope === "available"
          ? renderAvailableTagItem(tag, index === 0, resultKey)
          : renderAssignedTagItem(tag, index === 0, resultKey))
        .join("");
  const summary = tagSummaryText(row, scope, visible.length, total);
  return `<div class="corpora-manager-column"><div class="corpora-manager-header"><div class="corpora-manager-label">${escapeHtml(title)}</div>${summary ? `<div class="corpora-manager-summary">${escapeHtml(summary)}</div>` : ""}</div><div class="upload-corpus-search-wrap corpora-manager-search-wrap"><input type="search" class="menu-search tags-manager-search${create ? " corpora-manager-search-has-action" : ""}" data-tag-scope="${escapeHtml(scope)}" value="${escapeHtml(searchValue || "")}" placeholder="Search tags" aria-label="Search tags">${create || ""}</div><div class="corpora-manager-list">${body}</div></div>`;
}

function ensureTagsPopover() {
  let popover = getTagsPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "tags-popover";
  popover.className = "tags-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="tags-popover-header">
      <div class="tags-popover-title">Tags</div>
    </div>
    <div class="tags-popover-body"></div>
  `;
  document.body.appendChild(popover);
  return popover;
}

function positionTagsPopover(trigger, popover) {
  if (!(trigger instanceof HTMLElement) || !(popover instanceof HTMLElement) || popover.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
  const popoverRect = popover.getBoundingClientRect();
  const left = Math.max(12, Math.min(triggerRect.right - popoverRect.width, viewportWidth - popoverRect.width - 12));
  let top = triggerRect.bottom + 6;
  if (top + popoverRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - popoverRect.height - 6);
  }
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
}

function renderTagsPopover() {
  const popover = ensureTagsPopover();
  const body = popover?.querySelector?.(".tags-popover-body");
  if (!(popover instanceof HTMLElement) || !(body instanceof HTMLElement)) return;
  const activeInput = document.activeElement instanceof HTMLInputElement
    && document.documentElement.contains(document.activeElement)
    && document.activeElement.classList.contains("tags-manager-search")
    ? document.activeElement
    : null;
  const activeScope = String(activeInput?.dataset?.tagScope || "");
  const selectionStart = activeInput?.selectionStart ?? null;
  const selectionEnd = activeInput?.selectionEnd ?? null;
  const currentTrigger = currentTagsPopoverTrigger();
  if (currentTrigger) {
    activeTagTrigger = currentTrigger;
    activeTagTrigger.classList.add("active");
  }
  const row = activeTagResultKey ? findSearchRowByKey(activeTagResultKey) : null;
  if (!row) {
    closeTagsPopover();
    return;
  }
  if (!row.tags_loaded && !row.tags_loading) {
    loadRowTagsByKey(activeTagResultKey).catch((error) => {
      console.error("binlex-web tag load failed", error);
    });
  }
  const availableQuery = tagAvailableSearchValue();
  if (row.available_tags_loaded_query !== availableQuery && !row.available_tags_loading) {
    loadAvailableTagsByKey(activeTagResultKey, availableQuery).catch((error) => {
      console.error("binlex-web tag search failed", error);
    });
  }
  if (row.tag_error) {
    body.innerHTML = `<div class="tags-popover-status error">${escapeHtml(row.tag_error)}</div>`;
  } else {
    const available = filteredAvailableTags(row);
    const collection = filteredCollectionTags(row);
    const create = `<button type="button" class="upload-corpus-create-inline tags-manager-create-inline" data-tag-action="create"${canCreateTag(row) ? "" : " disabled"}>Create</button>`;
    body.innerHTML = `<div class="corpora-manager-grid">${
      renderTagsManagerColumn("Available", "available", available, row, activeTagResultKey, Number(row.available_tags_total_results || available.length), tagAvailableSearchValue(), create)
    }${
      renderTagsManagerColumn(tagCollectionTitle(row), "collection", collection, row, activeTagResultKey, collection.length, tagCollectionSearchValue(), "")
    }</div>`;
    body.querySelectorAll(".tags-manager-search").forEach((input) => {
      input.addEventListener("input", () => renderTagsPopover());
      input.addEventListener("keydown", (event) => handleTagsPopoverKeydown(event));
    });
    body.querySelectorAll('[data-tag-action="create"]').forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        createAvailableTag();
      });
    });
    body.querySelectorAll('[data-tag-action="apply"]').forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const target = event.currentTarget;
        applyAvailableTag(String(target?.dataset?.resultKey || ""), String(target?.dataset?.tag || ""));
      });
    });
    body.querySelectorAll('[data-tag-action="remove"]').forEach((button) => {
      button.addEventListener("click", (event) => {
        event.preventDefault();
        event.stopPropagation();
        const target = event.currentTarget;
        removeAssignedTag(String(target?.dataset?.resultKey || ""), String(target?.dataset?.tag || ""));
      });
    });
    if (activeScope) {
      const replacement = body.querySelector(`.tags-manager-search[data-tag-scope="${CSS.escape(activeScope)}"]`);
      if (replacement instanceof HTMLInputElement) {
        replacement.focus();
        if (selectionStart != null && selectionEnd != null) {
          replacement.setSelectionRange(selectionStart, selectionEnd);
        }
      }
    }
  }
  positionTagsPopover(currentTrigger || activeTagTrigger, popover);
}

function closeTagsPopover() {
  const popover = getTagsPopover();
  if (popover) {
    popover.hidden = true;
    popover.querySelectorAll(".tags-manager-search").forEach((input) => {
      if (input instanceof HTMLInputElement) input.value = "";
    });
  }
  if (activeTagTrigger instanceof HTMLElement) {
    activeTagTrigger.classList.remove("active");
  }
  activeTagTrigger = null;
  activeTagResultKey = null;
}

function toggleTagsPopover(button) {
  const popover = ensureTagsPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  const resultKey = String(button.dataset.resultKey || "");
  if (activeTagTrigger === button && activeTagResultKey === resultKey && !popover.hidden) {
    closeTagsPopover();
    return;
  }
  closeRowActionMenu();
  closeCorporaPopover();
  closeSymbolPopover();
  if (activeTagTrigger instanceof HTMLElement) {
    activeTagTrigger.classList.remove("active");
  }
  activeTagTrigger = button;
  activeTagResultKey = resultKey;
  activeTagTrigger.classList.add("active");
  popover.hidden = false;
  renderTagsPopover();
  const search = popover.querySelector('.tags-manager-search[data-tag-scope="available"]');
  if (search instanceof HTMLElement) {
    setTimeout(() => search.focus(), 0);
  }
}

function handleTagsPopoverKeydown(event) {
  if (event.key === "Escape") {
    event.preventDefault();
    closeTagsPopover();
    return;
  }
  if (event.key !== "Enter") return;
  const row = activeTagResultKey ? findSearchRowByKey(activeTagResultKey) : null;
  if (!row) return;
  event.preventDefault();
  const scope = String(event.target?.dataset?.tagScope || "available");
  if (scope === "available") {
    const available = filteredAvailableTags(row);
    if (available.length > 0) {
      applyAvailableTag(activeTagResultKey, encodeURIComponent(available[0]));
      return;
    }
    if (canCreateTag(row)) createAvailableTag();
    return;
  }
  const collection = filteredCollectionTags(row);
  if (collection.length > 0) {
    removeAssignedTag(activeTagResultKey, encodeURIComponent(collection[0]));
  }
}

async function createAvailableTag() {
  const row = activeTagResultKey ? findSearchRowByKey(activeTagResultKey) : null;
  const typed = tagAvailableSearchValue();
  if (!row || !typed || !activeTagResultKey) return;
  const confirmed = await requestTagsConfirmation({
    title: "Create Tag",
    message: `Create "${typed}" as a tag?`,
    confirmLabel: "Create",
  });
  if (!confirmed) return;
  try {
    await postJsonWithCredentials("/api/v1/tags/add", { tag: typed });
    renderTagsPopover();
    loadAvailableTagsByKey(activeTagResultKey, tagAvailableSearchValue(), true).catch((error) => console.error("binlex-web tag search failed", error));
  } catch (error) {
    row.tag_error = error instanceof Error ? error.message : "Unable to create tag.";
    renderTagsPopover();
  }
}

async function applyAvailableTag(resultKey, encodedTag) {
  const row = findSearchRowByKey(resultKey);
  const tag = decodeURIComponent(String(encodedTag || ""));
  if (!row || !tag) return;
  try {
    await postJsonWithCredentials("/api/v1/tags/collection/add", {
      sha256: row.sha256,
      collection: row.collection,
      address: Number(row.address || 0),
      tag,
    });
    row.collection_tags = normalizeTagList([...(row.collection_tags || []), tag]);
    row.collection_tag_count = row.collection_tags.length;
    row.tags_loaded = true;
    row.tag_error = null;
    updateTagsCell(resultKey);
    renderTagsPopover();
    loadRowTagsByKey(resultKey, true).catch((error) => console.error("binlex-web tag load failed", error));
    loadAvailableTagsByKey(resultKey, tagAvailableSearchValue(), true).catch((error) => console.error("binlex-web tag search failed", error));
  } catch (error) {
    row.tag_error = error instanceof Error ? error.message : "Unable to apply tag.";
    renderTagsPopover();
  }
}

async function removeAssignedTag(resultKey, encodedTag) {
  const row = findSearchRowByKey(resultKey);
  const tag = decodeURIComponent(String(encodedTag || ""));
  if (!row || !tag) return;
  const confirmed = await requestTagsConfirmation({
    title: "Delete Tag",
    message: `Remove "${tag}" from ${tagCollectionLabel(row)} tags?`,
    confirmLabel: "Delete",
  });
  if (!confirmed) return;
  try {
    await postJsonWithCredentials("/api/v1/tags/collection/remove", {
      sha256: row.sha256,
      collection: row.collection,
      address: Number(row.address || 0),
      tag,
    });
    row.collection_tags = normalizeTagList((row.collection_tags || []).filter((value) => value !== tag));
    row.collection_tag_count = row.collection_tags.length;
    row.tags_loaded = true;
    row.tag_error = null;
    updateTagsCell(resultKey);
    renderTagsPopover();
    loadRowTagsByKey(resultKey, true).catch((error) => console.error("binlex-web tag load failed", error));
    loadAvailableTagsByKey(resultKey, tagAvailableSearchValue(), true).catch((error) => console.error("binlex-web tag search failed", error));
  } catch (error) {
    row.tag_error = error instanceof Error ? error.message : "Unable to delete tag.";
    renderTagsPopover();
  }
}

function ensureColumnsPopover() {
  let popover = getColumnsPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "columns-popover";
  popover.className = "columns-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="columns-popover-header">Columns</div>
    <div class="columns-popover-grid">
      <div class="columns-popover-column">
        <div class="columns-popover-label">Disabled</div>
        <input type="search" class="menu-search columns-popover-search" data-columns-scope="disabled" placeholder="Search disabled" aria-label="Search disabled columns">
        <div class="columns-popover-list" data-columns-list="disabled"></div>
      </div>
      <div class="columns-popover-column">
        <div class="columns-popover-label">Enabled</div>
        <input type="search" class="menu-search columns-popover-search" data-columns-scope="enabled" placeholder="Search enabled" aria-label="Search enabled columns">
        <div class="columns-popover-list" data-columns-list="enabled"></div>
      </div>
    </div>
  `;
  popover.querySelectorAll(".columns-popover-search").forEach((input) => {
    input.addEventListener("input", () => renderColumnsPopover(popover));
    input.addEventListener("keydown", (event) => handleColumnsPopoverSearchKeydown(event, popover));
  });
  document.body.appendChild(popover);
  return popover;
}

function positionColumnsPopover(trigger, popover) {
  if (!(trigger instanceof HTMLElement) || !(popover instanceof HTMLElement) || popover.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const popoverRect = popover.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  const left = Math.max(
    12,
    Math.min(triggerRect.right - popoverRect.width, viewportWidth - popoverRect.width - 12)
  );
  let top = triggerRect.bottom + 6;
  if (top + popoverRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - popoverRect.height - 6);
  }
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
}

function columnsSearchValue(scope, popover) {
  const input = popover?.querySelector?.(`.columns-popover-search[data-columns-scope="${scope}"]`);
  return String(input?.value || "").trim().toLowerCase();
}

function filteredColumnItems(scope, popover) {
  const enabled = enabledResultColumnIds();
  const enabledSet = new Set(enabled);
  const needle = columnsSearchValue(scope, popover);
  const items = resultColumnsCatalog().filter((column) => {
    const isEnabled = enabledSet.has(column.id);
    return scope === "enabled" ? isEnabled : !isEnabled;
  });
  return items.filter((column) => {
    if (!needle) return true;
    return column.label.toLowerCase().includes(needle) || column.id.toLowerCase().includes(needle);
  });
}

function moveResultColumn(columnId, direction) {
  const id = String(columnId || "");
  if (!id) return;
  const enabled = enabledResultColumnIds();
  if (direction === "enabled") {
    if (!enabled.includes(id)) {
      enabled.push(id);
    }
  } else {
    const next = enabled.filter((item) => item !== id);
    if (next.length === 0) {
      return;
    }
    enabled.splice(0, enabled.length, ...next);
  }
  setEnabledResultColumnIds(enabled);
  const popover = getColumnsPopover();
  if (popover instanceof HTMLElement && !popover.hidden) {
    renderColumnsPopover(popover);
  }
}

function columnsItemHtml(column, direction, active) {
  const arrow = direction === "enabled" ? "&rarr;" : "&larr;";
  const activeClass = active ? " active" : "";
  return `<button type="button" class="columns-popover-item${activeClass}" onclick="event.stopPropagation(); moveResultColumn('${escapeHtml(column.id)}','${escapeHtml(direction)}')"><span class="columns-popover-item-name">${escapeHtml(column.label)}</span><span class="columns-popover-item-arrow">${arrow}</span></button>`;
}

function renderColumnsPopover(popover) {
  if (!(popover instanceof HTMLElement)) return;
  ["disabled", "enabled"].forEach((scope) => {
    const list = popover.querySelector(`.columns-popover-list[data-columns-list="${scope}"]`);
    if (!(list instanceof HTMLElement)) return;
    const items = filteredColumnItems(scope, popover);
    if (items.length === 0) {
      list.innerHTML = `<div class="columns-popover-empty">No ${scope} columns.</div>`;
      return;
    }
    const direction = scope === "disabled" ? "enabled" : "disabled";
    list.innerHTML = items.map((column, index) => columnsItemHtml(column, direction, index === 0)).join("");
  });
  positionColumnsPopover(activeColumnsTrigger, popover);
}

function closeColumnsPopover() {
  const popover = getColumnsPopover();
  if (popover) {
    popover.hidden = true;
    popover.querySelectorAll(".columns-popover-search").forEach((input) => {
      if (input instanceof HTMLInputElement) input.value = "";
    });
  }
  if (activeColumnsTrigger instanceof HTMLElement) {
    activeColumnsTrigger.classList.remove("active");
  }
  activeColumnsTrigger = null;
}

function toggleColumnsPopover(button) {
  const popover = ensureColumnsPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  if (activeColumnsTrigger === button && !popover.hidden) {
    closeColumnsPopover();
    return;
  }
  closeRowActionMenu();
  closeCorporaPopover();
  closeTagsPopover();
  if (activeColumnsTrigger instanceof HTMLElement) {
    activeColumnsTrigger.classList.remove("active");
  }
  activeColumnsTrigger = button;
  activeColumnsTrigger.classList.add("active");
  popover.hidden = false;
  renderColumnsPopover(popover);
  const firstSearch = popover.querySelector('.columns-popover-search[data-columns-scope="disabled"]')
    || popover.querySelector(".columns-popover-search");
  if (firstSearch instanceof HTMLElement) {
    setTimeout(() => firstSearch.focus(), 0);
  }
}

function handleColumnsPopoverSearchKeydown(event, popover) {
  if (!(popover instanceof HTMLElement)) return;
  if (event.key === "Escape") {
    event.preventDefault();
    event.stopPropagation();
    closeColumnsPopover();
    return;
  }
  if (event.key !== "Enter") {
    return;
  }
  const scope = String(event.target?.dataset?.columnsScope || "disabled");
  const items = filteredColumnItems(scope, popover);
  if (items.length === 0) return;
  event.preventDefault();
  event.stopPropagation();
  moveResultColumn(items[0].id, scope === "disabled" ? "enabled" : "disabled");
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
  closeCorporaPopover();
  closeTagsPopover();
  closeSymbolPopover();
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
  if (!label && path.length === 0) {
    return;
  }
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

function handleRowActionSearchKeydown(event, shell) {
  if (!(shell instanceof HTMLElement)) {
    return;
  }
  if (event.key === "Escape") {
    event.preventDefault();
    event.stopPropagation();
    const path = (shell.dataset.path || "").split("/").filter(Boolean);
    if (path.length > 0) {
      const back = shell.querySelector(".row-actions-back");
      if (back instanceof HTMLButtonElement) {
        navigateRowActions(back);
      } else {
        path.pop();
        shell.dataset.path = path.join("/");
        renderRowActionMenu(shell);
      }
    } else {
      closeRowActionMenu();
    }
    return;
  }
  if (event.key !== "Enter") {
    return;
  }
  const firstButton = shell.querySelector(".row-action-options .row-action-button");
  if (!(firstButton instanceof HTMLButtonElement)) {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
  firstButton.click();
}

async function runRowAction(button, item) {
  if (item?.action === "expand_all") {
    closeRowActionMenu();
    expandAllResultDetails();
    return;
  }
  if (item?.action === "collapse_all") {
    closeRowActionMenu();
    collapseAllResultDetails();
    return;
  }
  if (item?.action === "expand") {
    closeRowActionMenu();
    expandResultDetailsByKey(item?.result_key || "");
    return;
  }
  if (item?.action === "collapse") {
    closeRowActionMenu();
    collapseResultDetailsByKey(item?.result_key || "");
    return;
  }
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
  if (item?.action === "fetch_copy_json") {
    try {
      const response = await fetch(item?.url || "", {
        credentials: "same-origin",
        headers: {
          "X-Requested-With": "binlex-web",
          "Accept": "application/json",
        },
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `request failed with status ${response.status}`);
      }
      const payload = await response.json();
      await navigator.clipboard.writeText(prettyJson(payload));
      const previous = button.textContent;
      button.textContent = "Copied";
      button.classList.add("action-feedback");
      setTimeout(() => {
        button.textContent = previous;
        button.classList.remove("action-feedback");
      }, 1200);
    } catch (_) {
      const previous = button.textContent;
      button.textContent = "Copy failed";
      setTimeout(() => {
        button.textContent = previous;
      }, 1200);
    }
    return;
  }
  if (item?.action === "fetch_copy_text") {
    try {
      const response = await fetch(item?.url || "", {
        method: item?.method || "GET",
        credentials: "same-origin",
        headers: {
          "X-Requested-With": "binlex-web",
          "Content-Type": item?.content_type || "application/json",
          "Accept": item?.accept || "text/plain",
        },
        body: item?.body || undefined,
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `request failed with status ${response.status}`);
      }
      const payload = await response.text();
      await navigator.clipboard.writeText(payload);
      const previous = button.textContent;
      button.textContent = "Copied";
      button.classList.add("action-feedback");
      setTimeout(() => {
        button.textContent = previous;
        button.classList.remove("action-feedback");
      }, 1200);
    } catch (_) {
      const previous = button.textContent;
      button.textContent = "Copy failed";
      setTimeout(() => {
        button.textContent = previous;
      }, 1200);
    }
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

async function copyQuery(button) {
  const input = getQueryInput();
  const query = input?.value || "";
  try {
    await navigator.clipboard.writeText(query);
    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("action-feedback");
    }, 1200);
  } catch (_) {
    const previous = button.textContent;
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  }
}

function dismissNotice(button) {
  button.closest(".notice")?.remove();
}

function buildSearchPayload(form) {
  const formData = new FormData(form);
  const query = String(formData.get("query") || "");
  const topKRaw = Number(formData.get("top_k"));
  const pageRaw = Number(formData.get("page"));
  return {
    query,
    top_k: Number.isFinite(topKRaw) ? topKRaw : null,
    page: Number.isFinite(pageRaw) ? pageRaw : null,
  };
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function serializeActions(actions) {
  try {
    return escapeHtml(JSON.stringify(Array.isArray(actions) ? actions : []));
  } catch (_) {
    return "[]";
  }
}

function urlEncode(value) {
  return encodeURIComponent(String(value ?? ""));
}

function displayArchitecture(value) {
  return String(value ?? "").toLowerCase();
}

function displayCollection(value) {
  return String(value ?? "").toLowerCase();
}

function resultColumnsCatalog() {
  if (typeof resultColumnDefinitions === "function") {
    return resultColumnDefinitions();
  }
  return [];
}

function normalizeEnabledResultColumnIds(ids) {
  const definitions = resultColumnsCatalog();
  const known = new Set(definitions.map((column) => column.id));
  const ordered = [];
  (Array.isArray(ids) ? ids : []).forEach((id) => {
    const normalized = String(id || "");
    if (!known.has(normalized) || ordered.includes(normalized)) return;
    ordered.push(normalized);
  });
  if (ordered.length === 0) {
    return definitions.map((column) => column.id);
  }
  return ordered;
}

function enabledResultColumnIds() {
  try {
    return normalizeEnabledResultColumnIds(JSON.parse(localStorage.getItem(RESULT_COLUMNS_STORAGE_KEY) || "null"));
  } catch (_) {
    return normalizeEnabledResultColumnIds(null);
  }
}

function setEnabledResultColumnIds(ids) {
  const normalized = normalizeEnabledResultColumnIds(ids);
  try {
    localStorage.setItem(RESULT_COLUMNS_STORAGE_KEY, JSON.stringify(normalized));
  } catch (_) {}
  const data = currentSearchData();
  if (data) {
    renderSearchData(data);
  }
}

function abbreviateHex(value) {
  const text = String(value ?? "");
  const edge = 4;
  if (text.length <= edge * 2 + 3) return text;
  return `${text.slice(0, edge)}...${text.slice(-edge)}`;
}

function compactCount(value) {
  const numeric = Number(value || 0);
  if (!Number.isFinite(numeric)) return "0";
  if (numeric < 1000) return String(Math.trunc(numeric));
  const compact = (unit, suffix) => {
    const scaled = numeric / unit;
    if (scaled < 10) {
      const rounded = Math.round(scaled * 10) / 10;
      return Number.isInteger(rounded) ? `${rounded}${suffix}` : `${rounded.toFixed(1)}${suffix}`;
    }
    return `${Math.round(scaled)}${suffix}`;
  };
  if (numeric < 1_000_000) return compact(1_000, "k");
  if (numeric < 1_000_000_000) return compact(1_000_000, "m");
  return compact(1_000_000_000, "b");
}

function formatMetricFloat(value) {
  if (value == null || !Number.isFinite(Number(value))) return "";
  return Number(value).toFixed(4).replace(/\.?0+$/, "");
}

function formatResultSize(value) {
  const numeric = Number(value || 0);
  const kb = 1024;
  const mb = kb * 1024;
  const gb = mb * 1024;
  const compactBytes = (scaled, suffix) => {
    const rounded = Math.round(scaled * 10) / 10;
    return Number.isInteger(rounded) ? `${rounded} ${suffix}` : `${rounded.toFixed(1)} ${suffix}`;
  };
  if (numeric >= gb) return compactBytes(numeric / gb, "GB");
  if (numeric >= mb) return compactBytes(numeric / mb, "MB");
  if (numeric >= kb) return compactBytes(numeric / kb, "KB");
  return `${Math.trunc(numeric)} B`;
}

function formatResultDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? "");
  const pad = (part) => String(part).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function uniqueValues(values) {
  return Array.from(new Set((values || []).map((value) => String(value ?? "")))).sort();
}

function prettyJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_) {
    return "null";
  }
}

function jsonScalarPayload(value) {
  return typeof value === "string" ? value : JSON.stringify(value);
}

const JSON_ACTION_ARRAY_EXPAND_LIMIT = 12;
const JSON_ACTION_MAX_DEPTH = 6;

function actionLeaf(label, payload) {
  return { label, payload };
}

function actionCopy(label, payload) {
  return { label, action: "copy", payload };
}

function actionFetchCopyJson(label, url) {
  return { label, action: "fetch_copy_json", url };
}

function actionFetchCopyText(label, url, method, body, contentType, accept) {
  return { label, action: "fetch_copy_text", url, method, body, content_type: contentType, accept };
}

function actionBranch(label, children) {
  return { label, children };
}

function actionDownload(label, url) {
  return { label, action: "download", url };
}

function actionDownloadPayload(label, filename, contentType, payload) {
  return { label, action: "download_text", filename, content_type: contentType, payload };
}

function actionNavigate(label, url) {
  return { label, action: "navigate", url };
}

function actionExpand(label, resultKey) {
  return { label, action: "expand", result_key: resultKey };
}

function actionCollapse(label, resultKey) {
  return { label, action: "collapse", result_key: resultKey };
}

function actionExpandAll(label) {
  return { label, action: "expand_all" };
}

function actionCollapseAll(label) {
  return { label, action: "collapse_all" };
}

function resultRowKey(row) {
  return `${row.side}:${row.sha256}:${row.collection}:${row.architecture}:${row.address}:${row.symbol || ""}`;
}

const resultDetailRequests = new Set();

function currentSearchData() {
  const data = window.__BINLEX_SEARCH_DATA__;
  return data && typeof data === "object" ? data : null;
}

function findSearchRowByKey(resultKey) {
  const data = currentSearchData();
  if (!data || !Array.isArray(data.results)) return null;
  return data.results.find((row) => resultRowKey(row) === resultKey) || null;
}

function buildSearchDetailUrl(row) {
  const params = new URLSearchParams();
  params.set("sha256", row.sha256 || "");
  params.set("collection", row.collection || "");
  params.set("architecture", row.architecture || "");
  params.set("address", String(Number(row.address || 0)));
  if (row.symbol) params.set("symbol", row.symbol);
  return `/api/v1/search/detail?${params.toString()}`;
}

async function requestResultDetailByKey(resultKey) {
  if (!resultKey || resultDetailRequests.has(resultKey)) return;
  const row = findSearchRowByKey(resultKey);
  if (!row || row.detail_loaded) return;
  resultDetailRequests.add(resultKey);
  try {
    const response = await fetch(buildSearchDetailUrl(row), {
      credentials: "same-origin",
      headers: {
        "X-Requested-With": "binlex-web",
        "Accept": "application/json",
      },
    });
    if (!response.ok) {
      const message = await response.text();
      throw new Error(message || `request failed with status ${response.status}`);
    }
    const payload = await response.json();
    Object.assign(row, payload);
    row.detail_loaded = true;
    const data = currentSearchData();
    if (data) {
      renderSearchData(data);
      expandResultDetailsByKey(resultKey);
    }
    if (!row.corpora_loaded) {
      loadRowCorporaByKey(resultKey).catch((error) => {
        console.error("binlex-web corpora preview load failed", error);
      });
    }
    if (!row.tags_loaded) {
      loadRowTagsByKey(resultKey).catch((error) => {
        console.error("binlex-web tags preview load failed", error);
      });
    }
    if (!row.symbols_loaded) {
      loadRowSymbolsByKey(resultKey).catch((error) => {
        console.error("binlex-web symbols preview load failed", error);
      });
    }
  } finally {
    resultDetailRequests.delete(resultKey);
  }
}

function tableRowClass(row) {
  if (!row.grouped) return "";
  return row.group_end ? "compare-row compare-row-rhs compare-row-end" : "compare-row compare-row-lhs";
}

function buildJsonCopyNode(label, value, depth) {
  if (value && typeof value === "object") {
    return actionBranch(label, buildJsonCopyActions(value, depth));
  }
  return actionCopy(label, jsonScalarPayload(value));
}

function buildJsonCopyActions(value, depth = 0) {
  if (Array.isArray(value)) {
    const children = [actionCopy("Value", prettyJson(value))];
    if (depth >= JSON_ACTION_MAX_DEPTH || value.length > JSON_ACTION_ARRAY_EXPAND_LIMIT) {
      return children;
    }
    value.forEach((nested, index) => {
      children.push(buildJsonCopyNode(`[${index}]`, nested, depth + 1));
    });
    return children;
  }
  if (value && typeof value === "object") {
    const children = [actionCopy("Value", prettyJson(value))];
    if (depth >= JSON_ACTION_MAX_DEPTH) {
      return children;
    }
    Object.entries(value).forEach(([key, nested]) => {
      children.push(buildJsonCopyNode(key, nested, depth + 1));
    });
    return children;
  }
  return [actionCopy("Value", jsonScalarPayload(value))];
}

if (typeof document !== "undefined") {
  document.addEventListener("click", (event) => {
    const popover = getRowActionPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeRowActionTrigger && activeRowActionTrigger.contains(event.target)) return;
    closeRowActionMenu();
  });
  document.addEventListener("click", (event) => {
    const popover = getCorporaPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeCorporaTrigger && activeCorporaTrigger.contains(event.target)) return;
    closeCorporaPopover();
  });
  document.addEventListener("click", (event) => {
    const popover = getTagsPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeTagTrigger && activeTagTrigger.contains(event.target)) return;
    closeTagsPopover();
  });
  document.addEventListener("click", (event) => {
    const popover = getSymbolPopover();
    if (!popover || popover.hidden) return;
    if (isInsideTagsConfirmModal(event.target)) return;
    if (popover.contains(event.target)) return;
    if (activeSymbolTrigger && activeSymbolTrigger.contains(event.target)) return;
    closeSymbolPopover();
  });
  document.addEventListener("click", (event) => {
    const popover = getColumnsPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeColumnsTrigger && activeColumnsTrigger.contains(event.target)) return;
    closeColumnsPopover();
  });
}

if (typeof window !== "undefined") {
  window.addEventListener("resize", () => {
    const popover = getRowActionPopover();
    if (popover && !popover.hidden) {
      positionRowActionMenu(activeRowActionTrigger, popover);
    }
    const corporaPopover = getCorporaPopover();
    if (corporaPopover && !corporaPopover.hidden) {
      positionCorporaPopover(activeCorporaTrigger, corporaPopover);
    }
    const tagsPopover = getTagsPopover();
    if (tagsPopover && !tagsPopover.hidden) {
      positionTagsPopover(activeTagTrigger, tagsPopover);
    }
    const symbolPopover = getSymbolPopover();
    if (symbolPopover && !symbolPopover.hidden) {
      positionSymbolPopover(activeSymbolTrigger, symbolPopover);
    }
    const columnsPopover = getColumnsPopover();
    if (columnsPopover && !columnsPopover.hidden) {
      positionColumnsPopover(activeColumnsTrigger, columnsPopover);
    }
  });

  window.addEventListener("scroll", (event) => {
    const popover = getRowActionPopover();
    if (popover && !popover.hidden && popover.contains(event.target)) {
      return;
    }
    closeRowActionMenu();
    const corporaPopover = getCorporaPopover();
    if (corporaPopover && !corporaPopover.hidden && corporaPopover.contains(event.target)) {
      return;
    }
    closeCorporaPopover();
    const tagsPopover = getTagsPopover();
    if (tagsPopover && !tagsPopover.hidden && tagsPopover.contains(event.target)) {
      return;
    }
    closeTagsPopover();
    const symbolPopover = getSymbolPopover();
    if (symbolPopover && !symbolPopover.hidden && symbolPopover.contains(event.target)) {
      return;
    }
    closeSymbolPopover();
    const columnsPopover = getColumnsPopover();
    if (columnsPopover && !columnsPopover.hidden && columnsPopover.contains(event.target)) {
      return;
    }
    closeColumnsPopover();
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

function getUploadCorpusRoot() {
  return document.querySelector("[data-upload-corpus-root='1']");
}

function getUploadTagRoot() {
  return document.querySelector("[data-upload-tag-root='1']");
}

function parseUploadCorpusDataset(name) {
  const root = getUploadCorpusRoot();
  if (!root) return [];
  try {
    const value = JSON.parse(root.dataset[name] || "[]");
    return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean) : [];
  } catch (_) {
    return [];
  }
}

function parseUploadTagDataset(name) {
  const root = getUploadTagRoot();
  if (!root) return [];
  try {
    const value = JSON.parse(root.dataset[name] || "[]");
    return Array.isArray(value) ? value.map((item) => String(item || "").trim()).filter(Boolean) : [];
  } catch (_) {
    return [];
  }
}

function setUploadCorpusDataset(name, values) {
  const root = getUploadCorpusRoot();
  if (!root) return;
  root.dataset[name] = JSON.stringify(values);
}

function setUploadTagDataset(name, values) {
  const root = getUploadTagRoot();
  if (!root) return;
  root.dataset[name] = JSON.stringify(values);
}

function uploadCorpusLoadedQuery() {
  return String(getUploadCorpusRoot()?.dataset?.loadedQuery || "");
}

function uploadTagLoadedQuery() {
  return String(getUploadTagRoot()?.dataset?.loadedQuery || "");
}

function setUploadCorpusLoadedQuery(value) {
  const root = getUploadCorpusRoot();
  if (!root) return;
  root.dataset.loadedQuery = String(value || "");
}

function setUploadTagLoadedQuery(value) {
  const root = getUploadTagRoot();
  if (!root) return;
  root.dataset.loadedQuery = String(value || "");
}

function uploadCorpusPendingCreate() {
  const root = getUploadCorpusRoot();
  return String(root?.dataset?.pendingCreate || "").trim();
}

function uploadTagPendingCreate() {
  const root = getUploadTagRoot();
  return String(root?.dataset?.pendingCreate || "").trim();
}

function setUploadCorpusPendingCreate(value) {
  const root = getUploadCorpusRoot();
  if (!root) return;
  const normalized = String(value || "").trim();
  if (normalized) {
    root.dataset.pendingCreate = normalized;
  } else {
    delete root.dataset.pendingCreate;
  }
}

function setUploadTagPendingCreate(value) {
  const root = getUploadTagRoot();
  if (!root) return;
  const normalized = String(value || "").trim();
  if (normalized) {
    root.dataset.pendingCreate = normalized;
  } else {
    delete root.dataset.pendingCreate;
  }
}

function uploadCorpusOptions() {
  return parseUploadCorpusDataset("options");
}

function uploadTagOptions() {
  return parseUploadTagDataset("options");
}

function selectedUploadCorpusValues() {
  return parseUploadCorpusDataset("selected");
}

function selectedUploadTagValues() {
  return parseUploadTagDataset("selected");
}

function setSelectedUploadCorpusValues(values) {
  const unique = Array.from(
    new Set(
      [DEFAULT_UPLOAD_CORPUS, ...(values || [])]
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    )
  );
  setUploadCorpusDataset("selected", unique);
  renderUploadCorpusPicker();
}

function setSelectedUploadTagValues(values) {
  const unique = Array.from(
    new Set(
      (values || [])
        .map((value) => String(value || "").trim())
        .filter(Boolean)
    )
  );
  setUploadTagDataset("selected", unique);
  renderUploadTagPicker();
}

function setUploadCorpusOptions(values) {
  const unique = Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean)));
  setUploadCorpusDataset("options", unique);
}

function setUploadTagOptions(values) {
  const unique = Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean)));
  setUploadTagDataset("options", unique);
}

async function loadUploadCorpora(query = "", force = false) {
  const root = getUploadCorpusRoot();
  if (!root) return;
  const normalizedQuery = String(query || "").trim();
  const requestKey = normalizedQuery.toLowerCase();
  if (uploadCorporaRequests.has(requestKey)) return;
  if (!force && uploadCorpusLoadedQuery() === normalizedQuery) return;
  uploadCorporaRequests.add(requestKey);
  try {
    const payload = await fetchJsonWithCredentials(`/api/v1/corpora?q=${encodeURIComponent(normalizedQuery)}`);
    setUploadCorpusOptions(Array.isArray(payload) ? payload : []);
    setUploadCorpusLoadedQuery(normalizedQuery);
    renderUploadCorpusPicker();
  } catch (error) {
    console.error("binlex-web upload corpora search failed", error);
  } finally {
    uploadCorporaRequests.delete(requestKey);
  }
}

const uploadTagRequests = new Set();
let uploadTagSearchHandle = null;

async function loadUploadTags(query = "", force = false) {
  const root = getUploadTagRoot();
  if (!root) return;
  const normalizedQuery = String(query || "").trim();
  const requestKey = normalizedQuery.toLowerCase();
  if (uploadTagRequests.has(requestKey)) return;
  if (!force && uploadTagLoadedQuery() === normalizedQuery) return;
  uploadTagRequests.add(requestKey);
  try {
    const payload = await fetchJsonWithCredentials(`/api/v1/tags/search?q=${encodeURIComponent(normalizedQuery)}`);
    const items = Array.isArray(payload?.tags) ? payload.tags : [];
    setUploadTagOptions(items);
    setUploadTagLoadedQuery(normalizedQuery);
    renderUploadTagPicker();
  } catch (error) {
    console.error("binlex-web upload tags search failed", error);
  } finally {
    uploadTagRequests.delete(requestKey);
  }
}

function findUploadCorpusByName(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return null;
  return uploadCorpusOptions().find((option) => option.toLowerCase() === normalized) || null;
}

function findUploadTagByName(value) {
  const normalized = String(value || "").trim().toLowerCase();
  if (!normalized) return null;
  return uploadTagOptions().find((option) => option.toLowerCase() === normalized) || null;
}

function availableUploadCorpusQuery() {
  const input = document.getElementById("upload-corpus-available-search");
  return String(input?.value || "").trim();
}

function selectedUploadCorpusQuery() {
  const input = document.getElementById("upload-corpus-selected-search");
  return String(input?.value || "").trim();
}

function availableUploadTagQuery() {
  const input = document.getElementById("upload-tag-available-search");
  return String(input?.value || "").trim();
}

function selectedUploadTagQuery() {
  const input = document.getElementById("upload-tag-selected-search");
  return String(input?.value || "").trim();
}

function filteredAvailableUploadCorpora() {
  const selected = new Set(selectedUploadCorpusValues());
  const needle = availableUploadCorpusQuery().toLowerCase();
  return uploadCorpusOptions()
    .filter((value) => value.toLowerCase() !== DEFAULT_UPLOAD_CORPUS)
    .filter((value) => !selected.has(value))
    .filter((value) => value.toLowerCase().includes(needle));
}

function filteredSelectedUploadCorpora() {
  const needle = selectedUploadCorpusQuery().toLowerCase();
  return selectedUploadCorpusValues().filter((value) => value.toLowerCase().includes(needle));
}

function filteredAvailableUploadTags() {
  const selected = new Set(selectedUploadTagValues());
  const needle = availableUploadTagQuery().toLowerCase();
  return uploadTagOptions()
    .filter((value) => !selected.has(value))
    .filter((value) => value.toLowerCase().includes(needle));
}

function filteredSelectedUploadTags() {
  const needle = selectedUploadTagQuery().toLowerCase();
  return selectedUploadTagValues().filter((value) => value.toLowerCase().includes(needle));
}

function shouldOfferUploadCorpusCreate() {
  const typed = availableUploadCorpusQuery();
  return !!typed && !findUploadCorpusByName(typed) && filteredAvailableUploadCorpora().length === 0;
}

function shouldOfferUploadTagCreate() {
  const typed = availableUploadTagQuery();
  return !!typed && !findUploadTagByName(typed) && filteredAvailableUploadTags().length === 0;
}

function corpusButtonHtml(value, direction, active, handler) {
  const arrow = direction === "selected" ? "&larr;" : "&rarr;";
  const activeClass = active ? " active" : "";
  return `<div class="upload-corpus-item${activeClass}"><span class="upload-corpus-item-name" title="${escapeHtml(value)}">${escapeHtml(value)}</span><div class="upload-corpus-item-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button><button type="button" class="symbol-picker-move" onclick="${handler}('${encodeURIComponent(value)}')">${arrow}</button></div></div>`;
}

function renderUploadCorpusPicker() {
  const root = getUploadCorpusRoot();
  if (!root) return;
  const availableList = document.getElementById("upload-corpus-available-list");
  const selectedList = document.getElementById("upload-corpus-selected-list");
  if (!(availableList instanceof HTMLElement) || !(selectedList instanceof HTMLElement)) return;
  const available = filteredAvailableUploadCorpora();
  const selected = filteredSelectedUploadCorpora();
  availableList.innerHTML = available.map((value, index) => corpusButtonHtml(value, "available", index === 0, "selectUploadCorpus")).join("");
  selectedList.innerHTML = selected.length === 0
    ? '<div class="upload-corpus-empty">No selected corpora.</div>'
    : selected.map((value, index) => corpusButtonHtml(value, "selected", index === 0, "unselectUploadCorpus")).join("");
  renderUploadCorpusCreatePrompt();
  renderUploadCorpusCreateInline();
}

function renderUploadTagPicker() {
  const root = getUploadTagRoot();
  if (!root) return;
  const availableList = document.getElementById("upload-tag-available-list");
  const selectedList = document.getElementById("upload-tag-selected-list");
  if (!(availableList instanceof HTMLElement) || !(selectedList instanceof HTMLElement)) return;
  const available = filteredAvailableUploadTags();
  const selected = filteredSelectedUploadTags();
  availableList.innerHTML = available.map((value, index) => corpusButtonHtml(value, "available", index === 0, "selectUploadTag")).join("");
  selectedList.innerHTML = selected.length === 0
    ? '<div class="upload-corpus-empty">No tags selected.</div>'
    : selected.map((value, index) => corpusButtonHtml(value, "selected", index === 0, "unselectUploadTag")).join("");
  renderUploadTagCreatePrompt();
  renderUploadTagCreateInline();
}

function selectUploadCorpus(encodedValue) {
  const decoded = decodeURIComponent(String(encodedValue || ""));
  const value = findUploadCorpusByName(decoded) || decoded.trim();
  if (!value) return;
  const next = selectedUploadCorpusValues();
  if (!next.includes(value)) {
    next.push(value);
  }
  setSelectedUploadCorpusValues(next);
}

function unselectUploadCorpus(encodedValue) {
  const value = decodeURIComponent(String(encodedValue || "")).trim();
  if (!value) return;
  if (value.toLowerCase() === DEFAULT_UPLOAD_CORPUS) return;
  setSelectedUploadCorpusValues(selectedUploadCorpusValues().filter((item) => item !== value));
}

function selectUploadTag(encodedValue) {
  const decoded = decodeURIComponent(String(encodedValue || ""));
  const value = findUploadTagByName(decoded) || decoded.trim();
  if (!value) return;
  const next = selectedUploadTagValues();
  if (!next.includes(value)) {
    next.push(value);
  }
  setSelectedUploadTagValues(next);
}

function unselectUploadTag(encodedValue) {
  const value = decodeURIComponent(String(encodedValue || "")).trim();
  if (!value) return;
  setSelectedUploadTagValues(selectedUploadTagValues().filter((item) => item !== value));
}

function handleUploadCorpusAvailableKeydown(event) {
  if (event.key !== "Enter") return;
  event.preventDefault();
  const available = filteredAvailableUploadCorpora();
  if (available.length > 0) {
    selectUploadCorpus(encodeURIComponent(available[0]));
    return;
  }
  if (!shouldOfferUploadCorpusCreate()) {
    return;
  }
  promptCreateUploadCorpus();
}

function handleUploadCorpusSelectedKeydown(event) {
  if (event.key !== "Enter") return;
  event.preventDefault();
  const selected = filteredSelectedUploadCorpora();
  if (selected.length > 0) {
    unselectUploadCorpus(encodeURIComponent(selected[0]));
  }
}

function handleUploadTagAvailableKeydown(event) {
  if (event.key !== "Enter") return;
  event.preventDefault();
  const available = filteredAvailableUploadTags();
  if (available.length > 0) {
    selectUploadTag(encodeURIComponent(available[0]));
    return;
  }
  if (!shouldOfferUploadTagCreate()) {
    return;
  }
  promptCreateUploadTag();
}

function handleUploadTagSelectedKeydown(event) {
  if (event.key !== "Enter") return;
  event.preventDefault();
  const selected = filteredSelectedUploadTags();
  if (selected.length > 0) {
    unselectUploadTag(encodeURIComponent(selected[0]));
  }
}

function renderUploadCorpusCreatePrompt() {
  const overlay = document.getElementById("upload-corpus-create-overlay");
  const prompt = document.getElementById("upload-corpus-create-prompt");
  const text = document.getElementById("upload-corpus-create-text");
  if (!(overlay instanceof HTMLElement) || !(prompt instanceof HTMLElement) || !(text instanceof HTMLElement)) return;
  const value = uploadCorpusPendingCreate();
  if (!value) {
    overlay.hidden = true;
    text.textContent = "";
    return;
  }
  overlay.hidden = false;
  text.textContent = `Create corpus "${value}"?`;
}

function renderUploadCorpusCreateInline() {
  const button = document.getElementById("upload-corpus-create-inline");
  if (!(button instanceof HTMLButtonElement)) return;
  const enabled = shouldOfferUploadCorpusCreate();
  button.disabled = !enabled;
  button.setAttribute("aria-disabled", enabled ? "false" : "true");
}

function renderUploadTagCreatePrompt() {
  const overlay = document.getElementById("upload-tag-create-overlay");
  const prompt = document.getElementById("upload-tag-create-prompt");
  const text = document.getElementById("upload-tag-create-text");
  if (!(overlay instanceof HTMLElement) || !(prompt instanceof HTMLElement) || !(text instanceof HTMLElement)) return;
  const value = uploadTagPendingCreate();
  if (!value) {
    overlay.hidden = true;
    text.textContent = "";
    return;
  }
  overlay.hidden = false;
  text.textContent = `Create tag "${value}"?`;
}

function renderUploadTagCreateInline() {
  const button = document.getElementById("upload-tag-create-inline");
  if (!(button instanceof HTMLButtonElement)) return;
  const enabled = shouldOfferUploadTagCreate();
  button.disabled = !enabled;
  button.setAttribute("aria-disabled", enabled ? "false" : "true");
}

function handleUploadCorpusAvailableInput() {
  const typed = availableUploadCorpusQuery();
  if (!typed || findUploadCorpusByName(typed)) {
    setUploadCorpusPendingCreate("");
  } else if (uploadCorpusPendingCreate() && uploadCorpusPendingCreate().toLowerCase() !== typed.toLowerCase()) {
    setUploadCorpusPendingCreate("");
  }
  renderUploadCorpusPicker();
  if (uploadCorporaSearchHandle) {
    clearTimeout(uploadCorporaSearchHandle);
  }
  uploadCorporaSearchHandle = setTimeout(() => {
    uploadCorporaSearchHandle = null;
    loadUploadCorpora(typed).catch((error) => console.error("binlex-web upload corpora search failed", error));
  }, 180);
}

function handleUploadTagAvailableInput() {
  const typed = availableUploadTagQuery();
  if (!typed || findUploadTagByName(typed)) {
    setUploadTagPendingCreate("");
  } else if (uploadTagPendingCreate() && uploadTagPendingCreate().toLowerCase() !== typed.toLowerCase()) {
    setUploadTagPendingCreate("");
  }
  renderUploadTagPicker();
  if (uploadTagSearchHandle) {
    clearTimeout(uploadTagSearchHandle);
  }
  uploadTagSearchHandle = setTimeout(() => {
    uploadTagSearchHandle = null;
    loadUploadTags(typed).catch((error) => console.error("binlex-web upload tags search failed", error));
  }, 180);
}

function promptCreateUploadCorpus() {
  const typed = availableUploadCorpusQuery();
  if (!shouldOfferUploadCorpusCreate()) return;
  setUploadCorpusPendingCreate(typed);
  renderUploadCorpusCreatePrompt();
}

function promptCreateUploadTag() {
  const typed = availableUploadTagQuery();
  if (!shouldOfferUploadTagCreate()) return;
  setUploadTagPendingCreate(typed);
  renderUploadTagCreatePrompt();
}

async function confirmCreateUploadCorpus() {
  const typed = uploadCorpusPendingCreate();
  const value = String(typed || "").trim();
  if (!value) return;
  try {
    await postJsonWithCredentials("/api/v1/corpora/add", { corpus: value });
    setUploadCorpusPendingCreate("");
    const input = document.getElementById("upload-corpus-available-search");
    if (input instanceof HTMLInputElement) {
      input.value = value;
    }
    setUploadCorpusLoadedQuery("");
    await loadUploadCorpora(value, true);
    renderUploadCorpusPicker();
    syncUploadState();
  } catch (error) {
    console.error("binlex-web upload corpus create failed", error);
  }
}

async function confirmCreateUploadTag() {
  const typed = uploadTagPendingCreate();
  const value = String(typed || "").trim();
  if (!value) return;
  try {
    await postJsonWithCredentials("/api/v1/tags/add", { tag: value });
    setUploadTagPendingCreate("");
    const input = document.getElementById("upload-tag-available-search");
    if (input instanceof HTMLInputElement) {
      input.value = value;
    }
    setUploadTagLoadedQuery("");
    await loadUploadTags(value, true);
    renderUploadTagPicker();
    syncUploadState();
  } catch (error) {
    console.error("binlex-web upload tag create failed", error);
  }
}

function cancelCreateUploadCorpus() {
  setUploadCorpusPendingCreate("");
  renderUploadCorpusPicker();
}

function cancelCreateUploadTag() {
  setUploadTagPendingCreate("");
  renderUploadTagPicker();
}

function clearActiveModalSelect(except = null) {
  document.querySelectorAll(".modal-select.is-active").forEach((root) => {
    if (root === except) return;
    root.classList.remove("is-active");
    root.style.removeProperty("z-index");
  });
}

function closeSiblingModalSelects(activeRoot) {
  if (!(activeRoot instanceof HTMLElement)) return;
  const scope = activeRoot.closest("#upload-modal") || document;
  scope.querySelectorAll(".modal-select[open]").forEach((root) => {
    if (root === activeRoot) return;
    root.open = false;
    if (root instanceof HTMLElement) {
      root.classList.remove("is-active");
      root.style.removeProperty("z-index");
    }
  });
}

function activateModalSelect(root) {
  if (!(root instanceof HTMLElement) || !root.classList.contains("modal-select")) return;
  closeSiblingModalSelects(root);
  clearActiveModalSelect(root);
  root.classList.add("is-active");
  root.style.zIndex = MODAL_SELECT_ACTIVE_Z_INDEX;
}

function initializeModalSelectStacking() {
  document.querySelectorAll(".modal-select").forEach((root) => {
    if (!(root instanceof HTMLElement) || root.dataset.stackInstalled === "1") return;
    root.dataset.stackInstalled = "1";
    root.addEventListener("click", (event) => {
      if (!(event.target instanceof HTMLElement)) return;
      if (!root.contains(event.target)) return;
      activateModalSelect(root);
    });
    root.addEventListener("toggle", () => {
      if (root.open) {
        activateModalSelect(root);
      } else {
        root.classList.remove("is-active");
        root.style.removeProperty("z-index");
      }
    });
  });
}

function openUploadModal() {
  const modal = document.getElementById("upload-modal");
  if (!modal) return;
  modal.hidden = false;
  installDropzone();
  const uploadMetadataRoot = document.querySelector("[data-upload-metadata-root='1']");
  if (uploadMetadataRoot instanceof HTMLElement) {
    toggleUploadMetadataTab(String(uploadMetadataRoot.dataset.activeTab || "tags"));
  }
  renderUploadCorpusPicker();
  loadUploadCorpora("", true).catch((error) => console.error("binlex-web upload corpora search failed", error));
  renderUploadTagPicker();
  loadUploadTags("", true).catch((error) => console.error("binlex-web upload tags search failed", error));
  updateUploadModalState();
}

function toggleUploadMetadataTab(tab) {
  const root = document.querySelector("[data-upload-metadata-root='1']");
  if (!(root instanceof HTMLElement)) return;
  const normalized = String(tab || "tags").toLowerCase() === "corpora" ? "corpora" : "tags";
  root.dataset.activeTab = normalized;
  root.querySelectorAll("[data-upload-metadata-tab]").forEach((button) => {
    if (!(button instanceof HTMLElement)) return;
    button.classList.toggle("is-active", String(button.dataset.uploadMetadataTab || "") === normalized);
  });
  root.querySelectorAll("[data-upload-metadata-panel]").forEach((panel) => {
    if (!(panel instanceof HTMLElement)) return;
    panel.hidden = String(panel.dataset.uploadMetadataPanel || "") !== normalized;
  });
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
  const searchButton = document.getElementById("upload-status-search");
  if (!modal || !icon || !title || !text || !extra || !closeButton || !searchButton) return;

  icon.classList.remove("uploading", "success", "failed");
  icon.classList.add(state === "success" || state === "failed" ? state : "uploading");
  modal.hidden = false;
  extra.innerHTML = "";
  closeButton.hidden = state === "uploading" || state === "pending" || state === "processing";
  searchButton.hidden = true;
  searchButton.dataset.sha256 = "";

  if (state === "uploading") {
    title.textContent = "Uploading Sample";
    text.textContent = "Binlex Web is uploading and processing the sample.";
  } else if (state === "pending") {
    title.textContent = "Analysis Pending";
    text.textContent = "The sample was uploaded successfully. Binlex Web accepted analysis and is waiting for processing to begin.";
    if (payload.sha256) {
      extra.innerHTML = renderUploadStatusSha(payload.sha256);
    }
  } else if (state === "processing") {
    title.textContent = "Analyzing Sample";
    text.textContent = "Binlex Web is analyzing and indexing the sample now.";
    if (payload.sha256) {
      extra.innerHTML = renderUploadStatusSha(payload.sha256);
    }
  } else if (state === "success") {
    title.textContent = "Analysis Complete";
    text.textContent = "The sample was uploaded, analyzed, and indexed successfully.";
    if (payload.sha256) {
      extra.innerHTML = renderUploadStatusSha(payload.sha256);
      searchButton.hidden = false;
      searchButton.dataset.sha256 = payload.sha256;
    }
  } else {
    title.textContent = "Upload Failed";
    text.textContent = payload.error || "The upload failed.";
    if (payload.sha256) {
      extra.innerHTML = renderUploadStatusSha(payload.sha256);
    }
  }
}

function renderUploadStatusSha(sha256) {
  return `<div class="upload-status-sha"><span>SHA256</span><div class="upload-status-sha-row"><code id="upload-status-sha-value">${escapeHtml(sha256)}</code><button type="button" class="row-actions-trigger upload-status-copy" onclick="copyUploadSha(this)" data-sha256="${escapeHtml(sha256)}">Copy</button></div></div>`;
}

let uploadStatusPollToken = 0;

function stopUploadStatusPolling() {
  uploadStatusPollToken += 1;
}

function startUploadStatusPolling(sha256) {
  stopUploadStatusPolling();
  if (!sha256) return;
  const token = uploadStatusPollToken;
  pollUploadStatus(sha256, token);
}

async function pollUploadStatus(sha256, token) {
  if (!sha256 || token !== uploadStatusPollToken) return;
  try {
    const response = await fetch(`/api/v1/upload/status?sha256=${encodeURIComponent(sha256)}`, {
      method: "GET",
      headers: {
        Accept: "application/json",
      },
      cache: "no-store",
    });
    if (!response.ok) {
      if (token === uploadStatusPollToken) {
        setTimeout(() => pollUploadStatus(sha256, token), 1000);
      }
      return;
    }
    const payload = await response.json();
    if (token !== uploadStatusPollToken) return;
    if (payload.status === "pending") {
      openUploadStatusModal("pending", { sha256 });
      setTimeout(() => pollUploadStatus(sha256, token), 1000);
      return;
    }
    if (payload.status === "processing") {
      openUploadStatusModal("processing", { sha256 });
      setTimeout(() => pollUploadStatus(sha256, token), 1200);
      return;
    }
    if (payload.status === "complete") {
      openUploadStatusModal("success", { sha256 });
      return;
    }
    if (payload.status === "failed") {
      openUploadStatusModal("failed", {
        sha256,
        error: payload.error_message || "The upload failed.",
      });
      return;
    }
    setTimeout(() => pollUploadStatus(sha256, token), 1000);
  } catch (_) {
    if (token === uploadStatusPollToken) {
      setTimeout(() => pollUploadStatus(sha256, token), 1000);
    }
  }
}

function closeUploadStatusModal() {
  const modal = document.getElementById("upload-status-modal");
  if (!modal) return;
  modal.hidden = true;
  stopUploadStatusPolling();
}

function searchUploadedSample() {
  const button = document.getElementById("upload-status-search");
  const queryInput = getQueryInput();
  const form = getSearchForm();
  const sha256 = button?.dataset?.sha256 || "";
  if (!sha256 || !(queryInput instanceof HTMLInputElement) || !(form instanceof HTMLFormElement)) {
    return;
  }
  queryInput.value = `sample:${sha256}`;
  clearCommittedQueryClause(queryInput);
  const pageInput = getPageInput();
  if (pageInput) pageInput.value = "1";
  syncSearchState();
  closeUploadStatusModal();
  form.requestSubmit();
}

async function copyUploadSha(button) {
  const sha256 = button?.dataset?.sha256 || "";
  if (!sha256 || !(button instanceof HTMLButtonElement)) return;
  try {
    await navigator.clipboard.writeText(sha256);
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

function setUploadedSha256State(sha256) {
  document.querySelectorAll('input[name="uploaded_sha256"]').forEach((item) => item.remove());
  if (!sha256) return;
  ["search-form"].forEach((id) => {
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
  const format = document.querySelector('input[name="upload-format"]:checked')?.value || "Auto";
  const arch = document.querySelector('input[name="upload-architecture"]:checked')?.value || "Auto";
  const formatTarget = document.getElementById("upload-format");
  const archTarget = document.getElementById("upload-architecture");
  if (formatTarget) formatTarget.value = format === "Auto" ? "" : format;
  if (archTarget) archTarget.value = arch === "Auto" ? "" : arch;
  const form = document.getElementById("upload-form");
  if (!(form instanceof HTMLFormElement)) return;
  const formData = new FormData(form);
  formData.delete("corpus");
  selectedUploadCorpusValues().forEach((value) => {
    formData.append("corpus", value);
  });
  formData.delete("tag");
  selectedUploadTagValues().forEach((value) => {
    formData.append("tag", value);
  });
  const submit = document.getElementById("upload-submit");
  if (submit) submit.disabled = true;
  closeUploadModal();
  openUploadStatusModal("uploading");
  try {
    const response = await fetch("/api/v1/upload/sample", {
      method: "POST",
      body: formData,
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      openUploadStatusModal("failed", { error: payload.error || "The upload failed." });
      return;
    }
    setUploadedSha256State(payload.sha256 || "");
    openUploadStatusModal("pending", { sha256: payload.sha256 || "" });
    startUploadStatusPolling(payload.sha256 || "");
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
    if (!(event.target instanceof Element) || !event.target.closest(".modal-select")) {
      clearActiveModalSelect();
    }
  });

  document.addEventListener("submit", (event) => {
    handleEnhancedFormSubmit(event);
  });

  document.addEventListener("DOMContentLoaded", () => {
    initializeSearchPage();
    initializeModalSelectStacking();
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
const DEFAULT_UPLOAD_CORPUS = "default";
