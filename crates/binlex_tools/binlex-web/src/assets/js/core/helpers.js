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
  { label: "username:", insert: "username:", kind: "field", usage: "username:alice", description: "Filter by the indexing username" },
  { label: "address:", insert: "address:", kind: "field", usage: "address:0x401000", description: "Filter by exact address" },
  { label: "date:", insert: "date:", kind: "field", usage: "date:>=2026-03-01", description: "Filter by indexed UTC date or date range bounds" },
  { label: "size:", insert: "size:", kind: "field", usage: "size:>1mb", description: "Filter by instruction, block, or function byte size" },
  { label: "symbol:", insert: "symbol:", kind: "field", usage: "symbol:\"kernel32:CreateFileW\"", description: "Filter by quoted fuzzy symbol name matches" },
  { label: "tag:", insert: "tag:", kind: "field", usage: "tag:malware:emotet", description: "Filter by exact entity tag name" },
  { label: "symbols:", insert: "symbols:", kind: "field", usage: "symbols:>0", description: "Filter by the number of entity symbols" },
  { label: "tags:", insert: "tags:", kind: "field", usage: "tags:>0", description: "Filter by the number of entity tags" },
  { label: "comments:", insert: "comments:", kind: "field", usage: "comments:>0", description: "Filter by the number of entity comments" },
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
let tagSuggestionAbort = null;
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
let activeCommentsTrigger = null;
let activeCommentsResultKey = null;
let activePickerTooltipHost = null;
const QUERY_COMMIT_DATASET_KEY = "committedQueryClause";
let queryAssistantUpdateHandle = null;
const MODAL_SELECT_ACTIVE_Z_INDEX = "120";
const tagRowRequests = new Set();
const tagSearchRequests = new Set();
const symbolRowRequests = new Set();
const symbolSearchRequests = new Set();
const corporaRowRequests = new Set();
const corporaSearchRequests = new Set();
const RESULT_COLUMNS_STORAGE_KEY = "binlex-web-result-columns-v2";
const TAGS_POPOVER_VISIBLE_LIMIT = 6;
const COMMENTS_PAGE_SIZE = 20;
const COMMENT_MAX_LENGTH = 2048;
let activeColumnsTrigger = null;
const LOCKED_CORE_CORPORA = new Set(["default", "goodware", "malware"]);

function isAdmin() {
  return String(globalThis.__BINLEX_AUTH__?.role || "").toLowerCase() === "admin";
}

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

function getCommentsPopover() {
  return document.getElementById("comments-popover");
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
