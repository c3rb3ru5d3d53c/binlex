function resultCorpora(row) {
  return Array.isArray(row?.corpora)
    ? row.corpora.map((item) => metadataItemName(item)).filter(Boolean)
    : [];
}

function canWrite() {
  return !!globalThis.__BINLEX_AUTH__?.can_write;
}

function displayCorpora(row) {
  return resultCorpora(row).join(", ");
}

function primaryCorpus(row) {
  return resultCorpora(row)[0] || "";
}

function buildResultJsonUrl(row) {
  return `/api/v1/download/json?corpus=${urlEncode(primaryCorpus(row))}&sha256=${urlEncode(row.sha256)}&collection=${urlEncode(row.collection)}&address=${Number(row.address)}`;
}

function buildYaraActionRequest(query, rows) {
  return JSON.stringify({
    query: String(query || ""),
    items: (rows || []).map((row) => ({
      corpus: primaryCorpus(row),
      sha256: row.sha256 || "",
      collection: row.collection || "",
      architecture: row.architecture || "",
      address: Number(row.address || 0),
    })),
  });
}

function serializeCorpora(values) {
  try {
    return escapeHtml(JSON.stringify(Array.isArray(values) ? values : []));
  } catch (_) {
    return "[]";
  }
}

async function copyResultPill(button, encodedValue) {
  if (!(button instanceof HTMLElement)) return;
  const value = decodeURIComponent(String(encodedValue || ""));
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.classList.remove("action-feedback");
    }, 900);
  } catch (_) {}
}

function usernameTooltipHtml(row) {
  const username = String(row?.username || "").trim();
  if (!username) return "";
  const html = metadataTooltipEntryHtml(
    {
      username,
      profile_picture: String(row?.profile_picture || "").trim() || null,
    },
    "Indexed by",
    row?.timestamp || "",
  );
  if (!html) return "";
  return `<span class="picker-tooltip-anchor" hidden data-picker-tooltip="${escapeHtml(encodeURIComponent(html))}"></span>`;
}

function renderResultCopyPill(displayValue, copyValue, options = {}) {
  const display = String(displayValue ?? "").trim();
  const copy = String(copyValue ?? "").trim();
  if (!display || !copy) return "";
  const tooltipHtml = options.tooltipHtml || "";
  const classes = `result-copy-pill${tooltipHtml ? " has-tooltip" : ""}${options.className ? ` ${options.className}` : ""}`;
  const title = tooltipHtml ? "" : (options.title || `${copy}\nClick to copy`);
  const titleAttr = title ? ` title="${escapeHtml(title)}"` : "";
  return `<button type="button" class="${classes}"${titleAttr} onclick="event.stopPropagation(); copyResultPill(this,'${escapeHtml(encodeURIComponent(copy))}')">${escapeHtml(display)}${tooltipHtml}</button>`;
}

function renderCorporaCell(row) {
  const resultKey = resultRowKey(row);
  const count = Array.isArray(row?.corpora) ? row.corpora.length : 0;
  const triggerLabel = count > 0 ? `+${count}` : "+";
  if (!canWrite()) {
    return `<div class="corpora-cell"><span class="corpora-popover-trigger readonly-count">${escapeHtml(triggerLabel)}</span></div>`;
  }
  return `<div class="corpora-cell"><button type="button" class="corpora-popover-trigger" data-result-key="${escapeHtml(resultKey)}" onclick="event.stopPropagation(); toggleCorporaPopover(this)">${escapeHtml(triggerLabel)}</button></div>`;
}

function renderTagsCell(row) {
  const resultKey = resultRowKey(row);
  const count = Number(row?.collection_tag_count || 0);
  const triggerLabel = count > 0 ? `+${count}` : "+";
  if (!canWrite()) {
    return `<div class="tags-cell"><span class="tags-popover-trigger readonly-count">${escapeHtml(triggerLabel)}</span></div>`;
  }
  return `<div class="tags-cell"><button type="button" class="tags-popover-trigger" data-result-key="${escapeHtml(resultKey)}" onclick="event.stopPropagation(); toggleTagsPopover(this)">${escapeHtml(triggerLabel)}</button></div>`;
}

function rowSymbolEntries(row) {
  const loaded = Array.isArray(row?.symbols)
    ? row.symbols.map((symbol) => metadataItemName(symbol)).filter(Boolean)
    : [];
  if (loaded.length > 0) {
    return loaded.filter((symbol, index, items) => items.findIndex((candidate) => candidate.toLowerCase() === symbol.toLowerCase()) === index);
  }
  const primary = String(row?.symbol || "").trim();
  return primary && primary !== "-" ? [primary] : [];
}

function renderSymbolCell(row) {
  const resultKey = resultRowKey(row);
  const applied = rowSymbolEntries(row);
  const count = applied.length;
  const triggerLabel = count > 0 ? `+${count}` : "+";
  if (!canWrite()) {
    return `<div class="symbol-cell"><span class="symbol-popover-trigger readonly-count">${escapeHtml(triggerLabel)}</span></div>`;
  }
  return `<div class="symbol-cell"><button type="button" class="symbol-popover-trigger" data-result-key="${escapeHtml(resultKey)}" onclick="event.stopPropagation(); toggleSymbolPopover(this)">${escapeHtml(triggerLabel)}</button></div>`;
}

function renderCommentsCell(row) {
  const resultKey = resultRowKey(row);
  const count = Number(row?.collection_comment_count || 0);
  const triggerLabel = count > 0 ? `+${count}` : "+";
  return `<div class="comments-cell"><button type="button" class="comments-popover-trigger" data-result-key="${escapeHtml(resultKey)}" onclick="event.stopPropagation(); toggleCommentsPopover(this)">${escapeHtml(triggerLabel)}</button></div>`;
}

function formatScoreValue(score) {
  if (score == null || !Number.isFinite(Number(score))) return "";
  const value = Number(score);
  if (value === 1) return "1.00000000";
  if (value > 0.9999) return value.toFixed(8);
  if (value > 0.99) return value.toFixed(6);
  return value.toFixed(4);
}

function renderResultsCsv(rows) {
  const lines = [[
    "side",
    "date",
    "size",
    "score",
    "embeddings",
    "embedding",
    "instructions",
    "blocks",
    "markov",
    "contiguous",
    "corpus",
    "architecture",
    "username",
    "sha256",
    "collection",
    "address",
    "symbol",
  ].join(",")];
  (rows || []).forEach((row) => {
    lines.push([
      csvCell(row.side),
      csvCell(row.timestamp),
      csvCell(String(row.size ?? 0)),
      csvCell(String(row.score ?? row.similarity_score ?? "")),
      csvCell(String(row.embeddings ?? 0)),
      csvCell(row.embedding),
      csvCell(row.collection === "function" || row.collection === "block" ? String(row.number_of_instructions ?? "") : ""),
      csvCell(row.collection === "function" ? String(row.number_of_blocks ?? "") : ""),
      csvCell(row.collection === "block" && row.markov != null ? formatMetricFloat(row.markov) : ""),
      csvCell(row.contiguous == null ? "" : (row.contiguous ? "true" : "false")),
      csvCell(displayCorpora(row)),
      csvCell(row.architecture),
      csvCell(row.username || ""),
      csvCell(row.sha256),
      csvCell(row.collection),
      csvCell(`0x${Number(row.address).toString(16)}`),
      csvCell(row.symbol || ""),
    ].join(","));
  });
  return lines.join("\n");
}

function buildResultActionTree(row, sampleDownloadsEnabled, query) {
  const copyChildren = [];
  if (primaryCorpus(row)) {
    copyChildren.push(actionFetchCopyJson("JSON", buildResultJsonUrl(row)));
  }
  if (Array.isArray(row.vector) && row.vector.length > 0) {
    copyChildren.push(actionLeaf("Vector", JSON.stringify(row.vector)));
  }
  copyChildren.push(actionLeaf("Score", formatScoreValue(row.score ?? row.similarity_score)));
  copyChildren.push(actionLeaf("Embeddings", String(row.embeddings ?? 0)));
  copyChildren.push(actionLeaf("Size", String(row.size ?? 0)));
  copyChildren.push(actionLeaf("Address", `0x${Number(row.address).toString(16)}`));
  copyChildren.push(actionLeaf("Timestamp", row.timestamp || ""));
  copyChildren.push(actionLeaf("Username", row.username || ""));
  copyChildren.push(actionLeaf("Sample SHA256", row.sha256 || ""));
  copyChildren.push(actionLeaf("Embedding", row.embedding || ""));
  copyChildren.push(actionLeaf("Corpora", displayCorpora(row)));
  copyChildren.push(actionLeaf("Architecture", row.architecture || ""));
  if (row.symbol && row.symbol !== "-") {
    copyChildren.push(actionLeaf("Symbol", row.symbol));
  }
  if (row?.contiguous === true) {
    copyChildren.push(actionFetchCopyText(
      "YARA",
      "/api/v1/action/yara",
      "POST",
      buildYaraActionRequest(query, [row]),
      "application/json",
      "text/plain"
    ));
  }
  const chromosome = row?.json?.chromosome;
  if (chromosome && typeof chromosome === "object") {
    const chromosomeChildren = [];
    if (typeof chromosome.pattern === "string") chromosomeChildren.push(actionLeaf("Pattern", chromosome.pattern));
    if (typeof chromosome.minhash === "string") chromosomeChildren.push(actionLeaf("Minhash", chromosome.minhash));
    if (typeof chromosome.tlsh === "string") chromosomeChildren.push(actionLeaf("TLSH", chromosome.tlsh));
    if (typeof chromosome.sha256 === "string") chromosomeChildren.push(actionLeaf("SHA256", chromosome.sha256));
    if (chromosomeChildren.length > 0) {
      copyChildren.push(actionBranch("Chromosome", chromosomeChildren));
    }
  }
  const root = [];
  if (copyChildren.length > 0) {
    root.push(actionBranch("Copy", copyChildren));
  }
  root.push(actionBranch("Search", [
    actionSearchQuery("Embedding", `embedding:${row.embedding} | collection:${row.collection} | architecture:${row.architecture}`),
    actionSearchQuery("Sample", `sample:${row.sha256} | collection:${row.collection} | architecture:${row.architecture}`),
    actionSearchQuery("Vector", `vector:${JSON.stringify(row.vector || [])} | collection:${row.collection} | architecture:${row.architecture}`),
  ]));
  const downloadChildren = [];
  if (sampleDownloadsEnabled) {
    downloadChildren.push(actionDownload("Sample", `/api/v1/download/sample?sha256=${urlEncode(row.sha256)}`));
  }
  if (primaryCorpus(row)) {
    downloadChildren.push(actionDownload("JSON", buildResultJsonUrl(row)));
  }
  if (downloadChildren.length > 0) {
    root.push(actionBranch("Download", downloadChildren));
  }
  const key = resultRowKey(row);
  root.push(actionExpand("Expand", key));
  root.push(actionCollapse("Collapse", key));
  return root;
}

function buildGlobalResultsActionTree(rows, sampleDownloadsEnabled, query) {
  if (!Array.isArray(rows) || rows.length === 0) return [];
  const csv = renderResultsCsv(rows);
  const json = JSON.stringify(rows, null, 2);
  const sha256 = uniqueValues(rows.map((row) => row.sha256)).join("\n");
  const embedding = uniqueValues(rows.map((row) => row.embedding)).join("\n");
  const contiguousRows = rows.filter((row) => row?.contiguous === true);
  const copyChildren = [
    actionCopy("CSV", csv),
    actionCopy("JSON", json),
    actionCopy("Sample SHA256", sha256),
    actionCopy("Embedding", embedding),
  ];
  if (contiguousRows.length > 0) {
    copyChildren.push(actionFetchCopyText(
      "YARA",
      "/api/v1/action/yara",
      "POST",
      buildYaraActionRequest(query, contiguousRows),
      "application/json",
      "text/plain"
    ));
  }
  const root = [
    actionBranch("Copy", copyChildren),
    actionExpandAll("Expand"),
    actionCollapseAll("Collapse"),
  ];
  const downloadChildren = [
    actionDownloadPayload("CSV", "results.csv", "text/csv;charset=utf-8", csv),
    actionDownloadPayload("JSON", "results.json", "application/json", json),
  ];
  if (sampleDownloadsEnabled) {
    downloadChildren.push(actionDownload("Samples", `/api/v1/download/samples?sha256=${urlEncode(uniqueValues(rows.map((row) => row.sha256)).join(","))}`));
  }
  root.push(actionBranch("Download", downloadChildren));
  return root;
}

function renderNoticeBlock(kind, message) {
  if (!message) return "";
  return `<div class="notice ${escapeHtml(kind)}"><span>${escapeHtml(message)}</span><button type="button" class="notice-dismiss" onclick="dismissNotice(this)">Close</button></div>`;
}

function renderNoticesSection(data) {
  return [
    renderNoticeBlock("success", data.message),
    renderNoticeBlock("warning", data.warning),
    renderNoticeBlock("error", data.error),
  ].join("");
}

function renderGlobalResultsActions(rows, sampleDownloadsEnabled, query) {
  const actions = buildGlobalResultsActionTree(rows, sampleDownloadsEnabled, query);
  if (actions.length === 0) {
    return '<button type="button" class="row-actions-trigger global-actions-trigger" disabled>Action</button>';
  }
  return `<button type="button" class="row-actions-trigger global-actions-trigger" data-actions="${serializeActions(actions)}" onclick="toggleRowActionMenu(this)">Action</button>`;
}

function resultColumnDefinitions() {
  return [
    { id: "side", label: "side" },
    { id: "timestamp", label: "Timestamp (UTC)" },
    { id: "size", label: "size" },
    { id: "score", label: "score" },
    { id: "embeddings", label: "embeddings" },
    { id: "embedding", label: "embedding" },
    { id: "instructions", label: "instructions" },
    { id: "blocks", label: "blocks" },
    { id: "markov", label: "markov" },
    { id: "contiguous", label: "contiguous" },
    { id: "corpora", label: "corpora" },
    { id: "architecture", label: "architecture" },
    { id: "username", label: "username" },
    { id: "sample", label: "Sample SHA256" },
    { id: "collection", label: "collection" },
    { id: "symbol", label: "symbols" },
    { id: "tags", label: "tags" },
    { id: "comments", label: "comments" },
    { id: "address", label: "address" },
    { id: "action", label: "action" },
  ];
}

function defaultEnabledResultColumnIds() {
  return resultColumnDefinitions().map((column) => column.id);
}

function renderResultsCount(totalResults) {
  const total = Number(totalResults || 0);
  return `${escapeHtml(compactCount(total))} results`;
}

function renderColumnsTrigger() {
  return '<button type="button" class="row-actions-trigger columns-trigger" onclick="toggleColumnsPopover(this)">Columns</button>';
}

function renderResultsMeta(data, rows) {
  return `<div class="results-meta"><div class="results-meta-count">${renderResultsCount(data.total_results)}</div><div class="results-meta-actions">${renderColumnsTrigger()}${renderGlobalResultsActions(rows, data.sample_downloads_enabled, data.query)}</div></div>`;
}

function renderResultActions(row, sampleDownloadsEnabled, query) {
  const actions = buildResultActionTree(row, sampleDownloadsEnabled, query);
  if (actions.length === 0) {
    return "-";
  }
  return `<button type="button" class="row-actions-trigger" data-actions="${serializeActions(actions)}" onclick="event.stopPropagation(); toggleRowActionMenu(this)">Action</button>`;
}

const DETAIL_PREVIEW_LIMITS = {
  corpora: 6,
  tags: 6,
  symbols: 4,
};

function detailPreviewValues(row, kind) {
  switch (kind) {
    case "corpora":
      return normalizeMetadataItems(row?.collection_corpora || row?.corpora || []);
    case "tags":
      return normalizeMetadataItems(row?.collection_tags || []);
    case "symbols":
      return normalizeMetadataItems(row?.symbols || rowSymbolEntries(row));
    default:
      return [];
  }
}

function detailPreviewLoading(row, kind) {
  switch (kind) {
    case "corpora":
      return !!row?.corpora_loading;
    case "tags":
      return !!row?.tags_loading;
    case "symbols":
      return !!row?.symbols_loading;
    default:
      return false;
  }
}

function renderDetailPreviewRow(label, values, kind, loading) {
  if (loading && values.length === 0) {
    return `<div class="result-detail-preview-item"><span class="result-detail-label">${escapeHtml(label)}</span><div class="result-detail-preview-list is-empty"><span class="result-detail-preview-empty">Loading...</span></div></div>`;
  }
  if (!values.length) {
    return `<div class="result-detail-preview-item"><span class="result-detail-label">${escapeHtml(label)}</span><div class="result-detail-preview-list is-empty"><span class="result-detail-preview-empty">None</span></div></div>`;
  }
  const limit = DETAIL_PREVIEW_LIMITS[kind] || 6;
  const visible = values.slice(0, limit);
  const remaining = Math.max(0, values.length - visible.length);
  const chips = visible.map((value) => {
    const itemLabel = metadataItemName(value);
    return renderResultCopyPill(itemLabel, itemLabel, {
      className: "result-detail-preview-chip",
      tooltipHtml: metadataTooltipHtml(value, "full"),
    });
  }).join("");
  const more = remaining > 0 ? `<span class="result-detail-preview-more">+${escapeHtml(String(remaining))} more</span>` : "";
  return `<div class="result-detail-preview-item"><span class="result-detail-label">${escapeHtml(label)}</span><div class="result-detail-preview-list">${chips}${more}</div></div>`;
}

function renderResultDetails(row, resultKey, columnCount) {
  const collection = String(row?.collection || "").trim().toLowerCase();
  const metrics = [];
  if (collection === "function") {
    metrics.push(
      ["Cyclomatic Complexity", row.cyclomatic_complexity],
      ["Average Instructions per Block", row.average_instructions_per_block != null ? formatMetricFloat(row.average_instructions_per_block) : null],
      ["Number Of Instructions", row.number_of_instructions],
      ["Number Of Blocks", row.number_of_blocks],
    );
  } else if (collection === "block") {
    metrics.push(
      ["Number Of Instructions", row.number_of_instructions],
      ["Markov", row.markov != null ? formatMetricFloat(row.markov) : null],
    );
  }
  metrics.push(
    ["Entropy", row.entropy != null ? formatMetricFloat(row.entropy) : null],
    ["Contiguous", row.contiguous == null ? null : (row.contiguous ? "true" : "false")],
    ["Chromosome / Entropy", row.chromosome_entropy != null ? formatMetricFloat(row.chromosome_entropy) : null],
  );
  const items = metrics
    .filter(([, value]) => value != null && value !== "")
    .map(([label, value]) => {
      const text = String(value);
      return `<div class="result-detail-item"><span class="result-detail-label">${escapeHtml(label)}</span>${renderResultCopyPill(text, text, { className: "result-detail-metric-pill" })}</div>`;
    })
    .join("");
  const previews = [
    renderDetailPreviewRow("Corpora", detailPreviewValues(row, "corpora"), "corpora", detailPreviewLoading(row, "corpora")),
    renderDetailPreviewRow("Tags", detailPreviewValues(row, "tags"), "tags", detailPreviewLoading(row, "tags")),
    renderDetailPreviewRow("Symbols", detailPreviewValues(row, "symbols"), "symbols", detailPreviewLoading(row, "symbols")),
  ].join("");
  return `<tr class="result-detail-row" data-result-key="${escapeHtml(resultKey)}" hidden><td colspan="${escapeHtml(String(Math.max(1, Number(columnCount || 1))))}"><div class="result-detail-grid">${items}</div><div class="result-detail-preview-grid">${previews}</div></td></tr>`;
}

function renderPaginationButton(label, page, data) {
  const uploadedSha256 = data.uploaded_sha256
    ? `<input type="hidden" name="uploaded_sha256" value="${escapeHtml(data.uploaded_sha256)}">`
    : "";
  return `<form method="post" action="/api/v1/search" class="pagination-form"><input type="hidden" name="search" value="1"><input type="hidden" name="query" value="${escapeHtml(data.query || "")}"><input type="hidden" name="top_k" value="${escapeHtml(String(data.top_k ?? 16))}"><input type="hidden" name="page" value="${escapeHtml(String(page))}">${uploadedSha256}<button type="submit" class="secondary pagination-button" aria-label="Page ${escapeHtml(String(page))}">${escapeHtml(label)}</button></form>`;
}

function renderPagination(data) {
  if (!data.has_previous_page && !data.has_next_page) {
    return "";
  }
  const previous = data.has_previous_page
    ? renderPaginationButton("←", Math.max(1, (data.page || 1) - 1), data)
    : '<span class="pagination-spacer" aria-hidden="true"></span>';
  const next = data.has_next_page
    ? renderPaginationButton("→", (data.page || 1) + 1, data)
    : '<span class="pagination-spacer" aria-hidden="true"></span>';
  return `<div class="pagination">${previous}<span class="pagination-label">Page ${escapeHtml(String(data.page || 1))}</span>${next}</div>`;
}

function renderResultCell(columnId, row, data) {
  const scoreValue = row.score == null ? "" : formatScoreValue(row.score);
  const collection = String(row?.collection || "").trim().toLowerCase();
  switch (columnId) {
    case "side":
      return `<td>${renderResultCopyPill(row.side, row.side, { className: "result-copy-pill-compact" })}</td>`;
    case "timestamp":
      return `<td>${renderResultCopyPill(formatResultDate(row.timestamp), row.timestamp, { title: `${row.timestamp}\nClick to copy` })}</td>`;
    case "size":
      return `<td>${renderResultCopyPill(formatResultSize(row.size), formatResultSize(row.size), { title: `${String(row.size)} bytes\nClick to copy` })}</td>`;
    case "score":
      return `<td>${renderResultCopyPill(scoreValue, scoreValue)}</td>`;
    case "embeddings":
      return `<td>${renderResultCopyPill(compactCount(row.embeddings), String(row.embeddings ?? ""))}</td>`;
    case "embedding":
      return `<td>${renderResultCopyPill(abbreviateHex(row.embedding), row.embedding)}</td>`;
    case "instructions": {
      const value = collection === "function" || collection === "block" ? String(row.number_of_instructions ?? "") : "";
      return `<td>${renderResultCopyPill(value, value)}</td>`;
    }
    case "blocks": {
      const value = collection === "function" ? String(row.number_of_blocks ?? "") : "";
      return `<td>${renderResultCopyPill(value, value)}</td>`;
    }
    case "markov": {
      const value = collection === "block" && row.markov != null ? formatMetricFloat(row.markov) : "";
      return `<td>${renderResultCopyPill(value, value)}</td>`;
    }
    case "contiguous":
      return `<td>${renderResultCopyPill(row.contiguous == null ? "" : (row.contiguous ? "true" : "false"), row.contiguous == null ? "" : (row.contiguous ? "true" : "false"))}</td>`;
    case "corpora":
      return `<td class="corpora-cell-td">${renderCorporaCell(row)}</td>`;
    case "architecture":
      return `<td>${renderResultCopyPill(displayArchitecture(row.architecture), displayArchitecture(row.architecture))}</td>`;
    case "username":
      return `<td>${renderResultCopyPill(row.username || "", row.username || "", { tooltipHtml: usernameTooltipHtml(row) })}</td>`;
    case "sample":
      return `<td class="sha256-cell">${renderResultCopyPill(abbreviateHex(row.sha256), row.sha256)}</td>`;
    case "collection":
      return `<td>${renderResultCopyPill(displayCollection(row.collection), displayCollection(row.collection))}</td>`;
    case "symbol":
      return `<td class="symbol-cell-td">${renderSymbolCell(row)}</td>`;
    case "tags":
      return `<td class="tags-cell-td">${renderTagsCell(row)}</td>`;
    case "comments":
      return `<td class="comments-cell-td">${renderCommentsCell(row)}</td>`;
    case "address":
      return `<td>${renderResultCopyPill(`0x${Number(row.address).toString(16)}`, `0x${Number(row.address).toString(16)}`)}</td>`;
    case "action":
      return `<td class="action-cell">${renderResultActions(row, data.sample_downloads_enabled, data.query)}</td>`;
    default:
      return "";
  }
}

function renderResultsSection(data) {
  const results = Array.isArray(data.results) ? data.results : [];
  const definitions = resultColumnDefinitions();
  const enabledIds = enabledResultColumnIds();
  const visibleColumns = definitions.filter((column) => enabledIds.includes(column.id));
  const columnCount = Math.max(1, visibleColumns.length);
  const head = visibleColumns
    .map((column) => {
      const className = column.id === "action" ? ' class="action-cell"' : "";
      return `<th${className}>${escapeHtml(column.label)}</th>`;
    })
    .join("");
  let body = "";
  if (results.length === 0) {
    const emptyMessage = (data.query || "").trim() === "" ? "No results yet." : "No results matched the current query.";
    body = `<tr><td colspan="${escapeHtml(String(columnCount))}" class="empty">${escapeHtml(emptyMessage)}</td></tr>`;
  } else {
    body = results
      .map((row) => {
        const resultKey = resultRowKey(row);
        const rowClass = tableRowClass(row);
        const rowClassWithBase = rowClass ? `${rowClass} result-row` : "result-row";
        const summaryCells = visibleColumns.map((column) => renderResultCell(column.id, row, data)).join("");
        const summary = `<tr class="${escapeHtml(rowClassWithBase)}" data-result-key="${escapeHtml(resultKey)}" onclick="toggleResultDetails(this)">${summaryCells}</tr>`;
        return summary + renderResultDetails(row, resultKey, columnCount);
      })
      .join("");
  }
  return `${renderResultsMeta(data, results)}<div class="results-table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body}</tbody></table></div>${renderPagination(data)}`;
}
