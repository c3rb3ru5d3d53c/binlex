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
  return normalizeMetadataItems(tags).filter((tag) => !lowered || metadataItemName(tag).toLowerCase().includes(lowered));
}

function filteredAvailableTags(row) {
  const assigned = new Set((row?.collection_tags || []).map((tag) => metadataItemName(tag).toLowerCase()));
  return filterTagsForSearch(row?.available_tags || [], tagAvailableSearchValue())
    .filter((tag) => !assigned.has(metadataItemName(tag).toLowerCase()));
}

function filteredCollectionTags(row) {
  return filterTagsForSearch(row?.collection_tags || [], tagCollectionSearchValue());
}

function canCreateTag(row) {
  const typed = tagAvailableSearchValue();
  const lowered = typed.toLowerCase();
  if (!lowered) return false;
  const known = normalizeMetadataItems([...(row?.available_tags || []), ...(row?.collection_tags || [])]);
  return !known.some((tag) => metadataItemName(tag).toLowerCase() === lowered);
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
  return normalizeMetadataItems(symbols)
    .filter((symbol) => !lowered || metadataItemName(symbol).toLowerCase().includes(lowered));
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

function currentSymbolPopoverTrigger() {
  if (!activeSymbolResultKey) return null;
  const trigger = document.querySelector(
    `.symbol-popover-trigger[data-result-key="${CSS.escape(activeSymbolResultKey)}"]`
  );
  return trigger instanceof HTMLElement ? trigger : null;
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
    row.collection_tags = normalizeMetadataItems(collection?.tags || []);
    row.collection_tag_count = row.collection_tags.length;
    row.tags_loaded = true;
    row.tag_error = null;
  } catch (error) {
    row.collection_tags = normalizeMetadataItems(row.collection_tags || []);
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
    row.available_tags = normalizeMetadataItems(payload?.tags || []);
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
  const applied = new Set(filterSymbolsForSearch(row?.symbols || [], "").map((symbol) => metadataItemName(symbol).toLowerCase()));
  return filterSymbolsForSearch(row?.available_symbols || [], "")
    .filter((symbol) => !applied.has(metadataItemName(symbol).toLowerCase()));
}

function filteredAppliedSymbols(row) {
  return filterSymbolsForSearch(row?.symbols || [], symbolAppliedSearchValue());
}

function symbolCanCreate(row) {
  const typed = symbolAvailableSearchValue();
  const lowered = typed.trim().toLowerCase();
  if (!lowered) return false;
  const known = [...filterSymbolsForSearch(row?.symbols || [], ""), ...filterSymbolsForSearch(row?.available_symbols || [], "")];
  return !known.some((symbol) => metadataItemName(symbol).toLowerCase() === lowered);
}

function symbolPickerItemHtml(item, direction, active, resultKey) {
  const moveArrow = direction === "apply" ? "&rarr;" : "&larr;";
  const activeClass = active ? " active" : "";
  const symbol = metadataItemName(item);
  const mode = direction === "apply" ? "created" : "full";
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(symbol)}">${escapeHtml(symbol)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copySymbolValue(this,'${escapeHtml(encodeURIComponent(symbol))}')">Copy</button><button type="button" class="symbol-picker-move" onclick="event.stopPropagation(); ${direction === "apply" ? `applyAvailableSymbol('${escapeHtml(resultKey)}','${escapeHtml(encodeURIComponent(symbol))}')` : `unapplySymbol('${escapeHtml(resultKey)}','${escapeHtml(encodeURIComponent(symbol))}')`}">${moveArrow}</button></div>${metadataTooltipHtml(item, mode)}</div>`;
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
      <button type="button" class="secondary result-popover-close" onclick="closeSymbolPopover()">Close</button>
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
  closeCommentsPopover();
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
      applyAvailableSymbol(activeSymbolResultKey, encodeURIComponent(metadataItemName(available[0])));
      return;
    }
    if (symbolCanCreate(row)) {
      createAvailableSymbol();
    }
    return;
  }
  const applied = filteredAppliedSymbols(row);
  if (applied.length > 0) {
    unapplySymbol(activeSymbolResultKey, encodeURIComponent(metadataItemName(applied[0])));
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

function renderAvailableTagItem(item, active, resultKey) {
  const activeClass = active ? " active" : "";
  const tag = metadataItemName(item);
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(tag)}">${escapeHtml(tag)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(tag))}')">Copy</button><button type="button" class="symbol-picker-move" data-tag-action="apply" data-result-key="${escapeHtml(resultKey)}" data-tag="${escapeHtml(encodeURIComponent(tag))}">&rarr;</button></div>${metadataTooltipHtml(item, "created")}</div>`;
}

function renderAssignedTagItem(item, active, resultKey) {
  const activeClass = active ? " active" : "";
  const tag = metadataItemName(item);
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(tag)}">${escapeHtml(tag)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(tag))}')">Copy</button><button type="button" class="symbol-picker-move" data-tag-action="remove" data-result-key="${escapeHtml(resultKey)}" data-tag="${escapeHtml(encodeURIComponent(tag))}">&larr;</button></div>${metadataTooltipHtml(item, "full")}</div>`;
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
      <button type="button" class="secondary result-popover-close" onclick="closeTagsPopover()">Close</button>
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
  closeCommentsPopover();
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
      applyAvailableTag(activeTagResultKey, encodeURIComponent(metadataItemName(available[0])));
      return;
    }
    if (canCreateTag(row)) createAvailableTag();
    return;
  }
  const collection = filteredCollectionTags(row);
  if (collection.length > 0) {
    removeAssignedTag(activeTagResultKey, encodeURIComponent(metadataItemName(collection[0])));
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
    row.collection_tags = normalizeMetadataItems([...(row.collection_tags || []), { name: tag, created_actor: { username: "", profile_picture: null }, created_timestamp: "", assigned_actor: { username: "", profile_picture: null }, assigned_timestamp: "" }]);
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
    row.collection_tags = normalizeMetadataItems((row.collection_tags || []).filter((value) => metadataItemName(value) !== tag));
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
