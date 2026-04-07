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
  row.collection_corpora = normalizeMetadataItems(row.collection_corpora || row.corpora || []);
  row.corpora = row.collection_corpora.map((item) => metadataItemName(item));
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
    row.collection_corpora = normalizeMetadataItems(collection?.corpora || []);
    row.corpora = row.collection_corpora.map((item) => metadataItemName(item));
    row.corpora_loaded = true;
    row.corpora_error = null;
  } catch (error) {
    row.collection_corpora = normalizeMetadataItems(row.collection_corpora || row.corpora || []);
    row.corpora = row.collection_corpora.map((item) => metadataItemName(item));
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
    row.available_corpora = normalizeMetadataItems([...(Array.isArray(payload?.corpora) ? payload.corpora : []), ...(row.available_corpora_created || [])]);
    row.available_corpora_total_results = Number(payload?.total_results || row.available_corpora.length);
    row.available_corpora_loaded_query = normalizedQuery;
  } catch (error) {
    row.available_corpora = normalizeMetadataItems(row.available_corpora_created || []);
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
  return normalizeMetadataItems(values).filter((value) => !lowered || metadataItemName(value).toLowerCase().includes(lowered));
}

function filteredAvailableCorpora(row) {
  const assigned = new Set([...(row?.collection_corpora || [])].map((value) => metadataItemName(value).toLowerCase()));
  return filteredCorporaForSearch(row?.available_corpora || [], corporaAvailableSearchValue())
    .filter((value) => !assigned.has(metadataItemName(value).toLowerCase()));
}

function filteredCollectionCorpora(row) {
  return filteredCorporaForSearch(row?.collection_corpora || row?.corpora || [], corporaCollectionSearchValue());
}

function canCreateCorpus(row) {
  if (!isAdmin()) return false;
  const typed = corporaAvailableSearchValue();
  const lowered = typed.toLowerCase();
  if (!lowered) return false;
  const known = normalizeMetadataItems([...(row?.available_corpora || []), ...(row?.collection_corpora || [])]);
  return !known.some((value) => metadataItemName(value).toLowerCase() === lowered);
}

function corporaCollectionTitle(row) {
  return `Collection (${tagCollectionLabel(row)})`;
}

function corporaSummaryText(visible, total) {
  return total > visible ? `Showing ${compactCount(visible)} of ${compactCount(total)}` : "";
}

function renderAvailableCorpusItem(item, active, resultKey) {
  const activeClass = active ? " active" : "";
  const value = metadataItemName(item);
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(value)}">${escapeHtml(value)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button><button type="button" class="symbol-picker-move" data-corpora-action="apply" data-corpora-scope="collection" data-result-key="${escapeHtml(resultKey)}" data-corpus="${escapeHtml(encodeURIComponent(value))}">&rarr;</button></div>${metadataTooltipHtml(item, "created")}</div>`;
}

function renderAssignedCorpusItem(item, scope, active, resultKey) {
  const activeClass = active ? " active" : "";
  const value = metadataItemName(item);
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(value)}">${escapeHtml(value)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button><button type="button" class="symbol-picker-move" data-corpora-action="remove" data-corpora-scope="${escapeHtml(scope)}" data-result-key="${escapeHtml(resultKey)}" data-corpus="${escapeHtml(encodeURIComponent(value))}">&larr;</button></div>${metadataTooltipHtml(item, "full")}</div>`;
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
  closeCommentsPopover();
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
      applyAvailableCorpus(activeCorporaResultKey, "collection", encodeURIComponent(metadataItemName(available[0])));
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
    const createdItem = { name: typed, created_actor: { username: "", profile_picture: null }, created_timestamp: "", assigned_actor: null, assigned_timestamp: null };
    row.available_corpora_created = normalizeMetadataItems([...(row.available_corpora_created || []), createdItem]);
    row.available_corpora = normalizeMetadataItems([...(row.available_corpora || []), createdItem]);
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
    row.collection_corpora = normalizeMetadataItems([...(row.collection_corpora || []), { name: corpus, created_actor: { username: "", profile_picture: null }, created_timestamp: "", assigned_actor: { username: "", profile_picture: null }, assigned_timestamp: "" }]);
    row.corpora = row.collection_corpora.map((item) => metadataItemName(item));
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
    row.collection_corpora = normalizeMetadataItems((row.collection_corpora || []).filter((value) => metadataItemName(value) !== corpus));
    row.corpora = row.collection_corpora.map((item) => metadataItemName(item));
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

function commentAuthorHtml(actor) {
  const username = metadataActorUsername(actor) || "?";
  const profilePicture = metadataActorProfilePicture(actor);
  if (profilePicture) {
    return `<img class="comment-avatar" src="${escapeHtml(profilePicture)}" alt="${escapeHtml(username)}">`;
  }
  return `<div class="comment-avatar comment-avatar-fallback">${escapeHtml(username.slice(0, 1).toLowerCase())}</div>`;
}

function commentCardHtml(comment, options = {}) {
  const body = escapeHtml(String(comment?.body || "")).replace(/\n/g, "<br>");
  const deleteButton = options.showDelete
    ? `<button type="button" class="symbol-picker-move comment-delete" title="Delete comment" aria-label="Delete comment" onclick="event.stopPropagation(); deleteCommentById(${Number(comment?.id || 0)},'${escapeHtml(options.resultKey || "")}')">🗑</button>`
    : "";
  return `
    <div class="comment-card">
      <div class="comment-avatar-wrap">${commentAuthorHtml(comment?.actor)}</div>
      <div class="comment-card-body">
        <div class="comment-card-header">
          <div class="comment-card-identity">
            <span class="comment-card-username">${escapeHtml(metadataActorUsername(comment?.actor) || "unknown")}</span>
            <span class="comment-card-time">${escapeHtml(formatUtcTimestamp(comment?.timestamp || ""))}</span>
          </div>
          ${deleteButton}
        </div>
        <div class="comment-card-text">${body}</div>
      </div>
    </div>
  `;
}

function commentsTotalPages(row) {
  const totalResults = Math.max(0, Number(row?.comments_total_results ?? row?.collection_comment_count ?? 0));
  const pageSize = Math.max(1, Number(row?.comments_page_size || COMMENTS_PAGE_SIZE));
  return Math.max(1, Math.ceil(totalResults / pageSize));
}

function commentsPagerHtml(row) {
  const page = Math.max(1, Number(row?.comments_page || 1));
  const totalPages = commentsTotalPages(row);
  return `
    <div class="comments-pager-copy">Showing page ${page} of ${totalPages}</div>
    <div class="comments-pager-actions">
      <button type="button" class="secondary comments-page-button" onclick="event.stopPropagation(); changeCommentsPage('${escapeHtml(resultRowKey(row))}', -1)"${page <= 1 ? " disabled" : ""}>←</button>
      <button type="button" class="secondary comments-page-button" onclick="event.stopPropagation(); changeCommentsPage('${escapeHtml(resultRowKey(row))}', 1)"${page >= totalPages ? " disabled" : ""}>→</button>
    </div>
  `;
}

function commentsPopoverContent(row) {
  const comments = Array.isArray(row?.entity_comments) ? row.entity_comments : [];
  const items = comments.length
    ? comments.map((item) => commentCardHtml(item, { showDelete: isAdmin(), resultKey: resultRowKey(row) })).join("")
    : '<div class="comments-empty">No comments yet.</div>';
  const composer = canWrite()
    ? `
      <div class="comments-composer">
        <textarea
          class="menu-search comments-input"
          id="comments-input"
          maxlength="${COMMENT_MAX_LENGTH}"
          placeholder="Add a documentation note"
          oninput="updateCommentsComposerState()"
        ></textarea>
        <div class="comments-composer-footer">
          <div class="comments-count" id="comments-count">0 / ${COMMENT_MAX_LENGTH}</div>
          <button type="button" class="primary comments-post" id="comments-post-button" onclick="postActiveComment()" disabled>Post</button>
        </div>
        <div class="auth-form-error users-search-error" id="comments-error"></div>
      </div>
    `
    : '<div class="comments-readonly-note">Login to add comments.</div>';
  return `
    <div class="comments-thread">${items}</div>
    <div class="comments-thread-footer">${commentsPagerHtml(row)}</div>
    ${composer}
  `;
}

function ensureCommentsPopover() {
  let popover = getCommentsPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "comments-popover";
  popover.className = "comments-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="comments-popover-header">
      <div class="comments-popover-title">Comments</div>
      <button type="button" class="secondary result-popover-close" onclick="closeCommentsPopover()">Close</button>
    </div>
    <div class="comments-popover-body"></div>
  `;
  document.body.appendChild(popover);
  return popover;
}

function positionCommentsPopover(trigger, popover) {
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

function currentCommentsPopoverTrigger() {
  if (!activeCommentsResultKey) return null;
  return document.querySelector(`.comments-popover-trigger[data-result-key="${CSS.escape(activeCommentsResultKey)}"]`);
}

async function loadRowCommentsByKey(resultKey, options = {}) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const page = Number(options.page || row.comments_page || 1);
  row.comments_loading = true;
  row.comments_error = "";
  const popover = getCommentsPopover();
  if (popover && !popover.hidden && activeCommentsResultKey === resultKey) {
    renderCommentsPopover();
  }
  try {
    const payload = await getJson(`/api/v1/comments?sha256=${encodeURIComponent(row.sha256 || "")}&collection=${encodeURIComponent(row.collection || "")}&address=${Number(row.address || 0)}&page=${page}&page_size=${COMMENTS_PAGE_SIZE}`);
    const items = Array.isArray(payload?.items) ? payload.items : [];
    row.entity_comments = items;
    row.comments_loaded = true;
    row.comments_loading = false;
    row.comments_error = "";
    row.comments_page = Number(payload?.page || page);
    row.comments_page_size = Number(payload?.page_size || COMMENTS_PAGE_SIZE);
    row.comments_total_results = Number(payload?.total_results || 0);
    row.comments_has_next = !!payload?.has_next;
    row.collection_comment_count = Number(payload?.total_results || row.collection_comment_count || 0);
    const data = currentSearchData();
    if (data) renderSearchData(data);
    if (popover && !popover.hidden && activeCommentsResultKey === resultKey) {
      renderCommentsPopover();
    }
  } catch (error) {
    row.comments_loading = false;
    row.comments_error = error.message || "Failed to load comments.";
    if (popover && !popover.hidden && activeCommentsResultKey === resultKey) {
      renderCommentsPopover();
    }
  }
}

function renderCommentsPopover() {
  const popover = ensureCommentsPopover();
  const body = popover?.querySelector?.(".comments-popover-body");
  if (!(popover instanceof HTMLElement) || !(body instanceof HTMLElement)) return;
  const currentTrigger = currentCommentsPopoverTrigger();
  if (currentTrigger) {
    activeCommentsTrigger = currentTrigger;
    activeCommentsTrigger.classList.add("active");
  }
  const row = activeCommentsResultKey ? findSearchRowByKey(activeCommentsResultKey) : null;
  if (!row) {
    closeCommentsPopover();
    return;
  }
  if (!row.comments_loaded && !row.comments_loading) {
    loadRowCommentsByKey(activeCommentsResultKey).catch((error) => {
      console.error("binlex-web comment load failed", error);
    });
  }
  if (row.comments_loading && !Array.isArray(row.entity_comments)) {
    body.innerHTML = '<div class="tags-popover-status">Loading comments...</div>';
  } else if (row.comments_error) {
    body.innerHTML = `<div class="tags-popover-status error">${escapeHtml(row.comments_error)}</div>`;
  } else {
    body.innerHTML = commentsPopoverContent(row);
    updateCommentsComposerState();
  }
  positionCommentsPopover(currentTrigger || activeCommentsTrigger, popover);
}

function closeCommentsPopover() {
  const popover = getCommentsPopover();
  if (popover) popover.hidden = true;
  if (activeCommentsTrigger instanceof HTMLElement) {
    activeCommentsTrigger.classList.remove("active");
  }
  activeCommentsTrigger = null;
  activeCommentsResultKey = null;
}

function toggleCommentsPopover(button) {
  const popover = ensureCommentsPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  const resultKey = String(button.dataset.resultKey || "");
  if (activeCommentsTrigger === button && activeCommentsResultKey === resultKey && !popover.hidden) {
    closeCommentsPopover();
    return;
  }
  closeRowActionMenu();
  closeCorporaPopover();
  closeTagsPopover();
  closeSymbolPopover();
  closeCommentsPopover();
  if (activeCommentsTrigger instanceof HTMLElement) {
    activeCommentsTrigger.classList.remove("active");
  }
  activeCommentsTrigger = button;
  activeCommentsResultKey = resultKey;
  activeCommentsTrigger.classList.add("active");
  popover.hidden = false;
  renderCommentsPopover();
  if (canWrite()) {
    const input = popover.querySelector("#comments-input");
    if (input instanceof HTMLElement) {
      setTimeout(() => input.focus(), 0);
    }
  }
}

function updateCommentsComposerState() {
  const input = document.getElementById("comments-input");
  const counter = document.getElementById("comments-count");
  const button = document.getElementById("comments-post-button");
  if (!(input instanceof HTMLTextAreaElement)) return;
  const length = Array.from(input.value || "").length;
  if (counter) counter.textContent = `${length} / ${COMMENT_MAX_LENGTH}`;
  if (button instanceof HTMLButtonElement) {
    button.disabled = !String(input.value || "").trim() || length > COMMENT_MAX_LENGTH;
  }
}

async function postActiveComment() {
  if (!activeCommentsResultKey) return;
  const row = findSearchRowByKey(activeCommentsResultKey);
  const input = document.getElementById("comments-input");
  if (!row || !(input instanceof HTMLTextAreaElement)) return;
  const body = String(input.value || "").trim();
  setInlineError("comments-error", "");
  if (!body) return;
  try {
    const created = await postJson("/api/v1/comments/add", {
      sha256: row.sha256,
      collection: row.collection,
      address: Number(row.address || 0),
      body,
    });
    row.entity_comments = [created, ...(Array.isArray(row.entity_comments) ? row.entity_comments : [])];
    row.comments_loaded = true;
    row.comments_error = "";
    row.collection_comment_count = Number(row.collection_comment_count || 0) + 1;
    row.comments_total_results = Number(row.comments_total_results || 0) + 1;
    row.comments_page = 1;
    input.value = "";
    updateCommentsComposerState();
    const data = currentSearchData();
    if (data) renderSearchData(data);
    renderCommentsPopover();
  } catch (error) {
    setInlineError("comments-error", error.message);
  }
}

async function changeCommentsPage(resultKey, delta) {
  const row = findSearchRowByKey(resultKey);
  if (!row || row.comments_loading) return;
  const nextPage = Math.max(1, Number(row.comments_page || 1) + Number(delta || 0));
  if (nextPage === Number(row.comments_page || 1) || nextPage > commentsTotalPages(row)) return;
  await loadRowCommentsByKey(resultKey, { page: nextPage });
}

async function deleteCommentById(id, resultKey = "") {
  const commentId = Number(id || 0);
  if (!commentId || !isAdmin()) return;
  try {
    const response = await fetch(`/api/v1/comments/${commentId}`, {
      method: "DELETE",
      credentials: "same-origin",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data?.error || "Request failed");
    }
    const row = resultKey ? findSearchRowByKey(resultKey) : null;
    if (row) {
      const before = Array.isArray(row.entity_comments) ? row.entity_comments : [];
      row.entity_comments = before.filter((item) => Number(item?.id || 0) !== commentId);
      row.collection_comment_count = Math.max(0, Number(row.collection_comment_count || 0) - (before.length === row.entity_comments.length ? 0 : 1));
      const searchData = currentSearchData();
      if (searchData) renderSearchData(searchData);
      renderCommentsPopover();
    }
    await loadAdminComments();
  } catch (error) {
    setInlineError("comments-error", error.message || "Failed to delete comment.");
    setInlineError("admin-comments-error", error.message || "Failed to delete comment.");
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
