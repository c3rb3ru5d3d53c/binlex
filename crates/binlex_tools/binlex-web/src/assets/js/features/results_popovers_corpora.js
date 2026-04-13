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
  const removable = value.trim().toLowerCase() !== "default";
  const moveButton = removable
    ? `<button type="button" class="symbol-picker-move" data-corpora-action="remove" data-corpora-scope="${escapeHtml(scope)}" data-result-key="${escapeHtml(resultKey)}" data-corpus="${escapeHtml(encodeURIComponent(value))}">&larr;</button>`
    : "";
  return `<div class="symbol-picker-item${activeClass}"><span class="symbol-picker-name" title="${escapeHtml(value)}">${escapeHtml(value)}</span><div class="symbol-picker-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button>${moveButton}</div>${metadataTooltipHtml(item, "full")}</div>`;
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
    await postJsonWithCredentials("/api/v1/corpora", { corpus: typed });
    const createdItem = { name: typed, created_by: { username: "", profile_picture: null }, created_timestamp: "", assigned_by: null, assigned_timestamp: null };
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
    await postJsonWithCredentials("/api/v1/corpora/collection", {
      sha256: row.sha256,
      collection: row.collection,
      architecture: row.architecture,
      address: Number(row.address || 0),
      corpus,
    });
    row.collection_corpora = normalizeMetadataItems([...(row.collection_corpora || []), { name: corpus, created_by: { username: "", profile_picture: null }, created_timestamp: "", assigned_by: { username: "", profile_picture: null }, assigned_timestamp: "" }]);
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
    await deleteJsonWithCredentials("/api/v1/corpora/collection", {
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
