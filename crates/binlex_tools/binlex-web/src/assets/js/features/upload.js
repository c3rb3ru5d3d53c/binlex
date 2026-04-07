const DEFAULT_UPLOAD_CORPUS = "default";
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
    setUploadCorpusOptions(Array.isArray(payload?.corpora) ? payload.corpora.map((item) => metadataItemName(item)) : []);
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
    const items = Array.isArray(payload?.tags) ? payload.tags.map((item) => metadataItemName(item)) : [];
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
  if (!isAdmin()) return false;
  const typed = availableUploadCorpusQuery();
  return !!typed && !metadataNameHasWhitespace(typed) && !findUploadCorpusByName(typed) && filteredAvailableUploadCorpora().length === 0;
}

function shouldOfferUploadTagCreate() {
  const typed = availableUploadTagQuery();
  return !!typed && !metadataNameHasWhitespace(typed) && !findUploadTagByName(typed) && filteredAvailableUploadTags().length === 0;
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
  const availableSummary = document.getElementById("upload-tag-available-summary");
  const selectedSummary = document.getElementById("upload-tag-selected-summary");
  if (!(availableList instanceof HTMLElement) || !(selectedList instanceof HTMLElement)) return;
  const available = filteredAvailableUploadTags();
  const selected = filteredSelectedUploadTags();
  const visibleAvailable = available.slice(0, 6);
  const visibleSelected = selected.slice(0, 6);
  if (availableSummary) {
    availableSummary.textContent = `Showing ${compactCount(visibleAvailable.length)} of ${compactCount(available.length)}`;
  }
  if (selectedSummary) {
    selectedSummary.textContent = `Showing ${compactCount(visibleSelected.length)} of ${compactCount(selected.length)}`;
  }
  availableList.innerHTML = visibleAvailable.map((value, index) => corpusButtonHtml(value, "available", index === 0, "selectUploadTag")).join("");
  selectedList.innerHTML = visibleSelected.length === 0
    ? '<div class="upload-corpus-empty">No tags selected.</div>'
    : visibleSelected.map((value, index) => corpusButtonHtml(value, "selected", index === 0, "unselectUploadTag")).join("");
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
    selectUploadCorpus(encodeURIComponent(metadataItemName(available[0])));
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
    selectUploadTag(encodeURIComponent(metadataItemName(available[0])));
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
  const title = document.getElementById("upload-corpus-create-title");
  const text = document.getElementById("upload-corpus-create-text");
  if (!(overlay instanceof HTMLElement) || !(prompt instanceof HTMLElement) || !(title instanceof HTMLElement) || !(text instanceof HTMLElement)) return;
  const value = uploadCorpusPendingCreate();
  if (!value) {
    overlay.hidden = true;
    title.textContent = "Create Corpus";
    text.textContent = "";
    return;
  }
  overlay.hidden = false;
  title.textContent = "Create Corpus";
  text.textContent = `Create "${value}"?`;
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
  const title = document.getElementById("upload-tag-create-title");
  const text = document.getElementById("upload-tag-create-text");
  if (!(overlay instanceof HTMLElement) || !(prompt instanceof HTMLElement) || !(title instanceof HTMLElement) || !(text instanceof HTMLElement)) return;
  const value = uploadTagPendingCreate();
  if (!value) {
    overlay.hidden = true;
    title.textContent = "Create Tag";
    text.textContent = "";
    return;
  }
  overlay.hidden = false;
  title.textContent = "Create Tag";
  text.textContent = `Create "${value}"?`;
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
  if (!value || metadataNameHasWhitespace(value)) return;
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
  if (!value || metadataNameHasWhitespace(value)) return;
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
        positionFloatingSingleSelectMenu(root);
      } else {
        root.classList.remove("is-active");
        root.style.removeProperty("z-index");
        clearFloatingSingleSelectMenu(root);
      }
    });
  });
  if (!document.body.dataset.floatingSingleSelectInstalled) {
    document.body.dataset.floatingSingleSelectInstalled = "1";
    window.addEventListener("resize", repositionFloatingSingleSelectMenus);
    document.addEventListener("scroll", repositionFloatingSingleSelectMenus, true);
  }
}

function initializeProfilePictureCrop() {
  const stage = document.getElementById("profile-picture-crop-stage");
  if (!(stage instanceof HTMLElement)) return;
  stage.addEventListener("pointerdown", beginProfilePictureCropDrag);
  stage.addEventListener("pointermove", moveProfilePictureCropDrag);
  stage.addEventListener("pointerup", endProfilePictureCropDrag);
  stage.addEventListener("pointercancel", endProfilePictureCropDrag);
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
    text.textContent = "Binlex is uploading and processing the sample.";
  } else if (state === "pending") {
    title.textContent = "Analysis Pending";
    text.textContent = "The sample was uploaded successfully. Binlex accepted analysis and is waiting for processing to begin.";
    if (payload.sha256) {
      extra.innerHTML = renderUploadStatusSha(payload.sha256);
    }
  } else if (state === "processing") {
    if (payload.allowSearchNow) {
      title.textContent = "Still Processing";
      text.textContent = "Binlex is still analyzing and indexing the sample. You can search now while results continue to come in.";
    } else {
      title.textContent = "Analyzing Sample";
      text.textContent = "Binlex is analyzing and indexing the sample.";
    }
    if (payload.sha256) {
      extra.innerHTML = renderUploadStatusSha(payload.sha256);
      if (payload.allowSearchNow) {
        searchButton.hidden = false;
        searchButton.dataset.sha256 = payload.sha256;
      }
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
  return `<div class="upload-status-sha"><span>SHA256</span><div class="upload-status-sha-row"><input class="menu-search upload-status-sha-value" id="upload-status-sha-value" type="text" value="${escapeHtml(sha256)}" readonly><button type="button" class="symbol-picker-copy upload-status-copy" onclick="copyUploadSha(this)" data-sha256="${escapeHtml(sha256)}">Copy</button></div></div>`;
}

let uploadStatusPollToken = 0;
let uploadStatusStartedAt = 0;
const UPLOAD_STATUS_SEARCH_THRESHOLD_MS = 15000;

function stopUploadStatusPolling() {
  uploadStatusPollToken += 1;
  uploadStatusStartedAt = 0;
}

function startUploadStatusPolling(sha256) {
  stopUploadStatusPolling();
  if (!sha256) return;
  uploadStatusStartedAt = Date.now();
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
      const allowSearchNow = uploadStatusStartedAt > 0 && (Date.now() - uploadStatusStartedAt) >= UPLOAD_STATUS_SEARCH_THRESHOLD_MS;
      openUploadStatusModal("processing", { sha256, allowSearchNow });
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
  const label = String(root.dataset.singleLabel || "").trim() || "Select";
  summary.textContent = `${label}: ${value}`;
}

function isFloatingSingleSelect(root) {
  return root instanceof HTMLElement && !!root.closest(".users-create-role-field");
}

function clearFloatingSingleSelectMenu(root) {
  if (!(root instanceof HTMLElement)) return;
  const menu = root.querySelector(".menu");
  if (!(menu instanceof HTMLElement)) return;
  menu.style.removeProperty("position");
  menu.style.removeProperty("top");
  menu.style.removeProperty("left");
  menu.style.removeProperty("right");
  menu.style.removeProperty("width");
  menu.style.removeProperty("z-index");
}

function positionFloatingSingleSelectMenu(root) {
  if (!(root instanceof HTMLElement) || !root.open || !isFloatingSingleSelect(root)) return;
  const summary = root.querySelector("summary");
  const menu = root.querySelector(".menu");
  if (!(summary instanceof HTMLElement) || !(menu instanceof HTMLElement)) return;
  const rect = summary.getBoundingClientRect();
  menu.style.position = "fixed";
  menu.style.top = `${Math.round(rect.bottom - 1)}px`;
  menu.style.left = `${Math.round(rect.left)}px`;
  menu.style.right = "auto";
  menu.style.width = `${Math.round(rect.width)}px`;
  menu.style.zIndex = "6200";
}

function repositionFloatingSingleSelectMenus() {
  document.querySelectorAll(".modal-select[open]").forEach((root) => {
    positionFloatingSingleSelectMenu(root);
  });
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
