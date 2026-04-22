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

function uploadCorpusLocked() {
  return String(getUploadCorpusRoot()?.dataset?.locked || "false") === "true";
}

function defaultUploadCorpus() {
  return String(getUploadCorpusRoot()?.dataset?.defaultCorpus || "default").trim() || "default";
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
  const baseValues = [defaultUploadCorpus()];
  const unique = Array.from(
    new Set(
      [...baseValues, ...(values || [])]
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

const uploadCorporaRequests = new Set();
let uploadCorporaSearchHandle = null;
const uploadTagRequests = new Set();
let uploadTagSearchHandle = null;
const uploadProjectSampleRequests = new Set();
let uploadProjectAvailablePage = 1;
let uploadProjectAvailableLoadedQuery = "";
let uploadProjectAvailableValues = [];
let uploadProjectSelectedValues = [];

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

function uploadProjectAvailableQuery() {
  return String(document.getElementById("upload-project-available-search")?.value || "").trim();
}

function uploadProjectSelectedQuery() {
  return String(document.getElementById("upload-project-selected-search")?.value || "").trim().toLowerCase();
}

function setUploadProjectSelectedValues(values) {
  uploadProjectSelectedValues = Array.from(new Set((values || []).map((value) => String(value || "").trim()).filter(Boolean)));
  renderUploadProjectPicker();
}

function filteredUploadProjectAvailable() {
  const selected = new Set(uploadProjectSelectedValues);
  return uploadProjectAvailableValues.filter((value) => !selected.has(value));
}

function filteredUploadProjectSelected() {
  const needle = uploadProjectSelectedQuery();
  return uploadProjectSelectedValues.filter((value) => !needle || value.toLowerCase().includes(needle));
}

async function loadUploadProjectSamples(query = "", page = 1, force = false) {
  const normalizedQuery = String(query || "").trim();
  const requestKey = `${normalizedQuery.toLowerCase()}:${page}`;
  if (uploadProjectSampleRequests.has(requestKey)) return;
  if (!force && uploadProjectAvailableLoadedQuery === normalizedQuery && uploadProjectAvailablePage === page) return;
  uploadProjectSampleRequests.add(requestKey);
  try {
    const payload = await fetchJsonWithCredentials(`/api/v1/samples/search?${new URLSearchParams({
      q: normalizedQuery,
      limit: "8",
      page: String(page),
    }).toString()}`);
    uploadProjectAvailableValues = Array.isArray(payload?.samples) ? payload.samples : [];
    uploadProjectAvailablePage = Number(payload?.page || page);
    uploadProjectAvailableLoadedQuery = normalizedQuery;
    renderUploadProjectPicker();
  } catch (error) {
    console.error("binlex-web upload project sample search failed", error);
  } finally {
    uploadProjectSampleRequests.delete(requestKey);
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
  const moveButton = handler
    ? `<button type="button" class="symbol-picker-move" onclick="${handler}('${encodeURIComponent(value)}')">${arrow}</button>`
    : "";
  return `<div class="upload-corpus-item${activeClass}"><span class="upload-corpus-item-name" title="${escapeHtml(value)}">${escapeHtml(value)}</span><div class="upload-corpus-item-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button>${moveButton}</div></div>`;
}

function selectedCorpusButtonHtml(value, active, removable) {
  return corpusButtonHtml(value, "selected", active, removable ? "unselectUploadCorpus" : null);
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
    : selected.map((value, index) => selectedCorpusButtonHtml(
      value,
      index === 0,
      value.trim().toLowerCase() !== defaultUploadCorpus().toLowerCase()
    )).join("");
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

function uploadProjectPickerItemHtml(value, direction, active, handler) {
  const arrow = direction === "selected" ? "&larr;" : "&rarr;";
  const activeClass = active ? " active" : "";
  return `<div class="upload-corpus-item${activeClass}"><span class="upload-corpus-item-name" title="${escapeHtml(value)}">${escapeHtml(abbreviateHex(value))}</span><div class="upload-corpus-item-actions"><button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(value))}')">Copy</button><button type="button" class="symbol-picker-move" onclick="${handler}('${encodeURIComponent(value)}')">${arrow}</button></div></div>`;
}

function renderUploadProjectPicker() {
  const availableList = document.getElementById("upload-project-available-list");
  const selectedList = document.getElementById("upload-project-selected-list");
  if (!(availableList instanceof HTMLElement) || !(selectedList instanceof HTMLElement)) return;
  const available = filteredUploadProjectAvailable();
  const selected = filteredUploadProjectSelected();
  availableList.innerHTML = available.length === 0
    ? '<div class="upload-corpus-empty">No available samples.</div>'
    : available.map((value, index) => uploadProjectPickerItemHtml(value, "available", index === 0, "selectUploadProjectSample")).join("");
  selectedList.innerHTML = selected.length === 0
    ? '<div class="upload-corpus-empty">No assigned samples.</div>'
    : selected.map((value, index) => uploadProjectPickerItemHtml(value, "selected", index === 0, "unselectUploadProjectSample")).join("");
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
  if (value.toLowerCase() === defaultUploadCorpus().toLowerCase()) return;
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

function selectUploadProjectSample(encodedValue) {
  const value = decodeURIComponent(String(encodedValue || "")).trim();
  if (!value) return;
  const next = uploadProjectSelectedValues.slice();
  if (!next.includes(value)) {
    next.push(value);
  }
  setUploadProjectSelectedValues(next);
}

function unselectUploadProjectSample(encodedValue) {
  const value = decodeURIComponent(String(encodedValue || "")).trim();
  if (!value) return;
  setUploadProjectSelectedValues(uploadProjectSelectedValues.filter((item) => item !== value));
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

function handleUploadProjectAvailableInput() {
  loadUploadProjectSamples(uploadProjectAvailableQuery(), 1, true).catch((error) => {
    console.error("binlex-web upload project sample search failed", error);
  });
}

function handleUploadProjectAvailableKeydown(event) {
  if (event.key !== "Enter") return;
  event.preventDefault();
  const available = filteredUploadProjectAvailable();
  if (available.length > 0) {
    selectUploadProjectSample(encodeURIComponent(available[0]));
  }
}

function handleUploadProjectSelectedKeydown(event) {
  if (event.key !== "Enter") return;
  event.preventDefault();
  const selected = filteredUploadProjectSelected();
  if (selected.length > 0) {
    unselectUploadProjectSample(encodeURIComponent(selected[0]));
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
    await postJsonWithCredentials("/api/v1/corpora", { corpus: value });
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
    await postJsonWithCredentials("/api/v1/tags", { tag: value });
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

function activeUploadSurfaceTab() {
  return String(document.querySelector("[data-upload-surface-tabs='1']")?.dataset?.activeTab || "analyze");
}

function toggleUploadSurfaceTab(tab) {
  const root = document.querySelector("[data-upload-surface-tabs='1']");
  if (!(root instanceof HTMLElement)) return;
  const normalized = ["analyze", "store", "project"].includes(String(tab || "")) ? String(tab) : "analyze";
  root.dataset.activeTab = normalized;
  root.querySelectorAll("[data-upload-surface-tab]").forEach((button) => {
    if (!(button instanceof HTMLElement)) return;
    button.classList.toggle("is-active", String(button.dataset.uploadSurfaceTab || "") === normalized);
  });
  document.querySelectorAll("[data-upload-surface-panel]").forEach((panel) => {
    if (!(panel instanceof HTMLElement)) return;
    panel.hidden = String(panel.dataset.uploadSurfacePanel || "") !== normalized;
  });
  updateUploadModalState();
}

function openUploadModal(tab = "analyze", sampleSha256 = "") {
  const modal = document.getElementById("upload-modal");
  if (!modal) return;
  modal.hidden = false;
  installDropzone();
  toggleUploadSurfaceTab(tab);
  const prefill = document.getElementById("upload-project-prefill");
  if (sampleSha256 && isSha256SearchValue(sampleSha256)) {
    setUploadProjectSelectedValues([sampleSha256]);
  } else if (tab !== "project") {
    setUploadProjectSelectedValues([]);
  }
  uploadProjectAvailablePage = 1;
  uploadProjectAvailableLoadedQuery = "";
  uploadProjectAvailableValues = [];
  if (prefill instanceof HTMLElement) {
    prefill.textContent = sampleSha256 && isSha256SearchValue(sampleSha256)
      ? `Prefilled sample SHA256: ${sampleSha256}`
      : "";
  }
  const uploadMetadataRoot = document.querySelector("[data-upload-metadata-root='1']");
  if (uploadMetadataRoot instanceof HTMLElement) {
    toggleUploadMetadataTab(String(uploadMetadataRoot.dataset.activeTab || "tags"));
  }
  renderUploadCorpusPicker();
  loadUploadCorpora("", true).catch((error) => console.error("binlex-web upload corpora search failed", error));
  renderUploadTagPicker();
  loadUploadTags("", true).catch((error) => console.error("binlex-web upload tags search failed", error));
  renderUploadProjectPicker();
  loadUploadProjectSamples("", 1, true).catch((error) => console.error("binlex-web upload project sample search failed", error));
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
  const mode = activeUploadSurfaceTab();
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
  const dropzoneTitle = document.getElementById("upload-dropzone-title");
  const dropzoneSubtitle = document.getElementById("upload-dropzone-subtitle");
  if (dropzoneTitle) {
    dropzoneTitle.textContent = mode === "store"
      ? "To Upload a Sample to Store"
      : mode === "project"
        ? "To Upload an IDA, Binja or Ghidra Project"
        : "Click to Upload or Drag and Drop";
  }
  if (dropzoneSubtitle) {
    const subtitle = mode === "store" || mode === "project"
      ? "Click or Drag and Drop"
      : "";
    dropzoneSubtitle.textContent = subtitle;
    dropzoneSubtitle.hidden = !subtitle;
  }
  if (tip) {
    tip.textContent = mode === "store"
      ? ""
      : "";
  }
  if (submit) {
    submit.disabled = file === 0 || (mode === "analyze" && shellcode && !arch);
  }
}

async function submitUploadModal() {
  const mode = activeUploadSurfaceTab();
  const format = document.querySelector('input[name="upload-format"]:checked')?.value || "Auto";
  const arch = document.querySelector('input[name="upload-architecture"]:checked')?.value || "Auto";
  const modeTarget = document.getElementById("upload-mode");
  const formatTarget = document.getElementById("upload-format");
  const archTarget = document.getElementById("upload-architecture");
  if (modeTarget) modeTarget.value = mode === "analyze" ? "" : mode;
  if (formatTarget) formatTarget.value = format === "Auto" ? "" : format;
  if (archTarget) archTarget.value = arch === "Auto" ? "" : arch;
  const form = document.getElementById("upload-form");
  if (!(form instanceof HTMLFormElement)) return;
  const formData = new FormData(form);
  if (mode === "analyze") {
    formData.delete("corpus");
    selectedUploadCorpusValues().forEach((value) => {
      formData.append("corpus", value);
    });
    formData.delete("tag");
    selectedUploadTagValues().forEach((value) => {
      formData.append("tag", value);
    });
  } else {
    formData.delete("corpus");
    formData.delete("tag");
  }
  if (mode === "project") {
    formData.delete("sha256");
    uploadProjectSelectedValues.forEach((value) => formData.append("sha256", value));
  }
  const submit = document.getElementById("upload-submit");
  if (submit) submit.disabled = true;
  closeUploadModal();
  openUploadStatusModal("uploading");
  try {
    const endpoint = mode === "project" ? "/api/v1/projects" : "/api/v1/index/sample";
    const response = await fetch(endpoint, {
      method: "POST",
      body: formData,
    });
    const payload = await response.json();
    if (!response.ok || !payload.ok) {
      openUploadStatusModal("failed", { error: payload.error || "The upload failed." });
      return;
    }
    if (mode === "store" || payload.stored) {
      setUploadedSha256State(payload.sha256 || "");
      openUploadStatusModal("stored", { sha256: payload.sha256 || "" });
      return;
    }
    if (mode === "project") {
      openUploadStatusModal("success", { sha256: payload.project_sha256 || "" });
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
