async function fetchSearchResults(url, payload) {
  setSearchSubmitLoading(true);
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: {
      "X-Requested-With": "binlex-web",
      "Content-Type": "application/json",
      "Accept": "application/json",
    },
    body: JSON.stringify(payload),
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `request failed with status ${response.status}`);
  }
  const data = await response.json();
  renderSearchData(data);
  setSearchSubmitLoading(false);
}

function expandedResultKeys() {
  return Array.from(document.querySelectorAll(".result-row.expanded[data-result-key]"))
    .map((row) => String(row.dataset.resultKey || ""))
    .filter(Boolean);
}

function renderSearchData(data) {
  const expandedKeys = expandedResultKeys();
  if (typeof window !== "undefined") {
    window.__BINLEX_SEARCH_DATA__ = data;
  }
  const notices = document.getElementById("page-notices");
  const results = document.getElementById("search-results");
  if (!(notices instanceof HTMLElement) || !(results instanceof HTMLElement)) {
    window.location.replace("/");
    return;
  }
  notices.innerHTML = renderNoticesSection(data);
  results.innerHTML = renderResultsSection(data);
  const topKInput = getTopKInput();
  const pageInput = getPageInput();
  if (topKInput && data.top_k != null) topKInput.value = String(data.top_k);
  if (pageInput && data.page != null) pageInput.value = String(data.page);
  const queryInput = getQueryInput();
  if (queryInput && typeof data.query === "string") queryInput.value = data.query;
  syncFormState("upload-form");
  expandedKeys.forEach((resultKey) => {
    expandResultDetailsByKey(resultKey);
  });
  closeRowActionMenu();
  closeTagsPopover();
  closeSymbolPopover();
  const columnsPopover = getColumnsPopover();
  if (columnsPopover instanceof HTMLElement && !columnsPopover.hidden) {
    const currentTrigger = document.querySelector(".columns-trigger");
    if (currentTrigger instanceof HTMLElement) {
      if (activeColumnsTrigger instanceof HTMLElement) {
        activeColumnsTrigger.classList.remove("active");
      }
      activeColumnsTrigger = currentTrigger;
      activeColumnsTrigger.classList.add("active");
      renderColumnsPopover(columnsPopover);
    } else {
      closeColumnsPopover();
    }
  }
}

async function handleEnhancedFormSubmit(event) {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) return;
  if (!form.matches(".search-form, .pagination-form")) return;
  event.preventDefault();
  try {
    const payload = buildSearchPayload(form);
    await fetchSearchResults(form.action, payload);
  } catch (error) {
    setSearchSubmitLoading(false);
    console.error("binlex-web form submit failed", error);
  }
}

function initializeSearchPage() {
  if (typeof window === "undefined") return;
  const data = window.__BINLEX_SEARCH_DATA__;
  if (data && typeof data === "object") {
    renderSearchData(data);
  }
}
