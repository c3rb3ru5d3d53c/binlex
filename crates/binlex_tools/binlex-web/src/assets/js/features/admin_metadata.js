const ADMIN_METADATA_CONFIG = {
  corpora: {
    listId: "admin-corpora-list",
    summaryId: "admin-corpora-summary",
    errorId: "admin-corpora-error",
    inputId: "admin-corpora-search-input",
    createButtonId: "admin-corpora-create-button",
    searchUrl: "/api/v1/corpora",
    createUrl: "/api/v1/corpora/add",
    deleteUrl: "/api/v1/admin/corpora/delete",
    responseKey: "corpora",
    requestKey: "corpus",
    singular: "corpus",
    plural: "corpora",
  },
  tags: {
    listId: "admin-tags-list",
    summaryId: "admin-tags-summary",
    errorId: "admin-tags-error",
    inputId: "admin-tags-search-input",
    createButtonId: "admin-tags-create-button",
    searchUrl: "/api/v1/tags/search",
    createUrl: "/api/v1/tags/add",
    deleteUrl: "/api/v1/admin/tags/delete",
    responseKey: "tags",
    requestKey: "tag",
    singular: "tag",
    plural: "tags",
  },
  symbols: {
    listId: "admin-symbols-list",
    summaryId: "admin-symbols-summary",
    errorId: "admin-symbols-error",
    inputId: "admin-symbols-search-input",
    createButtonId: "admin-symbols-create-button",
    searchUrl: "/api/v1/symbols/search",
    createUrl: "/api/v1/symbols/add",
    deleteUrl: "/api/v1/admin/symbols/delete",
    responseKey: "symbols",
    requestKey: "symbol",
    singular: "symbol",
    plural: "symbols",
  },
};

function adminMetadataConfig(kind) {
  return ADMIN_METADATA_CONFIG[kind] || null;
}

function isLockedAdminMetadata(kind, name) {
  if (kind !== "corpora") return false;
  return LOCKED_CORE_CORPORA.has(String(name || "").trim().toLowerCase());
}

function renderAdminMetadataSummary(kind, visibleCount, totalCount) {
  const config = adminMetadataConfig(kind);
  const summary = config ? document.getElementById(config.summaryId) : null;
  if (!summary) return;
  summary.textContent = `Showing ${visibleCount} of ${totalCount}`;
}

function metadataNameHasWhitespace(value) {
  return /\s/.test(String(value || "").trim());
}

function setAdminMetadataCreateState(kind, query, items) {
  const config = adminMetadataConfig(kind);
  const button = config ? document.getElementById(config.createButtonId) : null;
  if (!button) return;
  const normalizedQuery = String(query || "").trim().toLowerCase();
  const exists = Array.isArray(items) && items.some((item) => metadataItemName(item).trim().toLowerCase() === normalizedQuery);
  button.disabled = !normalizedQuery || exists || metadataNameHasWhitespace(query);
}

function renderAdminMetadataList(kind, items) {
  const config = adminMetadataConfig(kind);
  const container = config ? document.getElementById(config.listId) : null;
  if (!container) return;
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = `<div class="users-empty">No ${escapeHtml(config.plural)}.</div>`;
    return;
  }
  container.innerHTML = items.map((item) => {
    const name = metadataItemName(item);
    const locked = isLockedAdminMetadata(kind, name);
    const actions = locked
      ? ""
      : `<div class="symbol-picker-actions">
            <button
              type="button"
              class="symbol-picker-move admin-metadata-delete"
              title="Delete ${escapeHtml(config.singular)}"
              aria-label="Delete ${escapeHtml(config.singular)}"
              onclick="deleteAdminMetadata('${escapeHtml(kind)}','${escapeHtml(encodeURIComponent(name))}')"
            >🗑</button>
          </div>`;
    return `
      <div class="admin-metadata-item">
        <div class="symbol-picker-item admin-metadata-pill">
          <span class="symbol-picker-name" title="${escapeHtml(name)}">${escapeHtml(name)}</span>
          ${actions}
          ${metadataTooltipHtml(item, "created")}
        </div>
      </div>
    `;
  }).join("");
}

function pruneDeletedMetadataFromSearch(kind, value) {
  const data = currentSearchData();
  const needle = String(value || "").trim().toLowerCase();
  if (!data || !Array.isArray(data.results) || !needle) return;
  let changed = false;
  data.results.forEach((row) => {
    if (!row || typeof row !== "object") return;
    if (kind === "tags") {
      const tags = normalizeMetadataItems(row.collection_tags || []);
      const nextTags = tags.filter((item) => metadataItemName(item).toLowerCase() !== needle);
      if (nextTags.length !== tags.length) {
        row.collection_tags = nextTags;
        row.collection_tag_count = nextTags.length;
        row.tags_loaded = true;
        changed = true;
      }
    } else if (kind === "symbols") {
      const symbols = normalizeMetadataItems(row.symbols || (row.symbol ? [row.symbol] : []));
      const nextSymbols = symbols.filter((item) => metadataItemName(item).toLowerCase() !== needle);
      if (nextSymbols.length !== symbols.length || String(row.symbol || "").trim().toLowerCase() === needle) {
        row.symbols = nextSymbols;
        row.symbols_loaded = true;
        const currentPrimary = String(row.symbol || "").trim();
        if (!currentPrimary || currentPrimary.toLowerCase() === needle) {
          row.symbol = nextSymbols.length > 0 ? metadataItemName(nextSymbols[0]) : "";
        }
        changed = true;
      }
    } else if (kind === "corpora") {
      const corpora = normalizeMetadataItems(row.collection_corpora || row.corpora || []);
      const nextCorpora = corpora.filter((item) => metadataItemName(item).toLowerCase() !== needle);
      if (nextCorpora.length !== corpora.length) {
        row.collection_corpora = nextCorpora;
        row.corpora = nextCorpora;
        row.corpora_loaded = true;
        changed = true;
      }
    }
  });
  if (changed) {
    renderSearchData(data);
  }
}

async function loadAdminMetadata(kind) {
  const config = adminMetadataConfig(kind);
  if (!config) return;
  const query = document.getElementById(config.inputId)?.value || "";
  setAdminMetadataCreateState(kind, query, []);
  setInlineError(config.errorId, "");
  try {
    const response = await fetch(`${config.searchUrl}?q=${encodeURIComponent(query)}&limit=6`, {
      credentials: "same-origin",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data?.error || `Failed to load ${config.plural}`);
    }
    const items = normalizeMetadataItems(Array.isArray(data?.[config.responseKey]) ? data[config.responseKey] : []);
    const total = Number(data?.total_results || items.length || 0);
    setAdminMetadataCreateState(kind, query, items);
    renderAdminMetadataSummary(kind, items.length, total);
    renderAdminMetadataList(kind, items);
  } catch (error) {
    setAdminMetadataCreateState(kind, query, []);
    renderAdminMetadataSummary(kind, 0, 0);
    renderAdminMetadataList(kind, []);
    setInlineError(config.errorId, error.message);
  }
}

function renderAdminCommentsList(items) {
  const container = document.getElementById("admin-comments-list");
  if (!container) return;
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = '<div class="users-empty">No comments.</div>';
    return;
  }
  container.innerHTML = items.map((item) => `
    <div class="comment-card admin-comment-card">
      <div class="comment-avatar-wrap">${commentAuthorHtml(item?.actor)}</div>
      <div class="comment-card-body">
        <div class="comment-card-header">
          <div class="comment-card-identity">
            <span class="comment-card-username">${escapeHtml(metadataActorUsername(item?.actor) || "unknown")}</span>
            <span class="comment-card-time">${escapeHtml(formatUtcTimestamp(item?.timestamp || ""))}</span>
          </div>
          <button type="button" class="symbol-picker-move comment-delete" title="Delete comment" aria-label="Delete comment" onclick="deleteCommentById(${Number(item?.id || 0)})">🗑</button>
        </div>
        <div class="admin-comment-meta">
          <span>${escapeHtml(displayCollection(item?.collection || ""))}</span>
          <span>${escapeHtml(`0x${Number(item?.address || 0).toString(16)}`)}</span>
          <span>${escapeHtml(abbreviateHex(item?.sha256 || ""))}</span>
        </div>
        <div class="comment-card-text">${escapeHtml(String(item?.body || "")).replace(/\n/g, "<br>")}</div>
      </div>
    </div>
  `).join("");
}

async function loadAdminComments() {
  const query = document.getElementById("admin-comments-search-input")?.value || "";
  setInlineError("admin-comments-error", "");
  try {
    const payload = await getJson(`/api/v1/admin/comments?q=${encodeURIComponent(query)}&page=1&page_size=20`);
    const items = Array.isArray(payload?.items) ? payload.items : [];
    const summary = document.getElementById("admin-comments-summary");
    if (summary) {
      summary.textContent = `Showing ${items.length} of ${Number(payload?.total_results || items.length)}`;
    }
    renderAdminCommentsList(items);
  } catch (error) {
    renderAdminCommentsList([]);
    setInlineError("admin-comments-error", error.message);
  }
}

async function createAdminMetadata(kind) {
  const config = adminMetadataConfig(kind);
  if (!config) return;
  const input = document.getElementById(config.inputId);
  const value = String(input?.value || "").trim();
  if (!value) return;
  setInlineError(config.errorId, "");
  if (metadataNameHasWhitespace(value)) {
    setInlineError(config.errorId, `${config.singular} must not contain whitespace`);
    return;
  }
  const confirmed = await requestTagsConfirmation({
    title: `Create ${config.singular[0].toUpperCase()}${config.singular.slice(1)}`,
    message: `Create "${value}" as a ${config.singular}?`,
    confirmLabel: "Create",
  });
  if (!confirmed) return;
  try {
    await postJson(config.createUrl, { [config.requestKey]: value });
    await loadAdminMetadata(kind);
  } catch (error) {
    setInlineError(config.errorId, error.message);
  }
}

async function deleteAdminMetadata(kind, encodedValue) {
  const config = adminMetadataConfig(kind);
  if (!config) return;
  const value = decodeURIComponent(String(encodedValue || ""));
  if (!value) return;
  setInlineError(config.errorId, "");
  const confirmed = await requestTagsConfirmation({
    title: `Delete ${config.singular[0].toUpperCase()}${config.singular.slice(1)}`,
    message: `Delete "${value}" from ${config.plural} globally?`,
    confirmLabel: "Delete",
  });
  if (!confirmed) return;
  try {
    await postJson(config.deleteUrl, { [config.requestKey]: value });
    pruneDeletedMetadataFromSearch(kind, value);
    await loadAdminMetadata(kind);
  } catch (error) {
    setInlineError(config.errorId, error.message);
  }
}
