function openUsersModal() {
  closeAuthMenu();
  const modal = document.getElementById("users-modal");
  if (modal) modal.hidden = false;
  toggleUsersTab("search");
  loadUsers();
}

function closeUsersModal() {
  const modal = document.getElementById("users-modal");
  if (modal) modal.hidden = true;
}

function toggleUsersTab(tabName) {
  document.querySelectorAll("[data-users-tab-button]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.usersTabButton === tabName);
  });
  document.querySelectorAll("[data-users-panel]").forEach((panel) => {
    const active = panel.dataset.usersPanel === tabName;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
  if (tabName === "search") {
    loadUsers();
  } else if (tabName === "corpora" || tabName === "tags" || tabName === "symbols") {
    loadAdminMetadata(tabName);
  } else if (tabName === "comments") {
    loadAdminComments();
  }
}

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

function renderUsersList(items) {
  const container = document.getElementById("users-list");
  if (!container) return;
  const policyRequiresTwoFactor = !!globalThis.__BINLEX_AUTH__?.two_factor_required;
  if (!Array.isArray(items) || items.length === 0) {
    container.innerHTML = '<div class="users-empty">No users.</div>';
    return;
  }
  container.innerHTML = items.map((user) => `
    <div class="users-item">
      <div class="users-item-header">
        <div class="users-item-main">
          <div class="auth-avatar users-item-avatar">${avatarMarkupForUser(user)}</div>
          <div class="users-item-copy">
            <strong>${escapeHtml(user.username)}</strong>
            <small>role: ${escapeHtml(user.role)}${user.enabled ? "" : " | disabled"} | 2fa: ${user.two_factor_enabled ? "enabled" : user.two_factor_required ? "required" : "off"}</small>
          </div>
        </div>
      </div>
      <div class="users-item-actions">
        <button type="button" class="secondary" onclick="toggleUserEnabled('${escapeHtml(user.username)}', ${user.enabled ? "true" : "false"})">${user.enabled ? "Disable" : "Enable"}</button>
        <button type="button" class="secondary" onclick="toggleUserRole('${escapeHtml(user.username)}', '${escapeHtml(user.role)}')">Role</button>
        <button type="button" class="secondary" onclick="resetUserPassword('${escapeHtml(user.username)}')">Reset</button>
        ${policyRequiresTwoFactor
          ? (user.two_factor_enabled || user.two_factor_required
            ? `<button type="button" class="secondary" onclick="resetUserTwoFactor('${escapeHtml(user.username)}')">Reset 2FA</button>`
            : "")
          : `<button type="button" class="secondary" onclick="${user.two_factor_enabled || user.two_factor_required ? `disableUserTwoFactor('${escapeHtml(user.username)}')` : `requireUserTwoFactor('${escapeHtml(user.username)}')`}">${user.two_factor_enabled || user.two_factor_required ? "Disable 2FA" : "Require 2FA"}</button>`}
        ${!policyRequiresTwoFactor && user.two_factor_enabled ? `<button type="button" class="secondary" onclick="resetUserTwoFactor('${escapeHtml(user.username)}')">Reset 2FA</button>` : ""}
        ${user.profile_picture ? `<button type="button" class="secondary" onclick="deleteUserPicture('${escapeHtml(user.username)}')">Delete Avatar</button>` : ""}
        <button type="button" class="secondary" onclick="deleteUser('${escapeHtml(user.username)}')">Delete</button>
      </div>
      <div class="admin-user-key-section">
        <div class="admin-user-key-label">API Key</div>
        <div class="admin-user-key-wrap">
          <input class="menu-search profile-key-input admin-user-key-input" id="admin-user-key-${escapeHtml(user.username)}" type="password" value="${escapeHtml(user.key || "")}" readonly data-secret="${escapeHtml(user.key || "")}">
          <button type="button" class="symbol-picker-copy admin-user-key-copy" id="admin-user-key-copy-${escapeHtml(user.username)}" onclick="copyAdminUserKey('${escapeHtml(user.username)}')">Copy</button>
          <button type="button" class="secondary recovery-codes-visibility admin-user-key-toggle" id="admin-user-key-toggle-${escapeHtml(user.username)}" onclick="toggleAdminUserKeyVisibility('${escapeHtml(user.username)}')" aria-label="Show API key" title="Show API key"><span class="recovery-codes-eye" aria-hidden="true">👁</span></button>
        </div>
      </div>
    </div>
  `).join("");
}

function renderUsersSummary(visibleCount, totalCount) {
  const summary = document.getElementById("users-summary");
  if (!summary) return;
  summary.textContent = `Showing ${visibleCount} of ${totalCount}`;
}

async function loadUsers() {
  const query = document.getElementById("users-search-input")?.value || "";
  setInlineError("users-search-error", "");
  try {
    const response = await fetch(`/api/v1/admin/users?q=${encodeURIComponent(query)}&page=1&limit=3`, {
      credentials: "same-origin",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data?.error || "Failed to load users");
    }
    const items = Array.isArray(data.items) ? data.items : [];
    renderUsersSummary(items.length, Number(data.total_results) || 0);
    renderUsersList(items);
  } catch (error) {
    renderUsersSummary(0, 0);
    setInlineError("users-search-error", error.message);
  }
}

async function createUser(event) {
  event.preventDefault();
  const form = event.currentTarget;
  setInlineError("users-create-error", "");
  const validationError = await validateFormBeforeSubmit(form);
  if (validationError) {
    setInlineError("users-create-error", validationError);
    return;
  }
  try {
    const data = await postJson("/api/v1/admin/users/create", Object.fromEntries(new FormData(form).entries()));
    form.reset();
    updateValidationForRoot(form);
    if (Array.isArray(data?.recovery_codes) && data.recovery_codes.length) {
      openRecoveryCodesModal(
        `Recovery Codes For ${data?.user?.username || "User"}`,
        data.recovery_codes,
        `Save these recovery codes for ${data?.user?.username || "this user"}. Each code can be used once to reset the password.`
      );
    }
    loadUsers();
  } catch (error) {
    setInlineError("users-create-error", error.message);
  }
}

async function toggleUserRole(username, currentRole) {
  setInlineError("users-search-error", "");
  try {
    await postJson("/api/v1/admin/users/role", {
      username,
      role: currentRole === "admin" ? "user" : "admin",
    });
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}

async function toggleUserEnabled(username, currentlyEnabled) {
  setInlineError("users-search-error", "");
  try {
    await postJson("/api/v1/admin/users/enabled", {
      username,
      enabled: !currentlyEnabled,
    });
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}

async function resetUserPassword(username) {
  try {
    const data = await postJson("/api/v1/admin/users/password/reset", { username });
    alert(`Temporary password for ${username}: ${data.password || ""}`);
  } catch (error) {
    alert(error.message);
  }
}

async function regenerateUserKey(username) {
  try {
    const data = await postJson("/api/v1/admin/users/key/regenerate", { username });
    alert(`API key for ${username}: ${data.key || ""}`);
  } catch (error) {
    alert(error.message);
  }
}

async function deleteUser(username) {
  setInlineError("users-search-error", "");
  try {
    await postJson("/api/v1/admin/users/delete", { username });
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}

async function deleteUserPicture(username) {
  setInlineError("users-search-error", "");
  try {
    await postJson("/api/v1/admin/users/picture/delete", { username });
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}

async function requireUserTwoFactor(username) {
  setInlineError("users-search-error", "");
  try {
    await postJson("/api/v1/admin/users/2fa/require", { username, required: true });
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}

async function disableUserTwoFactor(username) {
  setInlineError("users-search-error", "");
  try {
    await postJson("/api/v1/admin/users/2fa/disable", { username });
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}

async function resetUserTwoFactor(username) {
  setInlineError("users-search-error", "");
  try {
    await postJson("/api/v1/admin/users/2fa/reset", { username });
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}
