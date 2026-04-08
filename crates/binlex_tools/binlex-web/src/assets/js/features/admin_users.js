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
    await deleteJson(`/api/v1/admin/users/${encodeURIComponent(username)}`);
    loadUsers();
  } catch (error) {
    setInlineError("users-search-error", error.message);
  }
}

async function deleteUserPicture(username) {
  setInlineError("users-search-error", "");
  try {
    await deleteJson(`/api/v1/admin/users/${encodeURIComponent(username)}/picture`);
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
