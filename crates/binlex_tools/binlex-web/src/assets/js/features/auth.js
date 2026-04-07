function getAuthMenu() {
  return document.getElementById("auth-menu");
}

function closeAuthMenu() {
  const menu = getAuthMenu();
  if (menu) menu.hidden = true;
}

function toggleAuthMenu() {
  const menu = getAuthMenu();
  if (!menu) return;
  menu.hidden = !menu.hidden;
}

function getAuthModal() {
  return document.getElementById("auth-modal");
}

function openAuthModal(tab = "login") {
  closeAuthMenu();
  const modal = getAuthModal();
  if (!modal) return;
  modal.hidden = false;
  toggleAuthTab(tab);
}

function closeAuthModal() {
  const modal = getAuthModal();
  if (modal) modal.hidden = true;
}

async function logout() {
  closeAuthMenu();
  try {
    await postJson("/api/v1/auth/logout", {});
  } catch (_) {}
  window.location.reload();
}

function toggleAuthTab(tab) {
  document.querySelectorAll("[data-auth-tab]").forEach((button) => {
    button.classList.toggle("is-active", button.getAttribute("data-auth-tab") === tab);
  });
  document.querySelectorAll("[data-auth-panel]").forEach((panel) => {
    panel.hidden = panel.getAttribute("data-auth-panel") !== tab;
  });
  if (tab === "register") {
    refreshRegisterCaptcha().catch(() => {});
  } else if (tab === "reset") {
    refreshResetCaptcha().catch(() => {});
  }
}

async function refreshRegisterCaptcha() {
  return refreshAuthCaptcha("auth-register-form", "auth-register-captcha-image", "auth-register-captcha-id", "auth-register-error");
}

async function refreshResetCaptcha() {
  return refreshAuthCaptcha("auth-reset-form", "auth-reset-captcha-image", "auth-reset-captcha-id", "auth-reset-error");
}

async function refreshAuthCaptcha(formId, imageId, fieldId, errorId) {
  const form = document.getElementById(formId);
  const image = document.getElementById(imageId);
  const field = document.getElementById(fieldId);
  if (!(form instanceof HTMLElement) || !(image instanceof HTMLImageElement) || !(field instanceof HTMLInputElement)) return;
  try {
    const data = await getJson("/api/v1/auth/captcha");
    field.value = String(data?.captcha_id || "");
    image.src = `data:image/png;base64,${String(data?.image_base64 || "")}`;
    image.hidden = false;
  } catch (error) {
    setInlineError(errorId, error.message || "Unable to load captcha.");
  }
}

function setInlineError(id, message) {
  const target = document.getElementById(id);
  if (target) target.textContent = message || "";
}

let recoveryCodesState = {
  title: "Recovery Codes",
  description: "Save these recovery codes somewhere secure. Each code can be used once to reset your password.",
  codes: [],
  visible: false,
  onClose: null,
};

const USERNAME_MAX_LENGTH = 15;
const PASSWORD_MIN_LENGTH = 12;
const PASSWORD_MAX_LENGTH = 32;
const usernameValidationTimers = new WeakMap();
const usernameValidationTokens = new WeakMap();

function getValidationContainer(root, key) {
  return root?.querySelector?.(`[data-feedback-for="${key}"]`) || null;
}

function renderValidationFeedback(target, items) {
  if (!target) return;
  const normalized = Array.isArray(items) ? items.filter(Boolean) : [];
  if (!normalized.length) {
    target.innerHTML = "";
    return;
  }
  target.innerHTML = `<div class="auth-feedback-list">${normalized
    .map((item) => `<div class="auth-feedback-item ${item.kind === "ok" ? "is-ok" : item.kind === "error" ? "is-error" : "is-neutral"}">${escapeHtml(item.text || "")}</div>`)
    .join("")}</div>`;
}

function getFormValidationScope(root) {
  return root?.dataset?.liveValidation || "";
}

function getUsernameInput(root) {
  return root?.querySelector?.('input[name="username"]') || null;
}

function getPasswordInput(root) {
  return root?.querySelector?.('input[name="new_password"], input[name="password"]') || null;
}

function getPasswordConfirmInput(root) {
  return root?.querySelector?.('input[name="password_confirm"]') || null;
}

function validateUsernameLocally(rawValue) {
  const trimmed = String(rawValue || "").trim();
  const normalized = trimmed.toLowerCase();
  const validChars = /^[a-z0-9]*$/.test(normalized);
  const validLength = normalized.length > 0 && normalized.length <= USERNAME_MAX_LENGTH;
  const error = !trimmed
    ? "username must not be empty"
    : !validLength
      ? `username must be at most ${USERNAME_MAX_LENGTH} characters`
      : !validChars
        ? "username must contain only lowercase letters and digits"
        : "";
  return {
    normalized,
    valid: !!trimmed && validChars && validLength,
    error,
    items: trimmed
      ? [
          {
            kind: validChars ? "ok" : "error",
            text: "lowercase letters and digits only",
          },
          {
            kind: validLength ? "ok" : "error",
            text: `at most ${USERNAME_MAX_LENGTH} characters`,
          },
        ]
      : [],
  };
}

function validatePasswordLocally(value) {
  const password = String(value || "");
  const minOk = password.length >= PASSWORD_MIN_LENGTH;
  const maxOk = password.length <= PASSWORD_MAX_LENGTH;
  const error = !password
    ? `password must be at least ${PASSWORD_MIN_LENGTH} characters`
    : !minOk
      ? `password must be at least ${PASSWORD_MIN_LENGTH} characters`
      : !maxOk
        ? `password must be at most ${PASSWORD_MAX_LENGTH} characters`
        : "";
  return {
    valid: !!password && minOk && maxOk,
    error,
    items: [
      {
        kind: minOk ? "ok" : "error",
        text: `at least ${PASSWORD_MIN_LENGTH} characters`,
      },
      {
        kind: maxOk ? "ok" : "error",
        text: `at most ${PASSWORD_MAX_LENGTH} characters`,
      },
    ],
  };
}

function updateUsernameValidation(root) {
  const input = getUsernameInput(root);
  const target = getValidationContainer(root, "username");
  if (!input || !target) return Promise.resolve(true);
  const local = validateUsernameLocally(input.value);
  if (input.value !== local.normalized) {
    input.value = local.normalized;
  }
  const scope = getFormValidationScope(root);
  const needsAvailability = scope === "create";
  root.dataset.usernameAvailable = local.valid && !needsAvailability ? "true" : "false";
  if (!local.valid || !needsAvailability) {
    renderValidationFeedback(
      target,
      local.items.length
        ? local.items
        : [
            { kind: "neutral", text: "lowercase letters and digits only" },
            { kind: "neutral", text: `at most ${USERNAME_MAX_LENGTH} characters` },
          ]
    );
    return Promise.resolve(local.valid);
  }
  const token = (usernameValidationTokens.get(input) || 0) + 1;
  usernameValidationTokens.set(input, token);
  clearTimeout(usernameValidationTimers.get(input));
  renderValidationFeedback(target, [
    ...local.items,
    { kind: "neutral", text: "checking availability" },
  ]);
  return new Promise((resolve) => {
    const timeout = window.setTimeout(async () => {
      try {
        const response = await fetch(
          `/api/v1/auth/username/check?username=${encodeURIComponent(local.normalized)}`,
          { credentials: "same-origin" }
        );
        const data = await response.json().catch(() => ({}));
        if (usernameValidationTokens.get(input) !== token) {
          resolve(false);
          return;
        }
        const available = !!data?.valid && !!data?.available;
        root.dataset.usernameAvailable = available ? "true" : "false";
        renderValidationFeedback(target, [
          ...local.items,
          {
            kind: available ? "ok" : "error",
            text: available ? "username is available" : (data?.error || "username is already taken"),
          },
        ]);
        resolve(available);
      } catch (_) {
        root.dataset.usernameAvailable = "false";
        renderValidationFeedback(target, [
          ...local.items,
          { kind: "error", text: "could not check username availability" },
        ]);
        resolve(false);
      }
    }, 250);
    usernameValidationTimers.set(input, timeout);
  });
}

function updatePasswordValidation(root) {
  const passwordInput = getPasswordInput(root);
  const passwordTarget = getValidationContainer(root, "password");
  const confirmInput = getPasswordConfirmInput(root);
  const confirmTarget = getValidationContainer(root, "password_confirm");
  let passwordValid = true;
  if (passwordInput && passwordTarget) {
    const local = validatePasswordLocally(passwordInput.value);
    renderValidationFeedback(
      passwordTarget,
      passwordInput.value
        ? local.items
        : [
            { kind: "neutral", text: `at least ${PASSWORD_MIN_LENGTH} characters` },
            { kind: "neutral", text: `at most ${PASSWORD_MAX_LENGTH} characters` },
          ]
    );
    passwordValid = local.valid;
  }
  if (confirmInput && confirmTarget) {
    const passwordValue = passwordInput?.value || "";
    const confirmValue = confirmInput.value || "";
    const items =
      passwordValue || confirmValue
        ? [{
            kind: passwordValue && confirmValue && passwordValue === confirmValue ? "ok" : "error",
            text:
              passwordValue && confirmValue && passwordValue === confirmValue
                ? "passwords match"
                : "passwords do not match",
          }]
        : [{ kind: "neutral", text: "passwords must match" }];
    renderValidationFeedback(confirmTarget, items);
  }
  return passwordValid;
}

function updateValidationForRoot(root) {
  if (!root?.dataset?.liveValidation) return;
  updateUsernameValidation(root);
  updatePasswordValidation(root);
}

async function validateFormBeforeSubmit(root) {
  const scope = getFormValidationScope(root);
  const usernameInput = getUsernameInput(root);
  if (usernameInput) {
    const local = validateUsernameLocally(usernameInput.value);
    usernameInput.value = local.normalized;
    if (!local.valid) {
      updateUsernameValidation(root);
      return local.error;
    }
    if (scope === "create") {
      const available = await updateUsernameValidation(root);
      if (!available) {
        return "username is already taken";
      }
    } else {
      updateUsernameValidation(root);
    }
  }
  const passwordInput = getPasswordInput(root);
  if (passwordInput) {
    const local = validatePasswordLocally(passwordInput.value);
    updatePasswordValidation(root);
    if (!local.valid) {
      return local.error;
    }
  }
  const confirmInput = getPasswordConfirmInput(root);
  if (confirmInput && passwordInput && passwordInput.value !== confirmInput.value) {
    updatePasswordValidation(root);
    return "password confirmation does not match";
  }
  return "";
}

function formatRecoveryCodes(codes) {
  return Array.isArray(codes) ? codes.filter(Boolean).join("\n") : "";
}

function maskRecoveryCode(code) {
  return "\u2022".repeat(Math.max(String(code || "").length, 8));
}

function renderRecoveryCodesModal() {
  const title = document.getElementById("recovery-codes-title");
  const description = document.getElementById("recovery-codes-description");
  const output = document.getElementById("recovery-codes-output");
  const toggle = document.getElementById("recovery-codes-toggle");
  const copy = document.getElementById("recovery-codes-copy");
  if (title) title.textContent = recoveryCodesState.title;
  if (description) description.textContent = recoveryCodesState.description;
  if (toggle) {
    toggle.setAttribute(
      "aria-label",
      recoveryCodesState.visible ? "Hide recovery codes" : "Show recovery codes"
    );
    toggle.setAttribute(
      "title",
      recoveryCodesState.visible ? "Hide recovery codes" : "Show recovery codes"
    );
    toggle.classList.toggle("is-active", recoveryCodesState.visible);
  }
  if (copy) copy.disabled = !recoveryCodesState.codes.length;
  if (!output) return;
  if (!recoveryCodesState.codes.length) {
    output.textContent = "";
    return;
  }
  output.textContent = recoveryCodesState.codes
    .map((code) => (recoveryCodesState.visible ? code : maskRecoveryCode(code)))
    .join("\n");
}

function openRecoveryCodesModal(title, codes, description = "", onClose = null) {
  const normalized = Array.isArray(codes) ? codes.filter((value) => typeof value === "string" && value.trim()) : [];
  if (!normalized.length) return;
  recoveryCodesState = {
    title: title || "Recovery Codes",
    description: description || "Save these recovery codes somewhere secure. Each code can be used once to reset your password.",
    codes: normalized,
    visible: false,
    onClose,
  };
  renderRecoveryCodesModal();
  const modal = document.getElementById("recovery-codes-modal");
  if (modal) modal.hidden = false;
}

function closeRecoveryCodesModal() {
  const modal = document.getElementById("recovery-codes-modal");
  if (modal) modal.hidden = true;
  const onClose = recoveryCodesState.onClose;
  recoveryCodesState.onClose = null;
  if (typeof onClose === "function") {
    onClose();
  }
}

function toggleRecoveryCodesVisibility() {
  recoveryCodesState.visible = !recoveryCodesState.visible;
  renderRecoveryCodesModal();
}

async function copyRecoveryCodes() {
  const copy = document.getElementById("recovery-codes-copy");
  const payload = formatRecoveryCodes(recoveryCodesState.codes);
  if (!payload) return;
  try {
    await navigator.clipboard.writeText(payload);
    if (copy) {
      copy.textContent = "Copied";
      copy.classList.add("is-copied");
      window.setTimeout(() => {
        copy.textContent = "Copy";
        copy.classList.remove("is-copied");
      }, 1200);
    }
  } catch (_) {}
}

async function submitBootstrap(event) {
  event.preventDefault();
  const form = event.currentTarget;
  setInlineError("bootstrap-error", "");
  const error = await validateFormBeforeSubmit(form);
  if (error) {
    setInlineError("bootstrap-error", error);
    return;
  }
  try {
    const data = await postJson("/api/v1/auth/bootstrap", Object.fromEntries(new FormData(form).entries()));
    if (data?.two_factor_required && data?.challenge_token) {
      const modal = document.getElementById("bootstrap-modal");
      if (modal) modal.hidden = true;
      openTwoFactorSetupModal("login", data.challenge_token);
      return;
    }
    openRecoveryCodesModal(
      "Recovery Codes",
      data?.recovery_codes,
      "Save these recovery codes before continuing. Each code can be used once to reset your password.",
      () => window.location.reload()
    );
  } catch (error) {
    setInlineError("bootstrap-error", error.message);
  }
}

async function submitLogin(event) {
  event.preventDefault();
  setInlineError("auth-login-error", "");
  try {
    const data = await postJson("/api/v1/auth/login", Object.fromEntries(new FormData(event.currentTarget).entries()));
    if (data?.two_factor_required && data?.challenge_token) {
      closeAuthModal();
      if (data?.two_factor_setup_required) {
        openTwoFactorSetupModal("login", data.challenge_token);
      } else {
        openTwoFactorLoginModal(data.challenge_token);
      }
      return;
    }
    window.location.reload();
  } catch (error) {
    setInlineError("auth-login-error", error.message);
  }
}

async function submitLoginTwoFactor(event) {
  if (event) {
    event.preventDefault();
  }
  setInlineError("auth-login-2fa-error", "");
  const code = document.getElementById("auth-login-2fa-code")?.value || "";
  try {
    await postJson("/api/v1/auth/login/2fa", {
      challenge_token: pendingLoginTwoFactor.challengeToken,
      code,
    });
    window.location.reload();
  } catch (error) {
    setInlineError("auth-login-2fa-error", error.message);
  }
}

async function submitRegister(event) {
  event.preventDefault();
  const form = event.currentTarget;
  setInlineError("auth-register-error", "");
  const error = await validateFormBeforeSubmit(form);
  if (error) {
    setInlineError("auth-register-error", error);
    return;
  }
  try {
    const data = await postJson("/api/v1/auth/register", Object.fromEntries(new FormData(form).entries()));
    if (data?.two_factor_required && data?.challenge_token) {
      closeAuthModal();
      openTwoFactorSetupModal("login", data.challenge_token);
      return;
    }
    openRecoveryCodesModal(
      "Recovery Codes",
      data?.recovery_codes,
      "Save these recovery codes before continuing. Each code can be used once to reset your password.",
      () => window.location.reload()
    );
  } catch (error) {
    setInlineError("auth-register-error", error.message);
    refreshRegisterCaptcha().catch(() => {});
  }
}

async function submitPasswordReset(event) {
  event.preventDefault();
  const form = event.currentTarget;
  setInlineError("auth-reset-error", "");
  const error = await validateFormBeforeSubmit(form);
  if (error) {
    setInlineError("auth-reset-error", error);
    return;
  }
  try {
    await postJson("/api/v1/auth/password/reset", Object.fromEntries(new FormData(form).entries()));
    setInlineError("auth-reset-error", "Password reset. You can sign in now.");
    form.reset();
    updateValidationForRoot(form);
    refreshResetCaptcha().catch(() => {});
  } catch (error) {
    setInlineError("auth-reset-error", error.message);
    refreshResetCaptcha().catch(() => {});
  }
}
