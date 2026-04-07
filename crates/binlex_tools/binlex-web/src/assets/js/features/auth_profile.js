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

function openTwoFactorLoginModal(challengeToken) {
  pendingLoginTwoFactor = {
    challengeToken: String(challengeToken || ""),
    setupRequired: false,
  };
  setInlineError("auth-login-2fa-error", "");
  const input = document.getElementById("auth-login-2fa-code");
  if (input instanceof HTMLInputElement) input.value = "";
  const modal = document.getElementById("two-factor-login-modal");
  if (modal) modal.hidden = false;
}

function closeTwoFactorLoginModal() {
  const modal = document.getElementById("two-factor-login-modal");
  if (modal) modal.hidden = true;
  pendingLoginTwoFactor = { challengeToken: "", setupRequired: false };
}

function openTwoFactorSetupModal(mode = "profile", challengeToken = "") {
  twoFactorSetupState = {
    mode: mode === "login" ? "login" : "profile",
    challengeToken: String(challengeToken || ""),
    generated: false,
  };
  setInlineError("two-factor-setup-error", "");
  syncTwoFactorSetupSecretField("", false);
  const passwordField = document.getElementById("two-factor-setup-password-field");
  const passwordStep = document.getElementById("two-factor-setup-password-step");
  const passwordStepHeading = document.getElementById("two-factor-password-step-heading");
  if (passwordField instanceof HTMLElement) {
    passwordField.hidden = twoFactorSetupState.mode !== "profile";
  }
  if (passwordStep instanceof HTMLElement) {
    passwordStep.classList.toggle("is-login-setup", twoFactorSetupState.mode === "login");
  }
  if (passwordStepHeading instanceof HTMLElement) {
    passwordStepHeading.textContent = twoFactorSetupState.mode === "login"
      ? "Step 2: Generate QR"
      : "Step 2: Confirm With Password";
  }
  const passwordInput = document.getElementById("two-factor-setup-password");
  if (passwordInput instanceof HTMLInputElement) {
    passwordInput.value = "";
    passwordInput.type = "password";
  }
  const codeInput = document.getElementById("two-factor-setup-code");
  if (codeInput instanceof HTMLInputElement) {
    codeInput.value = "";
    codeInput.type = "password";
  }
  const qrFrame = document.getElementById("two-factor-qr-frame");
  if (qrFrame instanceof HTMLElement) qrFrame.hidden = false;
  const qrSvg = document.getElementById("two-factor-qr-svg");
  if (qrSvg instanceof HTMLElement) {
    qrSvg.innerHTML = "";
    qrSvg.classList.add("is-empty");
  }
  const enableButton = document.getElementById("two-factor-enable-button");
  if (enableButton instanceof HTMLButtonElement) enableButton.disabled = true;
  const generateButton = document.getElementById("two-factor-generate-button");
  if (generateButton instanceof HTMLButtonElement) generateButton.disabled = false;
  syncTwoFactorInlineVisibility(
    "two-factor-password-toggle",
    false,
    "Show current password",
    "Hide current password"
  );
  syncTwoFactorInlineVisibility(
    "two-factor-code-toggle",
    false,
    "Show authenticator code",
    "Hide authenticator code"
  );
  const tip = document.getElementById("two-factor-setup-tip");
  if (tip) {
    tip.textContent = twoFactorSetupState.mode === "login"
      ? "Two-factor authentication is required for this account. Generate a QR code, scan it with your authenticator app, then confirm with a 6-digit code."
      : "Use an authenticator app to scan the QR code, then confirm setup with your password and a 6-digit code.";
  }
  const modal = document.getElementById("two-factor-setup-modal");
  if (modal) modal.hidden = false;
}

function closeTwoFactorSetupModal() {
  const modal = document.getElementById("two-factor-setup-modal");
  if (modal) modal.hidden = true;
  twoFactorSetupState = { mode: "profile", challengeToken: "", generated: false };
}

function openTwoFactorDisableModal() {
  setInlineError("two-factor-disable-error", "");
  const password = document.getElementById("two-factor-disable-password");
  const code = document.getElementById("two-factor-disable-code");
  const requiredByPolicy = !!globalThis.__BINLEX_AUTH__?.two_factor_required;
  const title = document.getElementById("two-factor-disable-title");
  const tip = document.getElementById("two-factor-disable-tip");
  const submit = document.getElementById("two-factor-disable-submit");
  if (password instanceof HTMLInputElement) password.value = "";
  if (code instanceof HTMLInputElement) code.value = "";
  if (title) {
    title.textContent = requiredByPolicy ? "Reset 2FA" : "Disable 2FA";
  }
  if (tip) {
    tip.textContent = requiredByPolicy
      ? "Confirm your password and enter an authenticator or recovery code to reset two-factor authentication. You will be required to enroll again on your next sign in."
      : "Confirm your password and enter an authenticator or recovery code to disable two-factor authentication.";
  }
  if (submit) {
    submit.textContent = requiredByPolicy ? "Reset 2FA" : "Disable 2FA";
  }
  const modal = document.getElementById("two-factor-disable-modal");
  if (modal) modal.hidden = false;
}

function closeTwoFactorDisableModal() {
  const modal = document.getElementById("two-factor-disable-modal");
  if (modal) modal.hidden = true;
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

let pendingLoginTwoFactor = {
  challengeToken: "",
  setupRequired: false,
};

let twoFactorSetupState = {
  mode: "profile",
  challengeToken: "",
  generated: false,
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

async function startTwoFactorSetup() {
  setInlineError("two-factor-setup-error", "");
  try {
    const payload = twoFactorSetupState.mode === "login"
      ? await postJson("/api/v1/auth/login/2fa/setup", {
          challenge_token: twoFactorSetupState.challengeToken,
        })
      : await postJson("/api/v1/profile/2fa/setup", {});
    syncTwoFactorSetupSecretField(String(payload?.manual_secret || ""), false);
    const qrFrame = document.getElementById("two-factor-qr-frame");
    const qrSvg = document.getElementById("two-factor-qr-svg");
    if (qrSvg instanceof HTMLElement) {
      qrSvg.innerHTML = String(payload?.qr_svg || "");
      qrSvg.classList.toggle("is-empty", !String(payload?.qr_svg || "").trim());
    }
    if (qrFrame instanceof HTMLElement) {
      qrFrame.hidden = false;
    }
    twoFactorSetupState.generated = true;
    const enableButton = document.getElementById("two-factor-enable-button");
    if (enableButton instanceof HTMLButtonElement) enableButton.disabled = false;
    const generateButton = document.getElementById("two-factor-generate-button");
    if (generateButton instanceof HTMLButtonElement) generateButton.disabled = true;
  } catch (error) {
    setInlineError("two-factor-setup-error", error.message);
  }
}

async function confirmTwoFactorSetup() {
  setInlineError("two-factor-setup-error", "");
  try {
    const mode = twoFactorSetupState.mode;
    const payload = twoFactorSetupState.mode === "login"
      ? await postJson("/api/v1/auth/login/2fa/enable", {
          challenge_token: twoFactorSetupState.challengeToken,
          code: document.getElementById("two-factor-setup-code")?.value || "",
        })
      : await postJson("/api/v1/profile/2fa/enable", {
          current_password: document.getElementById("two-factor-setup-password")?.value || "",
          code: document.getElementById("two-factor-setup-code")?.value || "",
        });
    closeTwoFactorSetupModal();
    if (payload?.user) {
      applyCurrentUserProfile(payload.user);
    }
    if (Array.isArray(payload?.recovery_codes) && payload.recovery_codes.length) {
      openRecoveryCodesModal(
        "Recovery Codes",
        payload.recovery_codes,
        "Save these recovery codes somewhere secure. Each code can be used once to sign in or reset your password.",
        mode === "login" ? () => window.location.reload() : null
      );
    } else if (mode === "login") {
      window.location.reload();
    }
  } catch (error) {
    setInlineError("two-factor-setup-error", error.message);
  }
}

function syncTwoFactorInlineVisibility(toggleId, visible, showLabel, hideLabel) {
  const toggle = document.getElementById(toggleId);
  if (!(toggle instanceof HTMLButtonElement)) return;
  toggle.classList.toggle("is-active", !!visible);
  toggle.setAttribute("aria-label", visible ? hideLabel : showLabel);
  toggle.setAttribute("title", visible ? hideLabel : showLabel);
}

function syncTwoFactorSetupSecretField(secret, visible) {
  const field = document.getElementById("two-factor-manual-secret");
  const toggle = document.getElementById("two-factor-secret-toggle");
  const copy = document.getElementById("two-factor-secret-copy");
  if (!(field instanceof HTMLInputElement) || !(toggle instanceof HTMLButtonElement) || !(copy instanceof HTMLButtonElement)) {
    return;
  }
  const hasSecret = typeof secret === "string" && secret.length > 0;
  field.dataset.secret = hasSecret ? secret : "";
  field.value = hasSecret ? secret : "";
  field.type = visible && hasSecret ? "text" : "password";
  field.placeholder = hasSecret ? "" : "Generate QR to reveal the secret.";
  toggle.disabled = !hasSecret;
  copy.disabled = !hasSecret;
  copy.textContent = "Copy";
  copy.classList.remove("is-copied");
  toggle.classList.toggle("is-active", visible && hasSecret);
  toggle.setAttribute("aria-label", visible && hasSecret ? "Hide secret" : "Show secret");
  toggle.setAttribute("title", visible && hasSecret ? "Hide secret" : "Show secret");
}

function toggleTwoFactorSetupSecretVisibility() {
  const field = document.getElementById("two-factor-manual-secret");
  if (!(field instanceof HTMLInputElement)) return;
  const secret = field.dataset.secret || "";
  if (!secret) return;
  syncTwoFactorSetupSecretField(secret, field.type === "password");
}

async function copyTwoFactorSetupSecret() {
  const field = document.getElementById("two-factor-manual-secret");
  const button = document.getElementById("two-factor-secret-copy");
  if (!(field instanceof HTMLInputElement) || !(button instanceof HTMLButtonElement)) return;
  const secret = field.dataset.secret || "";
  if (!secret) return;
  try {
    await navigator.clipboard.writeText(secret);
    button.textContent = "Copied";
    button.classList.add("is-copied");
    window.setTimeout(() => {
      button.textContent = "Copy";
      button.classList.remove("is-copied");
    }, 1200);
  } catch (_) {}
}

function toggleTwoFactorSetupPasswordVisibility() {
  const field = document.getElementById("two-factor-setup-password");
  if (!(field instanceof HTMLInputElement)) return;
  const visible = field.type === "password";
  field.type = visible ? "text" : "password";
  syncTwoFactorInlineVisibility(
    "two-factor-password-toggle",
    visible,
    "Show current password",
    "Hide current password"
  );
}

function toggleTwoFactorSetupCodeVisibility() {
  const field = document.getElementById("two-factor-setup-code");
  if (!(field instanceof HTMLInputElement)) return;
  const visible = field.type === "password";
  field.type = visible ? "text" : "password";
  syncTwoFactorInlineVisibility(
    "two-factor-code-toggle",
    visible,
    "Show authenticator code",
    "Hide authenticator code"
  );
}

async function submitTwoFactorDisable() {
  setInlineError("two-factor-disable-error", "");
  try {
    const payload = await postJson("/api/v1/profile/2fa/disable", {
      current_password: document.getElementById("two-factor-disable-password")?.value || "",
      code: document.getElementById("two-factor-disable-code")?.value || "",
    });
    if (payload) applyCurrentUserProfile(payload);
    closeTwoFactorDisableModal();
  } catch (error) {
    setInlineError("two-factor-disable-error", error.message);
  }
}

async function logout() {
  closeAuthMenu();
  try {
    await postJson("/api/v1/auth/logout", {});
  } catch (_) {}
  window.location.reload();
}

function openProfileModal() {
  closeAuthMenu();
  const modal = document.getElementById("profile-modal");
  if (modal) modal.hidden = false;
  toggleProfileTab("account");
  const field = document.getElementById("profile-key-output");
  syncProfileKeyField(field?.dataset.secret || "", false);
  syncProfileTwoFactorState(currentAuthUser());
}

function closeProfileModal() {
  const modal = document.getElementById("profile-modal");
  if (modal) modal.hidden = true;
}

function avatarMarkupForUser(user) {
  const username = String(user?.username || "").trim();
  const profilePicture = String(user?.profile_picture || "").trim();
  if (profilePicture) {
    return `<img src="${escapeHtml(profilePicture)}" alt="${escapeHtml(username)}">`;
  }
  const initial = username ? username[0] : "u";
  return `<span>${escapeHtml(initial)}</span>`;
}

function currentAuthUser() {
  return globalThis.__BINLEX_CURRENT_USER__ || null;
}

function syncProfileTwoFactorState(user) {
  const status = document.getElementById("profile-2fa-status");
  const setupButton = document.getElementById("profile-2fa-setup-button");
  const disableButton = document.getElementById("profile-2fa-disable-button");
  const enabled = !!user?.two_factor_enabled;
  const required = !!user?.two_factor_required;
  const requiredByPolicy = !!globalThis.__BINLEX_AUTH__?.two_factor_required;
  if (status) {
    status.textContent = `Status: ${enabled ? "Enabled" : required ? "Required on next sign in" : "Disabled"}`;
  }
  if (setupButton) {
    setupButton.hidden = enabled;
  }
  if (disableButton) {
    disableButton.hidden = !(enabled || required);
    disableButton.textContent = requiredByPolicy ? "Reset 2FA" : "Disable 2FA";
  }
}

function applyCurrentUserProfile(user) {
  if (!user || typeof user !== "object") return;
  globalThis.__BINLEX_CURRENT_USER__ = {
    ...(globalThis.__BINLEX_CURRENT_USER__ || {}),
    ...user,
  };
  const preview = document.getElementById("profile-avatar-preview");
  if (preview) {
    const camera = preview.querySelector(".profile-avatar-camera");
    preview.innerHTML = avatarMarkupForUser(user);
    if (camera) {
      preview.appendChild(camera);
    }
  }
  document.querySelectorAll(".auth-header .auth-avatar").forEach((node) => {
    node.innerHTML = avatarMarkupForUser(user);
  });
  syncProfileTwoFactorState(user);
}

function toggleProfileTab(tabName) {
  document.querySelectorAll("[data-profile-tab-button]").forEach((button) => {
    button.classList.toggle("is-active", button.dataset.profileTabButton === tabName);
  });
  document.querySelectorAll("[data-profile-panel]").forEach((panel) => {
    const active = panel.dataset.profilePanel === tabName;
    panel.hidden = !active;
    panel.classList.toggle("is-active", active);
  });
}

function syncProfileKeyField(secret, visible) {
  const field = document.getElementById("profile-key-output");
  const toggle = document.getElementById("profile-key-toggle");
  const copy = document.getElementById("profile-key-copy");
  if (!field || !toggle || !copy) return;
  const hasSecret = typeof secret === "string" && secret.length > 0;
  field.dataset.secret = hasSecret ? secret : "";
  field.value = hasSecret ? secret : "";
  field.type = visible && hasSecret ? "text" : "password";
  field.placeholder = hasSecret ? "" : "Regenerate to reveal a new API key.";
  toggle.disabled = !hasSecret;
  copy.disabled = !hasSecret;
  toggle.classList.toggle("is-active", visible && hasSecret);
  toggle.setAttribute(
    "aria-label",
    visible && hasSecret ? "Hide API key" : "Show API key"
  );
  toggle.setAttribute(
    "title",
    visible && hasSecret ? "Hide API key" : "Show API key"
  );
}

function toggleProfileKeyVisibility() {
  const field = document.getElementById("profile-key-output");
  if (!field) return;
  const secret = field.dataset.secret || "";
  if (!secret) return;
  syncProfileKeyField(secret, field.type === "password");
}

async function copyProfileKey() {
  const field = document.getElementById("profile-key-output");
  if (!field) return;
  const secret = field.dataset.secret || "";
  if (!secret) return;
  try {
    await navigator.clipboard.writeText(secret);
    setInlineError("profile-key-error", "API key copied.");
  } catch (_) {
    setInlineError("profile-key-error", "Failed to copy API key.");
  }
}

function toggleAdminUserKeyVisibility(username) {
  const field = document.getElementById(`admin-user-key-${username}`);
  const toggle = document.getElementById(`admin-user-key-toggle-${username}`);
  if (!field || !toggle) return;
  const secret = field.dataset.secret || "";
  if (!secret) return;
  const visible = field.type === "password";
  field.type = visible ? "text" : "password";
  toggle.classList.toggle("is-active", visible);
  toggle.setAttribute(
    "aria-label",
    visible ? "Hide API key" : "Show API key"
  );
  toggle.setAttribute(
    "title",
    visible ? "Hide API key" : "Show API key"
  );
}

async function copyAdminUserKey(username) {
  const field = document.getElementById(`admin-user-key-${username}`);
  const button = document.getElementById(`admin-user-key-copy-${username}`);
  if (!field || !button) return;
  const secret = field.dataset.secret || "";
  if (!secret) return;
  try {
    await navigator.clipboard.writeText(secret);
    button.textContent = "Copied";
    button.classList.add("is-copied");
    window.setTimeout(() => {
      button.textContent = "Copy";
      button.classList.remove("is-copied");
    }, 1200);
  } catch (_) {}
}

async function saveProfilePicture() {
  setInlineError("profile-picture-crop-error", "");
  if (!(profilePictureCropState.image instanceof Image)) {
    setInlineError("profile-picture-crop-error", "Choose an image first.");
    return;
  }
  try {
    const blob = await croppedProfilePictureBlob();
    const formData = new FormData();
    formData.append("picture", blob, "avatar.png");
    const response = await fetch("/api/v1/profile/picture", {
      method: "POST",
      body: formData,
      credentials: "same-origin",
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload?.error || "Failed to save profile picture.");
    }
    const data = await response.json().catch(() => ({}));
    applyCurrentUserProfile(data);
    const input = document.getElementById("profile-picture-file");
    if (input instanceof HTMLInputElement) {
      input.value = "";
    }
    closeProfilePictureCropModal();
  } catch (error) {
    setInlineError("profile-picture-crop-error", error.message);
  }
}

function chooseProfilePicture() {
  const input = document.getElementById("profile-picture-file");
  if (input instanceof HTMLInputElement) input.click();
}

function updateProfilePictureSelection() {
  const input = document.getElementById("profile-picture-file");
  if (!(input instanceof HTMLInputElement) || !input.files || input.files.length === 0) {
    return;
  }
  openProfilePictureCropModal(input.files[0]).catch((error) => {
    setInlineError("profile-picture-error", error.message || "Failed to load image.");
  });
}

async function deleteProfilePicture() {
  setInlineError("profile-picture-error", "");
  try {
    const response = await fetch("/api/v1/profile/picture", {
      method: "DELETE",
      credentials: "same-origin",
    });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({}));
      throw new Error(payload?.error || "Failed to delete avatar.");
    }
    const data = await response.json().catch(() => ({}));
    applyCurrentUserProfile(data);
    const input = document.getElementById("profile-picture-file");
    if (input instanceof HTMLInputElement) {
      input.value = "";
    }
    closeProfilePictureCropModal();
  } catch (error) {
    setInlineError("profile-picture-error", error.message);
  }
}

const PROFILE_PICTURE_CROP_VIEWPORT = 280;
const PROFILE_PICTURE_OUTPUT_SIZE = 128;
const PROFILE_PICTURE_CROP_DIAMETER = 192;
const PROFILE_PICTURE_CROP_RADIUS = PROFILE_PICTURE_CROP_DIAMETER / 2;
const profilePictureCropState = {
  image: null,
  imageUrl: "",
  baseScale: 1,
  zoom: 1,
  cropCenterX: PROFILE_PICTURE_CROP_VIEWPORT / 2,
  cropCenterY: PROFILE_PICTURE_CROP_VIEWPORT / 2,
  pointerId: null,
  dragStartX: 0,
  dragStartY: 0,
  dragOriginCenterX: PROFILE_PICTURE_CROP_VIEWPORT / 2,
  dragOriginCenterY: PROFILE_PICTURE_CROP_VIEWPORT / 2,
};

function clampProfilePictureCropCircle() {
  if (!(profilePictureCropState.image instanceof Image)) return;
  const displayedWidth = profilePictureCropState.image.naturalWidth * profilePictureCropState.baseScale * profilePictureCropState.zoom;
  const displayedHeight = profilePictureCropState.image.naturalHeight * profilePictureCropState.baseScale * profilePictureCropState.zoom;
  const imageLeft = (PROFILE_PICTURE_CROP_VIEWPORT - displayedWidth) / 2;
  const imageTop = (PROFILE_PICTURE_CROP_VIEWPORT - displayedHeight) / 2;
  const minCenterX = imageLeft + PROFILE_PICTURE_CROP_RADIUS;
  const maxCenterX = imageLeft + displayedWidth - PROFILE_PICTURE_CROP_RADIUS;
  const minCenterY = imageTop + PROFILE_PICTURE_CROP_RADIUS;
  const maxCenterY = imageTop + displayedHeight - PROFILE_PICTURE_CROP_RADIUS;
  profilePictureCropState.cropCenterX = Math.max(minCenterX, Math.min(maxCenterX, profilePictureCropState.cropCenterX));
  profilePictureCropState.cropCenterY = Math.max(minCenterY, Math.min(maxCenterY, profilePictureCropState.cropCenterY));
}

function renderProfilePictureCrop() {
  const image = document.getElementById("profile-picture-crop-image");
  const stage = document.getElementById("profile-picture-crop-stage");
  if (!(image instanceof HTMLImageElement) || !(stage instanceof HTMLElement) || !(profilePictureCropState.image instanceof Image)) return;
  const scale = profilePictureCropState.baseScale * profilePictureCropState.zoom;
  const width = profilePictureCropState.image.naturalWidth * scale;
  const height = profilePictureCropState.image.naturalHeight * scale;
  clampProfilePictureCropCircle();
  image.style.width = `${width}px`;
  image.style.height = `${height}px`;
  image.style.left = `${(PROFILE_PICTURE_CROP_VIEWPORT - width) / 2}px`;
  image.style.top = `${(PROFILE_PICTURE_CROP_VIEWPORT - height) / 2}px`;
  stage.style.setProperty("--crop-center-x", `${profilePictureCropState.cropCenterX}px`);
  stage.style.setProperty("--crop-center-y", `${profilePictureCropState.cropCenterY}px`);
  stage.style.setProperty("--crop-size", `${PROFILE_PICTURE_CROP_DIAMETER}px`);
}

async function openProfilePictureCropModal(file) {
  if (!(file instanceof File)) return;
  const dataUrl = await new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ""));
    reader.onerror = () => reject(new Error("Failed to read image."));
    reader.readAsDataURL(file);
  });
  const image = await new Promise((resolve, reject) => {
    const preview = new Image();
    preview.onload = () => resolve(preview);
    preview.onerror = () => reject(new Error("Failed to decode image."));
    preview.src = dataUrl;
  });
  profilePictureCropState.image = image;
  profilePictureCropState.imageUrl = dataUrl;
  profilePictureCropState.baseScale = Math.max(
    PROFILE_PICTURE_CROP_VIEWPORT / image.naturalWidth,
    PROFILE_PICTURE_CROP_VIEWPORT / image.naturalHeight,
  );
  profilePictureCropState.zoom = 1;
  profilePictureCropState.cropCenterX = PROFILE_PICTURE_CROP_VIEWPORT / 2;
  profilePictureCropState.cropCenterY = PROFILE_PICTURE_CROP_VIEWPORT / 2;
  const modal = document.getElementById("profile-picture-crop-modal");
  const preview = document.getElementById("profile-picture-crop-image");
  const slider = document.getElementById("profile-picture-crop-zoom");
  if (preview instanceof HTMLImageElement) {
    preview.src = dataUrl;
  }
  if (slider instanceof HTMLInputElement) {
    slider.value = "1";
  }
  setInlineError("profile-picture-crop-error", "");
  if (modal) modal.hidden = false;
  renderProfilePictureCrop();
}

function closeProfilePictureCropModal() {
  const modal = document.getElementById("profile-picture-crop-modal");
  if (modal) modal.hidden = true;
  const stage = document.getElementById("profile-picture-crop-stage");
  if (stage) stage.classList.remove("is-dragging");
  profilePictureCropState.pointerId = null;
}

function setProfilePictureCropZoom(value) {
  const parsed = Number(value);
  if (!Number.isFinite(parsed) || !(profilePictureCropState.image instanceof Image)) return;
  profilePictureCropState.zoom = Math.max(1, Math.min(4, parsed));
  renderProfilePictureCrop();
}

function beginProfilePictureCropDrag(event) {
  if (!(profilePictureCropState.image instanceof Image)) return;
  profilePictureCropState.pointerId = event.pointerId;
  profilePictureCropState.dragStartX = event.clientX;
  profilePictureCropState.dragStartY = event.clientY;
  profilePictureCropState.dragOriginCenterX = profilePictureCropState.cropCenterX;
  profilePictureCropState.dragOriginCenterY = profilePictureCropState.cropCenterY;
  const stage = document.getElementById("profile-picture-crop-stage");
  if (stage) {
    stage.classList.add("is-dragging");
    stage.setPointerCapture?.(event.pointerId);
  }
}

function moveProfilePictureCropDrag(event) {
  if (profilePictureCropState.pointerId !== event.pointerId) return;
  profilePictureCropState.cropCenterX = profilePictureCropState.dragOriginCenterX + (event.clientX - profilePictureCropState.dragStartX);
  profilePictureCropState.cropCenterY = profilePictureCropState.dragOriginCenterY + (event.clientY - profilePictureCropState.dragStartY);
  renderProfilePictureCrop();
}

function endProfilePictureCropDrag(event) {
  if (profilePictureCropState.pointerId !== event.pointerId) return;
  profilePictureCropState.pointerId = null;
  const stage = document.getElementById("profile-picture-crop-stage");
  if (stage) {
    stage.classList.remove("is-dragging");
    stage.releasePointerCapture?.(event.pointerId);
  }
}

async function croppedProfilePictureBlob() {
  if (!(profilePictureCropState.image instanceof Image)) {
    throw new Error("Choose an image first.");
  }
  const scale = profilePictureCropState.baseScale * profilePictureCropState.zoom;
  const displayedWidth = profilePictureCropState.image.naturalWidth * scale;
  const displayedHeight = profilePictureCropState.image.naturalHeight * scale;
  const left = (PROFILE_PICTURE_CROP_VIEWPORT - displayedWidth) / 2;
  const top = (PROFILE_PICTURE_CROP_VIEWPORT - displayedHeight) / 2;
  const cropLeft = profilePictureCropState.cropCenterX - PROFILE_PICTURE_CROP_RADIUS;
  const cropTop = profilePictureCropState.cropCenterY - PROFILE_PICTURE_CROP_RADIUS;
  const sx = Math.max(0, (cropLeft - left) / scale);
  const sy = Math.max(0, (cropTop - top) / scale);
  const sw = Math.min(profilePictureCropState.image.naturalWidth - sx, PROFILE_PICTURE_CROP_DIAMETER / scale);
  const sh = Math.min(profilePictureCropState.image.naturalHeight - sy, PROFILE_PICTURE_CROP_DIAMETER / scale);
  const canvas = document.createElement("canvas");
  canvas.width = PROFILE_PICTURE_OUTPUT_SIZE;
  canvas.height = PROFILE_PICTURE_OUTPUT_SIZE;
  const context = canvas.getContext("2d");
  if (!context) {
    throw new Error("Failed to prepare avatar image.");
  }
  context.drawImage(profilePictureCropState.image, sx, sy, sw, sh, 0, 0, PROFILE_PICTURE_OUTPUT_SIZE, PROFILE_PICTURE_OUTPUT_SIZE);
  return await new Promise((resolve, reject) => {
    canvas.toBlob((blob) => {
      if (blob) resolve(blob);
      else reject(new Error("Failed to create avatar image."));
    }, "image/png");
  });
}

async function changeProfilePassword() {
  setInlineError("profile-password-error", "");
  const root = document.querySelector('[data-profile-panel="security"]');
  const validationError = await validateFormBeforeSubmit(root);
  if (validationError) {
    setInlineError("profile-password-error", validationError);
    return;
  }
  try {
    await postJson("/api/v1/profile/password", {
      current_password: document.getElementById("profile-password-current")?.value || "",
      new_password: document.getElementById("profile-password-next")?.value || "",
      password_confirm: document.getElementById("profile-password-confirm")?.value || "",
    });
    setInlineError("profile-password-error", "Password changed.");
    document.getElementById("profile-password-current").value = "";
    document.getElementById("profile-password-next").value = "";
    document.getElementById("profile-password-confirm").value = "";
    if (root) updateValidationForRoot(root);
  } catch (error) {
    setInlineError("profile-password-error", error.message);
  }
}

async function regenerateProfileKey() {
  setInlineError("profile-key-error", "");
  try {
    const data = await postJson("/api/v1/profile/key/regenerate", {});
    syncProfileKeyField(data.key || "", false);
    setInlineError("profile-key-error", "API key regenerated.");
  } catch (error) {
    setInlineError("profile-key-error", error.message);
  }
}

async function regenerateProfileRecoveryCodes() {
  setInlineError("profile-recovery-error", "");
  try {
    const data = await postJson("/api/v1/profile/recovery/regenerate", {});
    setInlineError("profile-recovery-error", "Recovery codes regenerated.");
    openRecoveryCodesModal(
      "Recovery Codes",
      data?.recovery_codes,
      "Save this new recovery-code set somewhere secure. The previous set is no longer valid."
    );
  } catch (error) {
    setInlineError("profile-recovery-error", error.message);
  }
}

async function deleteProfile() {
  setInlineError("profile-delete-error", "");
  try {
    await postJson("/api/v1/profile/delete", {
      password: document.getElementById("profile-delete-password")?.value || "",
    });
    window.location.reload();
  } catch (error) {
    setInlineError("profile-delete-error", error.message);
  }
}
