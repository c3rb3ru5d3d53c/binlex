let pendingLoginTwoFactor = {
  challengeToken: "",
  setupRequired: false,
};

let twoFactorSetupState = {
  mode: "profile",
  challengeToken: "",
  generated: false,
};

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
