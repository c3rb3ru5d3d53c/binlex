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
    await deleteJson("/api/v1/profile", {
      password: document.getElementById("profile-delete-password")?.value || "",
    });
    window.location.reload();
  } catch (error) {
    setInlineError("profile-delete-error", error.message);
  }
}
