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
  icon.classList.add(state === "success" || state === "stored" || state === "failed" ? (state === "stored" ? "success" : state) : "uploading");
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
  } else if (state === "stored") {
    title.textContent = "Upload Complete";
    text.textContent = "The sample was uploaded successfully.";
    if (payload.sha256) {
      extra.innerHTML = renderUploadStatusSha(payload.sha256);
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
    const response = await fetch(`/api/v1/index/status?sha256=${encodeURIComponent(sha256)}`, {
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
