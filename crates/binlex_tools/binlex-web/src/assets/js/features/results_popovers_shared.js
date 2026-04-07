function refreshResultDetailRow(resultKey) {
  if (!resultKey) return;
  const row = findSearchRowByKey(resultKey);
  const summaryRow = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"]`);
  const detailRow = summaryRow instanceof HTMLElement ? summaryRow.nextElementSibling : null;
  if (!row || !(detailRow instanceof HTMLElement) || !detailRow.classList.contains("result-detail-row")) {
    return;
  }
  const wasHidden = detailRow.hidden;
  const columnCount = Math.max(1, enabledResultColumnIds().length);
  const wrapper = document.createElement("tbody");
  wrapper.innerHTML = renderResultDetails(row, resultKey, columnCount);
  const replacement = wrapper.firstElementChild;
  if (!(replacement instanceof HTMLElement)) return;
  replacement.hidden = wasHidden;
  detailRow.replaceWith(replacement);
}

function ensureTagsConfirmModal() {
  let modal = document.getElementById("tags-confirm-modal");
  if (modal) return modal;
  modal = document.createElement("div");
  modal.id = "tags-confirm-modal";
  modal.className = "modal-backdrop";
  modal.hidden = true;
  modal.innerHTML = `
    <div class="modal-card tags-confirm-card" role="dialog" aria-modal="true" aria-label="Tag Action">
      <div class="modal-grid modal-grid-single">
        <div class="tags-confirm-title" id="tags-confirm-title"></div>
        <div class="tags-confirm-text" id="tags-confirm-text"></div>
      </div>
      <div class="modal-actions">
        <button type="button" class="secondary" id="tags-confirm-cancel">Cancel</button>
        <button type="button" class="primary" id="tags-confirm-confirm">Confirm</button>
      </div>
    </div>
  `;
  modal.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  modal.querySelector(".tags-confirm-card")?.addEventListener("click", (event) => {
    event.stopPropagation();
  });
  document.body.appendChild(modal);
  return modal;
}

function requestTagsConfirmation({ title, message, confirmLabel }) {
  const modal = ensureTagsConfirmModal();
  const titleEl = document.getElementById("tags-confirm-title");
  const textEl = document.getElementById("tags-confirm-text");
  const cancel = document.getElementById("tags-confirm-cancel");
  const confirm = document.getElementById("tags-confirm-confirm");
  if (!(modal instanceof HTMLElement) || !(titleEl instanceof HTMLElement) || !(textEl instanceof HTMLElement) || !(cancel instanceof HTMLButtonElement) || !(confirm instanceof HTMLButtonElement)) {
    return Promise.resolve(false);
  }
  titleEl.textContent = title || "";
  textEl.textContent = message || "";
  confirm.textContent = confirmLabel || "Confirm";
  modal.hidden = false;
  setTimeout(() => confirm.focus(), 0);
  return new Promise((resolve) => {
    const cleanup = (value) => {
      modal.hidden = true;
      cancel.removeEventListener("click", onCancel);
      confirm.removeEventListener("click", onConfirm);
      modal.removeEventListener("keydown", onKeydown);
      resolve(value);
    };
    const onCancel = (event) => {
      event.stopPropagation();
      cleanup(false);
    };
    const onConfirm = (event) => {
      event.stopPropagation();
      cleanup(true);
    };
    const onKeydown = (event) => {
      if (event.key === "Escape") {
        event.preventDefault();
        event.stopPropagation();
        cleanup(false);
        return;
      }
      if (event.key === "Enter") {
        event.preventDefault();
        event.stopPropagation();
        cleanup(true);
      }
    };
    cancel.addEventListener("click", onCancel);
    confirm.addEventListener("click", onConfirm);
    modal.addEventListener("keydown", onKeydown);
  });
}

function isInsideTagsConfirmModal(target) {
  const modal = document.getElementById("tags-confirm-modal");
  return modal instanceof HTMLElement && !modal.hidden && modal.contains(target);
}

async function copyPickerValue(button, encodedValue) {
  const value = decodeURIComponent(String(encodedValue || ""));
  if (!value) return;
  try {
    await navigator.clipboard.writeText(value);
    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("action-feedback");
    }, 1200);
  } catch (_) {
    const previous = button.textContent;
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  }
}

async function copySymbolValue(button, encodedSymbol) {
  const symbol = decodeURIComponent(String(encodedSymbol || ""));
  if (!symbol) return;
  try {
    await navigator.clipboard.writeText(symbol);
    const previous = button.textContent;
    button.textContent = "Copied";
    button.classList.add("action-feedback");
    setTimeout(() => {
      button.textContent = previous;
      button.classList.remove("action-feedback");
    }, 1200);
  } catch (_) {
    const previous = button.textContent;
    button.textContent = "Copy failed";
    setTimeout(() => {
      button.textContent = previous;
    }, 1200);
  }
}
