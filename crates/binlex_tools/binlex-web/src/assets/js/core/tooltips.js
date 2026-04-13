function getPickerTooltipOverlay() {
  let overlay = document.getElementById("picker-tooltip-overlay");
  if (overlay) return overlay;
  overlay = document.createElement("div");
  overlay.id = "picker-tooltip-overlay";
  overlay.className = "picker-tooltip-card";
  overlay.hidden = true;
  document.body.appendChild(overlay);
  return overlay;
}

function tooltipHtmlForHost(host) {
  if (!(host instanceof HTMLElement)) return "";
  const anchor = host.querySelector(".picker-tooltip-anchor[data-picker-tooltip]");
  if (!(anchor instanceof HTMLElement)) return "";
  const encoded = String(anchor.dataset.pickerTooltip || "").trim();
  if (!encoded) return "";
  try {
    return decodeURIComponent(encoded);
  } catch (_) {
    return "";
  }
}

function positionPickerTooltip(host) {
  const overlay = getPickerTooltipOverlay();
  if (!(host instanceof HTMLElement) || overlay.hidden) return;
  const rect = host.getBoundingClientRect();
  const overlayRect = overlay.getBoundingClientRect();
  const margin = 10;
  let left = rect.left;
  let top = rect.bottom + 6;
  if (left + overlayRect.width > window.innerWidth - margin) {
    left = Math.max(margin, window.innerWidth - overlayRect.width - margin);
  }
  if (top + overlayRect.height > window.innerHeight - margin) {
    top = rect.top - overlayRect.height - 6;
  }
  if (top < margin) top = margin;
  overlay.style.left = `${Math.round(left)}px`;
  overlay.style.top = `${Math.round(top)}px`;
}

function hidePickerTooltip() {
  activePickerTooltipHost = null;
  const overlay = document.getElementById("picker-tooltip-overlay");
  if (!(overlay instanceof HTMLElement)) return;
  overlay.hidden = true;
  overlay.innerHTML = "";
}

function showPickerTooltip(host) {
  const html = tooltipHtmlForHost(host);
  if (!html) {
    hidePickerTooltip();
    return;
  }
  activePickerTooltipHost = host;
  const overlay = getPickerTooltipOverlay();
  overlay.innerHTML = html;
  overlay.hidden = false;
  positionPickerTooltip(host);
}

function syncPickerTooltipTarget(target) {
  const host = target instanceof Element
    ? target.closest(".symbol-picker-item, .result-detail-preview-chip.has-tooltip, .result-copy-pill.has-tooltip")
    : null;
  if (!(host instanceof HTMLElement)) {
    hidePickerTooltip();
    return;
  }
  if (host !== activePickerTooltipHost) {
    showPickerTooltip(host);
    return;
  }
  positionPickerTooltip(host);
}
