function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll("\"", "&quot;")
    .replaceAll("'", "&#39;");
}

function serializeActions(actions) {
  try {
    return escapeHtml(JSON.stringify(Array.isArray(actions) ? actions : []));
  } catch (_) {
    return "[]";
  }
}

function urlEncode(value) {
  return encodeURIComponent(String(value ?? ""));
}

function displayArchitecture(value) {
  return String(value ?? "").toLowerCase();
}

function displayCollection(value) {
  return String(value ?? "").toLowerCase();
}

function resultColumnsCatalog() {
  if (typeof resultColumnDefinitions === "function") {
    return resultColumnDefinitions();
  }
  return [];
}

function normalizeEnabledResultColumnIds(ids) {
  const definitions = resultColumnsCatalog();
  const known = new Set(definitions.map((column) => column.id));
  const ordered = [];
  (Array.isArray(ids) ? ids : []).forEach((id) => {
    const normalized = String(id || "");
    if (!known.has(normalized) || ordered.includes(normalized)) return;
    ordered.push(normalized);
  });
  if (ordered.length === 0) {
    return definitions.map((column) => column.id);
  }
  return ordered;
}

function enabledResultColumnIds() {
  try {
    return normalizeEnabledResultColumnIds(JSON.parse(localStorage.getItem(RESULT_COLUMNS_STORAGE_KEY) || "null"));
  } catch (_) {
    return normalizeEnabledResultColumnIds(null);
  }
}

function setEnabledResultColumnIds(ids) {
  const normalized = normalizeEnabledResultColumnIds(ids);
  try {
    localStorage.setItem(RESULT_COLUMNS_STORAGE_KEY, JSON.stringify(normalized));
  } catch (_) {}
  const data = currentSearchData();
  if (data) {
    renderSearchData(data);
  }
}

function abbreviateHex(value) {
  const text = String(value ?? "");
  const edge = 4;
  if (text.length <= edge * 2 + 3) return text;
  return `${text.slice(0, edge)}...${text.slice(-edge)}`;
}

function metadataItemName(item) {
  if (item && typeof item === "object" && !Array.isArray(item)) {
    return String(item.name || "").trim();
  }
  return String(item || "").trim();
}

function metadataItemCreatedActor(item) {
  return item && typeof item === "object" && !Array.isArray(item) && item.created_actor && typeof item.created_actor === "object"
    ? item.created_actor
    : null;
}

function metadataItemAssignedActor(item) {
  return item && typeof item === "object" && !Array.isArray(item) && item.assigned_actor && typeof item.assigned_actor === "object"
    ? item.assigned_actor
    : null;
}

function metadataActorUsername(actor) {
  return String(actor?.username || "").trim();
}

function metadataActorProfilePicture(actor) {
  return String(actor?.profile_picture || "").trim();
}

function metadataItemUsername(item) {
  return metadataActorUsername(metadataItemCreatedActor(item));
}

function metadataItemProfilePicture(item) {
  return metadataActorProfilePicture(metadataItemCreatedActor(item));
}

function metadataItemTimestamp(item) {
  return String(item && typeof item === "object" && !Array.isArray(item) ? item.created_timestamp || "" : "").trim();
}

function metadataItemAssignedUsername(item) {
  return metadataActorUsername(metadataItemAssignedActor(item));
}

function metadataItemAssignedProfilePicture(item) {
  return metadataActorProfilePicture(metadataItemAssignedActor(item));
}

function metadataItemAssignedTimestamp(item) {
  return String(item && typeof item === "object" && !Array.isArray(item) ? item.assigned_timestamp || "" : "").trim();
}

function normalizeMetadataItems(values) {
  const seen = new Map();
  (Array.isArray(values) ? values : []).forEach((value) => {
    const name = metadataItemName(value);
    if (!name) return;
    const key = name.toLowerCase();
    const normalized = typeof value === "object" && value !== null && !Array.isArray(value)
      ? {
          name,
          created_actor: {
            username: metadataItemUsername(value),
            profile_picture: metadataItemProfilePicture(value) || null,
          },
          created_timestamp: metadataItemTimestamp(value),
          assigned_actor: metadataItemAssignedActor(value)
            ? {
                username: metadataItemAssignedUsername(value),
                profile_picture: metadataItemAssignedProfilePicture(value) || null,
              }
            : null,
          assigned_timestamp: metadataItemAssignedTimestamp(value) || null,
        }
      : {
          name,
          created_actor: { username: "", profile_picture: null },
          created_timestamp: "",
          assigned_actor: null,
          assigned_timestamp: null,
        };
    seen.set(key, normalized);
  });
  return Array.from(seen.values()).sort((lhs, rhs) => lhs.name.localeCompare(rhs.name));
}

function metadataTooltipEntryHtml(actor, verb, timestamp) {
  const username = metadataActorUsername(actor);
  const profilePicture = metadataActorProfilePicture(actor);
  if (!username && !timestamp) return "";
  const avatar = profilePicture
    ? `<img class="picker-tooltip-avatar" src="${escapeHtml(profilePicture)}" alt="${escapeHtml(username || "user")}">`
    : `<div class="picker-tooltip-avatar picker-tooltip-avatar-fallback">${escapeHtml((username || "?").slice(0, 1).toLowerCase())}</div>`;
  const lines = [];
  if (username) lines.push(`<div class="picker-tooltip-username">${escapeHtml(username)}</div>`);
  lines.push(`<div class="picker-tooltip-verb">${escapeHtml(verb)}</div>`);
  if (timestamp) lines.push(`<div class="picker-tooltip-time">${escapeHtml(formatUtcTimestamp(timestamp))}</div>`);
  return `<div class="picker-tooltip-entry">${avatar}<div class="picker-tooltip-copy">${lines.join("")}</div></div>`;
}

function metadataTooltipHtml(item, mode = "created") {
  const entries = [];
  const created = metadataTooltipEntryHtml(metadataItemCreatedActor(item), "Created by", metadataItemTimestamp(item));
  const assigned = metadataTooltipEntryHtml(metadataItemAssignedActor(item), "Assigned by", metadataItemAssignedTimestamp(item));
  if (mode === "created") {
    if (created) entries.push(created);
  } else {
    if (created) entries.push(created);
    if (assigned) entries.push(assigned);
  }
  if (!entries.length) return "";
  return `<span class="picker-tooltip-anchor" hidden data-picker-tooltip="${escapeHtml(encodeURIComponent(entries.join("")))}"></span>`;
}

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

function formatUtcTimestamp(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value || "");
  const pad = (part) => String(part).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())} UTC`;
}

function compactCount(value) {
  const numeric = Number(value || 0);
  if (!Number.isFinite(numeric)) return "0";
  if (numeric < 1000) return String(Math.trunc(numeric));
  const compact = (unit, suffix) => {
    const scaled = numeric / unit;
    if (scaled < 10) {
      const rounded = Math.round(scaled * 10) / 10;
      return Number.isInteger(rounded) ? `${rounded}${suffix}` : `${rounded.toFixed(1)}${suffix}`;
    }
    return `${Math.round(scaled)}${suffix}`;
  };
  if (numeric < 1_000_000) return compact(1_000, "k");
  if (numeric < 1_000_000_000) return compact(1_000_000, "m");
  return compact(1_000_000_000, "b");
}

function formatMetricFloat(value) {
  if (value == null || !Number.isFinite(Number(value))) return "";
  return Number(value).toFixed(4).replace(/\.?0+$/, "");
}

function formatResultSize(value) {
  const numeric = Number(value || 0);
  const kb = 1024;
  const mb = kb * 1024;
  const gb = mb * 1024;
  const compactBytes = (scaled, suffix) => {
    const rounded = Math.round(scaled * 10) / 10;
    return Number.isInteger(rounded) ? `${rounded} ${suffix}` : `${rounded.toFixed(1)} ${suffix}`;
  };
  if (numeric >= gb) return compactBytes(numeric / gb, "GB");
  if (numeric >= mb) return compactBytes(numeric / mb, "MB");
  if (numeric >= kb) return compactBytes(numeric / kb, "KB");
  return `${Math.trunc(numeric)} B`;
}

function formatResultDate(value) {
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return String(value ?? "");
  const pad = (part) => String(part).padStart(2, "0");
  return `${date.getUTCFullYear()}-${pad(date.getUTCMonth() + 1)}-${pad(date.getUTCDate())} ${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}`;
}

function csvCell(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function uniqueValues(values) {
  return Array.from(new Set((values || []).map((value) => String(value ?? "")))).sort();
}

function prettyJson(value) {
  try {
    return JSON.stringify(value, null, 2);
  } catch (_) {
    return "null";
  }
}

function jsonScalarPayload(value) {
  return typeof value === "string" ? value : JSON.stringify(value);
}

const JSON_ACTION_ARRAY_EXPAND_LIMIT = 12;
const JSON_ACTION_MAX_DEPTH = 6;

function actionLeaf(label, payload) {
  return { label, payload };
}

function actionCopy(label, payload) {
  return { label, action: "copy", payload };
}

function actionFetchCopyJson(label, url) {
  return { label, action: "fetch_copy_json", url };
}

function actionFetchCopyText(label, url, method, body, contentType, accept) {
  return { label, action: "fetch_copy_text", url, method, body, content_type: contentType, accept };
}

function actionBranch(label, children) {
  return { label, children };
}

function actionDownload(label, url) {
  return { label, action: "download", url };
}

function actionDownloadPayload(label, filename, contentType, payload) {
  return { label, action: "download_text", filename, content_type: contentType, payload };
}

function actionNavigate(label, url) {
  return { label, action: "navigate", url };
}

function actionSearchQuery(label, query) {
  return { label, action: "search_query", query };
}

function actionExpand(label, resultKey) {
  return { label, action: "expand", result_key: resultKey };
}

function actionCollapse(label, resultKey) {
  return { label, action: "collapse", result_key: resultKey };
}

function actionExpandAll(label) {
  return { label, action: "expand_all" };
}

function actionCollapseAll(label) {
  return { label, action: "collapse_all" };
}

