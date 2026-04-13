function getColumnsPopover() {
  return document.getElementById("columns-popover");
}

function ensureColumnsPopover() {
  let popover = getColumnsPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "columns-popover";
  popover.className = "columns-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="columns-popover-header">Columns</div>
    <div class="columns-popover-grid">
      <div class="columns-popover-column">
        <div class="columns-popover-label">Disabled</div>
        <input type="search" class="menu-search columns-popover-search" data-columns-scope="disabled" placeholder="Search disabled" aria-label="Search disabled columns">
        <div class="columns-popover-list" data-columns-list="disabled"></div>
      </div>
      <div class="columns-popover-column">
        <div class="columns-popover-label">Enabled</div>
        <input type="search" class="menu-search columns-popover-search" data-columns-scope="enabled" placeholder="Search enabled" aria-label="Search enabled columns">
        <div class="columns-popover-list" data-columns-list="enabled"></div>
      </div>
    </div>
  `;
  popover.querySelectorAll(".columns-popover-search").forEach((input) => {
    input.addEventListener("input", () => renderColumnsPopover(popover));
    input.addEventListener("keydown", (event) => handleColumnsPopoverSearchKeydown(event, popover));
  });
  document.body.appendChild(popover);
  return popover;
}

function positionColumnsPopover(trigger, popover) {
  if (!(trigger instanceof HTMLElement) || !(popover instanceof HTMLElement) || popover.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const popoverRect = popover.getBoundingClientRect();
  const viewportWidth = window.innerWidth;
  const viewportHeight = window.innerHeight;
  const left = Math.max(
    12,
    Math.min(triggerRect.right - popoverRect.width, viewportWidth - popoverRect.width - 12)
  );
  let top = triggerRect.bottom + 6;
  if (top + popoverRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - popoverRect.height - 6);
  }
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
}

function columnsSearchValue(scope, popover) {
  const input = popover?.querySelector?.(`.columns-popover-search[data-columns-scope="${scope}"]`);
  return String(input?.value || "").trim().toLowerCase();
}

function filteredColumnItems(scope, popover) {
  const enabled = enabledResultColumnIds();
  const enabledSet = new Set(enabled);
  const needle = columnsSearchValue(scope, popover);
  const items = resultColumnsCatalog().filter((column) => {
    const isEnabled = enabledSet.has(column.id);
    return scope === "enabled" ? isEnabled : !isEnabled;
  });
  return items.filter((column) => {
    if (!needle) return true;
    return column.label.toLowerCase().includes(needle) || column.id.toLowerCase().includes(needle);
  });
}

function moveResultColumn(columnId, direction) {
  const id = String(columnId || "");
  if (!id) return;
  const enabled = enabledResultColumnIds();
  if (direction === "enabled") {
    if (!enabled.includes(id)) {
      enabled.push(id);
    }
  } else {
    const next = enabled.filter((item) => item !== id);
    if (next.length === 0) {
      return;
    }
    enabled.splice(0, enabled.length, ...next);
  }
  setEnabledResultColumnIds(enabled);
  const popover = getColumnsPopover();
  if (popover instanceof HTMLElement && !popover.hidden) {
    renderColumnsPopover(popover);
  }
}

function columnsItemHtml(column, direction, active) {
  const arrow = direction === "enabled" ? "&rarr;" : "&larr;";
  const activeClass = active ? " active" : "";
  return `<button type="button" class="columns-popover-item${activeClass}" onclick="event.stopPropagation(); moveResultColumn('${escapeHtml(column.id)}','${escapeHtml(direction)}')"><span class="columns-popover-item-name">${escapeHtml(column.label)}</span><span class="columns-popover-item-arrow">${arrow}</span></button>`;
}

function renderColumnsPopover(popover) {
  if (!(popover instanceof HTMLElement)) return;
  ["disabled", "enabled"].forEach((scope) => {
    const list = popover.querySelector(`.columns-popover-list[data-columns-list="${scope}"]`);
    if (!(list instanceof HTMLElement)) return;
    const items = filteredColumnItems(scope, popover);
    if (items.length === 0) {
      list.innerHTML = `<div class="columns-popover-empty">No ${scope} columns.</div>`;
      return;
    }
    const direction = scope === "disabled" ? "enabled" : "disabled";
    list.innerHTML = items.map((column, index) => columnsItemHtml(column, direction, index === 0)).join("");
  });
  positionColumnsPopover(activeColumnsTrigger, popover);
}

function closeColumnsPopover() {
  const popover = getColumnsPopover();
  if (popover) {
    popover.hidden = true;
    popover.querySelectorAll(".columns-popover-search").forEach((input) => {
      if (input instanceof HTMLInputElement) input.value = "";
    });
  }
  if (activeColumnsTrigger instanceof HTMLElement) {
    activeColumnsTrigger.classList.remove("active");
  }
  activeColumnsTrigger = null;
}

function toggleColumnsPopover(button) {
  const popover = ensureColumnsPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  if (activeColumnsTrigger === button && !popover.hidden) {
    closeColumnsPopover();
    return;
  }
  closeRowActionMenu();
  closeCorporaPopover();
  closeTagsPopover();
  closeSymbolPopover();
  closeCommentsPopover();
  if (activeColumnsTrigger instanceof HTMLElement) {
    activeColumnsTrigger.classList.remove("active");
  }
  activeColumnsTrigger = button;
  activeColumnsTrigger.classList.add("active");
  popover.hidden = false;
  renderColumnsPopover(popover);
  const firstSearch = popover.querySelector('.columns-popover-search[data-columns-scope="disabled"]')
    || popover.querySelector(".columns-popover-search");
  if (firstSearch instanceof HTMLElement) {
    setTimeout(() => firstSearch.focus(), 0);
  }
}

function handleColumnsPopoverSearchKeydown(event, popover) {
  if (!(popover instanceof HTMLElement)) return;
  if (event.key === "Escape") {
    event.preventDefault();
    event.stopPropagation();
    closeColumnsPopover();
    return;
  }
  if (event.key !== "Enter") {
    return;
  }
  const scope = String(event.target?.dataset?.columnsScope || "disabled");
  const items = filteredColumnItems(scope, popover);
  if (items.length === 0) return;
  event.preventDefault();
  event.stopPropagation();
  moveResultColumn(items[0].id, scope === "disabled" ? "enabled" : "disabled");
}
