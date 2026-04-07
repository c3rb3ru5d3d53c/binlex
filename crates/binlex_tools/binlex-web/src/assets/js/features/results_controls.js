function parseRowActions(shell) {
  try {
    return JSON.parse(shell?.dataset?.actions || "[]");
  } catch (_) {
    return [];
  }
}

function getRowActionItems(shell) {
  const tree = parseRowActions(shell);
  const path = (shell?.dataset?.path || "").split("/").filter(Boolean);
  let items = tree;
  for (const label of path) {
    const next = items.find((item) => item.label === label);
    if (!next || !Array.isArray(next.children)) return [];
    items = next.children;
  }
  return items;
}

function fuzzyMenuScore(query, label) {
  const rawQuery = (query || "").toLowerCase().trim();
  const rawLabel = (label || "").toLowerCase().trim();
  if (!rawQuery) return 0;
  if (rawLabel === rawQuery) return 5000;
  if (rawLabel.startsWith(rawQuery)) return 4000 - (rawLabel.length - rawQuery.length);
  if (rawLabel.includes(rawQuery)) return 3000 - (rawLabel.length - rawQuery.length);
  const q = rawQuery.replace(/[^a-z0-9]/g, "");
  const l = rawLabel.replace(/[^a-z0-9]/g, "");
  if (!q) return -1;
  if (l.includes(q)) return 1000 - (l.length - q.length);
  let score = 0;
  let position = 0;
  for (const ch of q) {
    const found = l.indexOf(ch, position);
    if (found === -1) return -1;
    score += 10;
    if (found === position) score += 4;
    position = found + 1;
  }
  return score - (l.length - q.length);
}

function getRowActionPopover() {
  return document.getElementById("row-action-popover");
}

function renderRowActionMenu(shell) {
  if (!shell) return;
  const items = getRowActionItems(shell);
  const query = shell.querySelector(".menu-search")?.value?.trim() || "";
  const breadcrumb = shell.querySelector(".row-actions-breadcrumb");
  const back = shell.querySelector(".row-actions-back");
  const container = shell.querySelector(".row-action-options");
  if (!container || !breadcrumb || !back) return;

  const path = (shell.dataset.path || "").split("/").filter(Boolean);
  breadcrumb.textContent = ["Action", ...path].join(" / ");
  back.disabled = path.length === 0;

  const ranked = items
    .map((item, index) => ({
      item,
      index,
      score: query ? fuzzyMenuScore(query, item.label || "") : 0,
    }))
    .filter((entry) => !query || entry.score >= 0)
    .sort((lhs, rhs) => {
      if (!query) return lhs.index - rhs.index;
      if (rhs.score !== lhs.score) return rhs.score - lhs.score;
      return lhs.index - rhs.index;
    });

  container.innerHTML = "";
  ranked.forEach(({ item }, index) => {
    const button = document.createElement("button");
    button.type = "button";
    button.className = "row-action-button";
    if (index === 0) {
      button.classList.add("active");
    }
    button.textContent = item.label || "";
    if (Array.isArray(item.children)) {
      button.classList.add("branch");
      button.onclick = (event) => {
        event.preventDefault();
        event.stopPropagation();
        navigateRowActions(button, item.label);
      };
    } else {
      button.onclick = async (event) => {
        event.preventDefault();
        event.stopPropagation();
        await runRowAction(button, item);
      };
    }
    container.appendChild(button);
  });
  if (shell.classList.contains("row-actions-popover")) {
    positionRowActionMenu(activeRowActionTrigger, shell);
  }
  const search = shell.querySelector(".menu-search");
  if (search instanceof HTMLElement && document.activeElement !== search) {
    setTimeout(() => search.focus(), 0);
  }
}

function positionRowActionMenu(trigger, menu) {
  if (!(trigger instanceof HTMLElement) || !(menu instanceof HTMLElement) || menu.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
  const menuRect = menu.getBoundingClientRect();
  const left = Math.max(
    12,
    Math.min(triggerRect.right - menuRect.width, viewportWidth - menuRect.width - 12)
  );
  let top = triggerRect.bottom + 6;
  if (top + menuRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - menuRect.height - 6);
  }
  menu.style.left = `${left}px`;
  menu.style.top = `${top}px`;
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

function closeRowActionMenu() {
  const popover = getRowActionPopover();
  if (popover) {
    popover.hidden = true;
    popover.dataset.actions = "[]";
    popover.dataset.path = "";
    const search = popover.querySelector(".menu-search");
    if (search) search.value = "";
  }
  if (activeRowActionTrigger instanceof HTMLElement) {
    activeRowActionTrigger.classList.remove("active");
  }
  activeRowActionTrigger = null;
}

function toggleRowActionMenu(button) {
  const popover = getRowActionPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  if (activeRowActionTrigger === button && !popover.hidden) {
    closeRowActionMenu();
    return;
  }
  closeCorporaPopover();
  closeTagsPopover();
  closeSymbolPopover();
  closeCommentsPopover();
  if (activeRowActionTrigger instanceof HTMLElement) {
    activeRowActionTrigger.classList.remove("active");
  }
  activeRowActionTrigger = button;
  activeRowActionTrigger.classList.add("active");
  popover.dataset.actions = button.dataset.actions || "[]";
  popover.dataset.path = "";
  popover.hidden = false;
  const search = popover.querySelector(".menu-search");
  if (search) search.value = "";
  renderRowActionMenu(popover);
  positionRowActionMenu(button, popover);
  if (search instanceof HTMLElement) {
    setTimeout(() => search.focus(), 0);
  }
}

function navigateRowActions(button, label = null) {
  const shell = button.closest(".row-actions-popover");
  if (!shell) return;
  const path = (shell.dataset.path || "").split("/").filter(Boolean);
  if (!label && path.length === 0) {
    return;
  }
  if (label) {
    path.push(label);
  } else {
    path.pop();
  }
  shell.dataset.path = path.join("/");
  const search = shell.querySelector(".menu-search");
  if (search) search.value = "";
  renderRowActionMenu(shell);
}

function handleRowActionSearchKeydown(event, shell) {
  if (!(shell instanceof HTMLElement)) {
    return;
  }
  if (event.key === "Escape") {
    event.preventDefault();
    event.stopPropagation();
    const path = (shell.dataset.path || "").split("/").filter(Boolean);
    if (path.length > 0) {
      const back = shell.querySelector(".row-actions-back");
      if (back instanceof HTMLButtonElement) {
        navigateRowActions(back);
      } else {
        path.pop();
        shell.dataset.path = path.join("/");
        renderRowActionMenu(shell);
      }
    } else {
      closeRowActionMenu();
    }
    return;
  }
  if (event.key !== "Enter") {
    return;
  }
  const firstButton = shell.querySelector(".row-action-options .row-action-button");
  if (!(firstButton instanceof HTMLButtonElement)) {
    return;
  }
  event.preventDefault();
  event.stopPropagation();
  firstButton.click();
}

async function runRowAction(button, item) {
  if (item?.action === "search_query") {
    const queryInput = getQueryInput();
    const form = getSearchForm();
    if ((queryInput instanceof HTMLInputElement || queryInput instanceof HTMLTextAreaElement) && form instanceof HTMLFormElement) {
      queryInput.value = String(item?.query || "");
      clearCommittedQueryClause(queryInput);
      const pageInput = getPageInput();
      if (pageInput) pageInput.value = "1";
      syncSearchState();
      closeRowActionMenu();
      form.requestSubmit();
    }
    return;
  }
  if (item?.action === "expand_all") {
    closeRowActionMenu();
    expandAllResultDetails();
    return;
  }
  if (item?.action === "collapse_all") {
    closeRowActionMenu();
    collapseAllResultDetails();
    return;
  }
  if (item?.action === "expand") {
    closeRowActionMenu();
    expandResultDetailsByKey(item?.result_key || "");
    return;
  }
  if (item?.action === "collapse") {
    closeRowActionMenu();
    collapseResultDetailsByKey(item?.result_key || "");
    return;
  }
  if (item?.action === "download_text") {
    const blob = new Blob([item?.payload || ""], {
      type: item?.content_type || "application/octet-stream",
    });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = item?.filename || "download.txt";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 0);
    return;
  }
  if (item?.action === "fetch_copy_json") {
    try {
      const response = await fetch(item?.url || "", {
        credentials: "same-origin",
        headers: {
          "X-Requested-With": "binlex-web",
          "Accept": "application/json",
        },
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `request failed with status ${response.status}`);
      }
      const payload = await response.json();
      await navigator.clipboard.writeText(prettyJson(payload));
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
    return;
  }
  if (item?.action === "fetch_copy_text") {
    try {
      const response = await fetch(item?.url || "", {
        method: item?.method || "GET",
        credentials: "same-origin",
        headers: {
          "X-Requested-With": "binlex-web",
          "Content-Type": item?.content_type || "application/json",
          "Accept": item?.accept || "text/plain",
        },
        body: item?.body || undefined,
      });
      if (!response.ok) {
        const message = await response.text();
        throw new Error(message || `request failed with status ${response.status}`);
      }
      const payload = await response.text();
      await navigator.clipboard.writeText(payload);
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
    return;
  }
  if ((item?.action || "copy") === "download" || item?.action === "navigate") {
    if (item?.url) {
      closeRowActionMenu();
      window.location.assign(item.url);
    }
    return;
  }
  const payload = item?.payload || "";
  try {
    await navigator.clipboard.writeText(payload);
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

async function copyQuery(button) {
  const input = getQueryInput();
  const query = input?.value || "";
  try {
    await navigator.clipboard.writeText(query);
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

