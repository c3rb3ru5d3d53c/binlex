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
