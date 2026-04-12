function commentUser(comment) {
  return comment && typeof comment === "object" && !Array.isArray(comment)
    ? (comment.user || comment.actor || null)
    : null;
}

function commentAuthorHtml(user) {
  const username = metadataUserUsername(user) || "?";
  const profilePicture = metadataUserProfilePicture(user);
  if (profilePicture) {
    return `<img class="comment-avatar" src="${escapeHtml(profilePicture)}" alt="${escapeHtml(username)}">`;
  }
  return `<div class="comment-avatar comment-avatar-fallback">${escapeHtml(username.slice(0, 1).toLowerCase())}</div>`;
}

function commentCardHtml(comment, options = {}) {
  const body = escapeHtml(String(comment?.body || "")).replace(/\n/g, "<br>");
  const deleteButton = options.showDelete
    ? `<button type="button" class="symbol-picker-move comment-delete" title="Delete comment" aria-label="Delete comment" onclick="event.stopPropagation(); deleteCommentById(${Number(comment?.id || 0)},'${escapeHtml(options.resultKey || "")}', true)">🗑</button>`
    : "";
  return `
    <div class="comment-card">
      <div class="comment-avatar-wrap">${commentAuthorHtml(commentUser(comment))}</div>
      <div class="comment-card-body">
        <div class="comment-card-header">
          <div class="comment-card-identity">
            <span class="comment-card-username">${escapeHtml(metadataUserUsername(commentUser(comment)) || "unknown")}</span>
            <span class="comment-card-time">${escapeHtml(formatUtcTimestamp(comment?.timestamp || ""))}</span>
          </div>
          ${deleteButton}
        </div>
        <div class="comment-card-text">${body}</div>
      </div>
    </div>
  `;
}

function commentsTotalPages(row) {
  const totalResults = Math.max(0, Number(row?.comments_total_results ?? row?.collection_comment_count ?? 0));
  const pageSize = Math.max(1, Number(row?.comments_page_size || COMMENTS_PAGE_SIZE));
  return Math.max(1, Math.ceil(totalResults / pageSize));
}

function commentsPagerHtml(row) {
  const page = Math.max(1, Number(row?.comments_page || 1));
  const totalPages = commentsTotalPages(row);
  return `
    <div class="comments-pager-copy">Showing page ${page} of ${totalPages}</div>
    <div class="comments-pager-actions">
      <button type="button" class="secondary comments-page-button" onclick="event.stopPropagation(); changeCommentsPage('${escapeHtml(resultRowKey(row))}', -1)"${page <= 1 ? " disabled" : ""}>←</button>
      <button type="button" class="secondary comments-page-button" onclick="event.stopPropagation(); changeCommentsPage('${escapeHtml(resultRowKey(row))}', 1)"${page >= totalPages ? " disabled" : ""}>→</button>
    </div>
  `;
}

function commentsPopoverContent(row) {
  const comments = Array.isArray(row?.entity_comments) ? row.entity_comments : [];
  const items = comments.length
    ? comments.map((item) => commentCardHtml(item, { showDelete: isAdmin(), resultKey: resultRowKey(row) })).join("")
    : '<div class="comments-empty">No comments yet.</div>';
  const composer = canWrite()
    ? `
      <div class="comments-composer">
        <textarea
          class="menu-search comments-input"
          id="comments-input"
          maxlength="${COMMENT_MAX_LENGTH}"
          placeholder="Add a documentation note"
          oninput="updateCommentsComposerState()"
        ></textarea>
        <div class="comments-composer-footer">
          <div class="comments-count" id="comments-count">0 / ${COMMENT_MAX_LENGTH}</div>
          <button type="button" class="primary comments-post" id="comments-post-button" onclick="postActiveComment()" disabled>Post</button>
        </div>
        <div class="auth-form-error users-search-error" id="comments-error"></div>
      </div>
    `
    : '<div class="comments-readonly-note">Login to add comments.</div>';
  return `
    <div class="comments-thread">${items}</div>
    <div class="comments-thread-footer">${commentsPagerHtml(row)}</div>
    ${composer}
  `;
}

function ensureCommentsPopover() {
  let popover = getCommentsPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "comments-popover";
  popover.className = "comments-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="comments-popover-header">
      <div class="comments-popover-title">Comments</div>
      <button type="button" class="secondary result-popover-close" onclick="closeCommentsPopover()">Close</button>
    </div>
    <div class="comments-popover-body"></div>
  `;
  document.body.appendChild(popover);
  return popover;
}

function positionCommentsPopover(trigger, popover) {
  if (!(trigger instanceof HTMLElement) || !(popover instanceof HTMLElement) || popover.hidden) return;
  const triggerRect = trigger.getBoundingClientRect();
  const viewportWidth = window.innerWidth || document.documentElement.clientWidth || 0;
  const viewportHeight = window.innerHeight || document.documentElement.clientHeight || 0;
  const popoverRect = popover.getBoundingClientRect();
  const left = Math.max(12, Math.min(triggerRect.right - popoverRect.width, viewportWidth - popoverRect.width - 12));
  let top = triggerRect.bottom + 6;
  if (top + popoverRect.height > viewportHeight - 12) {
    top = Math.max(12, triggerRect.top - popoverRect.height - 6);
  }
  popover.style.left = `${left}px`;
  popover.style.top = `${top}px`;
}

function currentCommentsPopoverTrigger() {
  if (!activeCommentsResultKey) return null;
  return document.querySelector(`.comments-popover-trigger[data-result-key="${CSS.escape(activeCommentsResultKey)}"]`);
}

async function loadRowCommentsByKey(resultKey, options = {}) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const page = Number(options.page || row.comments_page || 1);
  row.comments_loading = true;
  row.comments_error = "";
  const popover = getCommentsPopover();
  if (popover && !popover.hidden && activeCommentsResultKey === resultKey) {
    renderCommentsPopover();
  }
  try {
    const payload = await getJson(`/api/v1/comments?sha256=${encodeURIComponent(row.sha256 || "")}&collection=${encodeURIComponent(row.collection || "")}&address=${Number(row.address || 0)}&page=${page}&page_size=${COMMENTS_PAGE_SIZE}`);
    const items = Array.isArray(payload?.items) ? payload.items : [];
    row.entity_comments = items;
    row.comments_loaded = true;
    row.comments_loading = false;
    row.comments_error = "";
    row.comments_page = Number(payload?.page || page);
    row.comments_page_size = Number(payload?.page_size || COMMENTS_PAGE_SIZE);
    row.comments_total_results = Number(payload?.total_results || 0);
    row.comments_has_next = !!payload?.has_next;
    row.collection_comment_count = Number(payload?.total_results || row.collection_comment_count || 0);
    const data = currentSearchData();
    if (data) renderSearchData(data);
    if (popover && !popover.hidden && activeCommentsResultKey === resultKey) {
      renderCommentsPopover();
    }
  } catch (error) {
    row.comments_loading = false;
    row.comments_error = error.message || "Failed to load comments.";
    if (popover && !popover.hidden && activeCommentsResultKey === resultKey) {
      renderCommentsPopover();
    }
  }
}

function renderCommentsPopover() {
  const popover = ensureCommentsPopover();
  const body = popover?.querySelector?.(".comments-popover-body");
  if (!(popover instanceof HTMLElement) || !(body instanceof HTMLElement)) return;
  const currentTrigger = currentCommentsPopoverTrigger();
  if (currentTrigger) {
    activeCommentsTrigger = currentTrigger;
    activeCommentsTrigger.classList.add("active");
  }
  const row = activeCommentsResultKey ? findSearchRowByKey(activeCommentsResultKey) : null;
  if (!row) {
    closeCommentsPopover();
    return;
  }
  if (!row.comments_loaded && !row.comments_loading) {
    loadRowCommentsByKey(activeCommentsResultKey).catch((error) => {
      console.error("binlex-web comment load failed", error);
    });
  }
  if (row.comments_loading && !Array.isArray(row.entity_comments)) {
    body.innerHTML = '<div class="tags-popover-status">Loading comments...</div>';
  } else if (row.comments_error) {
    body.innerHTML = `<div class="tags-popover-status error">${escapeHtml(row.comments_error)}</div>`;
  } else {
    body.innerHTML = commentsPopoverContent(row);
    updateCommentsComposerState();
  }
  positionCommentsPopover(currentTrigger || activeCommentsTrigger, popover);
}

function closeCommentsPopover() {
  const popover = getCommentsPopover();
  if (popover) popover.hidden = true;
  if (activeCommentsTrigger instanceof HTMLElement) {
    activeCommentsTrigger.classList.remove("active");
  }
  activeCommentsTrigger = null;
  activeCommentsResultKey = null;
}

function toggleCommentsPopover(button) {
  const popover = ensureCommentsPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  const resultKey = String(button.dataset.resultKey || "");
  if (activeCommentsTrigger === button && activeCommentsResultKey === resultKey && !popover.hidden) {
    closeCommentsPopover();
    return;
  }
  closeRowActionMenu();
  closeCorporaPopover();
  closeTagsPopover();
  closeSymbolPopover();
  closeCommentsPopover();
  if (activeCommentsTrigger instanceof HTMLElement) {
    activeCommentsTrigger.classList.remove("active");
  }
  activeCommentsTrigger = button;
  activeCommentsResultKey = resultKey;
  activeCommentsTrigger.classList.add("active");
  popover.hidden = false;
  renderCommentsPopover();
  if (canWrite()) {
    const input = popover.querySelector("#comments-input");
    if (input instanceof HTMLElement) {
      setTimeout(() => input.focus(), 0);
    }
  }
}

function updateCommentsComposerState() {
  const input = document.getElementById("comments-input");
  const counter = document.getElementById("comments-count");
  const button = document.getElementById("comments-post-button");
  if (!(input instanceof HTMLTextAreaElement)) return;
  const length = Array.from(input.value || "").length;
  if (counter) counter.textContent = `${length} / ${COMMENT_MAX_LENGTH}`;
  if (button instanceof HTMLButtonElement) {
    button.disabled = !String(input.value || "").trim() || length > COMMENT_MAX_LENGTH;
  }
}

async function postActiveComment() {
  if (!activeCommentsResultKey) return;
  const row = findSearchRowByKey(activeCommentsResultKey);
  const input = document.getElementById("comments-input");
  if (!row || !(input instanceof HTMLTextAreaElement)) return;
  const body = String(input.value || "").trim();
  setInlineError("comments-error", "");
  if (!body) return;
  try {
    const created = await postJson("/api/v1/comments/add", {
      sha256: row.sha256,
      collection: row.collection,
      address: Number(row.address || 0),
      body,
    });
    row.entity_comments = [created, ...(Array.isArray(row.entity_comments) ? row.entity_comments : [])];
    row.comments_loaded = true;
    row.comments_error = "";
    row.collection_comment_count = Number(row.collection_comment_count || 0) + 1;
    row.comments_total_results = Number(row.comments_total_results || 0) + 1;
    row.comments_page = 1;
    input.value = "";
    updateCommentsComposerState();
    const data = currentSearchData();
    if (data) renderSearchData(data);
    renderCommentsPopover();
  } catch (error) {
    setInlineError("comments-error", error.message);
  }
}

async function changeCommentsPage(resultKey, delta) {
  const row = findSearchRowByKey(resultKey);
  if (!row || row.comments_loading) return;
  const nextPage = Math.max(1, Number(row.comments_page || 1) + Number(delta || 0));
  if (nextPage === Number(row.comments_page || 1) || nextPage > commentsTotalPages(row)) return;
  await loadRowCommentsByKey(resultKey, { page: nextPage });
}

async function deleteCommentById(id, resultKey = "", confirmFirst = false) {
  const commentId = Number(id || 0);
  if (!commentId || !isAdmin()) return;
  if (confirmFirst) {
    const confirmed = await requestTagsConfirmation({
      title: "Delete Comment",
      message: "Delete this comment permanently?",
      confirmLabel: "Delete",
    });
    if (!confirmed) return;
  }
  try {
    const response = await fetch(`/api/v1/comments/${commentId}`, {
      method: "DELETE",
      credentials: "same-origin",
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      throw new Error(data?.error || "Request failed");
    }
    const row = resultKey ? findSearchRowByKey(resultKey) : null;
    if (row) {
      const before = Array.isArray(row.entity_comments) ? row.entity_comments : [];
      row.entity_comments = before.filter((item) => Number(item?.id || 0) !== commentId);
      row.collection_comment_count = Math.max(0, Number(row.collection_comment_count || 0) - (before.length === row.entity_comments.length ? 0 : 1));
      const searchData = currentSearchData();
      if (searchData) renderSearchData(searchData);
      renderCommentsPopover();
    }
    await loadAdminComments();
  } catch (error) {
    setInlineError("comments-error", error.message || "Failed to delete comment.");
    setInlineError("admin-comments-error", error.message || "Failed to delete comment.");
  }
}
