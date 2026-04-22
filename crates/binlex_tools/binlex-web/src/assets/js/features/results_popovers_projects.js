let activeProjectsTrigger = null;
let activeProjectsResultKey = null;

function currentProjectsPopoverTrigger() {
  if (!activeProjectsResultKey) return null;
  const trigger = document.querySelector(
    `.projects-popover-trigger[data-result-key="${CSS.escape(activeProjectsResultKey)}"]`
  );
  return trigger instanceof HTMLElement ? trigger : null;
}

function updateProjectsCell(resultKey) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const cell = document.querySelector(`.result-row[data-result-key="${CSS.escape(resultKey)}"] .projects-cell-td`);
  if (cell instanceof HTMLElement) {
    cell.innerHTML = renderProjectsCell(row);
    if (activeProjectsResultKey === resultKey) {
      activeProjectsTrigger = document.querySelector(
        `.projects-popover-trigger[data-result-key="${CSS.escape(resultKey)}"]`
      );
      if (activeProjectsTrigger instanceof HTMLElement) {
        activeProjectsTrigger.classList.add("active");
      }
    }
  }
}

function projectsPopoverState(row) {
  if (!row.projects_state) {
    row.projects_state = {
      limit: 4,
      username: "",
      tool: "",
      project_sha256: "",
      available_query: "",
      assignment_query: "",
      selected_project_sha256: "",
    };
  }
  return row.projects_state;
}

async function loadProjectsByKey(resultKey, force = false) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const state = projectsPopoverState(row);
  const requestKey = JSON.stringify([resultKey, state.limit, state.username, state.tool, state.project_sha256]);
  if (!force && row.projects_request_key === requestKey && row.projects_loaded) return;
  row.projects_loading = true;
  row.projects_request_key = requestKey;
  row.projects_error = "";
  try {
    const query = new URLSearchParams({
      sha256: row.sha256 || "",
      limit: String(state.limit || 4),
      page: "1",
    });
    if (state.username) query.set("username", state.username);
    if (state.tool) query.set("tool", state.tool);
    if (state.project_sha256) query.set("project_sha256", state.project_sha256);
    const payload = await fetchJsonWithCredentials(`/api/v1/projects/search?${query.toString()}`);
    row.projects = Array.isArray(payload?.projects) ? payload.projects : [];
    row.projects_loaded = true;
    const visibleProjectIds = new Set(row.projects.map((item) => String(item?.project_sha256 || "")));
    if (!visibleProjectIds.has(state.selected_project_sha256)) {
      state.selected_project_sha256 = row.projects.length > 0
        ? String(row.projects[0]?.project_sha256 || "")
        : "";
      row.project_available_samples_loaded = false;
      row.project_assignments_loaded = false;
    }
  } catch (error) {
    row.projects_error = error instanceof Error ? error.message : "Unable to load projects.";
  } finally {
    row.projects_loading = false;
    updateProjectsCell(resultKey);
    if (activeProjectsResultKey === resultKey) {
      renderProjectsPopover();
    }
  }
}

async function loadProjectAssignmentsByKey(resultKey, force = false) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const state = projectsPopoverState(row);
  if (!state.selected_project_sha256) return;
  const requestKey = JSON.stringify([resultKey, state.selected_project_sha256, state.assignment_query]);
  if (!force && row.project_assignments_request_key === requestKey && row.project_assignments_loaded) return;
  row.project_assignments_loading = true;
  row.project_assignments_request_key = requestKey;
  row.project_assignments_error = "";
  try {
    const query = new URLSearchParams({
      project_sha256: state.selected_project_sha256,
      limit: "4",
      page: "1",
    });
    if (state.assignment_query) query.set("sample_sha256", state.assignment_query);
    const payload = await fetchJsonWithCredentials(`/api/v1/projects/${encodeURIComponent(state.selected_project_sha256)}/samples/search?${query.toString()}`);
    row.project_assignments = Array.isArray(payload?.samples) ? payload.samples : [];
    row.project_assignments_loaded = true;
  } catch (error) {
    row.project_assignments_error = error instanceof Error ? error.message : "Unable to load assignments.";
  } finally {
    row.project_assignments_loading = false;
    if (activeProjectsResultKey === resultKey) {
      renderProjectsPopover();
    }
  }
}

async function loadAvailableSamplesByKey(resultKey, force = false) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const state = projectsPopoverState(row);
  if (!state.selected_project_sha256) return;
  const requestKey = JSON.stringify([resultKey, state.selected_project_sha256, state.available_query]);
  if (!force && row.project_available_samples_request_key === requestKey && row.project_available_samples_loaded) return;
  row.project_available_samples_loading = true;
  row.project_available_samples_request_key = requestKey;
  row.project_available_samples_error = "";
  try {
    const query = new URLSearchParams({
      q: state.available_query || "",
      limit: "8",
      page: "1",
    });
    const payload = await fetchJsonWithCredentials(`/api/v1/samples/search?${query.toString()}`);
    row.project_available_samples = Array.isArray(payload?.samples) ? payload.samples : [];
    row.project_available_samples_loaded = true;
  } catch (error) {
    row.project_available_samples_error = error instanceof Error ? error.message : "Unable to load available samples.";
  } finally {
    row.project_available_samples_loading = false;
    if (activeProjectsResultKey === resultKey) {
      renderProjectsPopover();
    }
  }
}

function ensureProjectsPopover() {
  let popover = getProjectsPopover();
  if (popover) return popover;
  popover = document.createElement("div");
  popover.id = "projects-popover";
  popover.className = "symbol-popover projects-popover";
  popover.hidden = true;
  popover.innerHTML = `
    <div class="symbol-popover-header">
      <div class="symbol-popover-title">Projects</div>
      <button type="button" class="secondary result-popover-close" onclick="closeProjectsPopover()">Close</button>
    </div>
    <div class="symbol-popover-body"></div>
  `;
  document.body.appendChild(popover);
  return popover;
}

function positionProjectsPopover(trigger, popover) {
  positionSymbolPopover(trigger, popover);
}

function renderProjectCard(item, resultKey, selected) {
  const projectSha256 = String(item?.project_sha256 || "");
  const label = `${String(item?.tool || "").toUpperCase()} ${abbreviateHex(projectSha256)}`;
  const activeClass = selected ? " active" : "";
  const filename = String(item?.original_filename || "");
  const uploader = String(item?.uploaded_by?.username || "");
  return `<div class="symbol-picker-item${activeClass}" onclick="selectProjectForAssignments('${escapeHtml(resultKey)}','${escapeHtml(projectSha256)}')">
    <span class="symbol-picker-name" title="${escapeHtml(projectSha256)}">${escapeHtml(label)}</span>
    ${filename ? `<span class="symbol-picker-name" title="${escapeHtml(filename)}">${escapeHtml(filename)}</span>` : ""}
    ${uploader ? `<span class="symbol-picker-name" title="${escapeHtml(uploader)}">${escapeHtml(uploader)}</span>` : ""}
    <div class="symbol-picker-actions">
      <button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(projectSha256))}')">Copy</button>
      <button type="button" class="symbol-picker-move" onclick="event.stopPropagation(); window.location.href='/api/v1/download/project/${escapeHtml(projectSha256)}'">DL</button>
    </div>
  </div>`;
}

function renderAvailableSampleRow(sampleSha256, resultKey) {
  const normalized = String(sampleSha256 || "");
  return `<div class="symbol-picker-item">
    <span class="symbol-picker-name" title="${escapeHtml(normalized)}">${escapeHtml(abbreviateHex(normalized))}</span>
    <div class="symbol-picker-actions">
      <button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(normalized))}')">Copy</button>
      <button type="button" class="symbol-picker-move" onclick="event.stopPropagation(); assignProjectSample('${escapeHtml(resultKey)}','${escapeHtml(normalized)}')">→</button>
    </div>
  </div>`;
}

function renderProjectAssignmentRow(item, resultKey) {
  const sampleSha256 = String(item?.sample_sha256 || "");
  return `<div class="symbol-picker-item">
    <span class="symbol-picker-name" title="${escapeHtml(sampleSha256)}">${escapeHtml(abbreviateHex(sampleSha256))}</span>
    <div class="symbol-picker-actions">
      <button type="button" class="symbol-picker-copy" onclick="event.stopPropagation(); copyPickerValue(this,'${escapeHtml(encodeURIComponent(sampleSha256))}')">Copy</button>
      <button type="button" class="symbol-picker-move" onclick="event.stopPropagation(); unassignProjectSample('${escapeHtml(resultKey)}','${escapeHtml(sampleSha256)}')">←</button>
    </div>
  </div>`;
}

function renderProjectsToolFilter(selectedValue) {
  const normalized = String(selectedValue || "").trim().toLowerCase();
  const current = normalized || "any";
  const options = ["any", "ida", "binja", "ghidra"];
  return `<details class="multiselect modal-select" data-single-select="projects-tool-filter" data-single-label="Tool">
    <summary>Tool: ${escapeHtml(current)}</summary>
    <div class="menu">
      <div class="menu-options">
        ${options.map((option) => `<label class="menu-option" data-single-group="projects-tool-filter" data-option="${escapeHtml(option)}">
          <input type="radio" name="projects-tool-filter" value="${escapeHtml(option)}"${option === current ? " checked" : ""} onchange="selectProjectsToolFilter(this.value)">
          <span class="menu-option-pill"><span class="menu-option-indicator" aria-hidden="true"></span><span class="menu-option-label">${escapeHtml(option)}</span></span>
        </label>`).join("")}
      </div>
    </div>
  </details>`;
}

function projectsPopoverContent(row) {
  const state = projectsPopoverState(row);
  const projects = Array.isArray(row.projects) ? row.projects : [];
  const assignedSet = new Set((Array.isArray(row.project_assignments) ? row.project_assignments : []).map((item) => String(item?.sample_sha256 || "")));
  const availableSamples = (Array.isArray(row.project_available_samples) ? row.project_available_samples : [])
    .map((value) => String(value || ""))
    .filter((value) => value && !assignedSet.has(value));
  const assignments = Array.isArray(row.project_assignments) ? row.project_assignments : [];
  const projectItems = projects.length
    ? projects.map((item) => renderProjectCard(item, resultRowKey(row), String(item?.project_sha256 || "") === state.selected_project_sha256)).join("")
    : '<div class="symbol-popover-empty">No projects.</div>';
  const availableItems = !state.selected_project_sha256
    ? '<div class="symbol-popover-empty">Select a project.</div>'
    : availableSamples.length
      ? availableSamples.map((item) => renderAvailableSampleRow(item, resultRowKey(row))).join("")
      : '<div class="symbol-popover-empty">No available samples.</div>';
  const assignmentItems = assignments.length
    ? assignments.map((item) => renderProjectAssignmentRow(item, resultRowKey(row))).join("")
    : !state.selected_project_sha256
      ? '<div class="symbol-popover-empty">Select a project.</div>'
      : '<div class="symbol-popover-empty">No assigned samples.</div>';
  return `
    <div class="symbol-picker-grid projects-picker-grid">
      <div class="symbol-picker-column">
        <div class="symbol-picker-header"><div class="symbol-picker-label">Projects</div></div>
        <div class="upload-corpus-search-wrap symbol-picker-search-wrap">
          <input type="search" class="menu-search symbol-popover-search" data-project-filter="project_sha256" value="${escapeHtml(state.project_sha256 || "")}" placeholder="Project SHA256">
        </div>
        <div class="upload-corpus-search-wrap symbol-picker-search-wrap">
          <input type="search" class="menu-search symbol-popover-search" data-project-filter="username" value="${escapeHtml(state.username || "")}" placeholder="Username">
        </div>
        ${renderProjectsToolFilter(state.tool || "")}
        <div class="symbol-picker-list">${projectItems}</div>
      </div>
      <div class="symbol-picker-column">
        <div class="symbol-picker-header"><div class="symbol-picker-label">Available Samples</div></div>
        <div class="upload-corpus-search-wrap symbol-picker-search-wrap">
          <input type="search" class="menu-search symbol-popover-search" data-project-filter="available_query" value="${escapeHtml(state.available_query || "")}" placeholder="Sample SHA256">
        </div>
        <div class="symbol-picker-list">${availableItems}</div>
      </div>
      <div class="symbol-picker-column">
        <div class="symbol-picker-header"><div class="symbol-picker-label">Assigned Samples</div></div>
        <div class="upload-corpus-search-wrap symbol-picker-search-wrap">
          <input type="search" class="menu-search symbol-popover-search" data-project-filter="assignment_query" value="${escapeHtml(state.assignment_query || "")}" placeholder="Sample SHA256">
        </div>
        <div class="symbol-picker-list">${assignmentItems}</div>
      </div>
    </div>`;
}

function renderProjectsPopover() {
  const popover = ensureProjectsPopover();
  const body = popover?.querySelector?.(".symbol-popover-body");
  if (!(popover instanceof HTMLElement) || !(body instanceof HTMLElement)) return;
  const row = activeProjectsResultKey ? findSearchRowByKey(activeProjectsResultKey) : null;
  if (!row) {
    closeProjectsPopover();
    return;
  }
  if (!row.projects_loaded && !row.projects_loading) {
    loadProjectsByKey(activeProjectsResultKey).catch((error) => console.error("binlex-web projects load failed", error));
  }
  if (row.projects_loading) {
    body.innerHTML = '<div class="tags-popover-status">Loading projects...</div>';
  } else if (row.projects_error) {
    body.innerHTML = `<div class="tags-popover-status error">${escapeHtml(row.projects_error)}</div>`;
  } else {
    body.innerHTML = projectsPopoverContent(row);
    initializeModalSelectStacking();
    body.querySelectorAll(".symbol-popover-search").forEach((input) => {
      input.addEventListener("change", () => handleProjectsFilterInput(input));
      input.addEventListener("keydown", (event) => {
        if (event.key === "Enter") {
          event.preventDefault();
          handleProjectsFilterInput(input);
        } else if (event.key === "Escape") {
          closeProjectsPopover();
        }
      });
    });
    if (projectsPopoverState(row).selected_project_sha256) {
      if (!row.project_available_samples_loaded && !row.project_available_samples_loading) {
        loadAvailableSamplesByKey(activeProjectsResultKey).catch((error) => console.error("binlex-web project available samples load failed", error));
      }
      if (!row.project_assignments_loaded && !row.project_assignments_loading) {
        loadProjectAssignmentsByKey(activeProjectsResultKey).catch((error) => console.error("binlex-web project assignments load failed", error));
      }
    }
  }
  const trigger = currentProjectsPopoverTrigger();
  if (trigger) {
    activeProjectsTrigger = trigger;
    activeProjectsTrigger.classList.add("active");
  }
  positionProjectsPopover(trigger || activeProjectsTrigger, popover);
}

function handleProjectsFilterInput(input) {
  const row = activeProjectsResultKey ? findSearchRowByKey(activeProjectsResultKey) : null;
  if (!row || !(input instanceof HTMLInputElement)) return;
  const state = projectsPopoverState(row);
  const key = String(input.dataset.projectFilter || "");
  state[key] = String(input.value || "").trim();
  if (key === "project_sha256" || key === "username" || key === "tool") {
    row.projects_loaded = false;
    loadProjectsByKey(activeProjectsResultKey, true).catch((error) => console.error("binlex-web projects filter failed", error));
    return;
  }
  if (key === "available_query") {
    row.project_available_samples_loaded = false;
    loadAvailableSamplesByKey(activeProjectsResultKey, true).catch((error) => console.error("binlex-web available samples filter failed", error));
    return;
  }
  if (key === "assignment_query") {
    row.project_assignments_loaded = false;
    loadProjectAssignmentsByKey(activeProjectsResultKey, true).catch((error) => console.error("binlex-web project assignments filter failed", error));
  }
}

function selectProjectsToolFilter(value) {
  const row = activeProjectsResultKey ? findSearchRowByKey(activeProjectsResultKey) : null;
  if (!row) return;
  const state = projectsPopoverState(row);
  const normalized = String(value || "").trim().toLowerCase();
  state.tool = normalized === "any" ? "" : normalized;
  row.projects_loaded = false;
  loadProjectsByKey(activeProjectsResultKey, true).catch((error) => console.error("binlex-web projects tool filter failed", error));
}

function closeProjectsPopover() {
  const popover = getProjectsPopover();
  if (popover) popover.hidden = true;
  if (activeProjectsTrigger instanceof HTMLElement) {
    activeProjectsTrigger.classList.remove("active");
  }
  activeProjectsTrigger = null;
  activeProjectsResultKey = null;
}

function toggleProjectsPopover(button) {
  const popover = ensureProjectsPopover();
  if (!(button instanceof HTMLElement) || !(popover instanceof HTMLElement)) return;
  const resultKey = String(button.dataset.resultKey || "");
  if (activeProjectsTrigger === button && activeProjectsResultKey === resultKey && !popover.hidden) {
    closeProjectsPopover();
    return;
  }
  closeRowActionMenu();
  closeCorporaPopover();
  closeTagsPopover();
  closeSymbolPopover();
  closeCommentsPopover();
  if (activeProjectsTrigger instanceof HTMLElement) {
    activeProjectsTrigger.classList.remove("active");
  }
  activeProjectsTrigger = button;
  activeProjectsResultKey = resultKey;
  button.classList.add("active");
  popover.hidden = false;
  renderProjectsPopover();
}

function selectProjectForAssignments(resultKey, projectSha256) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const state = projectsPopoverState(row);
  state.selected_project_sha256 = String(projectSha256 || "");
  row.project_available_samples_loaded = false;
  row.project_assignments_loaded = false;
  loadAvailableSamplesByKey(resultKey, true).catch((error) => console.error("binlex-web project available samples load failed", error));
  loadProjectAssignmentsByKey(resultKey, true).catch((error) => console.error("binlex-web project assignments load failed", error));
}

async function assignProjectSample(resultKey, sampleSha256) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const state = projectsPopoverState(row);
  const normalizedSha256 = String(sampleSha256 || "").trim();
  if (!isSha256SearchValue(normalizedSha256) || !state.selected_project_sha256) return;
  try {
    await postJsonWithCredentials(`/api/v1/projects/${encodeURIComponent(state.selected_project_sha256)}/samples`, {
      sample_sha256: normalizedSha256,
    });
    row.project_available_samples_loaded = false;
    row.project_assignments_loaded = false;
    loadAvailableSamplesByKey(resultKey, true).catch((error) => console.error("binlex-web project available samples reload failed", error));
    loadProjectAssignmentsByKey(resultKey, true).catch((error) => console.error("binlex-web project assignments reload failed", error));
    if (normalizedSha256 === row.sha256) {
      row.sample_project_count = Number(row.sample_project_count || 0) + 1;
      updateProjectsCell(resultKey);
    }
  } catch (error) {
    row.project_assignments_error = error instanceof Error ? error.message : "Unable to assign sample.";
    renderProjectsPopover();
  }
}

async function unassignProjectSample(resultKey, sampleSha256) {
  const row = findSearchRowByKey(resultKey);
  if (!row) return;
  const state = projectsPopoverState(row);
  if (!state.selected_project_sha256) return;
  try {
    await deleteJsonWithCredentials(`/api/v1/projects/${encodeURIComponent(state.selected_project_sha256)}/samples/${encodeURIComponent(sampleSha256)}`);
    row.project_available_samples_loaded = false;
    row.project_assignments_loaded = false;
    loadAvailableSamplesByKey(resultKey, true).catch((error) => console.error("binlex-web project available samples reload failed", error));
    loadProjectAssignmentsByKey(resultKey, true).catch((error) => console.error("binlex-web project assignments reload failed", error));
    if (sampleSha256 === row.sha256) {
      row.sample_project_count = Math.max(0, Number(row.sample_project_count || 0) - 1);
      updateProjectsCell(resultKey);
    }
  } catch (error) {
    row.project_assignments_error = error instanceof Error ? error.message : "Unable to unassign sample.";
    renderProjectsPopover();
  }
}

function isSha256SearchValue(value) {
  return /^[a-fA-F0-9]{64}$/.test(String(value || "").trim());
}
