if (typeof document !== "undefined") {
  document.addEventListener("mouseover", (event) => {
    syncPickerTooltipTarget(event.target);
  });

  document.addEventListener("mousemove", (event) => {
    syncPickerTooltipTarget(event.target);
  });

  document.addEventListener("mouseout", (event) => {
    if (!(activePickerTooltipHost instanceof HTMLElement)) return;
    const related = event.relatedTarget;
    if (related instanceof Node && activePickerTooltipHost.contains(related)) return;
    if (event.target instanceof Node && activePickerTooltipHost.contains(event.target)) {
      hidePickerTooltip();
    }
  });

  document.addEventListener("focusin", (event) => {
    syncPickerTooltipTarget(event.target);
  });

  document.addEventListener("focusout", (event) => {
    if (!(activePickerTooltipHost instanceof HTMLElement)) return;
    const related = event.relatedTarget;
    if (related instanceof Node && activePickerTooltipHost.contains(related)) return;
    hidePickerTooltip();
  });

  document.addEventListener("click", (event) => {
    const assistant = document.getElementById("query-assistant");
    const input = getQueryInput();
    if (assistant && !assistant.contains(event.target) && input && event.target !== input) {
      hideQueryAssistantMenu();
    }
    const topK = document.querySelector(".top-k-control");
    if (topK && !topK.contains(event.target)) {
      closeTopKPopover();
    }
    if (!(event.target instanceof Element) || !event.target.closest(".modal-select")) {
      clearActiveModalSelect();
    }
    if (!(event.target instanceof Element) || !event.target.closest(".auth-header")) {
      closeAuthMenu();
    }
  });

  document.addEventListener("click", (event) => {
    const popover = getRowActionPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeRowActionTrigger && activeRowActionTrigger.contains(event.target)) return;
    closeRowActionMenu();
  });

  document.addEventListener("click", (event) => {
    const popover = getCorporaPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeCorporaTrigger && activeCorporaTrigger.contains(event.target)) return;
    closeCorporaPopover();
  });

  document.addEventListener("click", (event) => {
    const popover = getTagsPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeTagTrigger && activeTagTrigger.contains(event.target)) return;
    closeTagsPopover();
  });

  document.addEventListener("click", (event) => {
    const popover = getSymbolPopover();
    if (!popover || popover.hidden) return;
    if (isInsideTagsConfirmModal(event.target)) return;
    if (popover.contains(event.target)) return;
    if (activeSymbolTrigger && activeSymbolTrigger.contains(event.target)) return;
    closeSymbolPopover();
  });

  document.addEventListener("click", (event) => {
    const popover = getColumnsPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeColumnsTrigger && activeColumnsTrigger.contains(event.target)) return;
    closeColumnsPopover();
  });

  document.addEventListener("click", (event) => {
    const popover = getCommentsPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeCommentsTrigger && activeCommentsTrigger.contains(event.target)) return;
    closeCommentsPopover();
  });

  document.addEventListener("click", (event) => {
    const popover = getProjectsPopover();
    if (!popover || popover.hidden) return;
    if (popover.contains(event.target)) return;
    if (activeProjectsTrigger && activeProjectsTrigger.contains(event.target)) return;
    closeProjectsPopover();
  });

  document.addEventListener("submit", (event) => {
    handleEnhancedFormSubmit(event);
  });

  document.addEventListener("input", (event) => {
    if (!(event.target instanceof HTMLInputElement)) return;
    const root = event.target.closest("[data-live-validation]");
    if (!root) return;
    updateValidationForRoot(root);
  });

  document.addEventListener("DOMContentLoaded", () => {
    initializeSearchPage();
    initializeModalSelectStacking();
    initializeProfilePictureCrop();
    syncProfileTwoFactorState(currentAuthUser());
    document.querySelectorAll("[data-live-validation]").forEach((root) => {
      updateValidationForRoot(root);
    });
    let savedTheme = "dark";
    try {
      savedTheme = localStorage.getItem(THEME_STORAGE_KEY) || "dark";
    } catch (_) {}
    applyTheme(savedTheme);
    const input = getQueryInput();
    window.setTimeout(() => {
      if (input && document.activeElement === input) {
        input.blur();
      }
      if (document.body instanceof HTMLElement) {
        document.body.focus({ preventScroll: true });
      }
      hideQueryAssistantMenu();
    }, 0);
  });
}

if (typeof window !== "undefined") {
  window.addEventListener("resize", () => {
    const popover = getRowActionPopover();
    if (popover && !popover.hidden) {
      positionRowActionMenu(activeRowActionTrigger, popover);
    }
    const corporaPopover = getCorporaPopover();
    if (corporaPopover && !corporaPopover.hidden) {
      positionCorporaPopover(activeCorporaTrigger, corporaPopover);
    }
    const tagsPopover = getTagsPopover();
    if (tagsPopover && !tagsPopover.hidden) {
      positionTagsPopover(activeTagTrigger, tagsPopover);
    }
    const symbolPopover = getSymbolPopover();
    if (symbolPopover && !symbolPopover.hidden) {
      positionSymbolPopover(activeSymbolTrigger, symbolPopover);
    }
    const commentsPopover = getCommentsPopover();
    if (commentsPopover && !commentsPopover.hidden) {
      positionCommentsPopover(activeCommentsTrigger, commentsPopover);
    }
    const projectsPopover = getProjectsPopover();
    if (projectsPopover && !projectsPopover.hidden) {
      positionProjectsPopover(activeProjectsTrigger, projectsPopover);
    }
    const columnsPopover = getColumnsPopover();
    if (columnsPopover && !columnsPopover.hidden) {
      positionColumnsPopover(activeColumnsTrigger, columnsPopover);
    }
    if (activePickerTooltipHost instanceof HTMLElement) {
      positionPickerTooltip(activePickerTooltipHost);
    }
  });

  window.addEventListener("scroll", (event) => {
    hidePickerTooltip();
    const popover = getRowActionPopover();
    if (popover && !popover.hidden && popover.contains(event.target)) {
      return;
    }
    closeRowActionMenu();
    const corporaPopover = getCorporaPopover();
    if (corporaPopover && !corporaPopover.hidden && corporaPopover.contains(event.target)) {
      return;
    }
    closeCorporaPopover();
    const tagsPopover = getTagsPopover();
    if (tagsPopover && !tagsPopover.hidden && tagsPopover.contains(event.target)) {
      return;
    }
    closeTagsPopover();
    const symbolPopover = getSymbolPopover();
    if (symbolPopover && !symbolPopover.hidden && symbolPopover.contains(event.target)) {
      return;
    }
    closeSymbolPopover();
    const commentsPopover = getCommentsPopover();
    if (commentsPopover && !commentsPopover.hidden && commentsPopover.contains(event.target)) {
      return;
    }
    closeCommentsPopover();
    const projectsPopover = getProjectsPopover();
    if (projectsPopover && !projectsPopover.hidden && projectsPopover.contains(event.target)) {
      return;
    }
    closeProjectsPopover();
    const columnsPopover = getColumnsPopover();
    if (columnsPopover && !columnsPopover.hidden && columnsPopover.contains(event.target)) {
      return;
    }
    closeColumnsPopover();
  }, true);
}

if (typeof module !== "undefined" && module.exports) {
  module.exports = {
    analyzeQueryContext,
    continuationStateAfterSpace,
    fieldSuggestions,
    operatorSuggestions,
    isClauseComplete,
    isDelimitedValueContext,
    filterQuerySuggestions,
    continuationSuggestions,
    queryGroupDepth,
    applyQuerySuggestion,
    replacementStateForContext,
    syncQueryInputCaret,
  };
}
