function resultRowKey(row) {
  return `${row.side}:${row.sha256}:${row.collection}:${row.architecture}:${row.address}:${row.symbol || ""}`;
}

const resultDetailRequests = new Set();

function currentSearchData() {
  const data = window.__BINLEX_SEARCH_DATA__;
  return data && typeof data === "object" ? data : null;
}

function findSearchRowByKey(resultKey) {
  const data = currentSearchData();
  if (!data || !Array.isArray(data.results)) return null;
  return data.results.find((row) => resultRowKey(row) === resultKey) || null;
}

function buildSearchDetailUrl(row) {
  const params = new URLSearchParams();
  params.set("sha256", row.sha256 || "");
  params.set("collection", row.collection || "");
  params.set("architecture", row.architecture || "");
  params.set("address", String(Number(row.address || 0)));
  if (row.symbol) params.set("symbol", row.symbol);
  return `/api/v1/search/detail?${params.toString()}`;
}

async function requestResultDetailByKey(resultKey) {
  if (!resultKey || resultDetailRequests.has(resultKey)) return;
  const row = findSearchRowByKey(resultKey);
  if (!row || row.detail_loaded) return;
  resultDetailRequests.add(resultKey);
  try {
    const response = await fetch(buildSearchDetailUrl(row), {
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
    Object.assign(row, payload);
    row.detail_loaded = true;
    const data = currentSearchData();
    if (data) {
      renderSearchData(data);
      expandResultDetailsByKey(resultKey);
    }
    if (!row.corpora_loaded) {
      loadRowCorporaByKey(resultKey).catch((error) => {
        console.error("binlex-web corpora preview load failed", error);
      });
    }
    if (!row.tags_loaded) {
      loadRowTagsByKey(resultKey).catch((error) => {
        console.error("binlex-web tags preview load failed", error);
      });
    }
    if (!row.symbols_loaded) {
      loadRowSymbolsByKey(resultKey).catch((error) => {
        console.error("binlex-web symbols preview load failed", error);
      });
    }
  } finally {
    resultDetailRequests.delete(resultKey);
  }
}

function tableRowClass(row) {
  if (!row.grouped) return "";
  return row.group_end ? "compare-row compare-row-rhs compare-row-end" : "compare-row compare-row-lhs";
}

function buildJsonCopyNode(label, value, depth) {
  if (value && typeof value === "object") {
    return actionBranch(label, buildJsonCopyActions(value, depth));
  }
  return actionCopy(label, jsonScalarPayload(value));
}

function buildJsonCopyActions(value, depth = 0) {
  if (Array.isArray(value)) {
    const children = [actionCopy("Value", prettyJson(value))];
    if (depth >= JSON_ACTION_MAX_DEPTH || value.length > JSON_ACTION_ARRAY_EXPAND_LIMIT) {
      return children;
    }
    value.forEach((nested, index) => {
      children.push(buildJsonCopyNode(`[${index}]`, nested, depth + 1));
    });
    return children;
  }
  if (value && typeof value === "object") {
    const children = [actionCopy("Value", prettyJson(value))];
    if (depth >= JSON_ACTION_MAX_DEPTH) {
      return children;
    }
    Object.entries(value).forEach(([key, nested]) => {
      children.push(buildJsonCopyNode(key, nested, depth + 1));
    });
    return children;
  }
  return [actionCopy("Value", jsonScalarPayload(value))];
}
