async function getJson(url) {
  const response = await fetch(url, {
    method: "GET",
    credentials: "same-origin",
    headers: {
      "X-Requested-With": "binlex-web",
      "Accept": "application/json",
    },
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data?.error || "Request failed");
  }
  return data;
}

async function postJson(url, payload) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Requested-With": "binlex-web",
      "Accept": "application/json",
    },
    credentials: "same-origin",
    body: JSON.stringify(payload || {}),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data?.error || "Request failed");
  }
  return data;
}

async function deleteJson(url, payload) {
  const response = await fetch(url, {
    method: "DELETE",
    headers: {
      ...(payload !== undefined ? { "Content-Type": "application/json" } : {}),
      "X-Requested-With": "binlex-web",
      "Accept": "application/json",
    },
    credentials: "same-origin",
    ...(payload !== undefined ? { body: JSON.stringify(payload) } : {}),
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    throw new Error(data?.error || "Request failed");
  }
  return data;
}

async function fetchJsonWithCredentials(url, options = {}) {
  const response = await fetch(url, {
    credentials: "same-origin",
    headers: {
      "X-Requested-With": "binlex-web",
      "Accept": "application/json",
      ...(options.body ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
    ...options,
  });
  if (!response.ok) {
    const message = await response.text();
    throw new Error(message || `request failed with status ${response.status}`);
  }
  return response.json();
}

async function postJsonWithCredentials(url, payload) {
  return fetchJsonWithCredentials(url, {
    method: "POST",
    body: JSON.stringify(payload),
  });
}

async function putJsonWithCredentials(url, payload) {
  return fetchJsonWithCredentials(url, {
    method: "PUT",
    body: JSON.stringify(payload),
  });
}

async function deleteJsonWithCredentials(url, payload) {
  return fetchJsonWithCredentials(url, {
    method: "DELETE",
    body: JSON.stringify(payload),
  });
}
