// The policy page: show this home's current and retired host keys from GET /v0/host.
const key = document.getElementById("hostKey");
const facts = document.getElementById("hostFacts");

function row(label, value) {
  const dt = document.createElement("dt");
  dt.textContent = label;
  const dd = document.createElement("dd");
  dd.className = "mono";
  dd.textContent = value;
  facts.append(dt, dd);
}

fetch("/v0/host", { cache: "no-store" })
  .then((r) => (r.ok ? r.json() : Promise.reject(new Error(`status ${r.status}`))))
  .then((h) => {
    key.textContent = h.key;
    for (const k of h.retired_keys ?? []) row("Retired key", k);
    if (Array.isArray(h.urls)) row("Base URL", h.urls.join(", "));
  })
  .catch(() => {
    key.textContent = "Could not load; see /v0/host";
  });
