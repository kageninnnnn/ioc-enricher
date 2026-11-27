"use strict";
// No innerHTML with API data anywhere: everything is built with textContent (XSS-safe).
const $ = (id) => document.getElementById(id);
const el = (tag, cls, text) => {
  const n = document.createElement(tag);
  if (cls) n.className = cls;
  if (text !== undefined) n.textContent = text;
  return n;
};
const COLORS = { malicious: "var(--mal)", suspicious: "var(--sus)", clean: "var(--cln)", unknown: "var(--unk)" };

try { $("apikey").value = sessionStorage.getItem("apikey") || ""; } catch (_) { /* storage blocked */ }

function card(r) {
  const c = el("div", "card " + r.verdict);
  const head = el("div", "head");
  head.append(el("span", "ioc", r.indicator), el("span", "pill v-" + r.verdict, r.verdict + " · " + r.score));
  c.append(head);
  const meta = [r.type, r.sources.length + " source(s) with data"];
  if (r.cached) meta.push("cached");
  if (r.failed_sources.length) meta.push("failed: " + r.failed_sources.join(", "));
  c.append(el("div", "meta", meta.join(" · ")));
  const bar = el("div", "bar"); const fill = el("span");
  fill.style.width = r.score + "%"; bar.style.color = COLORS[r.verdict]; bar.append(fill); c.append(bar);
  const ul = el("ul"); r.explanation.forEach((e) => ul.append(el("li", null, e))); c.append(ul);
  if (r.sources.length) {
    const d = el("details"); d.append(el("summary", null, "source details"));
    d.append(el("pre", null, JSON.stringify(r.sources, null, 2))); c.append(d);
  }
  return c;
}

$("form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const indicators = $("iocs").value.split(/\s*\n\s*/).map((s) => s.trim()).filter(Boolean);
  if (!indicators.length) return;
  const key = $("apikey").value.trim();
  try { sessionStorage.setItem("apikey", key); } catch (_) { /* ignore */ }
  $("go").disabled = true; $("status").className = ""; $("status").textContent = "Enriching…";
  $("results").replaceChildren(); $("summary").hidden = true;
  const headers = { "Content-Type": "application/json" };
  if (key) headers["X-API-Key"] = key;
  try {
    const t0 = performance.now();
    const resp = await fetch("/enrich/batch", { method: "POST", headers, body: JSON.stringify({ indicators }) });
    const body = await resp.json();
    if (!resp.ok) throw new Error(resp.status + ": " + (typeof body.detail === "string" ? body.detail : JSON.stringify(body.detail)));
    const order = { malicious: 0, suspicious: 1, unknown: 2, clean: 3 };
    body.results.sort((a, b) => order[a.verdict] - order[b.verdict] || b.score - a.score);
    body.results.forEach((r) => $("results").append(card(r)));
    body.errors.forEach((e) => {
      const c = el("div", "card"); const h = el("div", "head");
      h.append(el("span", "ioc", e.indicator), el("span", "pill v-invalid", "invalid"));
      c.append(h, el("div", "meta", e.error)); $("results").append(c);
    });
    $("summary").replaceChildren(...Object.entries(body.summary).filter(([, n]) => n)
      .map(([k, n]) => el("span", "pill v-" + k, k + ": " + n)));
    $("summary").hidden = false;
    $("status").textContent = `Done in ${Math.round(performance.now() - t0)} ms`;
  } catch (err) {
    $("status").className = "err"; $("status").textContent = "Error " + err.message;
  } finally {
    $("go").disabled = false;
  }
});
