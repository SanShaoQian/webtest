const form = document.getElementById("scan-form");
const statusEl = document.getElementById("status");
const resultsEl = document.getElementById("results");
const statsEl = document.getElementById("stats");
const detectionsEl = document.getElementById("detections");
const explainBtn = document.getElementById("explain-btn");
const explanationEl = document.getElementById("explanation");
const explanationTextEl = document.getElementById("explanation-text");
const scanBtn = document.getElementById("scan-btn");

let latestSummary = null;

function setStatus(message, type = "") {
  statusEl.textContent = message;
  statusEl.className = `status ${type}`.trim();
}

async function parseApiResponse(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return await response.json();
  }

  const text = await response.text();
  const snippet = text.replace(/\s+/g, " ").trim().slice(0, 200);
  return {
    error: `Server returned non-JSON response (${response.status}). ${snippet}`,
  };
}

function renderStats(stats) {
  const items = [
    ["Malicious", stats.malicious],
    ["Suspicious", stats.suspicious],
    ["Undetected", stats.undetected],
    ["Harmless", stats.harmless],
    ["Timeout", stats.timeout],
  ];

  statsEl.innerHTML = items
    .map(([label, value]) => `<div class="stat"><strong>${label}:</strong> ${value}</div>`)
    .join("");
}

function renderDetections(detections) {
  if (!detections || detections.length === 0) {
    detectionsEl.innerHTML = "<p>No malicious detections reported by engines.</p>";
    return;
  }

  const rows = detections
    .map(
      (item) =>
        `<tr><td>${item.engine}</td><td>${item.category ?? ""}</td><td>${item.result ?? ""}</td><td>${item.method ?? ""}</td></tr>`
    )
    .join("");

  detectionsEl.innerHTML = `
    <table class="table">
      <thead>
        <tr><th>Engine</th><th>Category</th><th>Result</th><th>Method</th></tr>
      </thead>
      <tbody>${rows}</tbody>
    </table>
  `;
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();
  const fileInput = document.getElementById("file-input");
  if (!fileInput.files.length) {
    setStatus("Please select a file.", "error");
    return;
  }

  const data = new FormData();
  data.append("file", fileInput.files[0]);

  setStatus("Uploading and scanning file. This can take up to a minute...");
  resultsEl.classList.add("hidden");
  explanationEl.classList.add("hidden");
  explainBtn.disabled = true;
  scanBtn.disabled = true;

  try {
    const response = await fetch("/api/scan", {
      method: "POST",
      body: data,
    });
    const payload = await parseApiResponse(response);

    if (!response.ok) {
      throw new Error(payload.error || "Scan failed");
    }

    latestSummary = payload;
    renderStats(payload.stats || {});
    renderDetections(payload.detections || []);
    resultsEl.classList.remove("hidden");
    explainBtn.disabled = false;
    setStatus("Scan complete.", "ok");
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    scanBtn.disabled = false;
  }
});

explainBtn.addEventListener("click", async () => {
  if (!latestSummary) {
    setStatus("Run a scan first.", "error");
    return;
  }

  explainBtn.disabled = true;
  setStatus("Generating plain-English explanation...");

  try {
    const response = await fetch("/api/explain", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ summary: latestSummary }),
    });
    const payload = await parseApiResponse(response);

    if (!response.ok) {
      throw new Error(payload.error || "Explanation failed");
    }

    explanationTextEl.textContent = payload.explanation;
    explanationEl.classList.remove("hidden");
    if (payload.warning) {
      setStatus(payload.warning);
    } else {
      setStatus("Explanation ready.", "ok");
    }
  } catch (error) {
    setStatus(error.message, "error");
  } finally {
    explainBtn.disabled = false;
  }
});

