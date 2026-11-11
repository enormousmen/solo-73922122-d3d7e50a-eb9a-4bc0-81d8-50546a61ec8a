// Load built-in cross-sign example PEMs into the upload form (fully offline;
// files are served by this same container).
async function loadExample(name) {
  const resp = await fetch(`/api/examples/${encodeURIComponent(name)}`);
  if (!resp.ok) {
    alert("示例加载失败：" + (await resp.text()));
    return;
  }
  const payload = await resp.json();
  const manifest = JSON.parse(payload.manifest);

  function setFile(inputName, fileName) {
    const input = document.querySelector(`input[name="${inputName}"]`);
    const text = payload.files[fileName];
    if (!text) return;
    const file = new File([text], fileName, { type: "application/x-pem-file" });
    const d = new DataTransfer();
    d.items.add(file);
    input.files = d.files;
  }

  setFile("leaf", manifest.leaf);
  setFile("root", manifest.root);
  setFile("intermediates", manifest.intermediates);
  if (manifest.validation_time) {
    document.getElementById("validation_time").value = manifest.validation_time;
  }
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// Submit the diagnosis form via fetch so that 503 (capacity full) and 504
// (compute timeout) can be surfaced inline instead of a browser-native error
// page. Without JavaScript the plain HTML form still posts and the server
// renders a full error/result page on its own.
async function submitDiagnosis(form, errorBox, button) {
  errorBox.hidden = true;
  errorBox.textContent = "";
  button.disabled = true;
  const originalLabel = button.textContent;
  button.textContent = "诊断计算中…";
  try {
    const resp = await fetch(form.action, {
      method: "POST",
      body: new FormData(form),
      headers: { Accept: "text/html" },
    });
    const html = await resp.text();
    if (resp.ok || resp.status === 400) {
      // Full result page (200) or the index page re-rendered with an error
      // banner (400): replace the document, keeping the current base URL so
      // relative /static links keep working.
      const doc = document.open();
      doc.write(html);
      doc.close();
      return;
    }
    // 503 busy / 504 timeout / 502 worker failure: extract the server-side
    // banner text and show it without leaving the page.
    let message = `请求失败（HTTP ${resp.status}）。`;
    const parsed = new DOMParser().parseFromString(html, "text/html");
    const banner = parsed.querySelector(".banner.error");
    if (banner) {
      message = banner.textContent.trim();
    }
    errorBox.innerHTML =
      `<strong>HTTP ${resp.status}：</strong>${message} ` +
      '可稍后重试，或 <a href="/">返回首页</a>。';
    errorBox.hidden = false;
    window.scrollTo({ top: 0, behavior: "smooth" });
  } catch (err) {
    errorBox.innerHTML =
      `<strong>请求中断：</strong>${err} ` +
      '若这是您主动关闭/中止的请求，服务端已同步停止对应计算；否则请稍后重试。';
    errorBox.hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = originalLabel;
  }
}

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".load-example").forEach((btn) => {
    btn.addEventListener("click", () => loadExample(btn.dataset.example));
  });
  const params = new URLSearchParams(window.location.search);
  const example = params.get("example");
  if (example) loadExample(example);

  const form = document.querySelector("form[action='/diagnose']");
  if (form) {
    const errorBox = document.getElementById("submit-error");
    const button = document.getElementById("submit-btn");
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      submitDiagnosis(form, errorBox, button);
    });
  }
});
