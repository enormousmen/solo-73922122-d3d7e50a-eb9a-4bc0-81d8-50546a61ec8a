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
  const dt = new DataTransfer();

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

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".load-example").forEach((btn) => {
    btn.addEventListener("click", () => loadExample(btn.dataset.example));
  });
  const params = new URLSearchParams(window.location.search);
  const example = params.get("example");
  if (example) loadExample(example);
});
