// CipherLab — 암호별 페이지 상호작용
(function () {
  const app = document.getElementById("app");
  if (!app) return;

  const cipher = app.dataset.cipher;
  const $ = (id) => document.getElementById(id);

  let encoding = "base64";
  let selectedFile = null;

  // ---------- 토스트 / 에러 ----------
  const toast = $("toast");
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 1800);
  }
  const errorBox = $("error");
  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
  }
  function clearError() {
    errorBox.classList.add("hidden");
  }

  // ---------- 모드 토글 ----------
  document.querySelectorAll(".mode-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".mode-tab").forEach((t) => t.classList.remove("tab-active"));
      tab.classList.add("tab-active");
      const mode = tab.dataset.mode;
      $("panel-message").classList.toggle("hidden", mode !== "message");
      $("panel-file").classList.toggle("hidden", mode !== "file");
      clearError();
    });
  });

  // ---------- 인코딩 변환 헬퍼 (base64 <-> hex, 순수 클라이언트) ----------
  function decodeToBytes(text, enc) {
    const clean = text.replace(/\s+/g, "");
    if (enc === "hex") {
      if (clean.length % 2 !== 0 || /[^0-9a-fA-F]/.test(clean)) throw new Error("bad hex");
      const arr = new Uint8Array(clean.length / 2);
      for (let i = 0; i < arr.length; i++) arr[i] = parseInt(clean.substr(i * 2, 2), 16);
      return arr;
    }
    const bin = atob(clean); // base64
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr;
  }
  function encodeFromBytes(bytes, enc) {
    if (enc === "hex") {
      return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
    }
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  // ---------- 인코딩 토글 ----------
  document.querySelectorAll(".enc-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      const newEnc = tab.dataset.enc;
      if (newEnc === encoding) return;

      // 이미 표시된 암호문이 있으면 같은 바이트를 새 인코딩으로 즉시 재표기
      const ctField = $("ciphertext");
      const cur = ctField.value.trim();
      if (cur) {
        try {
          ctField.value = encodeFromBytes(decodeToBytes(cur, encoding), newEnc);
        } catch {
          /* 현재 값이 기존 인코딩으로 해석되지 않으면 그대로 둔다 */
        }
      }

      document.querySelectorAll(".enc-tab").forEach((t) => t.classList.remove("enc-active"));
      tab.classList.add("enc-active");
      encoding = newEnc;
      document.querySelectorAll(".enc-label").forEach((l) => (l.textContent = encoding));
    });
  });

  // ---------- 공통 입력 ----------
  function creds() {
    return {
      keytext: $("keytext").value,
      ivtext: $("ivtext") ? $("ivtext").value : "",
    };
  }

  // ---------- 메시지 암호화/복호화 ----------
  async function messageApi(action, body) {
    const res = await fetch(`/api/${cipher}/message/${action}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "요청 실패");
    return data;
  }

  $("btn-encrypt").addEventListener("click", async () => {
    clearError();
    try {
      const data = await messageApi("encrypt", {
        ...creds(),
        plaintext: $("plaintext").value,
        encoding,
      });
      $("ciphertext").value = data.ciphertext;
      showToast("암호화 완료");
    } catch (e) {
      showError(e.message);
    }
  });

  $("btn-decrypt").addEventListener("click", async () => {
    clearError();
    try {
      const data = await messageApi("decrypt", {
        ...creds(),
        ciphertext: $("ciphertext").value,
        encoding,
      });
      $("plaintext").value = data.plaintext;
      showToast("복호화 완료");
    } catch (e) {
      showError(e.message);
    }
  });

  $("btn-copy").addEventListener("click", async () => {
    const txt = $("ciphertext").value;
    if (!txt) return;
    try {
      await navigator.clipboard.writeText(txt);
      showToast("복사됨");
    } catch {
      showToast("복사 실패");
    }
  });

  // ---------- 파일 모드 ----------
  const dropzone = $("dropzone");
  const fileInput = $("file-input");
  const fileLabel = $("file-label");

  function setFile(f) {
    selectedFile = f;
    if (f) {
      fileLabel.textContent = `${f.name} (${f.size.toLocaleString()} B)`;
      dropzone.classList.add("has-file");
    } else {
      fileLabel.textContent = "파일을 드래그하거나 클릭해 선택";
      dropzone.classList.remove("has-file");
    }
  }

  dropzone.addEventListener("click", () => fileInput.click());
  fileInput.addEventListener("change", () => setFile(fileInput.files[0] || null));
  ["dragover", "dragenter"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.add("dragover");
    })
  );
  ["dragleave", "drop"].forEach((ev) =>
    dropzone.addEventListener(ev, (e) => {
      e.preventDefault();
      dropzone.classList.remove("dragover");
    })
  );
  dropzone.addEventListener("drop", (e) => {
    if (e.dataTransfer.files.length) setFile(e.dataTransfer.files[0]);
  });

  async function fileApi(action) {
    clearError();
    if (!selectedFile) {
      showError("파일을 선택하세요.");
      return;
    }
    const c = creds();
    const form = new FormData();
    form.append("file", selectedFile);
    form.append("keytext", c.keytext);
    form.append("ivtext", c.ivtext);

    const res = await fetch(`/api/${cipher}/file/${action}`, {
      method: "POST",
      body: form,
    });
    if (!res.ok) {
      let msg = "요청 실패";
      try {
        msg = (await res.json()).error || msg;
      } catch {}
      showError(msg);
      return;
    }
    // 다운로드 파일명 추출
    const disp = res.headers.get("Content-Disposition") || "";
    const match = disp.match(/filename\*?=(?:UTF-8'')?["']?([^"';]+)/i);
    const name = match ? decodeURIComponent(match[1]) : "download";
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
    showToast(`${name} 다운로드`);
  }

  $("btn-file-encrypt").addEventListener("click", () => fileApi("encrypt"));
  $("btn-file-decrypt").addEventListener("click", () => fileApi("decrypt"));
})();
