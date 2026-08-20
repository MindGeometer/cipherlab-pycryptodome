// RSA 키 생성 + 상태 표시
(function () {
  const toast = document.getElementById("toast");
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add("show");
    setTimeout(() => toast.classList.remove("show"), 1800);
  }

  const errorBox = document.getElementById("error");
  function showError(msg) {
    errorBox.textContent = msg;
    errorBox.classList.remove("hidden");
  }
  function clearError() {
    errorBox.classList.add("hidden");
  }

  const keyStatus = document.getElementById("key-status");
  let selectedBits = 2048;

  // 키 크기 토글
  document.querySelectorAll(".bits-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".bits-tab").forEach((b) => b.classList.remove("bits-active"));
      btn.classList.add("bits-active");
      selectedBits = parseInt(btn.dataset.bits, 10);
    });
  });

  function syncBitsToggle(bits) {
    if (!bits) return;
    document.querySelectorAll(".bits-tab").forEach((b) => {
      b.classList.toggle("bits-active", parseInt(b.dataset.bits, 10) === bits);
    });
    selectedBits = bits;
  }

  async function refreshStatus() {
    try {
      const res = await fetch("/api/rsa/keys");
      const data = await res.json();
      if (data.exists) {
        keyStatus.innerHTML =
          `<span class="text-neon">● 키쌍 있음</span> <span class="text-slate-600 text-xs">— enc_rsa_private.pem / enc_rsa_public.pem (RSA-${data.bits})</span>`;
        syncBitsToggle(data.bits);
      } else {
        keyStatus.innerHTML = '<span class="text-slate-500">○ 키쌍 없음</span> <span class="text-slate-600 text-xs">— 키를 생성하세요</span>';
      }
    } catch {
      keyStatus.textContent = "상태 확인 실패";
    }
  }

  document.getElementById("btn-keygen").addEventListener("click", async () => {
    clearError();
    try {
      const res = await fetch("/api/rsa/keygen", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ bits: selectedBits }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "키 생성 실패");
      showToast(`RSA-${data.bits} 키쌍 생성 완료`);
      await refreshStatus();
    } catch (e) {
      showError(e.message);
    }
  });

  refreshStatus();
})();
