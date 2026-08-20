// 전자서명 페이지 — RSA / ECDSA 알고리즘 토글, 키 생성, 서명, 검증
(function () {
  const ALGO_LABELS = {
    rsa: "RSA (PKCS#1 v1.5 + SHA-256)",
    ecdsa: "ECDSA (P-256 + SHA-256)",
  };

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

  let currentAlgo = "rsa";
  let selectedBits = 2048;

  const algoLabel = document.getElementById("algo-label");
  const keyStatus = document.getElementById("sign-key-status");
  const bitsWrap = document.getElementById("bits-wrap");
  const verifyResult = document.getElementById("verify-result");

  // 알고리즘 토글
  document.querySelectorAll(".algo-tab").forEach((tab) => {
    tab.addEventListener("click", () => {
      document.querySelectorAll(".algo-tab").forEach((t) => t.classList.remove("algo-active"));
      tab.classList.add("algo-active");
      currentAlgo = tab.dataset.algo;
      algoLabel.textContent = ALGO_LABELS[currentAlgo] || currentAlgo;
      bitsWrap.classList.toggle("hidden", currentAlgo !== "rsa");
      clearError();
      verifyResult.classList.add("hidden");
      refreshKeyStatus();
    });
  });

  // 키 크기 토글 (RSA 전용)
  document.querySelectorAll(".sign-bits-tab").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".sign-bits-tab").forEach((b) => b.classList.remove("sign-bits-active"));
      btn.classList.add("sign-bits-active");
      selectedBits = parseInt(btn.dataset.bits, 10);
    });
  });

  function syncSignBitsToggle(bits) {
    if (!bits) return;
    document.querySelectorAll(".sign-bits-tab").forEach((b) => {
      b.classList.toggle("sign-bits-active", parseInt(b.dataset.bits, 10) === bits);
    });
    selectedBits = bits;
  }

  async function refreshKeyStatus() {
    keyStatus.textContent = "확인 중…";
    try {
      const res = await fetch(`/api/sign/keys?algo=${currentAlgo}`);
      const data = await res.json();
      const prefix = currentAlgo === "rsa" ? "sign_rsa" : "sign_ecdsa";
      if (data.exists) {
        const bitsLabel = data.bits ? ` (RSA-${data.bits})` : "";
        keyStatus.innerHTML =
          `<span class="text-violet-400">● 키쌍 있음</span> ` +
          `<span class="text-slate-600 text-xs">— ${prefix}_private.pem / ${prefix}_public.pem${bitsLabel}</span>`;
        if (currentAlgo === "rsa") syncSignBitsToggle(data.bits);
      } else {
        keyStatus.innerHTML =
          `<span class="text-slate-500">○ 키쌍 없음</span> <span class="text-slate-600 text-xs">— 키를 생성하세요</span>`;
      }
    } catch {
      keyStatus.textContent = "상태 확인 실패";
    }
  }

  // 키 생성
  document.getElementById("btn-sign-keygen").addEventListener("click", async () => {
    clearError();
    const body = { algo: currentAlgo };
    if (currentAlgo === "rsa") body.bits = selectedBits;
    try {
      const res = await fetch("/api/sign/keygen", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "키 생성 실패");
      showToast(`${currentAlgo.toUpperCase()} 서명 키쌍 생성 완료`);
      await refreshKeyStatus();
    } catch (e) {
      showError(e.message);
    }
  });

  // 서명 생성
  document.getElementById("btn-sign").addEventListener("click", async () => {
    clearError();
    verifyResult.classList.add("hidden");
    const message = document.getElementById("sign-message").value;
    try {
      const res = await fetch("/api/sign/sign", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ algo: currentAlgo, message }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "서명 실패");
      document.getElementById("sign-signature").value = data.signature;
      showToast("서명 완료");
    } catch (e) {
      showError(e.message);
    }
  });

  // 서명 검증
  document.getElementById("btn-verify").addEventListener("click", async () => {
    clearError();
    const message = document.getElementById("sign-message").value;
    const signature = document.getElementById("sign-signature").value.trim();
    if (!signature) {
      showError("서명값을 입력하거나 서명 생성 후 검증하세요.");
      return;
    }
    try {
      const res = await fetch("/api/sign/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ algo: currentAlgo, message, signature }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "검증 실패");
      verifyResult.classList.remove("hidden");
      if (data.valid) {
        verifyResult.textContent = "+++ 서명 인증됨 — 메시지가 위변조되지 않았습니다";
        verifyResult.className =
          "px-4 py-3 rounded-xl border text-sm font-mono font-medium text-center " +
          "border-neon/40 bg-neon/10 text-neon";
      } else {
        verifyResult.textContent = "--- 서명 불일치 — 메시지 또는 서명이 변조되었을 수 있습니다";
        verifyResult.className =
          "px-4 py-3 rounded-xl border text-sm font-mono font-medium text-center " +
          "border-red-500/40 bg-red-500/10 text-red-300";
      }
    } catch (e) {
      showError(e.message);
    }
  });

  // 서명값 복사
  document.getElementById("btn-sign-copy").addEventListener("click", async () => {
    const txt = document.getElementById("sign-signature").value;
    if (!txt) return;
    try {
      await navigator.clipboard.writeText(txt);
      showToast("복사됨");
    } catch {
      showToast("복사 실패");
    }
  });

  // 초기 로드
  refreshKeyStatus();
})();
