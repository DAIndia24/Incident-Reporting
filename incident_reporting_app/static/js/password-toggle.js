// Robust password toggle with event delegation.
// Works for any button with class "password-toggle" and a data-target="#inputId" attribute.
// Also preserves caret position when toggling (Safari/Firefox friendly).

(function () {
  // Helper: find the input we should toggle
  function resolveTargetInput(btn) {
    const sel = btn.getAttribute("data-target");
    if (sel) {
      const node = document.querySelector(sel);
      if (node) return node;
      console.warn("[password-toggle] No input found for selector:", sel);
    }
    // Fallback: nearest input in the same group/container
    let parent = btn.closest(".mb-3, .form-group, .input-group, form") || btn.parentElement;
    if (parent) {
      const candidate = parent.querySelector('input[type="password"], input[type="text"]');
      if (candidate) return candidate;
    }
    return null;
  }

  // Event delegation for all current/future toggle buttons
  document.addEventListener("click", function (e) {
    const btn = e.target.closest(".password-toggle");
    if (!btn) return;

    e.preventDefault();

    const input = resolveTargetInput(btn);
    if (!input) {
      console.warn("[password-toggle] Could not resolve target input.");
      return;
    }

    const wasPassword = input.type === "password";
    // Preserve caret/selection where supported
    let posStart = null, posEnd = null;
    try {
      posStart = input.selectionStart;
      posEnd = input.selectionEnd;
    } catch (_) {}

    input.type = wasPassword ? "text" : "password";
    btn.setAttribute("aria-pressed", wasPassword ? "true" : "false");

    // Swap icon if present (Bootstrap Icons)
    const icon = btn.querySelector("i, svg");
    if (icon) {
      icon.classList.toggle("bi-eye", !wasPassword);
      icon.classList.toggle("bi-eye-slash", wasPassword);
    }

    // Restore focus/caret for a smooth experience
    input.focus({ preventScroll: true });
    try {
      if (posStart !== null && posEnd !== null) {
        input.setSelectionRange(posStart, posEnd);
      } else {
        // Move caret to end if positions are unknown
        const val = input.value;
        input.value = "";
        input.value = val;
      }
    } catch (_) {}
  });
})();
