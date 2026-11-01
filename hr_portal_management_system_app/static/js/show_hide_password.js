/* ===== Show / hide password (login and register forms) ===== */
document.querySelectorAll("[data-pw-toggle]").forEach(function (btn) {
  btn.addEventListener("click", function () {
    const input = document.getElementById(btn.dataset.pwToggle);
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    btn.setAttribute("aria-pressed", String(show));
    btn.setAttribute("aria-label", show ? "Hide password" : "Show password");
  });
});
