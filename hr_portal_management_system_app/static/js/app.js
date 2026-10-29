/* ===== Theme toggle (dark / light) ===== */
// Apply the stored theme before first paint to avoid a flash.
(function () {
  try {
    var stored = localStorage.getItem("theme");
    if (stored === "dark" || stored === "light") {
      document.documentElement.setAttribute("data-bs-theme", stored);
    }
  } catch (e) {}
})();

// get the current theme, either from the document or the OS preference
function currentTheme() {
  return (
    document.documentElement.getAttribute("data-bs-theme") ||
    (window.matchMedia("(prefers-color-scheme: dark)").matches
      ? "dark"
      : "light")
  );
}

// show/hide the theme icons based on the current theme
function syncThemeIcons(theme) {
  const show = theme === "dark" ? "sun" : "moon";
  document.querySelectorAll("[data-theme-icon]").forEach(function (el) {
    el.hidden = el.getAttribute("data-theme-icon") !== show;
  });
}

syncThemeIcons(currentTheme());

// Toggle the theme and save the preference to localStorage
document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
  btn.addEventListener("click", function () {
    const next = currentTheme() === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-bs-theme", next);
    try {
      localStorage.setItem("theme", next);
    } catch (e) {}
    syncThemeIcons(next);
  });
});
