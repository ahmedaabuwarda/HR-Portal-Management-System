/* Bootstrap's bundle is published as an ES module, so we import Toast from it. */
import { Toast } from "https://cdn.jsdelivr.net/npm/bootstrap@6.0.0-alpha.1/dist/js/bootstrap.bundle.min.js";

/* ===== Flash messages (the Django toasts) ===== */
document.querySelectorAll(".toast-container .toast").forEach(function (el) {
  const delay = Number(el.dataset.delay || 5000);
  Toast.getOrCreateInstance(el, { autohide: true, delay: delay }).show();
});
