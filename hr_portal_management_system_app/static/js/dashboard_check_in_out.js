import {
  showPasskeyStatus,
  passkeyUnavailableReason,
  clearPasskeyStatus,
  prepareAssertionOptions,
  serializeAssertion,
} from "./fingerprint_helper_functions.js";

/* ===== Dashboard page: clock in / clock out ===== */
const clockButton = document.getElementById("attendance_action");

if (clockButton && !clockButton.disabled) {
  const label = document.getElementById("attendance_action_label");
  const hint = document.getElementById("attendance_hint");
  const errorBox = document.getElementById("attendance_error");
  const beginUrl = clockButton.getAttribute("data-begin-url");
  const completeUrl = clockButton.getAttribute("data-complete-url");
  const dashboardUrl = clockButton.getAttribute("data-dashboard-url");
  const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    .getAttribute("content");
  const idleLabel = label.textContent.trim();

  /** Disable the clock action while the fingerprint prompt is open. */
  function setBusy(busy) {
    clockButton.disabled = busy;
    clockButton.setAttribute("aria-busy", String(busy));
    label.textContent = busy ? "Waiting for fingerprint…" : idleLabel;
  }

  const initialReason = passkeyUnavailableReason("Fingerprint clocking");

  if (initialReason) {
    clockButton.disabled = true;
    clockButton.title = initialReason;
    hint.textContent = initialReason;
    hint.classList.remove("fg-2");
    hint.classList.add("fg-warning");
  }

  clockButton.addEventListener("click", async function () {
    clearPasskeyStatus(errorBox);

    const reason = passkeyUnavailableReason("Fingerprint clocking");

    if (reason) {
      hint.textContent = reason;
      hint.classList.remove("fg-2");
      hint.classList.add("fg-warning");
      return;
    }

    setBusy(true);

    try {
      // Step 1: ask the server for a clocking challenge.
      const beginResponse = await fetch(beginUrl, {
        method: "POST",
        headers: { "X-CSRFToken": csrfToken },
      });
      const options = await beginResponse.json().catch(function () {
        return {};
      });

      if (!beginResponse.ok) {
        throw new Error(
          options.error || "Could not start fingerprint clocking.",
        );
      }

      // Step 2: let the browser/fingerprint sensor sign the challenge.
      const assertion = await navigator.credentials.get({
        publicKey: prepareAssertionOptions(options),
      });

      // Step 3: send the signed scan back; the server records attendance.
      const completeResponse = await fetch(completeUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({
          credential: serializeAssertion(assertion),
        }),
      });
      const result = await completeResponse.json().catch(function () {
        return {};
      });

      if (!completeResponse.ok) {
        throw new Error(result.error || "Fingerprint clocking failed.");
      }

      window.location.assign(result.redirect || dashboardUrl);
    } catch (error) {
      if (error && error.name === "NotAllowedError") {
        const action =
          clockButton.dataset.attendanceAction === "out"
            ? "Check-out"
            : "Check-in";
        showPasskeyStatus(
          errorBox,
          action + " was cancelled or timed out. Try again.",
          "info",
        );
      } else {
        showPasskeyStatus(
          errorBox,
          error.message || "Fingerprint clocking failed. Please try again.",
          "error",
        );
      }
    } finally {
      setBusy(false);
    }
  });
}
