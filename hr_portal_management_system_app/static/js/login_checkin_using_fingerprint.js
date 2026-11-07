import {
  showPasskeyStatus,
  passkeyUnavailableReason,
  clearPasskeyStatus,
  prepareAssertionOptions,
  serializeAssertion,
} from "./fingerprint_helper_functions.js";

/* ===== Log in page: sign in with a fingerprint ===== */
const loginButton = document.getElementById("passkey_login");

if (loginButton) {
  const errorBox = document.getElementById("passkey_error");
  const beginUrl = loginButton.getAttribute("data-begin-url");
  const completeUrl = loginButton.getAttribute("data-complete-url");
  const dashboardUrl = loginButton.getAttribute("data-dashboard-url");
  const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    .getAttribute("content");

  const initialReason = passkeyUnavailableReason();

  if (initialReason) {
    showPasskeyStatus(errorBox, initialReason, "error");
    loginButton.disabled = true;
    loginButton.title = initialReason;
  }

  loginButton.addEventListener("click", async function () {
    clearPasskeyStatus(errorBox);

    const reason = passkeyUnavailableReason();

    if (reason) {
      showPasskeyStatus(errorBox, reason, "error");
      return;
    }

    loginButton.disabled = true;

    try {
      // Step 1: ask the server for a login challenge.
      const email = document.getElementById("id_email").value.trim();
      const beginResponse = await fetch(beginUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({ email: email }),
      });
      const options = await beginResponse.json();

      if (!beginResponse.ok) {
        throw new Error(options.error || "Could not start fingerprint login.");
      }

      // Step 2: let the browser/fingerprint sensor sign the challenge.
      const assertion = await navigator.credentials.get({
        publicKey: prepareAssertionOptions(options),
      });

      // Step 3: send the signed scan back; the server logs us in.
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
      const result = await completeResponse.json();

      if (!completeResponse.ok) {
        throw new Error(result.error || "Fingerprint login failed.");
      }

      window.location.assign(result.redirect || dashboardUrl);
    } catch (error) {
      if (error && error.name === "NotAllowedError") {
        showPasskeyStatus(
          errorBox,
          "Fingerprint sign-in was cancelled or timed out. Try again.",
          "info",
        );
      } else {
        showPasskeyStatus(
          errorBox,
          error.message || "Fingerprint sign-in failed. Please try again.",
          "error",
        );
      }
    } finally {
      loginButton.disabled = false;
    }
  });
}
