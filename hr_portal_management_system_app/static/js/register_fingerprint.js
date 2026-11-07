import {
  toBuffer,
  fromBuffer,
  passkeyUnavailableReason,
  showPasskeyStatus,
  clearPasskeyStatus,
} from "./fingerprint_helper_functions.js";

/* ===== Settings page: enroll a fingerprint ===== */
const enrollButton = document.getElementById("passkey_register");

if (enrollButton) {
  const errorBox = document.getElementById("passkey_error");
  const beginUrl = enrollButton.getAttribute("data-begin-url");
  const completeUrl = enrollButton.getAttribute("data-complete-url");
  const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    .getAttribute("content");

  const initialReason = passkeyUnavailableReason();

  if (initialReason) {
    showPasskeyStatus(errorBox, initialReason, "error");
    enrollButton.disabled = true;
    enrollButton.title = initialReason;
  }

  enrollButton.addEventListener("click", async function () {
    clearPasskeyStatus(errorBox);

    const reason = passkeyUnavailableReason();

    if (reason) {
      showPasskeyStatus(errorBox, reason, "error");
      return;
    }

    enrollButton.disabled = true;

    try {
      // Step 1: ask the server for a registration challenge.
      const beginResponse = await fetch(beginUrl, {
        method: "POST",
        headers: { "X-CSRFToken": csrfToken },
      });

      if (!beginResponse.ok) {
        throw new Error("Could not start fingerprint enrollment.");
      }

      const options = await beginResponse.json();

      // Step 2: the browser creates the credential on this device.
      options.challenge = toBuffer(options.challenge);
      options.user.id = toBuffer(options.user.id);
      options.excludeCredentials = (options.excludeCredentials || []).map(
        function (credential) {
          return Object.assign({}, credential, {
            id: toBuffer(credential.id),
          });
        },
      );

      const credential = await navigator.credentials.create({
        publicKey: options,
      });

      const transports =
        typeof credential.response.getTransports === "function"
          ? credential.response.getTransports()
          : [];

      // Step 3: send the new credential to the server to store.
      const completeResponse = await fetch(completeUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-CSRFToken": csrfToken,
        },
        body: JSON.stringify({
          label: document.getElementById("passkey_label").value,
          transports: transports,
          credential: {
            id: credential.id,
            rawId: fromBuffer(credential.rawId),
            type: credential.type,
            response: {
              clientDataJSON: fromBuffer(credential.response.clientDataJSON),
              attestationObject: fromBuffer(
                credential.response.attestationObject,
              ),
            },
          },
        }),
      });

      if (!completeResponse.ok) {
        throw new Error("Fingerprint enrollment failed.");
      }

      window.location.reload();
    } catch (error) {
      if (error && error.name === "NotAllowedError") {
        showPasskeyStatus(
          errorBox,
          "Fingerprint setup was cancelled or timed out. Try again.",
          "info",
        );
      } else {
        showPasskeyStatus(
          errorBox,
          "Fingerprint enrollment failed. Please try again.",
          "error",
        );
      }
    } finally {
      enrollButton.disabled = false;
    }
  });
}
