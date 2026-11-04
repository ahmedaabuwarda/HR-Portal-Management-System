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

/* ===== Fingerprint helpers =====
   The browser's WebAuthn API speaks binary, but JSON speaks text.
   These first two functions convert between the two worlds. */

function toBuffer(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

function fromBuffer(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";

  bytes.forEach(function (byte) {
    binary += String.fromCharCode(byte);
  });

  return window
    .btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/** Why fingerprints can't be used right now — or null when they can. */
function passkeyUnavailableReason(featureName) {
  const label = featureName || "Fingerprint login";

  if (window.isSecureContext === false) {
    return featureName
      ? label +
          " requires a secure connection. Open this site over HTTPS or localhost."
      : "Fingerprint login requires a secure connection. Open this site over HTTPS or localhost.";
  }

  if (!window.PublicKeyCredential) {
    return featureName
      ? label +
          " is not supported in this browser. Try Chrome, Edge, or Safari."
      : "This browser does not support fingerprint login. Try Chrome, Edge, or Safari.";
  }

  return null;
}

/** Show a small status message next to a fingerprint button. */
function showPasskeyStatus(element, message, tone) {
  const isError = tone === "error";
  element.textContent = message;
  element.classList.remove("d-none", "theme-info", "theme-danger");
  element.classList.add(isError ? "theme-danger" : "theme-info");
  element.setAttribute("role", isError ? "alert" : "status");
  element.setAttribute("aria-live", isError ? "assertive" : "polite");
}

/** Hide the status message again. */
function clearPasskeyStatus(element) {
  element.textContent = "";
  element.classList.add("d-none");
}
