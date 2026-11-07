/* ===== Fingerprint helpers =====
   The browser's WebAuthn API speaks binary, but JSON speaks text.
   These first two functions convert between the two worlds. */

export function toBuffer(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = window.atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes.buffer;
}

export function fromBuffer(buffer) {
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
export function passkeyUnavailableReason(featureName) {
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
export function showPasskeyStatus(element, message, tone) {
  const isError = tone === "error";
  element.textContent = message;
  element.classList.remove("d-none", "theme-info", "theme-danger");
  element.classList.add(isError ? "theme-danger" : "theme-info");
  element.setAttribute("role", isError ? "alert" : "status");
  element.setAttribute("aria-live", isError ? "assertive" : "polite");
}

/** Hide the status message again. */
export function clearPasskeyStatus(element) {
  if (!element) return;
  element.textContent = "";
  element.classList.add("d-none");
}

// for login_checkin_using_fingerprint.js
/** Turn the server's login challenge into buffers the browser understands. */
export function prepareAssertionOptions(options) {
  options.challenge = toBuffer(options.challenge);
  (options.allowCredentials || []).forEach(function (credential) {
    credential.id = toBuffer(credential.id);
  });
  return options;
}

/** Turn the browser's fingerprint scan into JSON we can post to the server. */
export function serializeAssertion(assertion) {
  return {
    id: assertion.id,
    rawId: fromBuffer(assertion.rawId),
    type: assertion.type,
    response: {
      clientDataJSON: fromBuffer(assertion.response.clientDataJSON),
      authenticatorData: fromBuffer(assertion.response.authenticatorData),
      signature: fromBuffer(assertion.response.signature),
      userHandle: assertion.response.userHandle
        ? fromBuffer(assertion.response.userHandle)
        : null,
    },
  };
}
