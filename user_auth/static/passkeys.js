"use strict";

function decode(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(base64), c => c.charCodeAt(0));
}

function encode(buffer) {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function post(url, body) {
  const response = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": document.querySelector('meta[name="csrf-token"]').content
    },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const data = response.headers.get("content-type")?.includes("application/json")
      ? await response.json() : null;
    throw new Error(data?.error || `Request failed (${response.status}). Log in again or retry.`);
  }
  return response.json();
}

document.querySelectorAll("[data-passkey]").forEach(button => {
  button.addEventListener("click", async () => {
    const message = document.getElementById("passkey-error");
    message.textContent = "";
    button.disabled = true;
    try {
      if (!window.PublicKeyCredential || !window.isSecureContext) {
        throw new Error("Passkeys require a supported browser and HTTPS (or localhost).");
      }
      const ceremony = await post(button.dataset.options, {});
      const options = ceremony.options;
      options.challenge = decode(options.challenge);
      const registering = button.dataset.passkey === "register";
      if (registering) {
        options.user.id = decode(options.user.id);
        options.excludeCredentials?.forEach(item => { item.id = decode(item.id); });
      } else {
        options.allowCredentials?.forEach(item => { item.id = decode(item.id); });
      }
      const credential = registering
        ? await navigator.credentials.create({publicKey: options})
        : await navigator.credentials.get({publicKey: options});
      if (!credential) throw new Error("The passkey ceremony was cancelled.");
      const response = credential.response;
      const payload = {
        id: credential.id, rawId: encode(credential.rawId),
        type: credential.type,
        response: {clientDataJSON: encode(response.clientDataJSON)}
      };
      if (registering) {
        payload.response.attestationObject = encode(response.attestationObject);
      } else {
        payload.response.authenticatorData = encode(response.authenticatorData);
        payload.response.signature = encode(response.signature);
        payload.response.userHandle = response.userHandle ? encode(response.userHandle) : null;
      }
      const result = await post(button.dataset.complete, {
        challenge_id: ceremony.challenge_id, credential: payload,
        name: registering ? document.getElementById("passkey-name").value : ""
      });
      window.location.assign(result.redirect);
    } catch (error) {
      message.textContent = error.name === "NotAllowedError"
        ? "Passkey cancelled or unavailable. Try again." : error.message;
    } finally {
      button.disabled = false;
    }
  });
});
