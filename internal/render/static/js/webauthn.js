async function beginRegistration() {
    setEnrollButtonLoading();
    const response = await fetch("/webauthn/register", {
        method: "POST"
    });
    const params = await response.json();

    if (params.failed) {
        showWebauthnEnrollError(params.message);
        resetEnrollButton();
        return;
    }

    let credFinished;

    try {
        credFinished = await navigator.credentials.create({publicKey: parseCreationOptions(params.publicKey)});
    } catch (e) {
        console.log(e);
        showWebauthnEnrollError('User cancelled or Passkeys not available');
        resetEnrollButton();
        return;
    }

    if (!credFinished) {
        showWebauthnEnrollError('User cancelled or Passkeys not available');
        resetEnrollButton();
        return;
    }

    const payload = credentialToJSON(credFinished);

    let responseJSON;
    try {
        const createResponse = await fetch("/webauthn/finishregister", {
            method:"POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        responseJSON = await createResponse.json();
    } catch (e) {
        console.log(e);
        showWebauthnEnrollError('Could not complete passkey registration');
        resetEnrollButton();
        return;
    }

    if (responseJSON.failed) {
        showWebauthnEnrollError(responseJSON.message);
        resetEnrollButton();
        return;
    }

    location.reload();
}

function setEnrollButtonLoading() {
    document.getElementById('enroll_error').style.display = 'none';
    const elem = document.getElementById('passkey-enroll-button');
    elem.setAttribute('aria-busy', 'true');
    elem.innerText = 'Waiting for user response...';
}

function showWebauthnEnrollError(msg) {
    const elem = document.getElementById('enroll_error');
    elem.innerText = msg;
    elem.style.display = 'block';
}

function resetEnrollButton() {
    const elem = document.getElementById('passkey-enroll-button');
    elem.setAttribute('aria-busy', 'false');
    elem.innerText = 'Enroll new key';
}

function setLoginButtonLoading() {
    const elem = document.getElementById('passkey-login-button');
    elem.setAttribute('aria-busy', 'true');
    elem.innerHTML = 'Waiting for user response...';
}

function resetLoginButton() {
    const elem = document.getElementById('passkey-login-button');
    elem.setAttribute('aria-busy', 'false');
    elem.innerHTML = '<img src="/static/images/fido-passkey-white.svg" alt="Passkey Logo" class="passkey-logo" />Login with Passkey';
}

function showWebAuthnLoginError(msg) {
    const elem = document.getElementById('authn_login_error');
    elem.innerText = msg;
    elem.style.display = 'block';
}

function hideWebAuthnError() {
    const elem = document.getElementById('authn_login_error');
    elem.style.display = 'none';
}

let conditionalLoginAbortController = null;

async function startConditionalLogin() {
    if (!window.PublicKeyCredential?.isConditionalMediationAvailable) {
        return;
    }

    if (!(await PublicKeyCredential.isConditionalMediationAvailable())) {
        return;
    }

    conditionalLoginAbortController = new AbortController();
    const signal = conditionalLoginAbortController.signal;
    const error = await doDiscoverLogin({mediation: 'conditional', signal: signal});
    if (error && !signal.aborted) {
        showWebAuthnLoginError(error);
    }
}

function abortConditionalLogin() {
    conditionalLoginAbortController?.abort();
    conditionalLoginAbortController = null;
}

async function handleDiscoverLoginButton() {
    hideWebAuthnError();
    setLoginButtonLoading();
    const error = await doDiscoverLogin({});
    if (error) {
        showWebAuthnLoginError(error);
        resetLoginButton();
    }
}

async function doDiscoverLogin(credentialOptions) {
    let params;
    try {
        const response = await fetch("/webauthn/discover", {
            method: "POST",
            signal: credentialOptions.signal
        })
        params = await response.json();
    } catch (e) {
        console.log(e);
        return 'Could not get WebAuthn challenge';
    }

    if (credentialOptions.signal?.aborted) {
        return null;
    }

    if (params.failed) {
        return params.message;
    }

    let credFinished;
    try {
        credFinished = await navigator.credentials.get({
            ...params,
            ...credentialOptions,
            publicKey: parseRequestOptions(params.publicKey)
        });
    } catch (e) {
        console.log(e);
    }
    if (!credFinished) {
        return 'User cancelled login or Passkeys not available';
    }

    const payload = credentialToJSON(credFinished);

    let respJSON;
    try {
        const loginResponse = await fetch("/webauthn/finishdiscover", {
            method:"POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(payload)
        });

        respJSON = await loginResponse.json();
        if (respJSON.failed) {
            return respJSON.message;
        }
    } catch (e) {
        console.log(e);
        return 'Could not handle login finish';
    }

    let nextPage = document.getElementById('passkey-login-button').dataset.redirectUri || location.origin;
    if (respJSON.admin_messages) {
        nextPage = location.origin + "/admin/notices?redirect_uri=" + encodeURIComponent(document.getElementById('passkey-login-button').dataset.redirectUri)
    }

    window.location.href = nextPage;
    return null;
}

// Of course browsers now have nice convenience functions for building and parsing creation and request options...
// use those if they exist or fallback to my old base64 shuffling if they don't

function parseCreationOptions(publicKey) {
    if (typeof PublicKeyCredential.parseCreationOptionsFromJSON === 'function') {
        return PublicKeyCredential.parseCreationOptionsFromJSON(publicKey);
    }

    return {
        ...publicKey,
        challenge: base64ToArrayBuffer(publicKey.challenge),
        user: {...publicKey.user, id: base64ToArrayBuffer(publicKey.user.id)},
        excludeCredentials: publicKey.excludeCredentials?.map((x) => ({...x, id: base64ToArrayBuffer(x.id)}))
    };
}

function parseRequestOptions(publicKey) {
    if (typeof PublicKeyCredential.parseRequestOptionsFromJSON === 'function') {
        return PublicKeyCredential.parseRequestOptionsFromJSON(publicKey);
    }

    return {
        ...publicKey,
        challenge: base64ToArrayBuffer(publicKey.challenge),
        allowCredentials: publicKey.allowCredentials?.map((x) => ({...x, id: base64ToArrayBuffer(x.id)}))
    };
}

function credentialToJSON(cred) {
    if (typeof cred.toJSON === 'function') {
        return cred.toJSON();
    }

    let response;
    if (cred.response.attestationObject) {
        response = {
            attestationObject: arrayBufferToBase64(cred.response.attestationObject),
            clientDataJSON: arrayBufferToBase64(cred.response.clientDataJSON),
            transports: cred.response.getTransports?.() ?? []
        };
    } else {
        response = {
            authenticatorData: arrayBufferToBase64(cred.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64(cred.response.clientDataJSON),
            signature: arrayBufferToBase64(cred.response.signature),
            userHandle: arrayBufferToBase64(cred.response.userHandle)
        };
    }

    return {
        authenticatorAttachment: cred.authenticatorAttachment,
        id: cred.id,
        rawId: arrayBufferToBase64(cred.rawId),
        response: response,
        type: cred.type
    };
}

function patchBase64(input) {
    return input.replace(/-/g, '+').replace(/_/g, '/')
}

function base64ToArrayBuffer(base64) {
    const binaryString = atob(patchBase64(base64));
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes.buffer;
}

function arrayBufferToBase64( buffer ) {
    let binary = '';
    const bytes = new Uint8Array( buffer );
    const len = bytes.byteLength;
    for (let i = 0; i < len; i++) {
        binary += String.fromCharCode( bytes[ i ] );
    }
    return unpatchBase64(window.btoa( binary ));
}

function unpatchBase64(input) {
    return input.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
}