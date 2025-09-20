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

    console.log(params);
    params.publicKey.challenge = base64ToArrayBuffer(params.publicKey.challenge);
    params.publicKey.user.id = base64ToArrayBuffer(params.publicKey.user.id);

    // TODO: investigate why this doesn't actually seem to have an effect -- do we need more than just type and id here?
    if (params.publicKey.excludeCredentials) {
        params.publicKey.excludeCredentials = params.publicKey.excludeCredentials.map((x) => {
            return {
                type: x.type,
                id: base64ToArrayBuffer(x.id)
            }
        })
    }

    console.log(params);

    let credFinished;

    try {
        credFinished = await navigator.credentials.create({publicKey: params.publicKey});
    } catch (e) {
        showWebauthnEnrollError('User cancelled or Passkeys not available');
        resetEnrollButton();
        return;
    }

    if (!credFinished) {
        showWebauthnEnrollError('User cancelled or Passkeys not available');
        resetEnrollButton();
        return;
    }

    const payload = {
        authenticatorAttachment: credFinished.authenticatorAttachment,
        id: credFinished.id,
        rawId: arrayBufferToBase64(credFinished.rawId),
        response: {
            attestationObject: arrayBufferToBase64(credFinished.response.attestationObject),
            clientDataJSON: arrayBufferToBase64(credFinished.response.clientDataJSON)
        },
        type: credFinished.type
    }

    const createResponse = await fetch("/webauthn/finishregister", {
        method:"POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    const responseJSON = await createResponse.json();

    if (responseJSON.failed) {
        showWebauthnEnrollError(params.message);
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

async function handleDiscoverLogin() {
    hideWebAuthnError();
    setLoginButtonLoading();
    const response = await fetch("/webauthn/discover", {
        method: "POST"
    })
    const params = await response.json();

    if (params.failed) {
        showWebAuthnLoginError(params.message);
        resetLoginButton();
        return;
    }

    params.publicKey.challenge = base64ToArrayBuffer(params.publicKey.challenge);

    let credFinished;
    try {
        credFinished = await navigator.credentials.get(params);
        if (!credFinished) {
            showWebAuthnLoginError('User cancelled login or Passkeys not available');
            resetLoginButton();
            return;
        }
    } catch (e) {
        console.log(e);
        showWebAuthnLoginError('User cancelled login or Passkeys not available')
        resetLoginButton();
        return;
    }


    const payload = {
        authenticatorAttachment: credFinished.authenticatorAttachment,
        id: credFinished.id,
        rawId: arrayBufferToBase64(credFinished.rawId),
        response: {
            authenticatorData: arrayBufferToBase64(credFinished.response.authenticatorData),
            clientDataJSON: arrayBufferToBase64(credFinished.response.clientDataJSON),
            signature: arrayBufferToBase64(credFinished.response.signature),
            userHandle: arrayBufferToBase64(credFinished.response.userHandle)
        },
        type: credFinished.type
    }

    const loginResponse = await fetch("/webauthn/finishdiscover", {
        method:"POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify(payload)
    });

    const respJSON = await loginResponse.json();
    if (respJSON.failed) {
        showWebAuthnLoginError(respJSON.message);
        resetLoginButton();
        return;
    }

    let nextPage = location.origin; // this is a hack, will this always work?
    const searchParams = new URL(document.location).searchParams;
    if (searchParams.has('redirect_uri')) {
        nextPage = searchParams.get('redirect_uri');
    }

    window.location.href = nextPage;
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