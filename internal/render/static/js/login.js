window.addEventListener('load', function() {
    const passkeyButton = document.getElementById('passkey-login-button');
    if (!passkeyButton) {
        return;
    }

    passkeyButton.addEventListener('click', function() {
        abortConditionalLogin();
        handleDiscoverLoginButton();
    });

    startConditionalLogin();
});
