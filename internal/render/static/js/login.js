window.addEventListener('load', function() {
    const passkeyButton = document.getElementById('passkey-login-button');

    passkeyButton.addEventListener('click', function() {
        handleDiscoverLogin();
    });
});
