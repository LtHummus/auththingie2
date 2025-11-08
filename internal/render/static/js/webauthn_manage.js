window.addEventListener('load', function() {
    const passkeyButton = document.getElementById('passkey-enroll-button');

    passkeyButton.addEventListener('click', function() {
        beginRegistration();
    });
});
