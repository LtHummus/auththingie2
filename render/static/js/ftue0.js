window.addEventListener('load', function() {
    const button1 = document.getElementById('slash-config-radio');
    const button2 = document.getElementById('cwd-radio');
    const button3 = document.getElementById('custom-radio');

    [button1, button2, button3].forEach(function(x) {
        x.addEventListener('click', function () {
            showCustomFields();
        });
    });
});
