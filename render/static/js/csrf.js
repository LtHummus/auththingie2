
window.addEventListener('load', function () {
    document.body.addEventListener('cycle_csrf', function (evt) {
        console.log(evt.detail);
        console.log(evt.detail.value);

        Array.from(document.getElementsByTagName('input'))
            .filter(t => t.name === 'csrf_token' || t.name === 'csrf-token')
            .forEach(c => {
                c.setAttribute('value', evt.detail.value);
        });
    });
});

