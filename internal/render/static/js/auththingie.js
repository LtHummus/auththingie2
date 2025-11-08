document.body.addEventListener('htmx:beforeOnLoad', function (e) {
    if (e.detail.xhr.status === 422) {
        e.detail.shouldSwap = true;
        e.detail.isError = false;
    }
});

function clearWebauthnError() {
    const modifyErrorElem = document.getElementById('modify-error');
    modifyErrorElem.classList = "no-error";
}

function clearTagError() {
    const tagErrorElem = document.getElementById('tag-error');
    tagErrorElem.classList = "no-error";
}
