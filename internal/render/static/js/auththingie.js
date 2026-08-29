function clearWebauthnError() {
    const modifyErrorElem = document.getElementById('modify-error');
    modifyErrorElem.classList = "no-error";
}

function clearTagError() {
    const tagErrorElem = document.getElementById('tag-error');
    tagErrorElem.classList = "no-error";
}
