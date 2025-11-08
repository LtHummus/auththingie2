const showCustomFields = function() {
    if (document.getElementById('custom-radio').checked) {
        document.getElementById('custom-path-fields').style.display = 'block';
    } else {
        document.getElementById('custom-path-fields').style.display = 'none';
    }
}