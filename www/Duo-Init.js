Duo.init({
    'host': document.getElementById("duo_host").value,
    'post_action':'getduo.php?StateId=' + document.getElementById("StateId").value,
    'sig_request': document.getElementById("duo_sig_request").value,
});
