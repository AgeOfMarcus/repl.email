function doPOST(url, data, outfunc) {
    var xmlhttp = new XMLHttpRequest();

    xmlhttp.onreadystatechange = function() {
        if (this.readyState == 4 && this.status == 200) {
            try {
                var res = JSON.parse(this.responseText);
                if (outfunc === "return") {
                    return res;
                }
                else {
                    outfunc(res);
                }
            }
            catch(err) {
                if (outfunc === "return") {
                    return this.responseText;
                }
                else {
                    outfunc(this.responseText);
                }
            }
        }
    }
    xmlhttp.open("POST", url, false);
    xmlhttp.setRequestHeader("Content-Type", "application/json");
    xmlhttp.send(JSON.stringify(data));
}