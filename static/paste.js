function create_paste(content, password, callback) {
    $.ajax({
        url: 'https://paste.marcusj.tech/api/create',
        type: 'post',
        data: JSON.stringify({
            'content': content,
            'password': password,
        }),
        contentType: 'application/json',
        success: callback
    })
}

function get_paste(uid, password, callback) {
    $.ajax({
        url: 'https://paste.marcusj.tech/api/get',
        type: 'post',
        data: JSON.stringify({
            'uid': uid,
            'password': password,
        }),
        contentType: 'application/json',
        success: callback
    })
}