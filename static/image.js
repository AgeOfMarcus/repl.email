function upload_image(image, callback) {
    var formdata = new FormData();
    formdata.append('image', image);

    $.ajax({
        url: 'https://i.marcusj.tech/api/upload',
        data: formdata,
        type: 'post',
        processData: false,
        contentType: false,
        success: (data, res) => {
            callback(data.url);
        }
    })
}