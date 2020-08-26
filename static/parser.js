const parser = 3;

function uuidv4() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

const expressions = {
    'date': () => {
        var d = new Date();
        var parts = d.toString().split(' ');
        return [parts[0], parts[1], parts[2], parts[3]].join(' ');
    },
    'time': () => {
        return (new Date()).toString().split(' ')[4];
    },
    'js': (script) => {
        var u = uuidv4();
        var s = '<span id="' + u + '"></span>';
        var j = '<script>document.getElementById("' + u + '").innerHTML = eval(`' + script + '`)</script>';
        return s + j;
    },
    'gist': (g) => {
        return `<script src="https://gist.github.com/${g}.js"></script>`;
    },
    'repl': (r) => {
        return `<iframe height="400px" width="100%" src="https://repl.it/@${r}?lite=true" scrolling="no" frameborder="no" allowtransparency="true" allowfullscreen="true" sandbox="allow-forms allow-pointer-lock allow-popups allow-same-origin allow-scripts allow-modals"></iframe>`
    },
}

function parse(text) {
    var re = text.matchAll(/\{\{ (.*?) \}\}/g);
    var match = re.next();

    while (!match.done) {
        var exp = match.value[1];
        var rep = match.value[0];

        if (exp.includes('|')) {
            var parts = exp.split('|');
            if (parts[0] in expressions) {
                text = text.split(rep).join(expressions[parts[0]](parts[1]))
            }
        } else if (exp in expressions) {
            text = text.split(rep).join(expressions[exp]())
        }

        match = re.next();
    }

    return text;
}