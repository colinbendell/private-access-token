const TOKEN = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAmfx9AB3xGHk6MJhEo4QbUEv2ACjOFB8NV3kUuCSCldhSDKw5MNenDdSJGY8o9e4Zjlt249qJraUsstvhS7_6uKVfnf4-F80uUAnFvBkBQw3AmxoUN62VFZEF8JdQVRLobDD8R6Ck6Om4YSBDJ4Rc_F0_1p-aJXfVxb5MVTDGk7OKO00EDviNRP2an-nx67K8b7SgPyf6soZqgkLRg-IX7vJCMcnBNB7nxnCwAW1Og_AbnFjYUtbEgjcn3QJouFeFtQKMgXTqAJvjvGAaVZTgASucZrVmXRXg-zTKVkSmbl298zqooaz1eBAPy4M4SfQtfx-AiHJMjYYdA2NmzJz0qwIDAQAB";
const CHALLENGE = "AAIAHmRlbW8tcGF0Lmlzc3Vlci5jbG91ZGZsYXJlLmNvbQAAAA==";
const CHALLENGE_PREFIX = "AAIAHmRlbW8tcGF0Lmlzc3Vlci5jbG91ZGZsYXJlLmNvbSA"; // select cloudflare as origin
const CHALLENGE_SUFFIX = "AAlcHJpdmF0ZS1hY2Nlc3MtdG9rZW4uY29saW5iZW5kZWxsLmRldg=="; // specify private-acccess-token.colinbendell.dev as origin
// const WWW_AUTHENTICATE = `PrivateToken challenge=${CHALLENGE}, token-key=${TOKEN}, max-age=60`

async function handleRequest(request) {
  if (!request.url.includes('/test.html')) {
    return fetch(request);
  }

  const auth = request.headers.get("Authorization")?.split('PrivateToken token=')[1];
  if (auth) {
    return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset='utf-8'>
    <meta http-equiv='X-UA-Compatible' content='IE=edge'>
    <title>PASS: Private Acccess Token Test</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
    <style>
        /* Box sizing rules */
        *,
        *::before,
        *::after {
            box-sizing: border-box;
        }

        /* Remove default margin */
        body,
        h1,
        h2,
        h3,
        h4,
        p,
        figure,
        blockquote,
        dl,
        dd {
            margin: 0;
            padding: 0;
            font-family: -apple-system, system-ui, sans-serif;
        }

        /* Remove list styles on ul, ol elements with a list role, which suggests default styling will be removed */
        ul[role="list"],
        ol[role="list"] {
            list-style: none;
        }

        /* Set core root defaults */
        html:focus-within {
            scroll-behavior: smooth;
        }

        /* Set core body defaults */
        body {
            min-height: 100vh;
            text-rendering: optimizeSpeed;
            line-height: 1.5;
        }

        /* A elements that don't have a class get default styles */
        a:not([class]) {
            text-decoration-skip-ink: auto;
        }

        /* Make images easier to work with */
        img,
        picture {
            max-width: 100%;
            display: block;
        }

        /* Inherit fonts for inputs and buttons */
        input,
        button,
        textarea,
        select {
            font: inherit;
        }

        html {
            max-width: 70ch;
            padding: 3em 1em;
            margin: auto;
            line-height: 1.75;
            font-size: 1.25em;
        }
        p,ul,ol {
            margin-bottom: 2em;
            color: #1d1d1d;
            font-family: sans-serif;
        }
        main {
            max-width: 38rem;
            width: 38rem;
            padding: 2rem;
        }
        select, code {
            display: block;
        }

        code {
            font-family: monospace;
        }
    </style>
    <script>
        const CLOUDFLARE_PUB_KEY = "${TOKEN}";

        function getElement(id) {
            return document.getElementById(id).value;
        }

        function bin2str(value = []) {
            return value.map(char => String.fromCharCode(char)).join('');
        }

        function str2bin(data) {
            return data?.split('')?.map(char => char.charCodeAt(0)) || [];
        }

        function base64url(data) {
            return btoa(data).replace(/\\\+/g, '-').replace(/\\\//g, '_')
        }
        function base64urlDecode(data) {
            return atob(data.replace(/-/g, '+').replace(/_/g, '/'))
        }

        function debugHex(name, value = []) {
            // hex encode
            // document.getElementById(name).innerHTML = "[" + value.map(v => v.toString(16).padStart(2, '0')).join(", ") + "]";

            // keep decimal encode - because humans
            document.getElementById(name).innerHTML = JSON.stringify(value).replaceAll(",", ", ");
        }

        function hexToByte(s) {
            return s?.replaceAll(/[^0-9a-z]/gi, '0')?.match(/.{1,2}/g)?.map(a => parseInt(a, 16));
        }

        function b642ab(base64_string){
            return Uint8Array.from(base64urlDecode(base64_string), c => c.charCodeAt(0));
        }


        async function parseToken() {
            const token = getElement("token");
            const binToken = str2bin(base64urlDecode(token))

            const tokenType = binToken.slice(0,2);
            const nonce = binToken.slice(2,34);
            const challenge = binToken.slice(34,66);
            const tokenKeyID = binToken.slice(66,98);
            const authenticator = binToken.slice(98);
            debugHex('token_type_debug', tokenType);
            debugHex('nonce_debug', nonce);
            debugHex('challenge_digest_debug', challenge);
            debugHex('token_key_id_debug', tokenKeyID);
            debugHex('authenticator_debug', authenticator);
            try {
                const publicKey = await crypto.subtle.importKey("spki", b642ab(CLOUDFLARE_PUB_KEY), { name: "RSA-PSS", hash: "SHA-384" }, false, ["verify"])
                const signature = Uint8Array.from(token.slice(0,98))
                const encoded = Uint8Array.from(token.slice(98))
                console.log(await crypto.subtle.verify({name:"RSA-PSS", saltLength: 256},  publicKey, signature, encoded ));
            }
            catch (e) {
                console.error(e);
            }
            return token;
        }

        function init() {
            parseToken();
            document.getElementsByTagName('body')[0].onkeyup = parseToken;
            [...document.getElementsByTagName('input')].forEach(s => s.addEventListener('change', parseToken));
            [...document.getElementsByTagName('input')].forEach(s => s.addEventListener('click', parseToken));
        }

        window.addEventListener('load', init);
    </script>
</head>
<body>
<main>
    <h1>👍 Public Access Token Works!</h1>
    <div>
        <div>
        <label for="token">Token</label>
        <input id="token" type="text" value="${auth}">
        </div>
        <code id="token_debug"></code>
        <label for="token_type_debug">Token Type</label>
        <code id="token_type_debug"></code>
        <label for="nonce_debug">Nonce</label>
        <code id="nonce_debug"></code>
        <label for="challenge_digest_debug">Challenge Digest</label>
        <code id="challenge_digest_debug"></code>
        <label for="token_key_id_debug">Token Key ID</label>
        <code id="token_key_id_debug"></code>
        <label for="authenticator_debug">Authenticator</label>
        <code id="authenticator_debug"></code>
    </div>
</main>
</body>
</html>
`, {
      headers: {
        'Content-Type': `text/html`
      }
    });
  }

  const nonce = btoa(crypto.getRandomValues(new Uint16Array(33))).substring(1,43); // 31bytes (even though it should be 32)
  const challenge = `${CHALLENGE_PREFIX}${nonce}${CHALLENGE_SUFFIX}`;
  const resp = new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset='utf-8'>
    <meta http-equiv='X-UA-Compatible' content='IE=edge'>
    <title>FAIL: Private Acccess Token</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
</head>
<body>
<h1>😵😩 No Public-Access-Token for you.</h1>
</body>
</html>`, {
    status: 401,
    headers: {
      'Content-Type': `text/html`,
      'WWW-Authenticate': `PrivateToken challenge=${challenge}, token-key=${TOKEN}`,
    },
  });

  return resp;
}

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});
