const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAyKs0fkdzX-NVyob2xCfNi8DTewBG2MQLWM7UmHBXsz4StmTS_HnC-FKi6_YV531KDz1WxzdSVtZ8eUpg7ISzl7yRfp3Ti8jRVaNUd4fiHuL_QtLnAUr-PPUitTM2homTwHYiSlJxy4x_WSjx64rkWGEAmb58mJaXTueTn8HjecQ4mIafIlquNWL-jUK7o_d5pwdETFwHzOWlgWNLMnjrLth2djLJlGsgBIzudFgf-JdhDdDIuIPju3Q02WCoE1d4VrMzJtRNpnigbQsg6Xy18bcwY7Z8msp11pGkMy1qKBtV3VeD9G_wVRyaSHTen6J9-HBeCIeSe1HOJqhal2TReQIDAQAB";
const CHALLENGE = "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=";
// const CHALLENGE_PREFIX = "AAIAHmRlbW8tcGF0Lmlzc3Vlci5jbG91ZGZsYXJlLmNvbSA"; // select cloudflare as origin
// const CHALLENGE_SUFFIX = "AAlcHJpdmF0ZS1hY2Nlc3MtdG9rZW4uY29saW5iZW5kZWxsLmRldg=="; // specify private-acccess-token.colinbendell.dev as origin

async function handleRequest(request) {
  if (!request.url.includes("/test.html")) {
    return fetch(request);
  }

  const query = request.url.split("?")[1];
  const challenge = query?.split("challenge=")[1]?.split("&")[0] || encodeURI(CHALLENGE);
  //   const nonce = btoa(crypto.getRandomValues(new Uint16Array(33))).substring(1,43); // 31bytes (even though it should be 32)
  //   const challenge = `${CHALLENGE_PREFIX}${nonce}${CHALLENGE_SUFFIX}`;

  const publicKey = query?.split("key=")[1]?.split("&")[0] || encodeURI(CLOUDFLARE_PUB_KEY);
  const tokenParam = query?.split("token=")[1]?.split("&")[0];
  const tokenHeader = request.headers.get("Authorization")?.split("PrivateToken token=")[1];

  const token = encodeURI(tokenHeader||"") || tokenParam;
  const respInit = token
    ? { headers: { "Content-Type": `text/html` } }
    : {
        status: 401,
        headers: {
          "Content-Type": `text/html`,
          "WWW-Authenticate": `PrivateToken challenge=${decodeURIComponent(challenge)}, token-key=${decodeURIComponent(publicKey)}`,
        },
      };
  return new Response(
    `<!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset='utf-8'>
        <meta http-equiv='X-UA-Compatible' content='IE=edge'>
        <title>Private Acccess Token Test</title>
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

            @media only screen and (min-device-width: 500px) and (-webkit-device-pixel-ratio: 2) {
                html {
                    font-size: 1.25rem;
                }
            }
            html {
                max-width: 58ch;
                margin: auto;
                line-height: 1.75;
                /* font-size: 1.25rem; */
            }
            p,ul,ol {
                margin-bottom: 2em;
                color: #1d1d1d;
                font-family: -apple-system, system-ui, sans-serif;
            }
            h1 {
                line-height: 1;
                padding-bottom: 0.6rem;
            }
            a[href]:hover {
                background-color: #f2f2f2;
            }
            a[href] {
                color: #22e;
                text-decoration: none;
            }

            select, code {
                display: block;
            }

            code {
                border: 1px solid #eee;
                overflow-wrap: anywhere;
                margin: 0;
            }
            code + code {
                margin-top: 1em;
            }

            tt, code, pre {
                background-color: #f9f9f9;
                font-family: 'Roboto Mono', monospace;
            }
            .grid {
                display: grid;
                grid-template-columns: repeat(1, 2fr 1fr);
                grid-column-gap: 0.5rem;
            }
            .grid input {
                margin-bottom: auto;
                line-height: 1rem;
            }
            .grid.code {
                border: 1px solid #eee;
                background-color: #f9f9f9;
                grid-template-columns: repeat(1, 1fr 4fr);
                grid-column: span 2 / auto;
                margin-bottom: 0.5rem;
                padding: 0.5rem;
            }

            details {
                margin-left: 1.75rem;
            }
            details summary::-webkit-details-marker {
                display:none;
            }
            details summary::marker {
                display:none;
                content:"";
            }
            details summary {
                cursor: pointer;
            }
            details:not([open]) > summary:has(+ *):after {
                content: "᠁";
                display: block;
                margin-top: -0.5rem;
                margin-left: -0.25rem;
                margin-bottom: -0.5rem;
            }
            details > summary:before {
                margin-left: -1.75rem;
                color: initial;
                line-height: 1;
                font-size: 1.1rem;
                content: "❌";
            }
            details.pass > summary:before {
                content: "✅";
            }
            details.unknown > summary:before {
                content: "❓";
            }
            #token_valid_test:not(.unknown) > code {
                display: none;
            }
            details summary {
                color: darkgray;
            }
            details summary span {
                color: black;
            }
            details code {
                font-size: 0.75rem;
            }

            #www-authenticate.grid.code {
                grid-template-columns: repeat(1, 2fr 5fr);
                display: none;
            }
            h2 {
                margin: -0.6rem 0 0.6rem 0;
                font-weight: 100;
                font-size: 1rem;
            }
            h2.auth-header {
                display: block;
            }
        </style>
        <script>
        // host to network long
        function htonl(n) {
            return [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
        }

        // host to network short
        function htons(n) {
            return [(n >> 8) & 0xff, n & 0xff];
        }

        // network to host long
        function ntohl(n) {
            return (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];
        }

        // network to host short
        function ntohs(n) {
            return (n[0] << 8) + n[1];
        }
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
            return btoa(data).replaceAll('+', '-').replace('/', '_')
        }
        function base64urlDecode(data) {
            try {
                return atob(decodeURIComponent(data)?.replace(/-/g, '+')?.replace(/_/g, '/'))
            }
            catch {

            }
            return ""
        }

        function debugHex(name, value = []) {
            // hex encode
            // document.getElementById(name).innerHTML = "[" + value.map(v => v.toString(16).padStart(2, '0')).join(", ") + "]";

            // keep decimal encode - because humans
            document.getElementById(name).innerHTML = JSON.stringify(value).replaceAll(",", ", ");
        }

        function debugBool(name, value) {
            const status = value === null ? 'unknown' : (value ? 'pass' : 'fail')
            console.log(name, ":", status)
            document.getElementById(name + "_test").className = status;
        }

        function hexToByte(s) {
            return s?.replaceAll(/[^0-9a-z]/gi, '0')?.match(/.{1,2}/g)?.map(a => parseInt(a, 16));
        }

        function b642ab(base64_string){
            return Uint8Array.from(base64urlDecode(base64_string), c => c.charCodeAt(0));
        }

        function compareArray(a, b) {
            return a.toString() === b.toString();
        }
        async function parseToken() {
            let token = getElement("token");
            const binToken = str2bin(base64urlDecode(token.replaceAll(/^"|"$/g, ""))) || [];

            const tests = [];

            let {version, brand} = navigator.userAgentData?.brands[0] || {};
            if (!brand && !version) {
                [,version, brand] = /Version[/]((?:1[6-9]|[2-9])[.0-9]+) .*(Safari Mobile|Safari)/.exec(navigator.userAgent) || [];
            }
            if (!brand && !version) {
                [,brand, version] = /(Firefox)[/]([0-9]+)/.exec(navigator.userAgent) || [];
            }
            const ua = brand + " " + version;
            tests.push([
                "Browser supports PAT (Safari 16+)",
                /AppleWebKit[/][0-9.]+ [(]KHTML, like Gecko[)] Version[/](1[6-9]|[2-9])[.0-9]+ .*Safari[/][0-9.]+/.test(navigator.userAgent),
                " == " + ua
            ]);

            tests.push([
                "PrivateToken token= present",
                binToken.length > 0,
                '<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-09.html#name-token-redemption" style="vertical-align: super; font-size: 0.75rem;">ⓘ</a>',
                binToken
            ]);
            document.title = (binToken.length > 0 ? "PASS:" : "FAIL:") + " Private Access Token Test";

            tests.push([
                'token is "quoted"',
                /^[^="]+$|^"[^"=]+=*"$|^[^="]+$/.test(token),
                /=/.test(token) ? " (required with base64url() '=' padding)" : '',
            ]);

            const tokenType = ntohs(binToken.slice(0,2));
            tests.push([
                'token_type == 0x0002',
                tokenType === 2,
                '<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-06.html#section-8.1" style="vertical-align: super; font-size: 0.75rem;">ⓘ</a>',
                htons(tokenType),
            ]);

            const nonce = binToken.slice(2,34);
            tests.push([
                'nonce .length() ==256',
                nonce.length === 32,
                '<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-09.html#section-2.2-4.2" style="vertical-align: super; font-size: 0.75rem;">ⓘ</a>',
                nonce
            ]);

            const challenge = binToken.slice(34,66);
            const expectedChallengeBytes = str2bin(base64urlDecode(getElement("challenge").replaceAll('"', '')));
            const expectedChallenge = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from(expectedChallengeBytes))));

            tests.push([
                'challenge_digest == sha256(challenge)',
                compareArray(expectedChallenge, challenge),
                '<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-09.html#section-2.2-4.3" style="vertical-align: super; font-size: 0.75rem;">ⓘ</a>',
                challenge,
            ]);

            const tokenKeyID = binToken.slice(66,98);
            tests.push([
                'token_key_id .length()==32',
                tokenKeyID.length === 32,
                '<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-09.html#section-2.2-4.4" style="vertical-align: super; font-size: 0.75rem;">ⓘ</a>',
                tokenKeyID,
            ]);

            const authenticator = binToken.slice(98);
            tests.push([
                'authenticator .length()==256',
                authenticator.length === 256,
                '<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-auth-scheme-09.html#section-2.2-4.4" style="vertical-align: super; font-size: 0.75rem;">ⓘ</a>',
                authenticator,
            ]);

            // sadly WebCrypto support for rsa-pss on Chrome/WebKit is missing. Works on Firefox
            let valid = null;
            try {
                const data = Uint8Array.from(binToken.slice(0,98));
                const signature = Uint8Array.from(binToken.slice(98));

                // const legacyTokenKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAi7t2SG_6S5PbMQR2JYv4jCtH11wPase-oVbgIe4uYk_ZDeXa84Qrsy8bmaPZ_fO14Qzhy6mW5Vnxy12K0YdZ89sfkbgVAyRsVyU5s-i3m-uXdvG_W9Njas2xE8qx-YAWcc2wa5Z7Q3mS4DhflgiF8zP1qweXF0DRhhIO72R-4lLYBXzdNTK703YL24j7dmjh7hC7QBfKFA6pYeEti-K3IMVEXQwYKiK68LziIZW9_GiYJaEmYT0FMNuqcKD_1oPngnNNiBiNjrbpC9MRI7D1w0R4pQmY44XZVTqL-qTiQPfFtfU7fCgvvssqnemhz4qvYgIzsoD1nYWWaqO56xWJPwIDAQAB"
                // const legacyPublicKey = await crypto.subtle.importKey("spki", b642ab(legacyTokenKey), { name: "RSA-PSS", hash: "SHA-256" }, false, ["verify"]);
                // valid = await crypto.subtle.verify({name:"RSA-PSS", saltLength: 32},  legacyPublicKey, signature, data);

                const tokenKey = getElement("token-key").replaceAll('"', '');
                const publicKey = await crypto.subtle.importKey("spki", b642ab(tokenKey), { name: "RSA-PSS", hash: "SHA-384" }, false, ["verify"])
                valid = await crypto.subtle.verify({name:"RSA-PSS", saltLength: 48},  publicKey, signature, data);
            }
            catch (e) {
                console.error(e);
            }

            tests.push([
                "RSA-Verify(token[0-98], publicKey, authenticator)",
                valid,
                '<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-06.html#name-token-verification-2" style="vertical-align: super; font-size: 0.75rem;">ⓘ</a>',
                '<em>NB: Safari, Chrome and Cloudflare Workers do not support <a href="https://github.com/w3c/webcrypto/issues/307">oid=RSARSS-PSS in WebCrypto.validate()</a></em>',
                true
            ]);

            let output = "";
            for (const [name, result, value, longValue, open] of tests) {
                const code = longValue ? "<code>" + (JSON.stringify(longValue)?.replaceAll(',', ', ').replaceAll('"', '') || "") + "</code>" : "";
                const cssClass = (result === null ? 'unknown' : (result ? 'pass' : 'fail'));
                const detailsOpen = (open ? ' open' : '');
                output += '<details class="' + cssClass + '"' + detailsOpen + '><summary><span> '+ name + '</span>' + (value ?? "") + '</summary>' + code + '</details>';
            }
            document.getElementById('tests').innerHTML = output;
        }

        function init() {
            let token = challenge = publicKey = "";
            const params = new Proxy(new URLSearchParams(window.location.search), { get: (searchParams, prop) => searchParams.get(prop), });
            token = params.token || "${token || ''}";
            document.getElementById('token').value = decodeURIComponent(token);
            challenge = params.challenge || "${challenge || ''}";
            document.getElementById('challenge').value = decodeURIComponent(challenge).replaceAll('"', '');
            publicKey = params["token-key"] || "${publicKey || ''}";
            document.getElementById('token-key').value = decodeURIComponent(publicKey).replaceAll('"', '');

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
        <h1>Public Access Token Test</h1>
        <div  style="vertical-align: super; font-size: 0.75rem; margin: -0.6rem 0 0.6rem 0;">
                [<a href="https://github.com/colinbendell/private-access-token/blob/main/README.md">Notes</a>]
                [<a href="https://github.com/colinbendell/private-access-token">Github Source</a>]
                [<a href="https://www.ietf.org/archive/id/draft-ietf-privacypass-protocol-06.html">IETF Draft</a>]
                [<a href="https://private-access-token.colinbendell.dev">Generate</a>]
                [<a href="https://private-access-token.colinbendell.dev/debug.html">Debug</a>]
                [<a href="https://private-access-token.colinbendell.dev/test.html">UA Test</a>]

        </div>
        <h2 class="${token ? 'auth-header' : ''}">😵😩 No Public-Access-Token for you.</h2>
        <div class="grid code">
            <code style="grid-column: span 2 / auto; margin: 0; border: 0;">Authorization: PrivateToken</code>
            <code style="padding-left: 1rem; margin: 0; border: 0;">token=</code>
            <input id="token" type="text" value="">
        </div>
        <div id="www-authenticate" class="grid code">
            <code style="grid-column: span 2 / auto; margin: 0; border: 0;">WWW-Authenticate: PrivateToken</code>
            <code style="padding-left: 1rem; margin: 0; border: 0;">challenge=</code>
            <input id="challenge" type="text" value="">
            <code style="padding-left: 1rem; margin: 0; border: 0;">token-key=</code>
            <input id="token-key" type="text" value="">
        </div>

        <div id="tests"></div>
    </main>
    </body>
    </html>`,
    respInit
  );
}

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});
