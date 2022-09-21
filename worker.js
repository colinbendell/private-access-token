const CHALLENGE = "AAIAHmRlbW8tcGF0Lmlzc3Vlci5jbG91ZGZsYXJlLmNvbQAAACVwcml2YXRlLWFjY2Vzcy10b2tlbi5jb2xpbmJlbmRlbGwuZGV2";
const TOKEN_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAm6JetF74YBtERLPcIcqd5545MmIky5yVFiGXPPt28Ddn_5bPWvNxpB6AHrsr3Yn2ex6seGsW0B12M0HqPgvRaiWeAv3jiV52ikdfoHYdBxJBe-ykvjE-hktUXZ6KHk8A87hfoSMNOiB9Upm_TmRaVR_dybG2yXuF8hm6C5N6BZ8nNm9af4DETtDMeJFCUI_bLwoYfzI__YSzYIgeA3ywwdECUDy98u_t9Rc5tO27omB61d4akr6YetiRsJnoAd-muzM-IW12V-1oEbZAjT5AcfHlzpaVu-0o4TL8RhwLxobv9mRCjNjuOvEFau-ATaw8VlJv1_nhfyyu96kV3JQ__wIDAQAB";
const WWW_AUTHENTICATE = `PrivateToken challenge=${CHALLENGE}, token-key=${TOKEN_KEY}, max-age=60`

async function handleRequest(request) {
  if (!request.url.includes('/test.html')) {
    return fetch(request);
  }

  const auth = request.headers.get("Authorization");
  if (auth) {
    return new Response(`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset='utf-8'>
    <meta http-equiv='X-UA-Compatible' content='IE=edge'>
    <title>PASS: Private Acccess Token Test</title>
    <meta name='viewport' content='width=device-width, initial-scale=1'>
</head>
<body>
<h1>👍 Public Access Token Works!</h1>
Authorization: ${auth}
</body>
</html>`, {
      headers: {
        'Content-Type': `text/html`
      }
    });
  }

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
      'WWW-Authenticate': WWW_AUTHENTICATE,
    },
  });

  return resp;
}

addEventListener('fetch', event => {
  event.respondWith(handleRequest(event.request));
});