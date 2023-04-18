const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAvs9E2WtOHukHE4JlkcSimfV97Bu4XmGrVTg9BC-wZU49y0HWBQKs5YvbHxIZmJqWjJ7FVWmmRcr_AFezYdaWw4JszO0DdWVtxEuedcIsAWvjv7KczqNao28n-nQffA4QBBl2jgytBw-wzstRTLnbWRs03f2_SNNj2RPcs5LJ0KeDEoszg9DO2JLqxdaT5xCFqq-_J_eybiEZDs1XU3HxgR3EjTtfBjHy_PgVXFOgvvTitGT_dcU8dtRi9MJmoSBEFseWB5NDiCcmjfnxsuSEFCWk1BzC9jxLkGTweBm6amRGJlR06WyMoOsYAvTJclZJHkr2z_FzA1C5VQkNP6D-jwIDAQAB";
const CHALLENGE = "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=";
// const CHALLENGE_PREFIX = "AAIAHmRlbW8tcGF0Lmlzc3Vlci5jbG91ZGZsYXJlLmNvbSA"; // select cloudflare as origin
// const CHALLENGE_SUFFIX = "AAlcHJpdmF0ZS1hY2Nlc3MtdG9rZW4uY29saW5iZW5kZWxsLmRldg=="; // specify private-acccess-token.colinbendell.dev as origin

async function handleRequest(request) {
  if (!request.url.includes("/test.html")) {
    return fetch(request);
  }

  const params = new Proxy(new URLSearchParams(request.url.split("?")[1] ?? ""), { get: (searchParams, prop) => searchParams.get(prop), });

  const challenge = params.challenge || encodeURI(CHALLENGE);
  //   const nonce = btoa(crypto.getRandomValues(new Uint16Array(33))).substring(1,43); // 31bytes (even though it should be 32)
  //   const challenge = `${CHALLENGE_PREFIX}${nonce}${CHALLENGE_SUFFIX}`;

  const publicKey = params["token-key"] || encodeURI(CLOUDFLARE_PUB_KEY);
  const tokenHeader = request.headers.get("Authorization")?.split("PrivateToken token=")[1];

  const token = encodeURI(tokenHeader||"") || params.token;
  // ios16 and macOS13 don't actually support quoted challenge + token-key values ...
  let respInit = {
    status: 401,
    headers: {
      "WWW-Authenticate": `PrivateToken challenge=${decodeURIComponent(challenge).replaceAll('"', '')}, token-key=${decodeURIComponent(publicKey).replaceAll('"', '')}`,
    },
  };

  if (token) {
    respInit = {
        status: 200,
    }
  }

  const baseResponse = await fetch(request);
  const body = await baseResponse.text();
  const response = new Response(body, respInit);
  response.headers.set("Content-Type", `text/html`);
  response.headers.append("Set-Cookie", `lastchallenge=${Date.now()}; SameSite=Strict; Secure;`);
  response.headers.append("Set-Cookie", `token=${tokenHeader ? token : ''}; SameSite=Strict; Secure;`);
  response.headers.append("Set-Cookie", `challenge=${params.challenge ? '' : challenge}; SameSite=Strict; Secure;`);
  response.headers.append("Set-Cookie", `token-key=${params["token-key"] ? '' : publicKey}; SameSite=Strict; Secure;`);

  return response;
}

addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});
