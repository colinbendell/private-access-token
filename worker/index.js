const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAv-oHaLcoCLb_QMhvNUPVQiKa5mfhJedXY47NUCAyKHMLJfK0yUzyourEW4bOUty8zLvRcc4QY77kqdePpQgJsrdCQ9d40yS3zwbOCPGzMaLAeFQhvfqwDnUmm0mE5bpp324tGOC_mNJ_HVwpPgMW1t88xguGacC3DkHWfIvsHyaYNuF-ZaBAkZ6Dr5JJNXpnRmq8PmHY9Z9xOf3KJ33Ue9cc32jKTcsULI28_sU4RKrFpJRbp17pWKGeX1T3oVqO6k_AHKFOrIou1ZmFEZqJAzBM1VU6LC5LThPr5TcLK5CJUPMOooAEKuNpP3xGnn_bQvTrE-LPo9NjR-vTUHO_cQIDAQAB";
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
