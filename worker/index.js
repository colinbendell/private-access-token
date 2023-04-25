const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAmSYx82S-vjLRtQnwDoTUWfs-F-Hi-DRaYWzsCX96xyDJBsiM44vH3e84_i0ylmG4wHPdbDqOs-9hxtq2yC-5Ays-nZPHMmj-BATD7eCP8tff3gbELIvHB6suJ0Ov8j598aYWGzlna7KdXhdjuo7vVMUK7_2hoSO327Ph7hwZYODpPq8hQD9-EsghYZ5k13WxlZzx2DyqqVWBfUoJukkmuZwGW_nA2_uYwUwmOBoFmNSQh1FJD0MRRTrQrjvopK7mhVZL6y8Lt2cNdLdqEe4hxb_DiKlAzIpZIFpcG-VTmlREKGxQJEde4bCwTo6imlDb72prF9QxT6-cyS3FKFhdLwIDAQAB";
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
