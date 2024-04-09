const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA1QvuFhVj8-HIEpd2829MedEvnrcAHahftJq4lCTdordKDtEpBDr1tC6_z1kq102Fe8SVbT4nRFRPCH_vL6Pwcc16C8jLMMvXraoC-BiyzAX3Yyr6lZj9UCQ7aK3JEr-tlD2wmLRtqyXfZQu9FdZsCMm0LU5LDAKE1uUBeAV-vLkP_1imLjHgbFE2lJH52yahbxiIjoqT_3PjB45ow3W9ciKiR89cUoS7X-sc6I2Lo7P_Y_FH4aGxC4fBDbjKZDO7UYOs3i1xJCHhgRA2dPWk0tZTjV7-jJE-oyRiReJNq7shr4jYws0e9BzlY1UCMa-U_JWdRb9So4JnoGPmfvSU_QIDAQAB";
const CHALLENGE = "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=";

export default {
    async fetch(request, env) {
        const url = new URL(request.url);

        if (url.pathname === "/" || url.pathname === "/index.html") {

            const params = new Proxy(new URLSearchParams(request.url.split("?")[1] ?? ""), { get: (searchParams, prop) => searchParams.get(prop), });

            const challenge = params.challenge || encodeURI(CHALLENGE);
            const publicKey = params["token-key"] || encodeURI(CLOUDFLARE_PUB_KEY);
            const tokenHeader = request.headers.get("Authorization")?.split("PrivateToken token=")[1];

            const token = encodeURI(tokenHeader || "") || params.token;
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
        else {
            return fetch(request);
        }
    }
}
