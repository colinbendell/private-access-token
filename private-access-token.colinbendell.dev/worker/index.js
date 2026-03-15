// eslint-disable-next-line max-len
const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEApDzhTVmSGEsNNI7y-hx60lyG459b7a0Wz2qd5pbeowRv1FuKNwAYiBuaJm0B4pojlZHSK3ThJlH6PQjayY8h_Vx6yxAUwUG8Ps1jmOJDRLwmfm-DBsrCPVUzSKUxq7vsdR5erPahm4-Z5MYITnJJaWLQ5D7oUfU0JZGfsZbDNt6dVNI5NMCM9G8xnSvA7smkEQ5-JiA5TY8pWJppKwp6x_pGslE2EeqVWdxY0Q5Bibb7Pfnv9hJllZvk4cpwGN2amDi8RfY44hPv7rLX0vzy2maVdUJ4fCJaQ2UTBefq8HHg8SwGzcz_RXk40JxBWPnSPOUUmcWe3pZDstNSzjWgoQIDAQAB";
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
                    "WWW-Authenticate": `PrivateToken challenge=${decodeURIComponent(challenge).replaceAll('"', "")}, token-key=${decodeURIComponent(publicKey).replaceAll('"', "")}`,
                },
            };

            if (token) {
                respInit = {
                    status: 200,
                };
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
    },
};
