// eslint-disable-next-line max-len
const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAtDtEkyZVMYjqpx1QiWsxKAyUU20Zgc3DV59a7BK2FnlOFaf2JO44bI1wPnXJbQ0wWc3rvR7tDH4t7H880QaKC5RfyP5GtOuSDB6Z9cblLnA_nUMhUMu3nuMSMc1amkfgx2975-AwAMc8kPHP8f53TpOgLbwGmtzvM9oc7d04eZKiQD55Sn_dAdzqK0YqdHDVAIA4bPaRkjH_PJZ95lngKTkFlWa-Krbjmnnxk4u6aTtXUfIso9hRlIIzBTTt9UvqzKWcany05RN-QnXqOuGk5xsxvomWZzdiPcW3TQCC9ZEcqNa9KrBxcvhIW3WtpkQkSi0O6ln0QLL4PZWwg-199QIDAQAB";
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
