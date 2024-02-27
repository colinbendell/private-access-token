const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAqroPiq_1DtAaQSmpMQ4sgyBU6xKoYhLQuXK578kKkuqMO7H2HwV_giMHo-ARhxG34y42P-PhrRU4GA7I_Fd2hPO87Lh1vef0U9CedV6tipEzKIXS8Y6uXRd1gfwgRXLO3_Cpnss9gKSQAu5LmdeTmFw-KfuLguR_3w5xEyqPKYm2GJ_lqcAHtRLQtseMXJvPAYKGZ7A80eONcHiMsYcoWnVz_wCcDELo7HeZm_oRdgyv7UZt2_gBYDIJGKsQxqTYFZ5TzGS75kdVO1hNukAjKPJ_wR9JTXrAT5GNHRfMMu-BZq0tKvVGl3yWBahHfGjViRMMgek-aFwBiY2rEwaQwQIDAQAB";
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
