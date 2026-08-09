// eslint-disable-next-line max-len
const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA2XCWX8cqMKyXLsZPRoEmRqLj-krBrj5hNacaANLj1_1wP3oeJY-baY2U-57HgkwPSNvNYl0vbYwWgNmrh8_2gZV4sfBTYDR6SRQBp3leBam9jxy-JHO5u61AxyCzrGs_gM30jq4NX9ErhHiuTCBWYTy7ba2eyWmMtVQsY_wQeNjo7ygp9K9RpU7_ZjSMcN6n-em2QxlLANahcbZ4GowyWmcaHSnC-uJnYrCSoHtxW3k2ofEn_AVYGyxBS0WmRNbXhpyzxxabms5Y6LbYRuvTEsWUId9hOvnBiWdVmOnj8CAxyjYgU_q5C_KxmHJRAO2wxXJPpfCSyPO_cw094Nq25QIDAQAB";
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
