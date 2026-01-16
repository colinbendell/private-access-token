// eslint-disable-next-line max-len
const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAn2n-wTorVY-EOgM5eAhWzKF4Vh-M7FPiTeFUxeZ5xi-XSiB7z-Bc_Ol5IWUH6z_t27OUnwygQ5A6t9KiPBCvalSh86eU6vDL-TN0eOEFMiP0pdV_ll7IQcHzF1J7B6R7ogD28Z4aT-tRgAIZmla6f5vQrUYRD9vhA9RhbGTFo1Lh5aYbu1rBQD3sqIGVReyu4jYofbusCYFeROi3MrDYjKx_wr-UY9EbQs_edjrwb7c-4_s0EhseB7MeGo7phONYANfFw68EwxzZt5bZL4uJSCi6hBBmg4rHK7bjp_Lct4DtshDrdPz9Edgm0ZjzznX8HZq6bvctP5EM7-jy5h0u2QIDAQAB";
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
