// eslint-disable-next-line max-len
const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAohAEinEUN9MCsjzrxwxbvULf2hEf6DzoYCrpPtmo1i68wT-KS1NDTkyEOwRhONxJlS4B9bRrG8XsS8M1ZfVt9s1i9cNDF0N6g7mJVD6rfWQK7KpSFHayxJ9w6QE5l-T7ytgXgYa1rIg3uDCvf-xqBxgHWguUbVf_Y-idwoC9qrV7R7aDnyRjBMTgdG4n4zU7fBPwD7cTyVCXrbb7wXPOjk8Gs4DFLuV0cJC-xPAXSz4cUqwGtd-by3qQgMJK8joXpufuCiTvCsWWQu04bi-5Fr1GIJr3YU3zXweyeiaAuceRwZiE8tQlMi6FzRcTo_oDlRd0MIy4gR0RFNvPJnGyZQIDAQAB";
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
