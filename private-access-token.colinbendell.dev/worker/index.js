import { PrivateStateTokenIssuer, PrivateStateTokenKeyPair, IssueRequest, RedeemRequest } from "../../src/private-state-token.js";

const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEArTdvs2-VOeG1gRYSu6le9W8rphJ9hC05duH2SoyJxZcID7eB4pDegSJtNqv3OQbpK4Q95bHTqsH89BCAXLJI-Vt7ySrpRthX6rEPu-Vj7WesutfG-4HKj1HyDTGqAY6a7ewvPAO1MgMa2r1_gzOPEXZzJhEKT6UdIT2kff2r_Ykjw0jlNmXk5cDvIskrZ85GVfUW-rn9g1PLXw9OFhNDD6DD2EiFfNdypws_NYvMuOAHcmAxJlEJcf3CR8kfcZax5XW2G8thhT80V0huiKzfxYVtQL5b4HVbTcNvo9O7UCIklef8agJz95n7nyDUn68MLaxbYGJ0kAASzeN5eEb55QIDAQAB";
const CHALLENGE = "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=";
const issuer = new PrivateStateTokenIssuer('https://private-state-token.colinbendell.dev', 10, 1684870124)
if (issuer.publicKeys.length === 0) issuer.addKey(PrivateStateTokenKeyPair.TEST_JWK);

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
        if (url.hostname === 'private-state-token.colinbendell.dev') {

            const privateStateToken = request.headers.get("sec-private-state-token");
            const pstCryptoVersion = request.headers.get("sec-private-state-token-crypto-version");

            if (url.pathname === "/.well-known/token-issuer-directory") {
                const body = JSON.stringify(issuer.directory(), null, 2);
                return new Response(body, {
                    status: 200,
                    headers: {
                        "Content-Type": "application/token-issuer-directory",
                        "Cache-Control": "max-age=300"
                        // "Cache-Control": "max-age=86400"
                    },
                });
            }
            if (url.pathname === "/.well-known/key-commitment") {
                const body = JSON.stringify(issuer.keyCommitment(pstCryptoVersion), null, 2);
                return new Response(body, {
                    status: 200,
                    headers: {
                        "Content-Type": "application/token-issuer-directory",
                        "Cache-Control": "max-age=300"
                        // "Cache-Control": "max-age=86400"
                    },
                });
            }
            if (url.pathname === "/.well-known/jwks.json") {
                const body = JSON.stringify(issuer.jwks(), null, 2);
                return new Response(body, {
                    status: 200,
                    headers: {
                        "Content-Type": "application/json",
                        "Cache-Control": "max-age=300"
                        // "Cache-Control": "max-age=86400"
                    },
                });
            }            else if (url.pathname === "/request") {
                if (privateStateToken) {
                    const request = IssueRequest.from(privateStateToken);

                    const issueResponse = issuer.issue(0, request, pstCryptoVersion);
                    return new Response(`Issuing ${issueResponse.signed.length} tokens.`, {
                        status: 200,
                        headers: {
                            "Content-Type": "text/plain",
                            'Sec-Private-State-Token': issueResponse.toString(),
                            'Access-Control-Allow-Origin': '*',
                        },
                    });
                }
                return new Response(`No issuance provided.`);
            }
            else if (url.pathname === "/redeem") {
                const redeemPayload = Object.fromEntries([...request.headers.entries()])
                redeemPayload.cf = request.cf

                if (privateStateToken) {
                    const request = RedeemRequest.from(privateStateToken);
                    const redeemResponse = issuer.redeem(request, JSON.stringify(redeemPayload, null, 2), pstCryptoVersion);

                    return new Response(`RR: ${JSON.stringify(redeemPayload, null, 2)})`, {
                        status: 200,
                        headers: {
                            "Content-Type": "text/plain",
                            'Sec-Private-State-Token': redeemResponse?.toString() || "",
                            'Sec-Private-State-Token-Lifetime': 3660,
                            'Access-Control-Allow-Origin': '*',
                        },
                    });
                }
                return new Response(`No token provided.`);
            }
            else if (url.pathname === "/echo") {
                const redemptionRecord = request.headers.get("sec-redemption-record");

                return new Response(redemptionRecord, {
                    status: 200,
                    headers: {
                        "Content-Type": "text/plain",
                        'Sec-Private-State-Token': redemptionRecord,
                        'Access-Control-Allow-Origin': '*',
                    },
                });
            }
            else if (url.hostname === 'private-state-token.colinbendell.dev' &&
                        (url.pathname === "/" || url.pathname === "/index.html")) {
                return fetch('https://private-access-token.colinbendell.dev/pst.html');
            }
            else {
                return fetch(request);
            }
        }
        else if (url.pathname === "/" || url.pathname === "/index.html") {

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
