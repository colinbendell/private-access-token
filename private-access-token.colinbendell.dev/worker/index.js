import { PrivateStateTokenIssuer, PrivateStateTokenKeyPair, IssueRequest, RedeemRequest } from "../../src/private-state-token.js";

const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAySgKXvR721O-HwSCp6BF8TeuHicxXGVHXJN4EB8npTqPvHY_3JsFIv19McA1L_Hls3UzYxU0XpOgHKAk34hMPkndSXxOerIbkadB_CcGCGM3mS-MrXbJiPIuFgBG1c4mu9avO3K1PWqsKlOpNbqr3V0u4BiLmYsxv7KoBsqjvx76B8USG1V2-VBOhuDmcIwSxzaawL3Rm_dqQHqe805K_T89EWQFXwEL50CjRQCJvBgvj77mAuVESaB4GPQeDcPqKSlZ4wfa6jcuT9Va-g7stXB7YRLo2TZxdG5n_1yP6-jhXLmQ7q5ijd4DKvWX_BNTIc_g3efHdgEFkfHiizu1qwIDAQAB";
const CHALLENGE = "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=";
const issuer = new PrivateStateTokenIssuer('https://example.com', 11)

export default {
    async fetch(request, env) {
        if (issuer.publicKeys.length === 0) issuer.addKey(PrivateStateTokenKeyPair.TEST_JWK);

        const privateStateToken = request.headers.get("sec-private-state-token");
        const pstCryptoVersion = request.headers.get("sec-private-state-token-crypto-version");

        const url = new URL(request.url);
        if (url.pathname === "/pst/k") {
            const body = JSON.stringify(issuer.keyCommitment(pstCryptoVersion));
            return new Response(body, {
                status: 200,
                headers: { "Content-Type": "text/json" },
            });
        }
        else if (url.pathname === "/pst/i") {
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
        else if (url.pathname === "/pst/r") {
            const redeemPayload = Object.fromEntries([...request.headers.entries()])
            redeemPayload.cf = request.cf

            if (privateStateToken) {
                const request = RedeemRequest.from(privateStateToken);
                const redeemResponse = issuer.redeem(request, redeemPayload, pstCryptoVersion);

                return new Response(`RR: ${JSON.stringify(redeemPayload, null, 2)})`, {
                    status: 200,
                    headers: {
                        "Content-Type": "text/plain",
                        'Sec-Private-State-Token': redeemResponse.toString(),
                        'Sec-Private-State-Token-Lifetime': 3660,
                        'Access-Control-Allow-Origin': '*',
                    },
                });
            }
            return new Response(`No token provided.`);
        }
        else if (url.pathname === "/pst/echo") {
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
