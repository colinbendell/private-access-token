import { PrivateStateTokenIssuer, PrivateStateTokenKeyPair, IssueRequest, RedeemRequest } from "../src/private-state-token.js";

const issuer = new PrivateStateTokenIssuer('https://private-state-token.colinbendell.dev', 10, 1684870124)
if (issuer.publicKeys.length === 0) issuer.addKey(PrivateStateTokenKeyPair.TEST_JWK);

export default {
    async fetch(request, env) {
        const url = new URL(request.url);
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
        else if (url.pathname === "/.well-known/key-commitment") {
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
        else if (url.pathname === "/.well-known/jwks.json") {
            const body = JSON.stringify(issuer.jwks(), null, 2);
            return new Response(body, {
                status: 200,
                headers: {
                    "Content-Type": "application/json",
                    "Cache-Control": "max-age=300"
                    // "Cache-Control": "max-age=86400"
                },
            });
        }
        else if (url.pathname === "/request") {
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
        return env.ASSETS.fetch(request);
    }
}
