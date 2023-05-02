import { PrivateStateTokenIssuer, IssueRequest, RedeemRequest } from "../private-state-token.js";

const CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAmSYx82S-vjLRtQnwDoTUWfs-F-Hi-DRaYWzsCX96xyDJBsiM44vH3e84_i0ylmG4wHPdbDqOs-9hxtq2yC-5Ays-nZPHMmj-BATD7eCP8tff3gbELIvHB6suJ0Ov8j598aYWGzlna7KdXhdjuo7vVMUK7_2hoSO327Ph7hwZYODpPq8hQD9-EsghYZ5k13WxlZzx2DyqqVWBfUoJukkmuZwGW_nA2_uYwUwmOBoFmNSQh1FJD0MRRTrQrjvopK7mhVZL6y8Lt2cNdLdqEe4hxb_DiKlAzIpZIFpcG-VTmlREKGxQJEde4bCwTo6imlDb72prF9QxT6-cyS3FKFhdLwIDAQAB";
const CHALLENGE = "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=";
let issuer;

export default {
    async fetch(request, env) {
        if (!issuer) issuer = PrivateStateTokenIssuer.generate(`https://${request.headers.get("host")}/`, 10);
        if (request.url.includes("/pst/k")) {
            const body = issuer.keyCommitment.toString();
            return new Response(body, {
                status: 200,
                headers: { "Content-Type": "text/json" },
            });
        }
        else if (request.url.includes("/pst/i")) {
            const privateStateToken = request.headers.get("sec-private-state-token");
            const cookies = request.headers.get("cookie");

            if (privateStateToken) {
                const request = IssueRequest.from(privateStateToken);

                const issueResponse = issuer.issue(0, request);
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
        else if (request.url.includes("/pst/r")) {
            const privateStateToken = request.headers.get("sec-private-state-token");
            const cookies = request.headers.get("cookie");
            console.log("cookie: ", cookies);
            console.log("Redeem: ", privateStateToken);

            if (privateStateToken) {
                const request = RedeemRequest.from(privateStateToken);
                const redeemResponse = issuer.redeem(request, cookies);

                return new Response(`Redeemed 1 tokens. (RR: ${cookies})`, {
                    status: 200,
                    headers: {
                        "Content-Type": "text/plain",
                        'Sec-Private-State-Token': redeemResponse.toString(),
                        'Sec-Private-State-Token-Lifetime': 60,
                        'Access-Control-Allow-Origin': '*',
                    },
                });
            }
            return new Response(`No token provided.`);
        }
        else if (request.url.includes("/pst/echo")) {
            const redemptionRecord = request.headers.get("sec-redemption-record");
            const cookies = request.headers.get("cookie");

            return new Response(redemptionRecord, {
                status: 200,
                headers: {
                    "Content-Type": "text/plain",
                    'Sec-Private-State-Token': redemptionRecord,
                    'Access-Control-Allow-Origin': '*',
                },
            });
        }
        else if (request.url.includes("/test.html")) {

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
