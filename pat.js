import {base64urlDecode, base64urlEncode, byteArrayToString, hostToNetworkShort, networkToHostShort, stringToByteArray, sha256} from "./utils.js";

export class Challenge {
    static DEFAULT = Challenge.from("AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=");

    constructor(tokenType = Token.BLIND_RSA, issuerName = "", redemptionContext = "", originInfo = "") {
        this.tokenType = tokenType || Token.BLIND_RSA;
        this.issuerName = issuerName || "";
        this.redemptionContext = redemptionContext || [];
        this.originInfo = originInfo || "";
    }

    static from(data) {
        const challengeBytes = base64urlDecode(data) || [];

        const tokenType = networkToHostShort(challengeBytes.slice(0, 2));
        const issuerNameLength = networkToHostShort(challengeBytes.slice(2, 4));
        const issuerName = byteArrayToString(challengeBytes.slice(4, 4 + issuerNameLength));
        const redemptionContextLength = challengeBytes[4 + issuerNameLength];
        const redemptionContext = challengeBytes.slice(4 + issuerNameLength + 1, 4 + issuerNameLength + 1 + redemptionContextLength);
        const originInfoLength = networkToHostShort(challengeBytes.slice(4 + issuerNameLength + 1 + redemptionContextLength, 4 + issuerNameLength + 1 + redemptionContextLength + 2));
        const originInfo = byteArrayToString(challengeBytes.slice(4 + issuerNameLength + 1 + redemptionContextLength + 2, 4 + issuerNameLength + 1 + redemptionContextLength + 2 + originInfoLength));

        return new Challenge(tokenType, issuerName, redemptionContext, originInfo);
    }

    set redemptionContext(value) {
        if (Array.isArray(value)) {
            //noop
        }
        else if (!Array.isArray(value)) {
            value = stringToByteArray(value);
        }
        else {
            value = stringToByteArray(value);
        }

        if (value.length > 0) {
            // Pad to 32 bytes
            value = Array(32).fill(0).concat(value).slice(-32);
        }

        this._redemptionContext = value;
    }

    get redemptionContext() {
        return this._redemptionContext || [];
    }

    async tokenKey() {
        return await PublicKey.from(this.issuerName);
    }

    toByteArray() {
        return [].concat(
            hostToNetworkShort(this.tokenType),
            hostToNetworkShort(this.issuerName.length),
            stringToByteArray(this.issuerName),
            [this.redemptionContext.length],
            this.redemptionContext,
            hostToNetworkShort(this.originInfo.length),
            stringToByteArray(this.originInfo));
    }

    toString() {
        return base64urlEncode(this.toByteArray());
    }

}

export class PublicKey {
    static #CLOUDFLARE_DEMO_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAtST104YJy_s9Qugu4pwyLnamhUcEveiw9Lvkp9lm4qDMEnn1SguQu2ovy0pNAa4wVCeN5OPftpCQT8qbwFGgcnUzNTgwBT6SVRJU-ZM7ky4iBBqJ77siiYvaWue2-tOJMU68yt64W20EcS548RAiaZVL0aMFEWZpP81axUSj9knnCs3WoIlcerCGfesxSfov0ZMTRbtO2PUcLnzi0iTWO1NCb1gVHXFe_cV8UiB-uxCaETmpEbkXfvdLMXeJcYVKpr1kb_Mu4Q1TCf0GY0OvXzrDSy0HimuJMy6BdmvZgYzsfP6u0z9VF_PNxOlFPr8Uq5lLyGUcBsaOtDAcm2LEvwIDAQAB";
    static #CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAvs9E2WtOHukHE4JlkcSimfV97Bu4XmGrVTg9BC-wZU49y0HWBQKs5YvbHxIZmJqWjJ7FVWmmRcr_AFezYdaWw4JszO0DdWVtxEuedcIsAWvjv7KczqNao28n-nQffA4QBBl2jgytBw-wzstRTLnbWRs03f2_SNNj2RPcs5LJ0KeDEoszg9DO2JLqxdaT5xCFqq-_J_eybiEZDs1XU3HxgR3EjTtfBjHy_PgVXFOgvvTitGT_dcU8dtRi9MJmoSBEFseWB5NDiCcmjfnxsuSEFCWk1BzC9jxLkGTweBm6amRGJlR06WyMoOsYAvTJclZJHkr2z_FzA1C5VQkNP6D-jwIDAQAB";
    static #FASTLY_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA3u2Eqv0aOFEyI9Q42gqtgG2eo5Dgm7H8GUTJGdxOI7L8-10Jr1miUeTofM8d2ddSMTiJPNhsoniy3q2l2omwH_KXgEYuCUgUBykrMcse4m7mG2QijluejXwooHN9KtErBi_jlOlC1MRmuD1aYWI_egv78A6zw1wvUJOAQ3twQpCRWkzt9Q7eiAGMaPD_c2Te3oeOPTIuhpKaqKjVaRtNnng-3eRC5uIE8mGu-41iZM2efdcqO68lE1s4z8hLNM_0ZDzm3zMdLwpQYq1Bp0WXXrLYTQWDDu2MTR_aNTJ44wJdYutuK-FeRHQGIxUDTvA5PDq-M3ZuUHk_gAAHzYu12wIDAQAB";

    static CLOUDFLARE_DEMO = new PublicKey('demo-pat.issuer.cloudflare.com', PublicKey.#CLOUDFLARE_DEMO_PUB_KEY);
    static CLOUDFLARE = new PublicKey('pat-issuer.cloudflare.com', PublicKey.#CLOUDFLARE_PUB_KEY);
    static FASTLY = new PublicKey('demo-issuer.private-access-tokens.fastly.com', PublicKey.#FASTLY_PUB_KEY);

    static #PUBLIC_KEYS = new Map([
        [PublicKey.CLOUDFLARE_DEMO.issuerName, PublicKey.CLOUDFLARE_DEMO],
        [PublicKey.CLOUDFLARE.issuerName, PublicKey.CLOUDFLARE],
        [PublicKey.FASTLY.issuerName, PublicKey.FASTLY],
    ]);

    static async from(key) {
        if (key instanceof PublicKey) return key;

        const issuerName = key;
        if (PublicKey.#PUBLIC_KEYS.has(issuerName)) {
            return PublicKey.#PUBLIC_KEYS.get(issuerName);
        }

        const sPKI = key;
        for (const [k, v] of PublicKey.#PUBLIC_KEYS.entries()) {
            if (v.sPKI === sPKI) {
                return v;
            }
        }

        const tokenKeyID = key.toString();
        for (const [k, v] of PublicKey.#PUBLIC_KEYS.entries()) {
            if ((await v.tokenKeyID()).toString() === tokenKeyID) {
                return v;
            }
        }
        return new PublicKey('', key);
    }

    constructor(issuerName, sPKI) {
        this.issuerName = issuerName;
        this.sPKI = sPKI;
    }

    #sPKI;

    set sPKI(value) {
        this.#sPKI = value;
    }

    get sPKI() {
        return this.#sPKI;
    }

    get legacySPKI() {
        const legacySPKI = "MIIBIjANBgkqhkiG9w0BAQEFA" + this.sPKI.slice(-367);
        if (legacySPKI === this.sPKI) return null;
        return new PublicKey(this.issuerName, legacySPKI);
    }

    toByteArray() {
        return base64urlDecode(this.sPKI);
    }

    toString() {
        return this.sPKI;
    }

    async tokenKeyID() {
        return await sha256(this.toByteArray());
    }

    async cryptoKey() {
        let publicKey;
        try {
            publicKey = await crypto.subtle.importKey("spki", Uint8Array.from(this.toByteArray()), { name: "RSA-PSS", hash: "SHA-384" }, false, ["verify"])
        }
        catch (e) {
            // console.error("Falling back to legacy rsaEncoded without parameters");
            try {
                publicKey = await crypto.subtle.importKey("spki", Uint8Array.from(this.legacySPKI.toByteArray()), { name: "RSA-PSS", hash: "SHA-384" }, false, ["verify"]);
            }
            catch {
                throw e;
            }
        }
        return publicKey;
    }

}

// esm module of token class
export class Token {
    static VOPRF = 0x0001;
    static BLIND_RSA = 0x0002;

    constructor(tokenType, nonce, challengeHash, tokenKeyID, authenticator) {
        this.tokenType = tokenType;
        this.nonce = nonce;
        this.challengeHash = challengeHash;
        this.tokenKeyID = tokenKeyID;
        this.authenticator = authenticator;
    }

    static async from(data) {
        const tokenBytes = base64urlDecode(data);
        const tokenType = networkToHostShort(tokenBytes.slice(0,2));
        const nonce = tokenBytes.slice(2,34);
        const challengeHash = tokenBytes.slice(34,66);
        const tokenKeyID = tokenBytes.slice(66,98);
        const authenticator = tokenBytes.slice(98);

        return new Token(tokenType, nonce, challengeHash, tokenKeyID, authenticator);
    }

    toByteArray() {
        return [].concat(hostToNetworkShort(this.tokenType), this.nonce, this.challengeHash, this.tokenKeyID, this.authenticator);
    }

    toString() {
        return base64urlEncode(this.toByteArray());
    }

    async tokenKey() {
        return await PublicKey.from(this.tokenKeyID);
    }

    verifyTokenType() {
        return this.tokenType === Token.VOPRF || this.tokenType === Token.BLIND_RSA;
    }

    async verifyChallengeHash(challenge) {
        return this.challengeHash?.length > 0 && this.challengeHash.toString() === (await sha256(challenge.toByteArray())).toString();
    }

    async verifyTokenKeyID(challengeTokenKey) {
        const publicKey = await PublicKey.from(challengeTokenKey);
        return this.tokenKeyID.toString() === (await publicKey.tokenKeyID()).toString();
    }

    async verifyAuthenticator(challengeTokenKey) {
        const publicKey = await challengeTokenKey?.cryptoKey();
        if (publicKey) {
            const data = Uint8Array.from([].concat(hostToNetworkShort(this.tokenType), this.nonce, this.challengeHash, this.tokenKeyID));
            const signature = Uint8Array.from(this.authenticator);

            try {
                return await crypto.subtle.verify({name:"RSA-PSS", saltLength: 48},  publicKey, signature, data);
            }
            catch {
            }
        }

        return false;
    }

    async verify(challenge, challengeTokenKey) {
        return this.verifyTokenType()
            && await this.verifyChallengeHash(challenge)
            && await this.verifyTokenKeyID(challengeTokenKey)
            && await this.verifyAuthenticator(challengeTokenKey);
    }
}
