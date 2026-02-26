import {Base64, sha256, ByteBuffer} from "./utils.js";

export class Challenge {
    static DEFAULT = Challenge.from("AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=");

    constructor(tokenType = Token.BLIND_RSA, issuerName = "", redemptionContext = "", originInfo = "") {
        this.tokenType = tokenType || Token.BLIND_RSA;
        this.issuerName = issuerName || "";
        this.redemptionContext = redemptionContext || [];
        this.originInfo = originInfo || "";
    }

    static from(data) {
        const challengeBytes = Base64.decode(data) || [];
        const byteBuffer = new ByteBuffer(challengeBytes);

        const tokenType = byteBuffer.readInt(2);
        const issuerNameLength = byteBuffer.readInt(2)
        const issuerName = byteBuffer.readString(issuerNameLength);
        const redemptionContextLength = byteBuffer.readInt(1);
        const redemptionContext = byteBuffer.readBytes(redemptionContextLength);
        const originInfoLength = byteBuffer.readBytes(2);
        const originInfo = byteBuffer.readString(originInfoLength);

        return new Challenge(tokenType, issuerName, redemptionContext, originInfo);
    }

    #redemptionContext = [];

    set redemptionContext(value) {
        let redemptionContext = ByteBuffer.stringToBytes(value);

        if (redemptionContext.length > 0) {
            // Pad to 32 bytes
            redemptionContext = Array(32).fill(0).concat(redemptionContext).slice(-32);
        }

        this.#redemptionContext = redemptionContext;
    }

    get redemptionContext() {
        return this.#redemptionContext || [];
    }

    getTokenKey() {
        return PublicKey.from(this.issuerName);
    }

    toByteArray() {
        const byteBuffer = new ByteBuffer()
            .writeInt(this.tokenType, 2)
            .writeInt(this.issuerName.length, 2)
            .writeString(this.issuerName)
            .writeInt(this.redemptionContext.length, 1)
            .writeBytes(this.redemptionContext)
            .writeInt(this.originInfo.length, 2)
            .writeString(this.originInfo);
        return byteBuffer.toBytes();
    }

    toString() {
        return Base64.urlEncode(this.toByteArray());
    }

}

export class PublicKey {
    static #CLOUDFLARE_DEMO_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAniNgtp6lu-_Rsf2d3tPVy9q1BIU2SejVenyD1uDLWtkqi45NQZMTZgJLamVhr-QxeK0fYwgEkUsvARamQ_LGnvuIqxerHMfiPOMrLpS74hMZIohj3V33RH3KlrlNllxPAXP0I3ZSwAkT1OammG6Xr59mDmHW4qnaOEMblUoD1CqsRwLpAbBPo1bCcnFhKN_W5L92XSvxwcOEwKIwuFoeVjv6orxtLyUl4p7qeGOlxPctwf4olBGHMjLyrFvqJRTY9Au2JPFxOjXXC77i1v7iKRneOA4sotetqz_0MNgSpLH0-7SlOZRQquDgReaNOVW554m83mGJ9v4Jgb6hJIWJtQIDAQAB";
    static #CLOUDFLARE_DEMO_PUB_KEY_ID = "rN7ppnZkJvNowxH8kR4KthGe_veUsIz9qeETKxHQZoU=";
    static #CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAv-ElxfUQvtDu6xunbqaBMKJZgLZJjr37pHCdozMzbjl-dMZTRzujFhcdi7u-rj4XQX46hCwvWEpWRFCVs4d0I76Haua1SfDbZ0VwxuDtUzRW9RMNd1VxbpTKx5_4NJPn2cGwv8e981fVDhS8hPsKS1bNxNP9eFuh4u5HB2zIw66kyyeQUiYWcVfrzjP5zpV1eX4zxNKYeAViQ1XmoMExT4dF1nuXGL9gIYP4q4dLoiIcuyTmsP7t5picBhMhhLj6gd6N7iEOf5PD1usMd33HJ2L64w8gG0Ka0EiTkKBEbuH7Zk30beR6dZlI47inpa-jZDFq4QtOsyv9EmH7_KTjnQIDAQAB";
    static #CLOUDFLARE_PUB_KEY_ID = "2mfbEqPrXieZo9xE8p1RvTvnaWBfUYiS6A8BkuUcoEs=";
    static #FASTLY_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAmjL9TScJ92FmglEVRIu012-IqHGH1HXqhViQRQQkMIqgOsvQk54xBhN_gyeHGyzD9Z7Z-Tw0NZLEW8ysHeR0-YYHwRqFvY7UGXENpBPuYD8Fb8XqzNy5IzoEHsvFu1iFp8Fz3IUlXVQLVmS3t84Ox9rlfxZzexZ3K5iOXXl66UdWh1ro3PP5kdqGBsShkMLyHIqXlN3pFiNptN7TLajqKrefin9ZHNrTRVnrWzsIT8rxJ8k6c00mn8Onswc1DbXoxWQTrlSeAuVg9ZhZUy7fZBTktS1JEjrhySM7hgT01-FuOnnqb_xAbaRhFMRWM8oPIobhEZTb0f9hzvkhELZYawIDAQAB";
    static #FASTLY_PUB_KEY_ID = "9XpUEdHkOuPZCJC90B-dkfi23OSjPV2BPP4yjc3sLVM=";

    static CLOUDFLARE_DEMO = new PublicKey('demo-pat.issuer.cloudflare.com', PublicKey.#CLOUDFLARE_DEMO_PUB_KEY, PublicKey.#CLOUDFLARE_DEMO_PUB_KEY_ID);
    static CLOUDFLARE = new PublicKey('pat-issuer.cloudflare.com', PublicKey.#CLOUDFLARE_PUB_KEY, PublicKey.#CLOUDFLARE_PUB_KEY_ID);
    static FASTLY = new PublicKey('demo-issuer.private-access-tokens.fastly.com', PublicKey.#FASTLY_PUB_KEY, PublicKey.#FASTLY_PUB_KEY_ID);

    static #PUBLIC_KEYS = new Map([
        [PublicKey.CLOUDFLARE_DEMO.issuerName, PublicKey.CLOUDFLARE_DEMO],
        [PublicKey.CLOUDFLARE.issuerName, PublicKey.CLOUDFLARE],
        [PublicKey.FASTLY.issuerName, PublicKey.FASTLY],
    ]);

    static from(key) {
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
            if ((v.keyID).toString() === tokenKeyID) {
                return v;
            }
        }
        return new PublicKey('', key);
    }

    constructor(issuerName, sPKI, keyID) {
        this.issuerName = issuerName;
        this.sPKI = sPKI;
        this.keyID = keyID ? Base64.decode(keyID) : null;
    }

    sPKI;
    keyID;
    get legacySPKI() {
        const legacySPKI = "MIIBIjANBgkqhkiG9w0BAQEFA" + this.sPKI.slice(-367);
        if (legacySPKI === this.sPKI) return null;
        return new PublicKey(this.issuerName, legacySPKI);
    }

    toByteArray() {
        return Base64.decode(this.sPKI);
    }

    toString() {
        return this.sPKI;
    }

    async toTokenKeyID() {
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

    static from(data) {
        const tokenBytes = Base64.decode(data);
        const byteBuffer = new ByteBuffer(tokenBytes);

        const tokenType = byteBuffer.readInt(2);
        const nonce = byteBuffer.readBytes(32);
        const challengeHash = byteBuffer.readBytes(32);
        const tokenKeyID = byteBuffer.readBytes(32);
        const authenticator = byteBuffer.readBytes(256);

        return new Token(tokenType, nonce, challengeHash, tokenKeyID, authenticator);
    }

    toByteArray() {
        const byteBuffer = new ByteBuffer()
            .writeInt(this.tokenType, 2)
            .writeBytes(this.nonce)
            .writeBytes(this.challengeHash)
            .writeBytes(this.tokenKeyID)
            .writeBytes(this.authenticator);
        return byteBuffer.toBytes();
    }

    toBytes() {
        return this.toByteArray();
    }

    toString() {
        return Base64.urlEncode(this.toByteArray());
    }

    getTokenKey() {
        return PublicKey.from(this.tokenKeyID);
    }

    verifyTokenType() {
        return this.tokenType === Token.VOPRF || this.tokenType === Token.BLIND_RSA;
    }

    async verifyChallengeHash(challenge) {
        return this.challengeHash?.length > 0 && this.challengeHash.toString() === (await sha256(challenge.toByteArray())).toString();
    }

    verifyTokenKeyID(challengeTokenKey) {
        const publicKey = PublicKey.from(challengeTokenKey);
        return this.tokenKeyID.toString() === publicKey.keyID.toString();
    }

    async verifyAuthenticator(challengeTokenKey) {
        const publicKey = await challengeTokenKey?.cryptoKey();
        if (publicKey) {
            const data = Uint8Array.from([].concat(ByteBuffer.numberToBytes(this.tokenType, 2), this.nonce, this.challengeHash, this.tokenKeyID));
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
            && this.verifyTokenKeyID(challengeTokenKey)
            && await this.verifyAuthenticator(challengeTokenKey);
    }
}
