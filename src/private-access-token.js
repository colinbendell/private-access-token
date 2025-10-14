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
    static #CLOUDFLARE_DEMO_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAuYA1Px0TEEIAZhM-TTtYT0yfMK3A6QohB8Eyi1_WvmdxecWazIdNI1bPGEmKXA0kEdbUftRBvG1hoz0_7K_HmsK2MgCLc1y7X9A9YnY9VckF499t4Y9QqaZTMO4m-NNQcVCNTriKTKYo5elLC6ec6-vPqDYERmDOkAuC1lMWqIRrlQEutlDF3F9-VsMEX-QApcLACTzCvkLmyfgpBMbpapYg8VjCyIpW_KViBgU12T6ar09dg-wgifq5Qw9f4_32_Lhn3qno_tjv-0qGD_ri3GboJiqzQz53k3Cp-z6R2fthmetfMMGaekdtrJS81huNdARUGUHcBo7MLLRAPzQ5nwIDAQAB";
    static #CLOUDFLARE_DEMO_PUB_KEY_ID = "u1baVcAtzGb1Q76yb0eS5zIDhNzRnUMjeiGco39NFd4=";
    static #CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEApvvlnvPdqg_7xt3jcYapeuXGANQ0FnlfoJ-on1_T0yNTbtOo5WGvghph57fQ7J5C5e96Q3KbyqUOZZA8ieTu6S5gFZnQ2G8GRXIcYOiJycMvLL_oiUyBnGbd9h7eti2R13NSOfb2Jk-f6x1Ci7BV9lJ_5FrrCaDclTKu2kKxyGfzlUNEcBPxqGNdhZJ9dV4vrqACh-VzPZ7EKm5cErQxQJ9lLgUVli3X74OL0-iNqzUhNS5TSvf2xk5P01Gt1JGoQD6mhkgP6sDy7eHtEaEKOUGXbVbit-g029cswQ2G_LQKx-lql5AEy_b5Y-hChH52uHeV3ATta0ZUh3nPJAz-owIDAQAB";
    static #CLOUDFLARE_PUB_KEY_ID = "X8OfcHg7wvmp3UaHaX8YGKdQLuUZEvdySPKlYL6C7hU=";
    static #FASTLY_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA244pQc3U1BrcS5ltIt9c3Nyw8IX2ejITnClpo1M6MSNSNLdnc1yR5mIFC2MPOj2M9jIP-AEoOMK6F79O2UEUF96bQhnQHdQ5rDp3zVQyU6b0pZOafkysNz1sa8UVANXAOkfJ_mm1A_689fuQu4LcQiVmcFgRg3LIDIOqH8fVGkyaZ-lglXbng2LQdKeBWx5EOpT1TP3Ec7URSC7FARwx4Zx8pIA3Uqz070fT_bgilqJqIFUQyHQPvF3JFS5y_dXR3GcNMmUQSVqrEBXZACW42VeLAmpIcCKtUNay0cvpiiR1Zw7ii18dOeFp1Cq-j7ODdzBv76nIy5nDfadLveWQpQIDAQAB";
    static #FASTLY_PUB_KEY_ID = "_XPOGKvQ5AddbRbdFDG0ixKOrmcHKqFoi3SJ1DK6zv8=";

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
