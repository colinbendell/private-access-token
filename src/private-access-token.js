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
    static #CLOUDFLARE_DEMO_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAk68XtV0AhIYS7lZY6VFteBgS8jzUOOTy16cjuud0eFNxDpoHMzgArl9LE4y-Jgp4AcUd1IaEd7R7ZfoclBxDIPV7Qp_Z0gfKzQJUPK1GKJO8bVgS-hRp94XrTGZCNuLFIRCP7670qhy8rIYkjFZsRA8L46O3t3NRZzttbA5YrLXWn3X21t9rI_nM4Cqpi30GJaEhCru0Uic_hFVpTlauSbqLayW0t-2XdCsEuoHZ8a9Z33kWv4Hkblysdo8drur7uZz6wWwEhg3IXbydkpy6EsCcTUK9FND0XNSHKAQZQsz7AoMAMAh97DZBW88BlzMtPqZXpEPSxH9vhr2C7RljYQIDAQAB";
    static #CLOUDFLARE_DEMO_PUB_KEY_ID = "u7SirPGBt53pKWrNLX2Cuy29pMx7hdy4xgCLxaHwyxg=";
    static #CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAt6Lrvi31krXKO3CBv8uS0zgLWkdmwVxY2MQwx9Rj-hXvVnbghnxQ4yyqc9Q7jal7S8Uz_LxEKq4lJoJ0TkeymJ4iZbIzgyLX1OiLLf4kGHu8Bi-qXG0ngl0oLCZaVqz7CBMa51IjC6Gbjuuro9QVvSrVEK6_HGmxvGUYSEeuV1LgCmDbDpfnocAyV8RKlhINVYmhH-8GeRXLFT_URBhBPCzTB9WfYXuIX5B-fMd9oh61PVm47N-k8czLLW9RP1ru5EBsOZIdpc8hCZew1Knktv3Fgj3UajJ-QCBw1Ymb1qS3DlAdOt0kICL7U6F9hwpZzJnIZRj6qI_t_hYh6WkyPwIDAQAB";
    static #CLOUDFLARE_PUB_KEY_ID = "59TuzTqJ2VwmsoLmhddzZo6nGGKv6ebvGrlrxX5luaI=";
    static #FASTLY_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA2wmfeIV2NPDs3Rdv5rSs2Uzcr6dGWdTCJI2RyCGFG958HmCF1_yXMo7O3kGsuv8iEvZAQnEaEXnEtetMumg7m3tN_q8bf6TZcJYpDb5ACZN2_rWIw6vL-2RfMjp7HtquO_o4tKC9Ey4a-TN2tuLPeanD38llRbBNWHeUqRhm17lWrU8Zisb4tjbPTlYIFt09zDe5myBhw61y14Gcd37-YN_OqGc1Zm5NMFwwQCi-P2whXKP3-mH40H3fiWuPLzoNI43-FHjr8Pjgw1KRTdcAeh1M4OCkpHfuiS6bpdUMU4GxRs_4__T3RUhgIwAVGZockyQAoOBuOgZCvE1tLdngUQIDAQAB";
    static #FASTLY_PUB_KEY_ID = "kEjYnEtdtN3Xd6yJMMlqNUPWgR59XRjV6az5g-33gz8=";

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
