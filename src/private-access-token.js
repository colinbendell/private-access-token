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
    static #CLOUDFLARE_DEMO_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAoQuY5ol9uZMR9Odm2IFbzs_5arP9gLsSPwvDYsIHJMaI03GU1lCTclourYsoNlUOHfnl3B-w_vUF7RhFhUpu1RllccNeHDiEyZC3WvWsAK_wE7TW7sNomh1MKEabZIkLgYUEADtOIbUojE7OMFGeWrhtytfGl6dCzLV347KcnNIi8TVsiJW2qPjsA9b-J9cj7dW1DD6WstEW2iP8GpkjZI-xBeiOSqqpYtMlkzY-QWujEEWjsixEx14vSMc3jf455Z-neLzlj1kX4Exhl4LLDDzdyaUyllgP3rd2WLtX4enkLWwy1tpKAtuiFR6VOLhOM9ZUVbMItK9o1-08Tsn_BwIDAQAB";
    static #CLOUDFLARE_DEMO_PUB_KEY_ID = "NE16CANFuCRPTuk0XMj-YquS75yfGn8MaP1dBouoCD8=";
    static #CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAhC_HK84Ac4ECr43xSXKN1jAyX2Q-QWWSoJcfB3mHUsyJUXtyWiGmr9JH-Bo0n5fxEi6daJ2ji17Wfy7Cr55DxOf83ed1wIL1iyElL-oLPCg6G4gqEw11XdHh6VeLeRlJbA3P2oHgoM-dYutZVJbWZ2lx6TJdfoDBtOmJ664nR0a0JDG8mAXysSqnBqDGS6vkQPUDhBo1Mzthkw0uEhS6VmTUF9_36LzPNDaTM-VsN9DC0TKHWphFvRWllEOZ_UOoPlJod4222Ojvu8Iyefs2riAbThU0JZKmtxRgs9SnL6XN6nmkpTSG8Epd3_LYLK7sFY0_nLVjKbjO0HWMzkHmpwIDAQAB";
    static #CLOUDFLARE_PUB_KEY_ID = "Cdi6328TnVYSkUx3WVymibupzbnRcMJ6gQIBb8awI98=";
    static #FASTLY_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA2GP2e-Qp61qNSZwa29_OF6MvWzu0LMVVAnwDUWl_3tN3pSmyfi-0SJ-UAN6bp7xDqdW1ImQNGXf1B-S8myTW8oxWpOH9FDNwO4rk4psWnPG_vlZ_kC9qOEHb3VRT3vq3tCoDxTNP5cjiu8PQbvzaXH8VQvlujfqvOxt8-WTPKCVzqTrZ7U67iZLPRBkf8eRoGxqrLD5EMWre8qMYEzxhTVH11elkEkIZ8mh9pD7hYpSMcmdQmM2sUtWKROuvBm89l79vW_5gdxV6CWfFXBU1JhEZ71L4_A_si64T2_iEjAFCbjsMoJHVnBhuHmXlZ8eTqSeSZpA5652wuzAHGQ0PywIDAQAB";
    static #FASTLY_PUB_KEY_ID = "oApHvY4d5HG5xGNqnd5jZpRsSEORWwWNYAVye5OS5Vk=";

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
