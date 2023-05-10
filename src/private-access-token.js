import {Base64, sha256, DataBuffer} from "./utils.js";

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
        const dataBuffer = new DataBuffer(challengeBytes);

        const tokenType = dataBuffer.readInt(2);
        const issuerNameLength = dataBuffer.readInt(2)
        const issuerName = dataBuffer.readString(issuerNameLength);
        const redemptionContextLength = dataBuffer.readInt(1);
        const redemptionContext = dataBuffer.readBytes(redemptionContextLength);
        const originInfoLength = dataBuffer.readBytes(2);
        const originInfo = dataBuffer.readString(originInfoLength);

        return new Challenge(tokenType, issuerName, redemptionContext, originInfo);
    }

    #redemptionContext = [];

    set redemptionContext(value) {
        let redemptionContext = DataBuffer.stringToBytes(value);

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
        const dataBuffer = new DataBuffer();
        dataBuffer.writeInt(this.tokenType, 2);
        dataBuffer.writeInt(this.issuerName.length, 2);
        dataBuffer.writeString(this.issuerName);
        dataBuffer.writeInt(this.redemptionContext.length, 1);
        dataBuffer.writeBytes(this.redemptionContext);
        dataBuffer.writeInt(this.originInfo.length, 2);
        dataBuffer.writeString(this.originInfo);
        return dataBuffer.toBytes();
    }

    toString() {
        return Base64.urlEncode(this.toByteArray());
    }

}

export class PublicKey {
    static #CLOUDFLARE_DEMO_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAsdGa7tpezvILOCqnHwxIrZ3EIiscePjssjZbO0t4ooApVn-OZAPZRS1HC7MtXFEJFhhfInfC4t4sEa1EbIgygeyDaczfJTWEemib189NNoq2vLv63PYF7Q--7CWkwZ71FP5U2krZbylhmaRiwKTMb2epKnC9YweMUPvkEqoNu5lo4SzAR-qlDIm9Atr1oP_sV0WjGT_RJQVRwnod_9mhQ9OBFlyizmuUEpucS6pY_eOLpQMj3n9WwG7KLwbyeMwH9tKdSirRZJzCoSrTI0M__6KWOYd8aoZFV0hxyUijvG3fR3M7aYCJuI2WdmzAvKIPxWssU89H9ihTDDuK2kkgHQIDAQAB";
    static #CLOUDFLARE_DEMO_PUB_KEY_ID = "A6wc/97TCL8Uq3pTaSOeZmRXAp0ashaULCkuGq/96+k=";
    static #CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA4rsahmFFVx2QGy_ap9QoeqGO_4LxWlFPbUODzU9Bo98w9mAJ4v4SezAZlSzuxZ-whSKnBsLI3W5_Ffqa5QZq-iwBI1406WdT_zTiNPDh2mFkXG_Im_OGmdqx5iLiI7Fuvm_js7sFgoX4L1MP7saxCY9qsWQ9-EaZmth2qzK0kjGxqoLmOUkCHHBEHpL31alMgPXC9Ww_OcA9ZXMUHyOOuAlOKZzqGmlDmPboz3OwCbKYt1cZ1V9FMz6IsOnZQp8OuYjAy44mpD1HmcYG3Zrn5YVxNqabY20_Wq5phFYl1453MSJlA6LedzIL9g40P14VWOgORWCdVGb0V6icMjuT5QIDAQAB";
    static #CLOUDFLARE_PUB_KEY_ID = "Pr3odZ/fdrNceIga6RDMenB0wC3ubM7rnbKOUnrNWvA=";
    static #FASTLY_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEA3u2Eqv0aOFEyI9Q42gqtgG2eo5Dgm7H8GUTJGdxOI7L8-10Jr1miUeTofM8d2ddSMTiJPNhsoniy3q2l2omwH_KXgEYuCUgUBykrMcse4m7mG2QijluejXwooHN9KtErBi_jlOlC1MRmuD1aYWI_egv78A6zw1wvUJOAQ3twQpCRWkzt9Q7eiAGMaPD_c2Te3oeOPTIuhpKaqKjVaRtNnng-3eRC5uIE8mGu-41iZM2efdcqO68lE1s4z8hLNM_0ZDzm3zMdLwpQYq1Bp0WXXrLYTQWDDu2MTR_aNTJ44wJdYutuK-FeRHQGIxUDTvA5PDq-M3ZuUHk_gAAHzYu12wIDAQAB";
    static #FASTLY_PUB_KEY_ID = "252MlXJMAflvJYZiNQfUjk1SdnNQcDKvtEr/8vrxL5o=";

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
        const dataBuffer = new DataBuffer(tokenBytes);

        const tokenType = dataBuffer.readInt(2);
        const nonce = dataBuffer.readBytes(32);
        const challengeHash = dataBuffer.readBytes(32);
        const tokenKeyID = dataBuffer.readBytes(32);
        const authenticator = dataBuffer.readBytes(256);

        return new Token(tokenType, nonce, challengeHash, tokenKeyID, authenticator);
    }

    toByteArray() {
        const dataBuffer = new DataBuffer();
        dataBuffer.writeInt(this.tokenType, 2);
        dataBuffer.writeBytes(this.nonce);
        dataBuffer.writeBytes(this.challengeHash);
        dataBuffer.writeBytes(this.tokenKeyID);
        dataBuffer.writeBytes(this.authenticator);
        return dataBuffer.toBytes();
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
            const data = Uint8Array.from([].concat(DataBuffer.numberToBytes(this.tokenType, 2), this.nonce, this.challengeHash, this.tokenKeyID));
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
