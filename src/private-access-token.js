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
    static #CLOUDFLARE_DEMO_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAtH_X3l0_vwpR1E1lhRSFOu6XC7P1tyl55PzSOFlz71jmMyKVD4UMLk71iwddv3WY0Q59y5caN5DVnFSPQ91mRX32jvXFbih7wBPOOAoYNmCdaMtJOB_qDtKX-znrRT5Sk5LFEax1OhJy1dH5lxpt2BXTfEoGKTLiK3AtN0EYXBhHM5Bmi0tXvV_8B3NJD4B3C1UnmfLJboVxEe4E4ndKPRki8YceuSIzeNHHOkuj5RicDKblYv-Ba_Ydr1W9ERrT85jDNxDKelfNggpSxq-fBUk0SPea22ZejxAxJzTYng4EgrycXFzy3l4oLw3RhkVU55QpyNOK8BEtFgreg7WEUwIDAQAB";
    static #CLOUDFLARE_DEMO_PUB_KEY_ID = "Rr9-PDgEetJfyA3ULaWUeSPV1cOVFkonMCtCgHaq9yQ=";
    static #CLOUDFLARE_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAscjm_UO_k901rNdCKgLw5bvI4i6M_jDNCIXpfs2LRbtxwLOrUyplqVvML_hVlB5tIDMuj0ihhaOFHose-Y0_UjQnNUGE_vol46VvGgscTMtTjU4xINriap8AMTIygvljEBt6my-nBwkUGhY3U9v5iKC-eWR5bTfvrqFsuIVxafkSfhHqDXB4KLGNjvOOV71GGJ9x4yxA-C2OcULZ1uDDKuvAaMhuiWdF6OzSTXruP9yPg1vmuteavOW1re0YDbCbtK16PhHdSzWym7v_FrvId-2zf26j50FlTd_vl_DcKNDVCgWDoU0uX3cU6V3rSQoVXREEqPr-2ywSGru8ZuXRoQIDAQAB";
    static #CLOUDFLARE_PUB_KEY_ID = "RB3dC_hWTx5VoYXNRCtI-sBi3fvHy4cs-MFgVBnPgYc=";
    static #FASTLY_PUB_KEY = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEApjgfnIRLDa4kgSY8sqkrjeWHYOii_XXwZ1rE_hzbcqL98P5RAth6PbjsdvP7R5ZEbPR0hxnAsPpsnhDpIXQEcTlQS9pmJqymOznDg6ZYFc6AL7ShCBFsyiUne-U-zgjfDp1UxCTfiKwpGuzSSC_BAR7qC3goVRRGV4OjV3jlM9T-Glf4lNjvYDK3ifKQcyq1Ltovr93u94M6f9abiqmNntkCY0-41qbYaxjlOR59o4ywM4VpGsiN4EpFOukDKQes9wtsU0fDZAI3Od4SB_SB9_oGkVv_poQzajO2GxlwUk3vlmm7f8e3BJ9cU_VvBcmCP9E1oBwWOl4cMAoIZ5-UHQIDAQAB";
    static #FASTLY_PUB_KEY_ID = "9LZ-dK5EaMZbESTV4rEstK4oKWSfUnS7tq6WzQoJTTU=";

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
