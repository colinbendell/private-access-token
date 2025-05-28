import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import { PublicKey, Challenge, Token } from '../src/private-access-token.js';
import { sha256 } from '../src/utils.js';

describe('Private-Access-Tokens', async () => {
    it('PublicKey.from()', async () => {
        const fastly = PublicKey.FASTLY;

        assert.deepStrictEqual(PublicKey.from(fastly), fastly);
        assert.deepStrictEqual(PublicKey.from(fastly.sPKI), fastly);
        assert.deepStrictEqual(PublicKey.from(fastly.issuerName), fastly);
        assert.deepStrictEqual(PublicKey.from(await fastly.toTokenKeyID()), fastly);
    });

    it('Challenge.from()', async () => {
        const challenge = Challenge.from("AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=");
        assert.deepStrictEqual(challenge.issuerName, "pat-issuer.cloudflare.com");
        assert.deepStrictEqual(challenge.getTokenKey(), PublicKey.CLOUDFLARE);
        assert.deepStrictEqual(challenge.redemptionContext, []);
        assert.deepStrictEqual(challenge.originInfo, "");
    });

    it('Challenge.toString()', async () => {
        let challenge = new Challenge(Token.BLIND_RSA, "pat-issuer.cloudflare.com", "", "");
        assert.deepStrictEqual(challenge.toString(), "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=");

        // with origin
        challenge = new Challenge(Token.BLIND_RSA, "pat-issuer.cloudflare.com", "", "example.com");
        assert.deepStrictEqual(challenge.toString(), "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAtleGFtcGxlLmNvbQ==");

        //  some context value "asdf" which should be expanded to 32 bytes
        challenge = new Challenge(Token.BLIND_RSA, "pat-issuer.cloudflare.com", "asdf", "example.com");
        assert.deepStrictEqual(challenge.toString(), "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGFzZGYAC2V4YW1wbGUuY29t");

        challenge = new Challenge(Token.BLIND_RSA, "pat-issuer.cloudflare.com", Array(32).fill().map((_, i) => i).reverse().join(), "example.com");
        assert.deepStrictEqual(challenge.toString(), "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20gLDEzLDEyLDExLDEwLDksOCw3LDYsNSw0LDMsMiwxLDAAC2V4YW1wbGUuY29t");

        challenge = new Challenge(Token.BLIND_RSA, "pat-issuer.cloudflare.com", Array(64).fill().map((_, i) => i).reverse().join(), "example.com");
        assert.deepStrictEqual(challenge.toString(), "AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20gLDEzLDEyLDExLDEwLDksOCw3LDYsNSw0LDMsMiwxLDAAC2V4YW1wbGUuY29t");

    });

    it('Token.from()', async () => {
        const token = Token.from("AAKX5pNIYklVMbf4MFBRPCrv7lsehPyLIb-JrxRRhBn3iH5KiF5TAqGbeBQ6wy0MSzGrQl-h4QSDP-eRlprUYGADYGxwjWIWHdmidCezltPXnOAwu_H7uuKfaERZm_w9BEVQf5R1vludYDOk_kapvOVJC43mFLJV5ibvDk3jwAgRwqiBUdBJogdhNtCJ8SNULbBhU8Y7k3Q67C76LjVf-byGPDFNilZKVtaGIzJU4qzKnegpICe36SPPih5tikp1h5wZkqa3uEBc_p649YmvdwzpXIVIerDX2G7R_gmWjA_w5dsHia3aQ8brx3t0EdN9D0dBnxBhu9-mGUgQk92SiohAmEFCttl8LKhQBFFfiwNuEfRE-JGil1vHPIGqF1np1ekH1Gll-8Qr0Cxb1cFdVL3oz641-UF35uCe6D4-xlJObcIhfqYc7NONo2-l4V9D_IW6WBJIpxjgRk5uPjWWrNft");
        assert.deepStrictEqual(token.tokenType, Token.BLIND_RSA);
        // pat-issuer.cloudflare.com
        assert.deepStrictEqual(token.tokenKeyID, [96, 108, 112, 141, 98, 22, 29, 217, 162, 116, 39, 179, 150, 211, 215, 156, 224, 48, 187, 241, 251, 186, 226, 159, 104, 68, 89, 155, 252, 61, 4, 69]);
        assert.deepStrictEqual(token.nonce, [151, 230, 147, 72, 98, 73, 85, 49, 183, 248, 48, 80, 81, 60, 42, 239, 238, 91, 30, 132, 252, 139, 33, 191, 137, 175, 20, 81, 132, 25, 247, 136]);
        assert.deepStrictEqual(token.challengeHash, [126, 74, 136, 94, 83, 2, 161, 155, 120, 20, 58, 195, 45, 12, 75, 49, 171, 66, 95, 161, 225, 4, 131, 63, 231, 145, 150, 154, 212, 96, 96, 3]);
        assert.deepStrictEqual(token.authenticator, [80, 127, 148, 117, 190, 91, 157, 96, 51, 164, 254, 70, 169, 188, 229, 73, 11, 141, 230, 20, 178, 85, 230, 38, 239, 14, 77, 227, 192, 8, 17, 194, 168, 129, 81, 208, 73, 162, 7, 97, 54, 208, 137, 241, 35, 84, 45, 176, 97, 83, 198, 59, 147, 116, 58, 236, 46, 250, 46, 53, 95, 249, 188, 134, 60, 49, 77, 138, 86, 74, 86, 214, 134, 35, 50, 84, 226, 172, 202, 157, 232, 41, 32, 39, 183, 233, 35, 207, 138, 30, 109, 138, 74, 117, 135, 156, 25, 146, 166, 183, 184, 64, 92, 254, 158, 184, 245, 137, 175, 119, 12, 233, 92, 133, 72, 122, 176, 215, 216, 110, 209, 254, 9, 150, 140, 15, 240, 229, 219, 7, 137, 173, 218, 67, 198, 235, 199, 123, 116, 17, 211, 125, 15, 71, 65, 159, 16, 97, 187, 223, 166, 25, 72, 16, 147, 221, 146, 138, 136, 64, 152, 65, 66, 182, 217, 124, 44, 168, 80, 4, 81, 95, 139, 3, 110, 17, 244, 68, 248, 145, 162, 151, 91, 199, 60, 129, 170, 23, 89, 233, 213, 233, 7, 212, 105, 101, 251, 196, 43, 208, 44, 91, 213, 193, 93, 84, 189, 232, 207, 174, 53, 249, 65, 119, 230, 224, 158, 232, 62, 62, 198, 82, 78, 109, 194, 33, 126, 166, 28, 236, 211, 141, 163, 111, 165, 225, 95, 67, 252, 133, 186, 88, 18, 72, 167, 24, 224, 70, 78, 110, 62, 53, 150, 172, 215, 237]);

        assert.ok(token.verifyTokenType());
        const challenge = Challenge.from("AAIAGXBhdC1pc3N1ZXIuY2xvdWRmbGFyZS5jb20AAAA=");
        assert.ok(await token.verifyChallengeHash(challenge));

        PublicKey.CLOUDFLARE.sPKI = "MIIBUjA9BgkqhkiG9w0BAQowMKANMAsGCWCGSAFlAwQCAqEaMBgGCSqGSIb3DQEBCDALBglghkgBZQMEAgKiAwIBMAOCAQ8AMIIBCgKCAQEAmSYx82S-vjLRtQnwDoTUWfs-F-Hi-DRaYWzsCX96xyDJBsiM44vH3e84_i0ylmG4wHPdbDqOs-9hxtq2yC-5Ays-nZPHMmj-BATD7eCP8tff3gbELIvHB6suJ0Ov8j598aYWGzlna7KdXhdjuo7vVMUK7_2hoSO327Ph7hwZYODpPq8hQD9-EsghYZ5k13WxlZzx2DyqqVWBfUoJukkmuZwGW_nA2_uYwUwmOBoFmNSQh1FJD0MRRTrQrjvopK7mhVZL6y8Lt2cNdLdqEe4hxb_DiKlAzIpZIFpcG-VTmlREKGxQJEde4bCwTo6imlDb72prF9QxT6-cyS3FKFhdLwIDAQAB";

        PublicKey.CLOUDFLARE.keyID = await PublicKey.CLOUDFLARE.toTokenKeyID();
        assert.ok(token.verifyTokenKeyID(PublicKey.CLOUDFLARE));
        assert.ok(await token.verifyAuthenticator(PublicKey.CLOUDFLARE));
        assert.ok(await token.verify(challenge, PublicKey.CLOUDFLARE));
    });
});
