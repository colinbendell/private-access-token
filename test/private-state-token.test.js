import { should, describe } from 'micro-should';
import * as assert from 'assert';
import { IssueRequest, PrivateStateTokenKeyPair, PrivateStateTokenIssuer, RedeemRequest} from '../privateStateToken.js';

describe('Private-State-Tokens', async () => {
    should('IssueRequest.from()', async () => {

        let secPrivateStateToken = "AAEEVFIqN9o3HN46V8fr0KBj1GnlGTx2hX+Hej8tUG8AOI49fPHAQsjhbVY7m4P8DEG4dZMlsPYDQVS/kKkcG7aNnkm0yL9kUdskhfBc+/4OgH2ILjTj1zVRkest+62csHUN";
        let req = IssueRequest.from(secPrivateStateToken, 0);
        assert.deepStrictEqual(req.count, 1);
        assert.deepStrictEqual(req.nonces[0].toString(), "BFRSKjfaNxzeOlfH69CgY9Rp5Rk8doV/h3o/LVBvADiOPXzxwELI4W1WO5uD/AxBuHWTJbD2A0FUv5CpHBu2jZ5JtMi/ZFHbJIXwXPv+DoB9iC4049c1UZHrLfutnLB1DQ==");

        secPrivateStateToken = "AAoE6MVSc5AT8OyFhghz27roBKy9A1X+Tkjjr5OH9Tx/xvJa6Sl42DuS0lq+tR6gmN/iKvkUIGqlv+4m/M/N1Ww312UBn1/ayaklEjQxJp3gWtEp0YBx2PxXGGJIf24+z5AJBMUKrhoQSLzFTLQUsTNQi793uliKmCNt6BTg6XoTYaE3HztgCJ9ixPyRifwPM079sG1kdW+C17C4N3Hjd4U2yyKlaG9P7DuTIuStxoDNav7lfQXdbssN+e+DHR7tucKELgRJcrjoA7nabuTDGzRJ1Co5P0hPeCmX2up+W0KDDGUAsi9Upoj6IZmFV9OZWhdGXvDmRT5smXkKTq8JpQHoN6ZtAmAdC6492cDRfSu94drW5f3p357qoB94xPVqVDRbdmMEOK2IsHCnMotvCoZSRQsOXKwWqXx2JBWoHOO4wDGeEMEr5YJs+CjzOaSJkSznZvBZm/V1Ud7E2oXZkbVHnKFTge3Sv/DoIO46XjkpdgwA9oKaPjJkTx+1LkZahhCZOi/MBDIzt6q+zmkfAMoynQmym5dty0wjNKgrvOPS2CLdw0fiq7t2RmvppEww33XnWTlkrysgldaOyzEVdTrkGY+4RHpjJYlJaVIljEqUyhKXgD7wAU6uOHLyI0jzu/C+AV6prAQJ1qa8Z1OpchATYr/zWYcoQLGVQf+0YJmlCPuGJOT4hNH0y9zLv/5+gQyIdOGkSlP6HgQuVXRCHbt9PFIsb7dXPANtLekxwgdp5xFlX5rW8iihd1QYnwmjSFCEG7b1m5MEBt9MVIneAgqIzT4ADHYP44bPaC5UDLOW+3kAJhKKNuKoxHAglX3CEqArzIvrM4YdEDIy0CGK5q9HCMbjiF5VcC3exGXItL9YuSClCNRTSCXkcIr3/0o1F23og1ZN/kSnBK6BaIOlekz6e20DSeAD60KzcXUUGlK8wI0z/FOPAsYaMcFt0he2t/iSm7nU9UQrDwPtJ3atpip1XaqIg+M2QcSrLYZUF8nF3dtgh70IFBRC8YGFamLVNboXquMGqTYobwSh/GBZcDowgIEHF3ttJoxjHidfRqWhG2LXP029QONky3iic0ANewAP6fQDvMhF3+TeBSVjk3Rn0XmoJ/WTJLhgocXPxOOGMeEPlkxjjNmzOL+M5B8x4+aqCkRNm76Ico4E64nB5JcYKcMdwYJrplfGpXpq9OB1Az7U0SFZLJYhqv58GD53cgJbFnfto6q3qUvA0nVhhzhIM7Dhfv2vqMNqLtfS9PPC3/kR1DxUxJ/2ieXHdIAyMGUIxUPTN5fh4n08";
        req = IssueRequest.from(secPrivateStateToken, 0);
        assert.deepStrictEqual(req.count, 10);

    });
    should('PrivateStateTokenKeyPair.generate()', async () => {
        const keyPair = PrivateStateTokenKeyPair.generate(7);
        assert.deepEqual(keyPair.id, 7);
        assert.deepEqual(keyPair.publicKey.toString(), 'AAAABwSqh8oivosFN46xxx7zIK10bh07Younm5hZ90HgglQqOFUC8l2/VSlsOlReOHJ2CrfJ6CG1adnTkKJhZ0BtbSPWBwviQtdl64MWJc7sSg9HPvWfTjDigX5ihbzihG8V8aA=');
        assert.deepEqual(keyPair.secretKey.toString(), 'Mzk0MDIwMDYxOTYzOTQ0NzkyMTIyNzkwNDAxMDAxNDM2MTM4MDUwNzk3MzkyNzA0NjU0NDY2Njc5NDY5MDUyNzk2Mjc2NTkzOTkxMTMyNjM1NjkzOTg5NTYzMDgxNTIyOTQ5MTM1NTQ0MzM2NTM5NDI2NDI=');
    });

    should('KeyCommitment', async () => {
        const issuer = PrivateStateTokenIssuer.generate('https://example.com', 11, 0);
        const keyCommitment = issuer.keyCommitment;
        assert.deepEqual(keyCommitment.toString(), '{"https://example.com":{"PrivateStateTokenV3VOPRF":{"protocol_version":"PrivateStateTokenV3VOPRF","id":1,"batchsize":11,"keys":{"0":{"Y":"AAAAAASqh8oivosFN46xxx7zIK10bh07Younm5hZ90HgglQqOFUC8l2/VSlsOlReOHJ2CrfJ6CG1adnTkKJhZ0BtbSPWBwviQtdl64MWJc7sSg9HPvWfTjDigX5ihbzihG8V8aA=","expiry":"253402300799000000"}}}}}');
    });

    should('PrivateStateTokenIssuer.issue()', async () => {
        const issuer = PrivateStateTokenIssuer.generate('https://example.com', 10, 0);

        let secPrivateStateToken = "AAEEVFIqN9o3HN46V8fr0KBj1GnlGTx2hX+Hej8tUG8AOI49fPHAQsjhbVY7m4P8DEG4dZMlsPYDQVS/kKkcG7aNnkm0yL9kUdskhfBc+/4OgH2ILjTj1zVRkest+62csHUN";
        let req = IssueRequest.from(secPrivateStateToken, 0);
        let response = issuer.issue(0, req);

        assert.deepEqual(response.issued, 1);
        assert.deepEqual(response.signed[0].toString(), "BFRSKjfaNxzeOlfH69CgY9Rp5Rk8doV/h3o/LVBvADiOPXzxwELI4W1WO5uD/AxBuIps2k8J/L6rQG9W4+RJcmG2SzdAm64k23oPowQB8X+Bd9HLGyjKrm4U0gRTY0+K8g==");
        assert.deepEqual(response.proof, [
            226, 160, 199, 174,   1, 109, 218, 207, 244,  20, 111,  40,
             98, 204, 175, 235, 152, 180,  21, 142, 116, 212, 101,  83,
            139,  46, 205, 232,  32, 188, 227,  57,  71,  32, 133,   3,
            142, 182, 154,  34, 103,  94, 192,  17,  13, 195, 114, 150,
             29,  95,  56,  81, 254, 146,  37,  48,  11, 235, 144, 215,
            157,  51,  80,  20, 103,  75, 234, 113, 139,  43, 154, 172,
             60,  52, 127, 153, 211, 122,  74, 166,  16, 249, 136, 174,
            185, 250,  13,  88, 133, 141,  89,  89, 191,   1, 182, 220
          ]);
        assert.deepEqual(response.toString(), "AAEAAAAABFRSKjfaNxzeOlfH69CgY9Rp5Rk8doV/h3o/LVBvADiOPXzxwELI4W1WO5uD/AxBuIps2k8J/L6rQG9W4+RJcmG2SzdAm64k23oPowQB8X+Bd9HLGyjKrm4U0gRTY0+K8gBg4qDHrgFt2s/0FG8oYsyv65i0FY501GVTiy7N6CC84zlHIIUDjraaImdewBENw3KWHV84Uf6SJTAL65DXnTNQFGdL6nGLK5qsPDR/mdN6SqYQ+YiuufoNWIWNWVm/Abbc");

        secPrivateStateToken = "AAoE6MVSc5AT8OyFhghz27roBKy9A1X+Tkjjr5OH9Tx/xvJa6Sl42DuS0lq+tR6gmN/iKvkUIGqlv+4m/M/N1Ww312UBn1/ayaklEjQxJp3gWtEp0YBx2PxXGGJIf24+z5AJBMUKrhoQSLzFTLQUsTNQi793uliKmCNt6BTg6XoTYaE3HztgCJ9ixPyRifwPM079sG1kdW+C17C4N3Hjd4U2yyKlaG9P7DuTIuStxoDNav7lfQXdbssN+e+DHR7tucKELgRJcrjoA7nabuTDGzRJ1Co5P0hPeCmX2up+W0KDDGUAsi9Upoj6IZmFV9OZWhdGXvDmRT5smXkKTq8JpQHoN6ZtAmAdC6492cDRfSu94drW5f3p357qoB94xPVqVDRbdmMEOK2IsHCnMotvCoZSRQsOXKwWqXx2JBWoHOO4wDGeEMEr5YJs+CjzOaSJkSznZvBZm/V1Ud7E2oXZkbVHnKFTge3Sv/DoIO46XjkpdgwA9oKaPjJkTx+1LkZahhCZOi/MBDIzt6q+zmkfAMoynQmym5dty0wjNKgrvOPS2CLdw0fiq7t2RmvppEww33XnWTlkrysgldaOyzEVdTrkGY+4RHpjJYlJaVIljEqUyhKXgD7wAU6uOHLyI0jzu/C+AV6prAQJ1qa8Z1OpchATYr/zWYcoQLGVQf+0YJmlCPuGJOT4hNH0y9zLv/5+gQyIdOGkSlP6HgQuVXRCHbt9PFIsb7dXPANtLekxwgdp5xFlX5rW8iihd1QYnwmjSFCEG7b1m5MEBt9MVIneAgqIzT4ADHYP44bPaC5UDLOW+3kAJhKKNuKoxHAglX3CEqArzIvrM4YdEDIy0CGK5q9HCMbjiF5VcC3exGXItL9YuSClCNRTSCXkcIr3/0o1F23og1ZN/kSnBK6BaIOlekz6e20DSeAD60KzcXUUGlK8wI0z/FOPAsYaMcFt0he2t/iSm7nU9UQrDwPtJ3atpip1XaqIg+M2QcSrLYZUF8nF3dtgh70IFBRC8YGFamLVNboXquMGqTYobwSh/GBZcDowgIEHF3ttJoxjHidfRqWhG2LXP029QONky3iic0ANewAP6fQDvMhF3+TeBSVjk3Rn0XmoJ/WTJLhgocXPxOOGMeEPlkxjjNmzOL+M5B8x4+aqCkRNm76Ico4E64nB5JcYKcMdwYJrplfGpXpq9OB1Az7U0SFZLJYhqv58GD53cgJbFnfto6q3qUvA0nVhhzhIM7Dhfv2vqMNqLtfS9PPC3/kR1DxUxJ/2ieXHdIAyMGUIxUPTN5fh4n08";
        req = IssueRequest.from(secPrivateStateToken, 0);
        response = issuer.issue(0, req);
        assert.deepEqual(response.issued, 10);
        assert.deepEqual(response.proof, [
            112,  68,  49, 198,  77,  76, 240,  46, 197, 141, 238, 170,
             25,  61, 107, 194, 217, 132, 189,  67, 179,  87,  80, 234,
            141, 100,  37, 102, 105,  62,   5,  65, 186, 230,  51,  69,
            111, 228,  61, 231, 253, 145,  30, 201,  94, 216,  46, 214,
            143, 187, 206,  57, 178, 179,  15, 209,  58, 114,  17,  85,
            230, 194, 148,  61,  38, 123,  66, 188,  76, 168, 175,  21,
             57, 255,  40,  27, 138, 249,  40, 157, 157,  51, 218, 108,
            216, 204, 105, 146, 239,  90, 250, 161, 109, 236, 250, 156
          ]);
        assert.deepEqual(response.toString(), "AAoAAAAABOjFUnOQE/DshYYIc9u66ASsvQNV/k5I46+Th/U8f8byWukpeNg7ktJavrUeoJjf4tUG69+VWkAR2QMwMiqTyCia/mCgJTZW2u3LztliH6Ut1i5/jScDqOedt4CSwTBv9gTFCq4aEEi8xUy0FLEzUIu/d7pYipgjbegU4Ol6E2GhNx87YAifYsT8kYn8DzNO/bCSm4qQfShPR8iOHIh6yTTdWpeQsBPEbN0bUjl/MpUBGYL6IpA08gYQfOLhE0Y9e9EESXK46AO52m7kwxs0SdQqOT9IT3gpl9rqfltCgwxlALIvVKaI+iGZhVfTmVoXRl7wGbrBk2aG9bFQ9lr+F8hZkv2f4vRRwiY/LoLUQh4lKRkCFiBgFV/ghzsKlazLpImcBDitiLBwpzKLbwqGUkULDlysFql8diQVqBzjuMAxnhDBK+WCbPgo8zmkiZEs52bwWWQKiq4hOyV6Jm5KuGNerH4SLUAPF98RxaHG1onz/wl8ZcHNmrDgStG5pXnwZsXQMwQyM7eqvs5pHwDKMp0JspuXbctMIzSoK7zj0tgi3cNH4qu7dkZr6aRMMN9151k5ZK/U32opcTTO6orFG+ZwR7uFnNp2tpat2nO1azXtaH/BDv6xUcaNDdy3DEQPQv6hVlMECdamvGdTqXIQE2K/81mHKECxlUH/tGCZpQj7hiTk+ITR9Mvcy7/+foEMiHThpEpTBeH70aqLveJEgsOt05BIqMP8ktIWzj34lhjumqBlKQzXXoiq52D2XLeve+VJCmRsBAbfTFSJ3gIKiM0+AAx2D+OGz2guVAyzlvt5ACYSijbiqMRwIJV9whKgK8yL6zOGHe/NzS/edRlQuPc5HHehqo/SITuaN0tAp0bfWvcrrLfZG491BwC1yuiSF3yqsgG7WASugWiDpXpM+nttA0ngA+tCs3F1FBpSvMCNM/xTjwLGGjHBbdIXtrf4kpu51PVEKw/8EtiJUlnViqJVd3wcyb47VNJ5q+g2OiIkn3hC9+vrvA5+epSdKspF6FUc+lbJ15AEofxgWXA6MICBBxd7bSaMYx4nX0aloRti1z9NvUDjZMt4onNADXsAD+n0A7zIRd/kIfranGyLmC6GV9gKbNtHn146MDscec4e8GmznHMmTMZAcxvfzhwZVfW7smVBd41xBOuJweSXGCnDHcGCa6ZXxqV6avTgdQM+1NEhWSyWIar+fBg+d3ICWxZ37aOqt6lLwC2KnnjHt8xPHoECUFc8ldEoLQsMPSAG7ivDqztgCXYZOIt/zM+a9zq8LMhpHh2CwwBgcEQxxk1M8C7Fje6qGT1rwtmEvUOzV1DqjWQlZmk+BUG65jNFb+Q95/2RHsle2C7Wj7vOObKzD9E6chFV5sKUPSZ7QrxMqK8VOf8oG4r5KJ2dM9ps2Mxpku9a+qFt7Pqc");
    });

    should('PrivateStateTokenIssuer.redeem()', async () => {
        const issuer = PrivateStateTokenIssuer.generate('https://example.com', 10, 0);

        const secPrivateStateToken = "AKUAAAAAtVsA7lhWk9bStGA1fzKP/RvaKgcvVDAq1QvzW43xhYO9AamHe6u5wZIfrydStvtAcu0vNU+HXSdsokoaC02taQSYGczrEyU05BIvR2fl0osHsQvC/uTNq9+PQOBxXe8k3pAnRnV5CTOT4CuiuVO2/1JKtDEJMn4Ww51YOj7yLxkQ00Iv7iV8SmCXMnZ3V7ZyM3j/FfSdbolwS5qYSVM/0ucAT6JwcmVkZWVtaW5nLW9yaWdpbnghaHR0cHM6Ly9zaG9lc2J5Y29saW4uZGV2LmNvbTozMDAwdHJlZGVtcHRpb24tdGltZXN0YW1wGmRKygU=";
        const redeemRequest = RedeemRequest.from(secPrivateStateToken);

        assert.deepEqual(redeemRequest.keyID, 0);
        assert.deepEqual(redeemRequest.nonce, [
            181,  91,   0, 238,  88,  86, 147, 214, 210, 180,  96,
             53, 127,  50, 143, 253,  27, 218,  42,   7,  47,  84,
             48,  42, 213,  11, 243,  91, 141, 241, 133, 131, 189,
              1, 169, 135, 123, 171, 185, 193, 146,  31, 175,  39,
             82, 182, 251,  64, 114, 237,  47,  53,  79, 135,  93,
             39, 108, 162,  74,  26,  11,  77, 173, 105
          ]);
        assert.deepEqual(redeemRequest.point.toBytes(), [
            4, 152,  25, 204, 235,  19,  37,  52, 228,  18,  47,  71,
          103, 229, 210, 139,   7, 177,  11, 194, 254, 228, 205, 171,
          223, 143,  64, 224, 113,  93, 239,  36, 222, 144,  39,  70,
          117, 121,   9,  51, 147, 224,  43, 162, 185,  83, 182, 255,
           82,  74, 180,  49,   9,  50, 126,  22, 195, 157,  88,  58,
           62, 242,  47,  25,  16, 211,  66,  47, 238,  37, 124,  74,
           96, 151,  50, 118, 119,  87, 182, 114,  51, 120, 255,  21,
          244, 157, 110, 137, 112,  75, 154, 152,  73,  83,  63, 210,
          231
        ]);
        assert.deepEqual(redeemRequest.clientData, [
            162, 112, 114, 101, 100, 101, 101, 109, 105, 110, 103,  45,
            111, 114, 105, 103, 105, 110, 120,  33, 104, 116, 116, 112,
            115,  58,  47,  47, 115, 104, 111, 101, 115,  98, 121,  99,
            111, 108, 105, 110,  46, 100, 101, 118,  46,  99, 111, 109,
             58,  51,  48,  48,  48, 116, 114, 101, 100, 101, 109, 112,
            116, 105, 111, 110,  45, 116, 105, 109, 101, 115, 116,  97,
            109, 112,  26, 100,  74, 202,   5
          ]);
        assert.deepEqual(redeemRequest.decodeClientData(), {
            'redeeming-origin': 'https://shoesbycolin.dev.com:3000',
            'redemption-timestamp': 1682622981
          });
        assert.deepEqual(redeemRequest.toString(), secPrivateStateToken);

        const redeemResponse = issuer.redeem(redeemRequest);
        assert.notEqual(redeemResponse.toString(), null);
    });

});
