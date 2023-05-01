import { Base64, DataBuffer, CBOR} from './utils.js';

import { p384 as ec, hashToCurve} from '@noble/curves/p384';
// import { sha384, sha512 } from '@noble/hashes/sha512';
import { sha512 } from '@noble/hashes/sha512';
import { hash_to_field } from '@noble/curves/abstract/hash-to-curve';

const Point = ec.ProjectivePoint;

const MODULUS_P384 = ec.CURVE.p;
const ORDER_P384 = ec.CURVE.n;

const ORDER_P384_LEN = 384 / 8;
const TRUST_TOKEN_NONCE_LEN = 64;
const DEFAULT_HOST = "https://localhost:8444";
const DEFAULT_REDEMPTION_RECORD = DataBuffer.stringToBytes("dummy redemption record");

/**
 * An elliptic curve point used in elliptic curve operations over the curve P-384.
 *
 * Scalar multiplication can be written as `s*p` or `p*s`, where `s` is a
 * `Scalar` and `p` is an `ECPoint`. An `ECPoint` is encoded as an X9.62
 * uncompressed point.
 *
 * @param {Buffer} value An X9.62 encoded elliptic curve point.
 * @param {PointJacobi} point The `PointJacobi` representation of the point.
 */
export class ECPoint {
    /**
     * @param {Uint8Array} value The byte string to read values from.
     */
    constructor(value) {
        // super(value)
        this.#value = value;
        this.#point = ec.ProjectivePoint.fromHex(Uint8Array.from(this.#value));
    }

    static get length() { return 1 + 2 * ORDER_P384_LEN; }

    #value;
    #point;

    /**
     * @returns {Buffer} The point as an X9.62 uncompressed byte string.
     */
    toBytes() {
        return this.#value;
    }

    /**
     * @returns {string} The point as a Base64 string.
     */
    toString() {
        return Base64.encode(this.toBytes());
    }

    toJSON() {
        return this.toBytes();
    }

    toPoint() {
        return this.#point;
    }

    [Symbol.for('nodejs.util.inspect.custom')]() {
        return this.toString();
    }
}

/**
 * > Deterministically maps an array of bytes x to an element of Group.
 * > The map must ensure that, for any adversary receiving R = HashToGroup(x),
 * > it is computationally difficult to reverse the mapping. This function is
 * > optionally parameterized by a domain separation tag (DST); see Section 4.
 * > Security properties of this function are described in #I-D.irtf-cfrg-hash-to-curve
 *
 * > Use hash_to_curve with suite P384_XMD:SHA-384_SSWU_RO_ #I-D.irtf-cfrg-hash-to-curve
 * > and DST = "HashToGroup-" || contextString.
 *
 * Converts a string to one or more elements of the finite field F of P-384.
 * @param {string} message The message to convert.
 * @returns {Array<ECPoint>} A list of the form `(u_0, ..., u_(count - 1))` where
 *        `u_i = (e_0, ..., e_(m - 1))` and m is the extension degree of F.
 *        For P-384, m is equal to 1.
 */
function hashToGroup(message, dst="TrustToken VOPRF Experiment V2 HashToGroup\0") {
    return hashToCurve(Uint8Array.from(message), {DST: dst, p: MODULUS_P384, m: 1, k: 192, expand: 'xmd', hash: sha512});
}

/**
 * Converts a string to one or more scalars.
 * This is similar to `hash_to_field` except that the modulus used is `ORDER_P384` instead of `MODULUS_P384`.
 *
* @param {string} message The message to convert.
 * @param {number} count The number of field elements to generate.
 * @param {string} dst The domain separation tag.
 * @returns {Array<ECPoint>} A list of the form `(u_0, ..., u_(count - 1))` where
 *        `u_i = (e_0, ..., e_(m - 1))` and m is the extension degree of F.
 *        For P-384, m is equal to 1.
 */
// function hashToScalar(msg, count, dst = "HashToScalar-OPRFV1-\x01-P384-SHA384\0") {
function hashToScalar(msg, count, dst = "TrustToken VOPRF Experiment V2 HashToScalar\0") {
    msg = Uint8Array.from(DataBuffer.stringToBytes(msg));
    return hash_to_field(msg, count, {DST: dst, p: ORDER_P384, m: 1, k: 192, expand: 'xmd', hash: sha512});
}

/**
 * A public key for a trust token issuer.
 * The value of a secret key is a scalar. The secret key is used to sign
 * blinded tokens from the client.
 */
export class PrivateStateTokenSecretKey {
    /**
     * @param {number} id The ID of the secret key.
     * @param {number} value The value of the secret key.
     */
    constructor(id, value) {
        this.id = id;
        this.value = value;
    }

    /**
     * @returns {Buffer} Returns the value of the secret key as bytes.
     */
    toBytes() {
        return this.value;
    }

    /**
     *
     * @returns {string} Returns the value of the secret key as a Base64 string.
     */
    toString() {
        return Base64.encode(this.toBytes());
    }
}

/**
 * A public key for a trust token issuer.
 * The value of a public key is an elliptic curve point. A public key is
 * generated from a secret key.
 */
export class PrivateStateTokenPublicKey {
    /**
     * @param {number} id The ID of the secret key.
     * @param {ECPoint} value The value of the secret key.
     */
    constructor(id, value) {
        this.id = id;
        this.value = value;
    }

    /**
     * Returns the public key as bytes.
     * The structure takes the form:
     * ```
     * struct {
     *    uint32 id;
     *    ECPoint pub;
     * } TrustTokenPublicKey;
     * ```
     * @returns {Uint8Array} Returns the public key as bytes.
     */
    toBytes() {
        const buffer = new DataBuffer();
        buffer.writeInt(this.id, 4);
        buffer.writeBytes(this.value.toBytes());

        return buffer.toBytes();
    }

    /**
     * @returns {string} Returns the public key as a Base64 string suitable for use in key commitments.
     */
    toString() {
        return Base64.encode(this.toBytes());
    }
}

/**
 * A key pair for a trust token issuer.
 */
export class PrivateStateTokenKeyPair {
    /**
     * @param {number} id The ID associated with the key pair.
     * @param {PrivateStateTokenPublicKey} publicKey The public component of the key pair.
     * @param {PrivateStateTokenSecretKey} secretKey The secret component of the key pair.
     * @returns {PrivateStateTokenKeyPair} The key pair.
     */
    constructor(id, publicKey, secretKey) {
        this.id = id;
        this.publicKey = publicKey;
        this.secretKey = secretKey;
    }

    /**
     * Generates a key pair for a trust token issuer.
     * For testing purposes, the secret value is fixed. The public value is the
     * product of the secret value and the generator of P-384.
     *
     * @param {number} id The ID associated with the key pair.
     * @returns {PrivateStateTokenKeyPair} The key pair.
     */
    static generate(id = 0) {
        // priv cannot be 0
        // const priv = ec.utils.randomPrivateKey();
        // const priv = Uint8Array.from(DataBuffer.numberToBytes(ORDER_P384 - 1n, 48));
        const priv = ORDER_P384 - 1n;
        // Changes to the public key must be reflected in the key commitment
        const pub = ec.getPublicKey(priv, false);
        const publicKey = new PrivateStateTokenPublicKey(id, new ECPoint(pub));
        const secretKey = new PrivateStateTokenSecretKey(id, priv);
        return new PrivateStateTokenKeyPair(id, publicKey, secretKey);

    }
}

/**
 * A key commitment for the trust token issuer.
 * A key commitment defines the trust token protocol version and public key
 * information that the issuer will use for trust token operations.
 * @param {string} protocol_version The issuer protocol version.
 * @param {number} id The ID of the key commitment.
 * @param {number} batchsize The batch size for token issuance.
 * @param {Array<PrivateStateTokenPublicKey>} publicKeys The public keys for the issuer.
 * @param {string} host The server origin that maps to this key commitment.
 * @returns {KeyCommitment} The key commitment.
 */
export class KeyCommitment {
    constructor(protocol_version, id, batchsize, publicKeys, host) {
        this.protocol_version = protocol_version;
        this.id = id;
        this.batchsize = batchsize;
        this.publicKeys = publicKeys;
        this.host = host;
    }

    toJSON() {
        const keyCommitment = {
            "protocol_version": this.protocol_version,
            "id": this.id,
            "batchsize": this.batchsize,
            "keys": {}
        };
        for (const key of this.publicKeys) {
            keyCommitment["keys"][key.id] = {
                "Y": key.toString(),
                // epoch timestamp in microseconds
                // Friday, December 31, 9999 11:59:59 PM GMT
                "expiry": "253402300799000000",
            };
        }
        return {
            [this.host]: {
                [this.protocol_version]: keyCommitment
            }
        };
    }

    toString() {
        return JSON.stringify(this.toJSON());
    }
}

/**
 * A trust token issuance request.
 */
export class IssueRequest {
    /**
     * @param {number} count The number of token nonces in the request.
     * @param {Array<ECPoint>} nonces A list of elliptic curve points to be used as token nonces.
     */
    constructor(nonces) {
        this.nonces = nonces;
    }

    get count() {
        return this.nonces.length;
    }

    /**
     * Creates an `IssueRequest` from a Base64 string.
     *
     * The decoded byte string must have the form:
     * ```
     * struct {
     *   uint16 count;
     *   ECPoint nonces[count];
     * } IssueRequest;
     * ```
     * @param {string} s The Base64 string to decode.
     * @result {IssueRequest} Returns the decoded `IssueRequest`.
     */
    static from(s) {
        const decodedBytes = Base64.decode(s);
        const bytes = new DataBuffer(decodedBytes);

        const count = bytes.readInt(2);
        const nonces = [];
        while (nonces.length < count) {
            const value = bytes.readBytes(ECPoint.length);
            const ecPoint = value?.length === ECPoint.length ? new ECPoint(value) : null;
            nonces.push(ecPoint);
        }

        return new IssueRequest(nonces.filter(n => n !== null));
    }

    toBytes() {
        const bytes = new DataBuffer();
        bytes.writeInt(this.count, 2);
        for (const nonce of this.nonces) {
            bytes.writeBytes(nonce.toBytes());
        }
        return bytes.buffer;
    }

    toString() { return Base64.encode(this.toBytes()); }

    toJSON() { return this.toBytes(); }

    [Symbol.for('nodejs.util.inspect.custom')]() { return this.toString(); }
}

/**
 * A trust token issuance request.
 */
class SignedNonce {
    /**
     * @param {ECPoint} value The elliptic curve point representing the signed token.
     */
    constructor(point) {
        this.#point = point;
    }

    #point;

    toPoint() { return this.#point; }

    toBytes() {
        return Array.from(this.#point.toRawBytes(false));
    }

    toString() { return Base64.encode(this.toBytes()); }

    toJSON() { return this.toBytes(); }

    [Symbol.for('nodejs.util.inspect.custom')]() { return this.toString(); }
}

/**
 * A trust token public key.
 */
export class IssueResponse {
    /**
     *
     * @param {number} issued: The number of tokens issued.
     * @param {number} keyID: The ID of the key used for signing.
     * @param {Array<SignedNonce} signed: The list of signed nonces.
     * @param {Uint8Array} proof: The DLEQ proof.
     */
    constructor(keyID, signed, proof) {
        this.keyID = keyID;
        this.signed = signed;
        this.proof = proof;
    }

    get issued() { return this.signed.length; }

    /**
     * Returns the issue response as bytes.
     * The structure has the form:
     * ```
     * struct {
     *   uint16 issued;
     *   uint32 key_id = keyID;
     *   SignedNonce signed[issued];
     *   opaque proof<1..2^16-1>; // Length-prefixed form of DLEQProof.
     * } IssueResponse;
     *
     * @returns {Uint8Array} The issue response as bytes.
     */
    toBytes() {
        const buf = new DataBuffer();
        buf.writeInt(this.issued, 2);
        buf.writeInt(this.keyID, 4);
        for (const nonce of this.signed) {
            buf.writeBytes(nonce.toBytes());
        }
        buf.writeInt(this.proof.length, 2);
        buf.writeBytes(this.proof);
        return buf.toBytes();
    }

    toString() { return Base64.encode(this.toBytes()); }

    [Symbol.for('nodejs.util.inspect.custom')]() { return this.toString(); }
}

/**
 * A trust token redemption request.
 */
export class RedeemRequest {
    get contextString() { return "" }

    /**
     * @param {number} keyID The ID of the key used to sign the trust token.
     * @param {Uint8Array} nonce The nonce part of the token.
     * @param {ECPoint} point The elliptic curve point part of the token.
     * @param {Uint8Array} clientData Client data associated with the request.
     */
    constructor(keyID, nonce, point, clientData) {
        this.keyID = keyID;
        this.nonce = nonce;
        this.point = point;
        this.clientData = clientData;
    }

    decodeClientData() {
        return CBOR.decode(this.clientData);
    }

    /**
     * Creates a `RedeemRequest` from a Base64 string.
     *
     * The decoded byte string must have the form:
     * ```
     * struct {
     *   uint32 key_id;
     *   opaque nonce<nonce_size>;
     *   ECPoint W;
     * } Token;
     *
     * struct {
     *   opaque token<1..2^16-1>; // Bytestring containing a serialized Token struct.
     *   opaque client_data<1..2^16-1>;
     * } RedeemRequest;
     *
     * ```
     * @param {string} s The Base64 string to decode.
     */
    static from(s) {
        const decodedBytes = Base64.decode(s);
        const bytes = new DataBuffer(decodedBytes);

        const tokenLen = bytes.readInt(2);
        const keyID = bytes.readInt(4);
        const nonce = bytes.readBytes(TRUST_TOKEN_NONCE_LEN);

        const value = bytes.readBytes(ECPoint.length)
        const point = new ECPoint(value);

        const clientDataLen = bytes.readInt(2);
        const clientData = bytes.readBytes(clientDataLen);
        // const redemptionTime = bytes.readInt(4);

        return new RedeemRequest(keyID, nonce, point, clientData);
    }

    toBytes() {
        const buf = new DataBuffer();
        buf.writeInt(this.nonce.length + this.point.toBytes().length + 4, 2);
        buf.writeInt(this.keyID, 4);
        buf.writeBytes(this.nonce);
        buf.writeBytes(this.point.toBytes());
        buf.writeInt(this.clientData.length, 2);
        buf.writeBytes(this.clientData);
        return buf.toBytes();
    }

    toString() { return Base64.encode(this.toBytes()); }

    [Symbol.for('nodejs.util.inspect.custom')]() { return this.toString(); }
}

/**
 * The response to a trust token redemption request.
 * The client should treat the entire response as the redemption record.
 * By default, for testing purposes, this class returns a fixed byte string as the
 * redemption record.
 */
export class RedeemResponse {
    /**
     * @param {Uint8Array} record The redemption record.
     */
    constructor(record = DEFAULT_REDEMPTION_RECORD) {
        this.record = record;
    }

    toBytes() { return this.record; }

    toString() { return Base64.encode(this.record); }

    [Symbol.for('nodejs.util.inspect.custom')]() { return this.toString(); }
}

/**
 * A trust token issuer implementation.
 *
 * For simplicity the issuer has a single key pair.
 */
export class PrivateStateTokenIssuer {

    static get KEY_COMMITMENT_ID() { return 1; }
    static get PROTOCOL_VERSION() { return "PrivateStateTokenV3VOPRF"; }

    /**
     * @param {PrivateStateTokenKeyPair} keyPair A key pair to use for trust token operations.
     * @param {number} maxBatchSize The max batch size for trust tokens.
     * @param {string} host The server origin for this issuer.
     */
    constructor(keyPair, maxBatchSize, host) {
        this.keyPair = keyPair;
        this.maxBatchSize = maxBatchSize;
        this.host = host;
        this.keyCommitment = new KeyCommitment(
            PrivateStateTokenIssuer.PROTOCOL_VERSION,
            PrivateStateTokenIssuer.KEY_COMMITMENT_ID,
            this.maxBatchSize,
            [this.keyPair.publicKey],
            this.host
        );
    }

    /**
     * Creates a trust token issuer. A key pair is generated and used to
     * initialize the issuer.
     *
     * @returns {PrivateStateTokenIssuer} The trust token issuer.
     */

    static generate(host = DEFAULT_HOST, maxBatchSize = 10, id=0) {
        const keyPair = PrivateStateTokenKeyPair.generate(id);
        const issuer = new PrivateStateTokenIssuer(keyPair, maxBatchSize, host);
        return issuer;
    }

    /**
     * Parses an issuance request and returns a response with a valid DLEQ proof.
     *
     * The issuance request is based on the BlindEvaluate function:
     * ```
     * Input:
     *
     *   Scalar skS
     *   Element pkS
     *   Element blindedElement
     *
     * Output:
     *
     *   Element evaluatedElement
     *   Proof proof
     *
     * Parameters:
     *
     *   Group G
     *
     * def BlindEvaluate(skS, pkS, blindedElement):
     *   evaluatedElement = skS * blindedElement
     *   blindedElements = [blindedElement]     // list of length 1
     *   evaluatedElements = [evaluatedElement] // list of length 1
     *   proof = GenerateProof(skS, G.Generator(), pkS,
     *                         blindedElements, evaluatedElements)
     *   return evaluatedElement, proof
     * ```
     *
     * @param {number} keyId The key ID to use for this issuance.
     * @param {IssueRequest} request The issuance request.
     * @returns {IssueResponse} The issuance response.
     */
    issue(keyId, request) {
        // console.debug(`Issuance request:`, request);
        const secretKey = this.keyPair.secretKey;
        const count = request.nonces.length;
        const exponentList = [];
        const signedNonces = [];

        const batch = Array.from(this.keyPair.publicKey.value.toBytes());
        for (const blindedToken of request.nonces) {
            // const blindedToken = request.nonces[i];
            const z = blindedToken.toPoint().multiply(ec.utils.normPrivateKeyToScalar(secretKey.value));
            signedNonces.push(new SignedNonce(z));

            batch.push(...blindedToken.toBytes());
            batch.push(...z.toRawBytes(false));
        }

        // Batch DLEQ
        for (let i = 0; i < count; i++) {
            const buf = new DataBuffer();
            buf.writeString("DLEQ BATCH\0");
            buf.writeBytes(batch);
            buf.writeInt(i, 2);
            const exponent = hashToScalar(buf.toBytes(), 1)[0][0];
            exponentList.push(exponent);
        }

        let blindedTokenBatch = ec.ProjectivePoint.ZERO;
        for (let i = 0; i < count; i++) {
            const blindedToken = request.nonces[i];
            const exponent = exponentList[i];
            blindedTokenBatch = blindedTokenBatch.add(blindedToken.toPoint().multiply(exponent));
        }

        let zBatch = ec.ProjectivePoint.ZERO;
        for (let i = 0; i < count; i++) {
            const z = signedNonces[i];
            const e = exponentList[i];
            zBatch = zBatch.add(z.toPoint().multiply(e));
        }
        const proof = this.#generateDLEQProof(this.keyPair, blindedTokenBatch, zBatch);

        return new IssueResponse(keyId, signedNonces, proof);
    }

    /**
     * Parses an issuance request and returns a response with a valid DLEQ proof.
     *
     * @param {PrivateStateTokenKeyPair} key_pair The issuer's key pair.
     * @param {Point} btBatch The batched form of the blinded tokens.
     * @param {Point} zBatch The batched form of the signed tokens.
     */
    #generateDLEQProof(keyPair, btBatch, zBatch) {
        // Fix the random number r
        const r = ORDER_P384 - 1n;
        const k0 = ec.ProjectivePoint.BASE.multiply(r);
        const k1 = btBatch.multiply(r);

        const buf = new DataBuffer();
        buf.writeString("DLEQ\0");
        buf.writeBytes(keyPair.publicKey.value.toBytes());
        buf.writeBytes(btBatch.toRawBytes(false));
        buf.writeBytes(zBatch.toRawBytes(false));
        buf.writeBytes(k0.toRawBytes(false));
        buf.writeBytes(k1.toRawBytes(false));

        const c = hashToScalar(buf.toBytes(), 1)[0][0];
        const u = (r + c * ec.utils.normPrivateKeyToScalar(keyPair.secretKey.value)) % ORDER_P384;

        const result = [].concat(
            DataBuffer.numberToBytes(c, ORDER_P384_LEN),
            DataBuffer.numberToBytes(u, ORDER_P384_LEN)
        );
        return result;
    }
    /**
     * Parses an issuance request and returns a response with a valid DLEQ proof.
     *
     * This method ignores the input request and simply returns a redemption
     * response with a fixed byte string as the redemption record.
     *
     * Input:
     *
     *   Scalar skS
     *   PrivateInput input
     *
     * Output:
     *
     *   opaque output[Nh]
     *
     * Parameters:
     *
     *   Group G
     *
     * Errors: InvalidInputError
     *
     * def Evaluate(skS, input):
     *   inputElement = G.HashToGroup(input)
     *   if inputElement == G.Identity():
     *     raise InvalidInputError
     *   evaluatedElement = skS * inputElement
     *   issuedElement = G.SerializeElement(evaluatedElement)
     *
     *   hashInput = I2OSP(len(input), 2) || input ||
     *               I2OSP(len(issuedElement), 2) || issuedElement ||
     *               "Finalize"
     *   return Hash(hashInput)
     *
     * > Deterministically maps an array of bytes x to an element of Group.
     * > The map must ensure that, for any adversary receiving R = HashToGroup(x),
     * > it is computationally difficult to reverse the mapping. This function is
     * > optionally parameterized by a domain separation tag (DST); see Section 4.
     * > Security properties of this function are described in #I-D.irtf-cfrg-hash-to-curve
     *
     * > Use hash_to_curve with suite P384_XMD:SHA-384_SSWU_RO_ #I-D.irtf-cfrg-hash-to-curve
     * > and DST = "HashToGroup-" || contextString.
     *
     * @param {RedeemRequest} request The redemption request.
     * @returns {RedeemResponse} The redemption response.
     */
    redeem(request, redemptionRecord) {
        // console.debug(`Redeem request:`, request);
        // const evaluatedElement = hashToCurve(Uint8Array.from(request.nonce), {DST: "HashToGroup-OPRFV1-\x01-P384-SHA384\0"});
        const evaluatedElement = hashToGroup(request.nonce);
        const issuedElement = evaluatedElement.multiply(ec.utils.normPrivateKeyToScalar(this.keyPair.secretKey.value));

        if (request.point.toPoint().equals(issuedElement)) {
            return new RedeemResponse(redemptionRecord);
        }
        return null;
    }
}
