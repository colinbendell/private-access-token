import { Base64, ByteBuffer, CBOR, P384} from './utils.js';
import { VOPRF_P384, VOPRF_P384_Draft7, Point } from './oprfv1.js';
import { sha256 } from '@noble/hashes/sha256';

const DEFAULT_HOST = "https://localhost:8444";

/**
 * A key pair for a trust token issuer.
 */
export class PrivateStateTokenKeyPair {

    /**
     * @param {Point} publicKey The public key
     */
    publicKey;

    /**
     * @param {number} secretKey The secret key
     */
    secretKey;

    /**
     * @returns {number} The expiry of the key pair.
     */
    expiry;

    /**
     * Creates a new key pair for a trust token issuer.
     * @param {number} id The legacy-token-key-ID associated with the key pair (least significant byte)
     * @param {number[]} tokenKeyID The token-key-ID (or `sha(x509.1(key))`) associated with the key pair
     * @param {Point} publicKey The public component of the key pair.
     * @param {number} secretKey The secret component of the key pair.
     * @param {number} expiry The expiry of the key pair.
     */
    constructor(id, tokenKeyID, publicKey, secretKey, expiry) {

        // TODO: validate ID and tokenKeyID consistency, for now we just trust
        this.id = id;
        this.tokenKeyID = tokenKeyID
        this.publicKey = publicKey;

        if (secretKey instanceof Uint16Array || Array.isArray(secretKey)) {
            secretKey = ByteBuffer.bytesToNumber(Array.from(secretKey));
        }
        this.secretKey = secretKey;

        expiry = expiry || Date.now() + 90*24*60*60*1000; //+90 days default
        // quick sanitation to ensure that we are in microseconds
        expiry = expiry * (10**(Math.ceil(Math.max(16-Math.ceil(Math.log10(expiry)), 0)/3)*3))
        this.expiry = expiry;
    }

    /**
     * Convenience method to produce a valid JWK representation of the key pair.
     * @param {boolean} secure If true, the private key will be included in the JWK.
     * @returns {Object} Returns a JWK representation of the key pair.
     */
    toJWK(secure = false) {
        const jwk = {
            kty: 'EC',
            crv: 'P-384',
            use: 'sig',
            kid: this.id,
            "x5t#S256": Base64.urlEncode(this.tokenKeyID),
            x: Base64.urlEncode(VOPRF_P384.serializeScalar(this.publicKey.x)),
            y: Base64.urlEncode(VOPRF_P384.serializeScalar(this.publicKey.y)),
            exp: Math.floor(this.expiry / 1000 / 1000), //assume seconds since epoch; second resolution
        };
        if (secure) {
            jwk.d = Base64.urlEncode(VOPRF_P384.serializeScalar(this.secretKey));
        }

        return jwk;
    }

    /**
     * Creates a key pair from a JWK representation. Assumes a structure with the following fields:
     * - kty: 'EC'
     * - crv: 'P-384'
     * - kid: The ID associated with the key pair.
     * - x: The x coordinate of the public key.
     * - y: The y coordinate of the public key.
     * - d: The value of the secret key.
     * - exp: The expiry of the key pair in seconds since the epoch.
     *
     * @param {Object|number} data The JWK representation of the key pair.
     * @returns {PrivateStateTokenKeyPair} The key pair.
     */
    static from(data) {
        if (data instanceof PrivateStateTokenKeyPair) {
            return data;
        }
        if (data?.x && data?.y && data?.d) {
            const x = Base64.decode(data.x);
            const y = Base64.decode(data.y);
            const d = Base64.decode(data.d);
            // jwk typically uses milliseconds for the exp field, we need microseconds
            const expiry = data.exp;
            const publicKey = Point.fromAffine({x: ByteBuffer.bytesToNumber(x), y: ByteBuffer.bytesToNumber(y)});
            return new PrivateStateTokenKeyPair(data.kid, data["x5t#S256"], publicKey, d, expiry);
        }
        // else if (typeof data === 'bigint') {
        //     const secretKey = data;
        //     const publicKey = Point.BASE.multiply(data);

        //     // calculate the token_key_id and id. use the JWK generator for convenience.
        //     const jwk = P384.toJWK(publicKey);
        //     return new PrivateStateTokenKeyPair(jwk.kid, jwk["x5t#S256"], publicKey, secretKey);
        // }
    }

}

/**
 * A trust token issuance request.
 */
export class IssueRequest {
    /**
     * Creates a new issuance request
     * @param {Point[]} nonces A list of elliptic curve points to be used as token nonces.
     */
    constructor(nonces) {
        this.nonces = nonces;
    }

    /**
     * Returns the number of token nonces in the request
     * @returns {number} The number of token nonces in the request.
     */
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
     * @returns {IssueRequest} Returns the decoded `IssueRequest`.
     */
    static from(s) {
        const decodedBytes = Base64.decode(s);
        const bytes = new ByteBuffer(decodedBytes);

        const count = bytes.readInt(2);
        const blindedLength = Math.round((bytes.length - 2) / count); // to handle Ne=49 or legacy uncompressed (Ne=97)
        const nonces = [];
        for (let i = 0; i < count; i++) {
            const value = bytes.readBytes(blindedLength);
            try {
                const ecPoint = Point.fromHex(Uint8Array.from(value));
                nonces.push(ecPoint);
            }
            catch (e) {
                console.error(e);
                // null;
            }
        }

        return new IssueRequest(nonces.filter(n => n !== null));
    }

    /**
     * encodes the issuance request as bytes.
     * @returns {number[]} Returns the byte encoding of the request.
     */
    toBytes() {
        const bytes = new ByteBuffer();
        bytes.writeInt(this.count, 2);
        for (const nonce of this.nonces) {
            bytes.writeBytes(VOPRF_P384_Draft7.serializeElement(nonce));
        }
        return bytes.buffer;
    }

    [Symbol.for('nodejs.util.inspect.custom')]() {
        return Base64.encode(this.toBytes());
    }
}

/**
 * A trust token public key.
 */
export class IssueResponse {

    /**
     * Create a new issuance response
     *
     * @param {number} keyID The ID of the key used for signing.
     * @param {Point[]} signed The list of signed nonces.
     * @param {number[]} proof The DLEQ proof.
     */
    constructor(keyID, signed, proof) {
        this.keyID = keyID;
        this.signed = signed;
        this.proof = proof;
    }

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
     * @returns {number[]} The issue response as bytes.
     */
    toBytes() {
        const buf = new ByteBuffer();
        buf.writeInt(this.signed.length, 2); // the number issued
        buf.writeInt(this.keyID, 4); // the key ID associated with the public key
        for (const nonce of this.signed) {
            buf.writeBytes(VOPRF_P384_Draft7.serializeElement(nonce));
        }
        buf.writeInt(this.proof.length, 2);
        buf.writeBytes(this.proof);
        return buf.toBytes();
    }

    toHttpHeader() {
        return Base64.encode(this.toBytes());
    }

    [Symbol.for('nodejs.util.inspect.custom')]() {
        return Base64.encode(this.toBytes());
    }
}

/**
 * A trust token redemption request.
 */
export class RedeemRequest {
    /**
     * Create a RdemeemRequest instance
     *
     * @param {number} keyID The ID of the key used to sign the trust token.
     * @param {number[]} nonce The nonce part of the token.
     * @param {Point} W The elliptic curve point part of the token.
     * @param {number[]} clientData Client data associated with the request.
     */
    constructor(keyID, nonce, W, clientData) {
        this.keyID = keyID;
        this.nonce = nonce;
        this.W = W;
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
     * @returns {RedeemRequest} Returns the decoded `RedeemRequest` from `sec-private-state-token` http header
     */
    static from(s) {
        const decodedBytes = Base64.decode(s);
        const bytes = new ByteBuffer(decodedBytes);

        const tokenLen = bytes.readInt(2);
        const keyID = bytes.readInt(4);
        const nonce = bytes.readBytes(VOPRF_P384_Draft7.Nh);

        const value = bytes.readBytes(tokenLen - 4 - VOPRF_P384_Draft7.Nh);
        const point = Point.fromHex(Uint8Array.from(value));

        const clientDataLen = bytes.readInt(2);
        const clientData = bytes.readBytes(clientDataLen);

        return new RedeemRequest(keyID, nonce, point, clientData);
    }

    /**
     * encode the redemption request as bytes.
     * @returns {number[]} The redeem request as bytes.
     */
    toBytes() {
        const pointBytes = VOPRF_P384_Draft7.serializeElement(this.W);
        const buf = new ByteBuffer()
            .writeInt(this.nonce.length + pointBytes.length + 4, 2)
            .writeInt(this.keyID, 4)
            .writeBytes(this.nonce)
            .writeBytes(pointBytes)
            .writeInt(this.clientData.length, 2)
            .writeBytes(this.clientData);
        return buf.toBytes();
    }

    [Symbol.for('nodejs.util.inspect.custom')]() {
        return Base64.encode(this.toBytes());
    }
}

/**
 * The response to a trust token redemption request.
 * The client should treat the entire response as the redemption record.
 *
 * @see https://github.com/WICG/trust-token-api/blob/main/ISSUER_PROTOCOL.md#redeem-function
 *
 * RedemptionResponse structure as defined below.
 * ```
 * struct {
 *   opaque rr<1..2^16-1>;
 * } RedeemResponse;
 * ```
 */
export class RedeemResponse {
    /**
     * Create a RedeemResponse instance
     * @param {number[]|string} record The redemption record.
     */
    constructor(record = []) {
        if (ArrayBuffer.isView(record)) {
            record = Array.from(record);
        }
        else if (!Array.isArray(record)) {
            record = ByteBuffer.stringToBytes(record);
        }
        this.record = record;
    }

    /**
     * Encodes the redemption record as bytes
     * @returns {number[]} The redemption record as bytes.
     */
    toBytes() {
        return new ByteBuffer()
            .writeBytes(this.record.length, 2)
            .writeBytes(this.record)
            .toBytes();
    }

    toHttpHeader() {
        return Base64.encode(this.toBytes());
    }

    [Symbol.for('nodejs.util.inspect.custom')]() {
        return Base64.encode(this.toBytes());
    }
}

/**
 * A trust token issuer implementation.
 * @see https://wicg.github.io/trust-token-api/#issuer-public-keys
 */
export class PrivateStateTokenIssuer {

    static DEFAULT_VERSION = "PrivateStateTokenV1VOPRF";

    /**
     * Create a new trust token issuer
     * @param {string} host The server origin for this issuer.
     * @param {number} maxBatchSize The max batch size for tokens.
     * @param {number} id The issuer ID, must be increasing on each key rotation.
     * @param {PrivateStateTokenKeyPair[]} keys The key pairs for this issuer.
     */
    constructor(host, maxBatchSize, id = 1, keys = []) {
        if (!Array.isArray(keys)) keys = [keys];

        this.#keys = new Map(keys.map(k => [k.id, k]));
        this.maxBatchSize = maxBatchSize;
        this.host = host;
        this.id = id;
    }

    /**
     * The private keys for this issuer.
     */
    #keys;

    /**
     * The public keys for this issuer. We intentionally don't make the private keys accessible
     */
    get publicKeys() {
        return [...this.#keys.values()].map(k => k.publicKey);
    }

    get requestURI() {
        return `https://${this.host}/request`;
    }

    get redeemURI() {
        return `https://${this.host}/redeem`;
    }

    /**
     * Adds a key pair to the issuer.
     * @param {PrivateStateTokenKeyPair} key The key pair to add.
     * @returns {PrivateStateTokenIssuer} This issuer. Useful for chaining.
     */

    addKey(key) {
        this.#keys.set(key.id, key);
        return this;
    }

    /**
     * Adds a key pair from a JWK definition.
     * @param {Object|Object[]} jwks A JWK definition.
     * @see https://tools.ietf.org/html/rfc7517
     * @returns {PrivateStateTokenIssuer} This issuer (for chaining)
     */
    addJWK(jwks) {
        for (const jwk of Array.isArray(jwks) ? jwks : [jwks]) {
            this.addKey(PrivateStateTokenKeyPair.from(jwk));
        }
        return this;
    }

    /**
     * Produces a key commitment for this issuer. The structure for the key commitment is only partially documented in
     * the spec, the web tests provide more details that include the host and max batch size.
     *
     * @param {string} version The version of the protocol to use.
     * @returns {Object} The key commitment.
     * @see https://github.com/WICG/trust-token-api/blob/main/ISSUER_PROTOCOL.md#issuer-key-commitments
     * @see https://source.chromium.org/chromium/chromium/src/+/main:third_party/blink/web_tests/wpt_internal/trust-tokens/resources/trust_token_voprf.py;l=449-469
     */
    keyCommitment(version = PrivateStateTokenIssuer.DEFAULT_VERSION) {
        version = version || PrivateStateTokenIssuer.DEFAULT_VERSION;
        const keyCommitment = {
            "protocol_version": version,
            "id": this.id,
            "batchsize": this.maxBatchSize,
            "keys": {}
        };
        for (const key of this.#keys.values()) {
            // Returns the public key as bytes.
            // The structure takes the form:
            // ```
            // struct {
            //    uint32 id;
            //    ECPoint pub;
            // } TrustTokenPublicKey;
            // ```
            const buffer = new ByteBuffer()
                .writeInt(key.id, 4)
                .writeBytes(VOPRF_P384_Draft7.serializeElement(key.publicKey));

            keyCommitment.keys[key.id] = {
                "Y": Base64.encode(buffer.toBytes()),
                // epoch timestamp in microseconds
                // string escaped integer
                expiry: `${key.expiry}`,
            };
        }
        return {
            [this.host]: {
                [version]: keyCommitment
            }
        };
    }

    /**
     * A serializer for the issuer keys in token issuer directory format as specfiied in the PrivacyPass Protocol spec.
     * @returns {Object} a token-issuer-directory formatted object
     */
    directory() {
        const tokenKeys = [];
        for (const key of this.#keys.values()) {
            tokenKeys.push({
                "token-type": 2,
                "token-key": Base64.urlEncode(VOPRF_P384_Draft7.serializeElement(key.publicKey)) // we are expanding to the full form
            });

        }

        return {
            "issuer-request-uri": this.requestURI,
            "issuer-redeem-uri": this.redeemURI,
            "id": this.truncatedKeyID,
            "batchsize": this.maxBatchSize,
            "token-keys": tokenKeys
        }
    }

    /**
     * A serializer for the issuer keys in JWK Set format. Additional fields are added to the JWK Set to provide
     * the host, id (version), and max batch size.
     * @returns {Object} object formatted as a JWK Set.
     */
    jwks() {
        const keys = [];
        for (const key of this.#keys.values()) {
            keys.push(key.toJWK());
        }
        return {
            "host": this.host,
            "id": this.id,
            "batchsize": this.maxBatchSize,
            "keys": keys
        }
    }

    /**
     * Creates a trust token issuer. A key pair is generated and used to
     * initialize the issuer.
     *
     * @param {string} host The server origin for this issuer.
     * @param {number} maxBatchSize The max batch size for trust tokens.
     * @param {number} id The id for the key pair.
     * @returns {PrivateStateTokenIssuer} The trust token issuer with a generated key pair.
     */
    generateKey() {
        const seed = VOPRF_P384.randomScalar();
        const [privateKey, publicKey] = VOPRF_P384.deriveKeyPair(seed);
        const publicKeyID = Array.from(sha256(Uint8Array.from(P384.toASN(pub))));
        const truncatedPublicKeyID = publicKeyID.slice(-1)[0];
        const keyPair = new PrivateStateTokenKeyPair(truncatedPublicKeyID, publicKeyID, publicKey, privateKey);

        this.addKey(keyPair);
        return keyPair;
    }

    /**
     * Parses an issuance request and returns a response with a valid DLEQ proof.
     *
     * From: https://github.com/WICG/trust-token-api/blob/main/ISSUER_PROTOCOL.md#issue-function-1
     * > The Issue Evaluate stage of the VOPRF protocol.
     * > Input Serialization:
     * >   The Private State Token Issuance Request contains an IssueRequest structure defined below.
     * >   struct {
     * >     uint16 count;
     * >     ECPoint nonces[count];
     * >   } IssueRequest;
     * >
     * > Output Serialization:
     * >   The Private State Token Issuance Response contains an IssueResponse structure defined below.
     * >    struct {
     * >     opaque s<Nn>; // big-endian bytestring
     * >     ECPoint W;
     * >   } SignedNonce;
     *
     * >   struct {
     * >     Scalar c;
     * >     Scalar u;
     * >     Scalar v;
     * >   } DLEQProof;
     * >
     * >   struct {
     * >     uint16 issued;
     * >     uint32 key_id = keyID;
     * >     SignedNonce signed[issued];
     * >     opaque proof<1..2^16-1>; // Length-prefixed form of DLEQProof.
     * >   } IssueResponse;
     *
     * From: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#section-3.3.2
     *
     * > The VOPRF protocol begins with the client blinding its input ...
     * > Clients store the output blind locally and send blindedElement to the server for evaluation.
     * > Upon receipt, servers process blindedElement to compute an evaluated element and DLEQ proof
     * > using the following BlindEvaluate function.
     * >
     * > ```
     * > Input:
     * >   Scalar skS
     * >   Element pkS
     * >   Element blindedElement
     * >
     * > Output:
     * >   Element evaluatedElement
     * >   Proof proof
     * >
     * > Parameters:
     * >   Group G
     * >
     * > def BlindEvaluate(skS, pkS, blindedElement):
     * >   evaluatedElement = skS * blindedElement
     * >   blindedElements = [blindedElement]     // list of length 1
     * >   evaluatedElements = [evaluatedElement] // list of length 1
     * >   proof = GenerateProof(skS, G.Generator(), pkS,
     * >                         blindedElements, evaluatedElements)
     * >   return evaluatedElement, proof
     * > ```
     *
     * From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#section-2.1
     *
     * > HashToScalar(x): Deterministically maps an array of bytes x to an element in GF(p).
     * > This function is optionally parameterized by a DST;
     *
     * From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#section-4.4
     *
     * > Order():
     * >   Return 0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973.
     *
     * > HashToScalar():
     * >   Use hash_to_field from [I-D.irtf-cfrg-hash-to-curve] using L = 72, expand_message_xmd with SHA-384,
     * >   DST = "HashToScalar-" || contextString, and prime modulus equal to Group.Order()
     *
     * hash_to_field is defined in https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-hash-to-curve-16#section-3

     * @param {number} keyId The key ID to use for this issuance.
     * @param {IssueRequest} request The issuance request.
     * @param {string} version The version of PST to use
     * @param {number} r The random value to use for the DLEQ proof (use for testing)
     * @returns {IssueResponse} The issuance response.
     */
    issue(keyId, request, version=PrivateStateTokenIssuer.DEFAULT_VERSION, r) {
        const keyPair = this.#keys.get(keyId) || this.#keys.values().next().value;

        // TODO: validate host
        // TODO: is null the right way to handle errors?
        if (!keyPair) return null;

        const k = keyPair.secretKey;
        r = r ?? VOPRF_P384.randomScalar();
        const blindedElements = request.nonces;
        const evaluatedElements = [];

        for (const blindedToken of blindedElements) {
            const z = blindedToken.multiply(k);
            evaluatedElements.push(z);
        }

        const A = VOPRF_P384.generator;
        const B = keyPair.publicKey; // public key // ec.ProjectivePoint.BASE.multiply(k)
        const C = blindedElements;
        const D = evaluatedElements;
        let proof = [];

        if (version === "PrivateStateTokenV1VOPRF") {
            proof = VOPRF_P384.generateProof(k, A, B, C, D, r);
        }
        else {
            proof = VOPRF_P384_Draft7.generateProof(k, A, B, C, D, r);
        }

        const serializedProof = new ByteBuffer()
            .writeBytes(VOPRF_P384.serializeScalar(proof[0]))
            .writeBytes(VOPRF_P384.serializeScalar(proof[1]));

        return new IssueResponse(keyPair.id, evaluatedElements, serializedProof.toBytes());
    }

    /**
     * This method evaluates a redemption request. If it is valid (using the Evaluate() method of V/OPRF)
     * will return the redemption record. Again we are using the Group P-384
     *
     * From https://github.com/WICG/trust-token-api/blob/main/ISSUER_PROTOCOL.md#redeem-function-1
     * > The Redeem function corresponds to the VerifyFinalize stage of the VOPRF protocol.
     * > Input Serialization:
     * >   The Private State Token redemption request contains a RedemptionRequest structure as defined below.
     * >   struct {
     * >     uint32 key_id;
     * >     opaque nonce<nonce_size>;
     * >     ECPoint W;
     * >   } Token;
     * >   struct {
     * >     opaque token<1..2^16-1>; // Bytestring containing a serialized Token struct.
     * >     opaque client_data<1..2^16-1>;
     * >     uint64 redemption_time;
     * >   } RedeemRequest;
     * > Output Serialization:
     * >   The Private State Token redemption response contains a RedemptionResponse structure as defined below.
     * >   struct {
     * >     opaque rr<1..2^16-1>;
     * >   } RedeemResponse;
     *
     * @param {RedeemRequest} request The redemption request.
     * @param {RedemptionRecord} redemptionRecord The redemption record.
     * @param {string} version The version of the protocol to use.
     * @returns {RedeemResponse} The redemption response.
     */
    redeem(request, redemptionRecord, version=PrivateStateTokenIssuer.DEFAULT_VERSION) {
        const secretKey = this.#keys.get(request.keyID)?.secretKey;

        if (VOPRF_P384_Draft7.verifyFinalize(secretKey, request.nonce, request.W)) {
            return new RedeemResponse(redemptionRecord);
        }
        return null;
    }
}
