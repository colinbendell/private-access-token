import { p384 as ec, hashToCurve, encodeToCurve} from '@noble/curves/p384';
import { sha384 } from '@noble/hashes/sha512';
import { expand_message_xmd } from '@noble/curves/abstract/hash-to-curve';
import { ByteBuffer, Hex } from './utils.js';

const Point = ec.ProjectivePoint;

export class VOPRF {

    constructor(cipherSuite = "P384-SHA384", mode="\x01") {
        // TODO: make this actually multi-suite
        this.contextString = VOPRF.createContextString(mode, cipherSuite);
        this.identifier = cipherSuite;
        this.mode = mode;
        this.order = BigInt('0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973');
        this.expand = 'xmd';
        this.L = 72;
        this.Ns = 48;
        this.hash = sha384;
    }

    hashToScalar(msg) {
        // const hashTofieldConfig = {
        //     DST: "HashToScalar-" + this.contextString,
        //     m: 1,
        //     p: this.order,
        //     k: 192,
        //     // k: this.L / 8,
        //     // L: this.L,
        //     expand: this.expand,
        //     hash: this.hash
        // }
        // return hash_to_field(Uint8Array.from(msg), 1, hashTofieldConfig)[0][0];
        const DST = ByteBuffer.stringToBytes("HashToScalar-" + this.contextString);
        const xmd = expand_message_xmd(Uint8Array.from(msg), Uint8Array.from(DST), this.L, this.hash)
        return ByteBuffer.bytesToNumber(xmd) % this.order;
    }

    hashToGroup(msg) {
        const DST = "HashToGroup-" + this.contextString;
        const hash = this.hash;
        return hashToCurve(Uint8Array.from(msg), { DST, hash })
    }
    /**
     * from: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-configuration
     *
     * modeOPRF     0x00
     * modeVOPRF    0x01
     * modePOPRF    0x02
     *
     * ```
     * def CreateContextString(mode, identifier):
     *   return "OPRFV1-" || I2OSP(mode, 1) || "-" || identifier
     * ```
     */
    static createContextString(mode, identifier) {
        return "OPRFV1-" + mode + "-" + identifier;
    }

    /**
     * From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-proof-generation
     * > The helper function ComputeCompositesFast is as defined below, and is an optimization of the ComputeComposites function for servers since they have knowledge of the private key.
     *
     * > ```
     * > Input:
     * >   Scalar k
     * >   Element B
     * >   Element C[m]
     * >   Element D[m]
     * > Output:
     * >   Element M
     * >   Element Z
     * > Parameters:
     * >   Group G
     * >   PublicInput contextString
     * >
     * > def ComputeCompositesFast(k, B, C, D):
     * >   Bm = G.SerializeElement(B)
     * >   seedDST = "Seed-" || contextString
     * >   seedTranscript =
     * >     I2OSP(len(Bm), 2) || Bm ||
     * >     I2OSP(len(seedDST), 2) || seedDST
     * >   seed = Hash(seedTranscript)
     * >
     * >   M = G.Identity()
     * >   for i in range(m):
     * >     Ci = G.SerializeElement(C[i])
     * >     Di = G.SerializeElement(D[i])
     * >     compositeTranscript =
     * >       I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
     * >       I2OSP(len(Ci), 2) || Ci ||
     * >       I2OSP(len(Di), 2) || Di ||
     * >       "Composite"
     * >
     * >     di = G.HashToScalar(compositeTranscript)
     * >     M = di  * C[i] + M
     * >
     * >   Z = k  * M
     * >
     * >   return (M, Z)
     * > ```
     *
     * @param {number} k The secret key (scalar form).
     * @param {ec.Point} B The public key.
     * @param {ec.Point[]} C The blinded tokens.
     * @param {ec.Point[]} D The unblinded tokens.
     */
    computeCompositesFast(k, B, C = [], D = [], hashTofieldConfig) {

        // const A = ec.ProjectivePoint.BASE;
        // const B = keyPair.publicKey.toPoint();

        const seedDST = "Seed-" + this.contextString;
        const Bm = B.toRawBytes(true);

        const seedTranscript = new ByteBuffer()
            .writeInt16(Bm.length)
            .writeBytes(Bm)
            .writeInt16(seedDST.length)
            .writeString(seedDST);

        const seed = Array.from(sha384.create()
            .update(Uint8Array.from (seedTranscript.toBytes()))
            .digest());

        let M = ec.ProjectivePoint.ZERO;
        for (let i = 0; i < C.length; i++) {

            const Ci = C[i].toRawBytes(true);
            const Di = D[i].toRawBytes(true);

            const buf = new ByteBuffer()
                .writeInt16(seed.length)
                .writeBytes(seed)
                .writeInt16(i)
                .writeInt16(Ci.length)
                .writeBytes(Ci)
                .writeInt16(Di.length)
                .writeBytes(Di)
                .writeString("Composite");

            const di = this.hashToScalar(buf.toBytes());
            M = M.add(C[i].multiply(di));
        }

        const Z = M.multiply(k);

        return [ M, Z ];
    }

    /**
     * Generates the DLEQ proof for the issuance.
     * From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#section-2.2.1
     * > Generating a proof is done with the GenerateProof function, defined below. Given elements A and B,
     * > two non-empty lists of elements C and D of length m, and a scalar k; this function produces a proof
     * > that k *A == B and k *C[i] == D[i] for each i in [0, ..., m - 1]. The output is a value of type Proof,
     * > which is a tuple of two Scalar values. We use the notation proof[0] and proof[1] to denote the first
     * > and second elements in this tuple, respectively.
     * >
     * > GenerateProof accepts lists of inputs to amortize the cost of proof generation. Applications can take
     * > advantage of this functionality to produce a single, constant-sized proof for m DLEQ inputs, rather
     * > than m proofs for m DLEQ inputs.
     * >
     * > ```
     * > Input:
     * >   Scalar k
     * >   Element A
     * >   Element B
     * >   Element C[m]
     * >   Element D[m]
     * > Output:
     * >   Proof proof
     * > Parameters:
     * >   Group G
     * >
     * > def GenerateProof(k, A, B, C, D)
     * >   (M, Z) = ComputeCompositesFast(k, B, C, D)
     * >
     * >   r = G.RandomScalar()
     * >   t2 = r  * A
     * >   t3 = r  * M
     * >
     * >   Bm = G.SerializeElement(B)
     * >   a0 = G.SerializeElement(M)
     * >   a1 = G.SerializeElement(Z)
     * >   a2 = G.SerializeElement(t2)
     * >   a3 = G.SerializeElement(t3)
     * >
     * >   challengeTranscript =
     * >     I2OSP(len(Bm), 2) || Bm ||
     * >     I2OSP(len(a0), 2) || a0 ||
     * >     I2OSP(len(a1), 2) || a1 ||
     * >     I2OSP(len(a2), 2) || a2 ||
     * >     I2OSP(len(a3), 2) || a3 ||
     * >     "Challenge"
     * >
     * >   c = G.HashToScalar(challengeTranscript)
     * >   s = r - c  * k
     * >
     * >   return [c, s]
     * > ```
     *
     * The same defnitions for HashToScalar apply as in the VOPRF specification above.
     *
     * @param {number} k The secret key (scalar form).
     * @param {number} A The BASE point.
     * @param {number} B The public key.
     * @param {Point[]} C The blinded tokens.
     * @param {Point[]} D The evaluated tokens.
     * @param {string} version The version of the PrivateStateTokenVOPRF protocol to use.
     * @returns {Array<number>} The DLEQ proof.
     */
    generateProof(k, A, B, C, D, r) {

        const [ M, Z ] = this.computeCompositesFast(k, B, C, D);

        const t2 = A.multiply(r);
        const t3 = M.multiply(r);

        const Bm = B.toRawBytes(true);
        const a0 = M.toRawBytes(true);
        const a1 = Z.toRawBytes(true);
        const a2 = t2.toRawBytes(true);
        const a3 = t3.toRawBytes(true);

        const buf = new ByteBuffer();
        buf.writeInt16(Bm.length)
        buf.writeBytes(Bm);
        buf.writeInt16(a0.length)
        buf.writeBytes(a0);
        buf.writeInt16(a1.length)
        buf.writeBytes(a1);
        buf.writeInt16(a2.length)
        buf.writeBytes(a2);
        buf.writeInt16(a3.length)
        buf.writeBytes(a3);
        buf.writeString("Challenge");

        // hashToScalar = hash_to_field for
        const c = this.hashToScalar(buf.toBytes());

        // const u = (r + c * keyPair.secretKey.scalar) % VOPRF_P384.ORDER;
        // const s = (r - c * k);
        let s = (r - c * k) % this.order;
        if (s < 0n) {
            s += this.order;
        }
        // const s = ec.CURVE.Fp.sub(r, ec.CURVE.Fp.mul(c, k));

        return [c, s];
    }

    /**
     * From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-proof-verification
     * > Verifying a proof is done with the VerifyProof function
     * > ```
     * > Input:
     * >   Element A
     * >   Element B
     * >   Element C[m]
     * >   Element D[m]
     * >   Proof proof
     * > Output:
     * >   boolean verified
     * >
     * > Parameters:
     * >   Group G
     * >
     * > def VerifyProof(A, B, C, D, proof):
     * >   (M, Z) = ComputeComposites(B, C, D)
     * >   c = proof[0]
     * >   s = proof[1]
     * >
     * >   t2 = ((s * A) + (c * B))
     * >   t3 = ((s * M) + (c * Z))
     * >
     * >   Bm = G.SerializeElement(B)
     * >   a0 = G.SerializeElement(M)
     * >   a1 = G.SerializeElement(Z)
     * >   a2 = G.SerializeElement(t2)
     * >   a3 = G.SerializeElement(t3)
     * >
     * >   challengeTranscript =
     * >     I2OSP(len(Bm), 2) || Bm ||
     * >     I2OSP(len(a0), 2) || a0 ||
     * >     I2OSP(len(a1), 2) || a1 ||
     * >     I2OSP(len(a2), 2) || a2 ||
     * >     I2OSP(len(a3), 2) || a3 ||
     * >     "Challenge"
     * >
     * >   expectedC = G.HashToScalar(challengeTranscript)
     * >   verified = (expectedC == c)
     * >
     * >   return verified
     * > ```
     *
     * @param {number} A The BASE point.
     * @param {number} B The public key.
     * @param {Point[]} C The blinded tokens.
     * @param {Point[]} D The evaluated tokens.
     * @returns {boolean} True if the proof is valid.
     */
    verifyProof(A, B, C, D, proof) {
        const [ M, Z ] = this.computeComposites(B, C, D);

        const c = proof[0]
        const s = proof[1]

        const t2 = (A.multiply(s)).add(B.multiply(c));
        const t3 = (M.multiply(s)).add(Z.multiply(c));

        const Bm = B.toRawBytes(true);
        const a0 = M.toRawBytes(true);
        const a1 = Z.toRawBytes(true);
        const a2 = t2.toRawBytes(true);
        const a3 = t3.toRawBytes(true);

        const challengeTranscript = new ByteBuffer()
        challengeTranscript.writeInt16(Bm.length)
        challengeTranscript.writeBytes(Bm)
        challengeTranscript.writeInt16(a0.length)
        challengeTranscript.writeBytes(a0)
        challengeTranscript.writeInt16(a1.length)
        challengeTranscript.writeBytes(a1)
        challengeTranscript.writeInt16(a2.length)
        challengeTranscript.writeBytes(a2)
        challengeTranscript.writeInt16(a3.length)
        challengeTranscript.writeBytes(a3)
        challengeTranscript.writeString("Challenge");

        const expectedC = this.hashToScalar(challengeTranscript.toBytes());
        const verified = (expectedC == c);

        return verified
      }


    /**
     * From https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-proof-verification
     * > The definition of ComputeComposites is given below.
     * > ```
     * > Input:
     * >   Element B
     * >   Element C[m]
     * >   Element D[m]
     * >
     * > Output:
     * >   Element M
     * >   Element Z
     * >
     * > Parameters:
     * >   Group G
     * >   PublicInput contextString
     * >
     * > def ComputeComposites(B, C, D):
     * >   Bm = G.SerializeElement(B)
     * >   seedDST = "Seed-" || contextString
     * >   seedTranscript =
     * >     I2OSP(len(Bm), 2) || Bm ||
     * >     I2OSP(len(seedDST), 2) || seedDST
     * >   seed = Hash(seedTranscript)
     * >
     * >   M = G.Identity()
     * >   Z = G.Identity()
     * >   for i in range(m):
     * >     Ci = G.SerializeElement(C[i])
     * >     Di = G.SerializeElement(D[i])
     * >     compositeTranscript =
     * >       I2OSP(len(seed), 2) || seed || I2OSP(i, 2) ||
     * >       I2OSP(len(Ci), 2) || Ci ||
     * >       I2OSP(len(Di), 2) || Di ||
     * >       "Composite"
     * >
     * >     di = G.HashToScalar(compositeTranscript)
     * >     M = di  * C[i] + M
     * >     Z = di  * D[i] + Z
     * >
     * >   return (M, Z)
     * > ```
     *
     * @param {number} B The public key.
     * @param {Point[]} C The blinded tokens.
     * @param {Point[]} D The evaluated tokens.
     * @returns {Point[]} An array of two points, M and Z.
     */
    computeComposites(B, C, D) {

        const Bm = B.toRawBytes(true);
        const seedDST = "Seed-" + this.contextString;

        const seedTranscript = new ByteBuffer()
            .writeInt16(Bm.length)
            .writeBytes(Bm)
            .writeInt16(seedDST.length)
            .writeString(seedDST);

        const seed = Array.from(sha384.create()
            .update(Uint8Array.from(seedTranscript.toBytes()))
            .digest());

        let M = ec.ProjectivePoint.ZERO;
        let Z = ec.ProjectivePoint.ZERO;
        for (let i = 0; i < C.length; i++) {
            const Ci = C[i].toRawBytes(true);
            const Di = D[i].toRawBytes(true);
            const compositeTranscript = new ByteBuffer()
                .writeInt16(seed.length)
                .writeBytes(seed)
                .writeInt16(i)
                .writeInt16(Ci.length)
                .writeBytes(Ci)
                .writeInt16(Di.length)
                .writeBytes(Di)
                .writeString("Composite");

            const di = this.hashToScalar(compositeTranscript.toBytes());
            M = M.add(C[i].multiply(di));
            Z = Z.add(D[i].multiply(di));
        }
        return [ M, Z ]
    }


    /**
     * From: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-oprf-protocol
     *
     * > Upon receipt of evaluatedElement, clients process it to complete the OPRF evaluation with the Finalize function described below.
     * >
     * > Input:
     * >   PrivateInput input
     * >   Scalar blind
     * >   Element evaluatedElement
     * >
     * > Output:
     * >   opaque output[Nh]
     * >
     * > Parameters:
     * >   Group G
     * >
     * > def Finalize(input, blind, evaluatedElement):
     * >   N = G.ScalarInverse(blind) * evaluatedElement
     * >   unblindedElement = G.SerializeElement(N)
     * >
     * >   hashInput = I2OSP(len(input), 2) || input ||
     * >               I2OSP(len(unblindedElement), 2) || unblindedElement ||
     * >               "Finalize"
     * >   return Hash(hashInput)
     * > ```
     */
    finalize(input, blind, evaluatedElement) {
        const N = evaluatedElement.multiply(blind.invert());
        const unblindedElement = N.toRawBytes(true);

        const hashInput = new ByteBuffer()
            .writeInt16(input.length)
            .writeBytes(input)
            .writeInt16(unblindedElement.length)
            .writeBytes(unblindedElement)
            .writeString("Finalize");

        return sha384.create()
            .update(Uint8Array.from(hashInput.toBytes()))
            .digest();
    }

    /**
     * From: https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-voprf-21#name-oprf-protocol
     *
     * > An entity which knows both the private key and the input can compute the PRF result using the following Evaluate function.
     * >
     * > Input:
     * >   Scalar skS
     * >   PrivateInput input
     * >
     * > Output:
     * >   opaque output[Nh]
     * >
     * > Parameters:
     * >   Group G
     * >
     * > Errors: InvalidInputError
     * >
     * > def Evaluate(skS, input):
     * >   inputElement = G.HashToGroup(input)
     * >   if inputElement == G.Identity():
     * >     raise InvalidInputError
     * >   evaluatedElement = skS * inputElement
     * >   issuedElement = G.SerializeElement(evaluatedElement)
     * >
     * >   hashInput = I2OSP(len(input), 2) || input ||
     * >               I2OSP(len(issuedElement), 2) || issuedElement ||
     * >               "Finalize"
     * >   return Hash(hashInput)
     * > ```
     */
    evaluate(skS, input) {
        const inputElement = this.hashToGroup(input);
        if (inputElement.equals(ec.ProjectivePoint.ZERO)) {
            throw new Error("Invalid input");
        }
        const evaluatedElement = inputElement.multiply(skS);
        const issuedElement = evaluatedElement.toRawBytes(true);

        const hashInput = new ByteBuffer()
            .writeInt16(input.length)
            .writeString(input)
            .writeInt16(issuedElement.length)
            .writeBytes(issuedElement)
            .writeString("Finalize");

        return sha384.create()
            .update(Uint8Array.from(hashInput.toBytes()))
            .digest();
    }
}
