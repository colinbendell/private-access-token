/**
 * host to network long
 * @param {Number} n - Number to be encoded to byte array in network byte order.
 * @return {Array<number>} - 4 byte Encoded number in network byte order (big endian)
 */
export function hostToNetworkLong(n) {
    return ByteBuffer.numberToBytes(n, 4);
}
export { hostToNetworkLong as h2nl }

/**
 * host to network short
 * @param {Number} n - Number to be encoded to byte array in network byte order.
 * @return {Array<number>} - 2 byte Encoded number in network byte order (big endian)
 */
export function hostToNetworkShort(n) {
    return ByteBuffer.numberToBytes(n, 2);
}
export { hostToNetworkShort as h2ns }
export { hostToNetworkShort as i2osp }

/**
 * network to host long
 * @param {Array<number>} n - 4 byte Encoded number in network byte order (big endian)
 * @return {Number} - Decoded number
 */
export function networkToHostLong(n) {
    return ByteBuffer.bytesToNumber(n);
}
export { networkToHostLong as n2hl }

/**
 * network to host short
 * @param {Array<number>} n - 2 byte Encoded number in network byte order (big endian)
 * @return {Number} - Decoded number
 */
export function networkToHostShort(n) {
    return ByteBuffer.bytesToNumber(n);
}
export { networkToHostShort as n2hs }

/**
 * convenience function to sha256 hash a string and return a byte array
 * @param {string} data - string to be hashed
 * @return {Array<number>} - sha256 hash of the string
 */
export async function sha256(data = []) {
    if (Array.isArray(data)) {
        data = new Uint8Array(data);
    }
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)));
}

export class Hex {
    static decode(value = '') {
        const result = Array(value.length / 2);
        for (let i = 0; i < value.length / 2; i++) {
            result[i] = parseInt(value.slice(i * 2, i * 2 + 2), 16) || 0;
        }
        return result;
    }

    static encode(data = []) {
        return data.map(v => v.toString(16).padStart(2, '0')).join('');
    }
}

export class Base64 {
    static encode(data) {
        if (Array.isArray(data) || ArrayBuffer.isView(data)) {
            data = ByteBuffer.bytesToString(data);
        }

        return btoa(data ?? "");
    }
    static urlEncode(data, quoted=false) {
        const output = Base64.encode(data).replace(/\+/g, '-').replace(/\//g, '_');
        if (quoted && output.endsWith('=')) {
            return `"${output}"`;
        }
        return output;
    }

    static decode(data) {
        if (!data) return [];
        try {
            data = decodeURIComponent(data)
                ?.replaceAll('-', '+')
                ?.replaceAll('_', '/')
                ?.replaceAll(/^"|"$/g, '');
            const encodedData = atob(data);
            return ByteBuffer.stringToBytes(encodedData);
        }
        catch (e) {
            console.error(e);
            return [];
        }
    }
}

/**
* A helper class that reads values from a byte string.
*
* This class helps to parse issuance and redemption requests.
*/
export class ByteBuffer {
    /**
    * @param {Buffer} buffer The byte string to read values from.
    */
    constructor(buffer) {
        this.buffer = Array.from(buffer ?? []);
        this.offset = 0;
    }

    toBytes() {
        return this.buffer;
    }

    get length() {
        return this.buffer.length;
    }

    /**
    * Reads `size` bytes from the buffer and increments the offset by the same amount.
    *
    * @param {number} size The number of bytes to read.
    * @returns {Buffer} A byte string containing the bytes read.
    */
    readBytes(size) {
        const value = this.buffer.slice(this.offset, size ? this.offset + size : null);
        this.offset += size;
        return value;
    }

    readString(size) {
        return ByteBuffer.bytesToString(this.readBytes(size));
    }

    /**
    * Parses `size` bytes from the buffer as an integer and increments the offset by `size`.
    *
    * @param {number} size The number of bytes to parse.
    * @returns {number} The parsed integer.
    */
    readInt(size = 1) {
        const value = this.readBytes(size);
        if (size === 1) return value[0];
        return ByteBuffer.bytesToNumber(value);
    }

    peekInt() {
        return this.buffer[this.offset];
    }

    writeInt(value = 0, size = 2) {
        this.buffer = this.buffer.concat(ByteBuffer.numberToBytes(value, size));
        return this;
    }

    writeBytes(data = []) {
        if (data instanceof Uint8Array) {
            data = Array.from(data);
        }
        else if (!Array.isArray(data)) {
            data = [data];
        }


        this.buffer = this.buffer.concat(data);
        return this;
    }

    writeString(str = '') {
        return this.writeBytes(ByteBuffer.stringToBytes(str));
    }

    static bytesToString(bytes = []) {
        return Array.from(bytes).map(char => String.fromCharCode(char)).join('');
    }

    static stringToBytes(data = '') {
        if (Array.isArray(data)) {
            return data;
        }
        if (data instanceof Uint8Array) {
            return Array.from(data);
        }
        return Array.from(data || '', c => c.charCodeAt(0));
        // return [...new TextEncoder().encode(data ?? '')]
        // return data?.split('')?.map( c => c.charCodeAt(0)) ?? [];
    }

    static numberToBytes(value = 0n, length = 1) {

        // minor optimization to avoid casting to string and back
        if (length <= 4) {
            value = Number(value);
            return [(value >> 24) & 0xff, (value >> 16) & 0xff, (value >> 8) & 0xff, value & 0xff].slice(-length);
        }

        value = BigInt(value);
        const result = new Array(length);
        for (let i = 0; i < length; i++) {
            result[i] = Number(0xffn & (value >> (BigInt(i) * 8n)));
        }
        return result.reverse(); // big endian
    }

    static bytesToNumber(octets = []) {
        let result = 0n;
        for (const octet of octets) {
            result <<= 8n;
            result += BigInt(octet);
        }

        if (octets.length <= 8) {
            result = Number(result);
        }
        return result;
    }
}

export class CBOR {
    static decode(rawData = []) {
        const data = new ByteBuffer(rawData);

        return CBOR.#decodeItem(data);
    }

    static #readBreak(data) {
        if (data.peekInt() !== 0xff) return false;

        data.readInt(1);
        return true;
    }

    static #readLength(additionalInformation, data) {
        if (additionalInformation < 24)
            return additionalInformation;
        if (additionalInformation === 24)
            return data.readInt(1);
        if (additionalInformation === 25)
            return data.readInt(2);
        if (additionalInformation === 26)
            return data.readInt(4);
        if (additionalInformation === 27)
            return data.readInt(8);
        if (additionalInformation === 31)
            return -1;
        throw "Invalid length encoding";
    }
    static #readIndefiniteStringLength(data, majorType) {
        const initialByte = data.readInt(1);
        if (initialByte === 0xff)
            return -1;
        const length = CBOR.#readLength(initialByte & 0x1f, data);
        if (length < 0 || (initialByte >> 5) !== majorType)
            throw "Invalid indefinite length element";
        return length;
    }

    static #decodeItem(data) {
        const initialByte = data.readInt(1);
        const majorType = initialByte >> 5;
        const additionalInformation = initialByte & 0x1f;

        if (majorType === 7) {
            if (additionalInformation === 25)
                return data.readInt(2);
            if (additionalInformation === 26)
                return data.readInt(4);
            if (additionalInformation === 27)
                return data.readInt(6);
        }

        let length = CBOR.#readLength(additionalInformation, data);
        if (length < 0 && (majorType < 2 || majorType > 6)) throw "Invalid length";

        if (majorType === 0) {
            // 0 to 2^53
            return length;
        }
        else if (majorType === 1) {
            // -1 to -2^53
            return -1 - length;
        }
        else if (majorType === 2) {
            if (length < 0) {
                let result = [];
                while ((length = CBOR.#readIndefiniteStringLength(data, majorType)) >= 0) {
                    result = result.concat(data.readBytes(length));
                }
                return result;
            }
            return data.readBytes(length);
        }
        else if (majorType === 3) {
            if (length < 0) {
                let result = [];
                while ((length = CBOR.#readIndefiniteStringLength(data, majorType)) >= 0) {
                    result = result.concat(data.readBytes(length));
                }
                ByteBuffer.bytesToString(result);
            }
            return ByteBuffer.bytesToString(data.readBytes(length));
        }
        else if (majorType === 4) {
            const retArray = [];
            if (length < 0) {
                while (!CBOR.#readBreak(data)) {
                    retArray.push(CBOR.#decodeItem(data))
                }
            }
            else {
                for (let i = 0; i < length; ++i) {
                    retArray.push(CBOR.#decodeItem(data));
                }
            }
            return retArray;
        }
        else if (majorType === 5) {
            const retObject = {};
            for (let i = 0; i < length || length < 0 && !CBOR.#readBreak(data); ++i) {
                const key = CBOR.#decodeItem(data);
                retObject[key] = CBOR.#decodeItem(data);
            }
            return retObject;
        }
        else if (majorType === 6) {
            return;
        // return tagger(decodeItem(), length);
        }
        else if (majorType === 7) {
            if (length === 20) return false;
            if (length === 21) return true;
            if (length === 22) return null;
            if (length === 23) return undefined;
            // return simpleValue(length);
            return undefined;
        }
    }
}
