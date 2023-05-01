// host to network long
export function hostToNetworkLong(n) { return DataBuffer.numberToBytes(n, 4); }
export function h2nl(n) { return DataBuffer.numberToBytes(n, 4); }

// host to network short
export function hostToNetworkShort(n) { return DataBuffer.numberToBytes(n, 2); }
export function h2ns(n) { return DataBuffer.numberToBytes(n, 2); }

// network to host long
export function networkToHostLong(n) { return DataBuffer.bytesToNumber(n); }
export function n2hl(n) { return DataBuffer.bytesToNumber(n); }

// network to host short
export function networkToHostShort(n) { return DataBuffer.bytesToNumber(n); }
export function n2hs(n) { return DataBuffer.bytesToNumber(n); }

/**
 * I2OSP function
 * @param {Number} value - Number to be encoded to byte array in network byte order.
 * @param {Number} length - Length of byte array
 * @return {Uint8Array} - Encoded number.
 */
export function i2osp(value = 0, length = 2) { return DataBuffer.numberToBytes(value, length); }

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
            data = DataBuffer.bytesToString(data);
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
        try {
            data = decodeURIComponent(data)
                ?.replaceAll('-', '+')
                ?.replaceAll('_', '/')
                ?.replaceAll(/^"|"$/g, '');
            const encodedData = atob(data);
            return DataBuffer.stringToBytes(encodedData);
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
export class DataBuffer {
    /**
    * @param {Buffer} buffer The byte string to read values from.
    */
    constructor(buffer) {
        this.buffer = Array.from(buffer ?? []);
        this.offset = 0;
    }

    toBytes() { return this.buffer; }

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
        return DataBuffer.bytesToString(this.readBytes(size));
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
        return DataBuffer.bytesToNumber(value);
    }

    readInt8() {
        return this.readInt(1);
    }

    readInt16() {
        return this.readInt(2);
    }

    readInt32() {
        return this.readInt(4);
    }

    readInt64() {
        return this.readInt(8);
    }

    peekInt() {
        return this.buffer[this.offset];
    }

    writeInt(value = 0, size = 2) {
        this.buffer.push(...DataBuffer.numberToBytes(value, size));
    }

    writeBytes(bytes = []) {
        this.buffer.push(...bytes);
    }

    writeString(str = '') {
        this.writeBytes(DataBuffer.stringToBytes(str));
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

    static numberToBytes(value = 0n, length) {

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
        const data = new DataBuffer(rawData);

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
            return data.readInt8();
        if (additionalInformation === 25)
            return data.readInt16();
        if (additionalInformation === 26)
            return data.readInt32();
        if (additionalInformation === 27)
            return data.readInt64();
        if (additionalInformation === 31)
            return -1;
        throw "Invalid length encoding";
    }
    static #readIndefiniteStringLength(data, majorType) {
        const initialByte = data.readInt8();
        if (initialByte === 0xff)
            return -1;
        const length = CBOR.#readLength(initialByte & 0x1f, data);
        if (length < 0 || (initialByte >> 5) !== majorType)
            throw "Invalid indefinite length element";
        return length;
    }

    static #decodeItem(data) {
        const initialByte = data.readInt8();
        const majorType = initialByte >> 5;
        const additionalInformation = initialByte & 0x1f;

        if (majorType === 7) {
            switch (additionalInformation) {
                case 25:
                    return data.readInt16();
                case 26:
                    return data.readInt32();
                case 27:
                    return data.readInt64();
            }
        }

        let length = CBOR.#readLength(additionalInformation, data);
        if (length < 0 && (majorType < 2 || majorType > 6))
            throw "Invalid length";

        switch (majorType) {
            case 0: // 0 - 2^53
                return length;
            case 1: // -1 - -2^53
                return -1 - length;
            case 2:
                if (length < 0) {
                    const result = [];
                    while ((length = CBOR.#readIndefiniteStringLength(data, majorType)) >= 0) {
                        result.push(...data.readBytes(length));
                    }
                    return result;
                }
                return data.readBytes(length);
            case 3:
                const result = [];
                if (length < 0) {
                    while ((length = CBOR.#readIndefiniteStringLength(data, majorType)) >= 0) {
                        result.push(...data.readBytes(length));
                    }
                }
                else {
                    result.push(...data.readBytes(length));
                }
                return DataBuffer.bytesToString(result);
            case 4:
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
            case 5:
                const retObject = {};
                for (let i = 0; i < length || length < 0 && !CBOR.#readBreak(data); ++i) {
                    const key = CBOR.#decodeItem(data);
                    retObject[key] = CBOR.#decodeItem(data);
                }
                return retObject;
            case 6:
                return;
            // return tagger(decodeItem(), length);
            case 7:
                switch (length) {
                    case 20:
                        return false;
                    case 21:
                        return true;
                    case 22:
                        return null;
                    case 23:
                        return undefined;
                    default:
                        return undefined;
                    //     return simpleValue(length);
                }
        }
    }

}
