// host to network long
export function hostToNetworkLong(n) {
    return [(n >> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
}

// host to network short
export function hostToNetworkShort(n) {
    return [(n >> 8) & 0xff, n & 0xff];
}

// network to host long
export function networkToHostLong(n) {
    return (n[0] << 24) + (n[1] << 16) + (n[2] << 8) + n[3];
}

// network to host short
export function networkToHostShort(n) {
    return (n[0] << 8) + n[1];
}

export function bigIntToByteArray(data = 0n, length) {
    let hex = BigInt(data).toString(16);

    if (hex.length / 2 < length) { hex = hex.padStart(length * 2, '0'); }
    if (hex.length % 2) { hex = '0' + hex; }

    const result = Array(Math.max(hex.length / 2, length)).fill(0);

    for (let i = 0; i < hex.length / 2; i++) {
        result[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    }

    return result;
}

export function byteArrayToBigInt(octets = []) {
    let result = 0n;
    for (const octet of octets) {
        result <<= 8n;
        result += BigInt(octet);
    }
    return result;
}
/**
 * I2OSP function
 * @param {Number} value - Number to be encoded to byte array in network byte order.
 * @param {Number} len - Length of byte array
 * @return {Uint8Array} - Encoded number.
 */
function i2osp(value = 0, len = 2) {
    const r = new Uint8Array(len);

    for (let i = 0; i < len; i++) {
        const y = 0xff & (value >> (i * 8));
        r[len - i - 1] = y;
    }
    return r;
}

export function base64Encode(data) { return Base64.encode(data); }

export function base64urlEncode(data, quote = false) { return Base64.urlEncode(data, quote); }

export function base64urlDecode(data) { return Base64.decode(data); }

export function hexDecode(s) {
    if (/^[0-9a-fA-F]+$/.test(s)) {
        try {
            return s?.replaceAll(/[^0-9a-z]/gi, '0')?.match(/.{1,2}/g)?.map(a => parseInt(a, 16));
        }
        catch {
        }
    }
    return [];
}

export function hexEncode(data = []) {
    return data.map(v => v.toString(16).padStart(2, '0')).join('');
}

export function stringToByteArray(data) {
    if (Array.isArray(data)) {
        return data;
    }
    return Array.from(Uint8Array.from(data ?? '', c => c.charCodeAt(0)));
    // return [...new TextEncoder().encode(data ?? '')]
    // return data?.split('')?.map( c => c.charCodeAt(0)) ?? [];
}

export function byteArrayToString(value = []) {
    return Array.from(value).map(char => String.fromCharCode(char)).join('');
}

export async function sha256(data = []) {
    if (Array.isArray(data)) {
        data = new Uint8Array(data);
    }
    return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256', data)));
}

export class Base64 {
    static encode(data) {
        if (Array.isArray(data) || ArrayBuffer.isView(data)) {
            data = byteArrayToString(data);
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
            return stringToByteArray(encodedData);
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

    /**
    * Parses `size` bytes from the buffer as an integer and increments the offset by `size`.
    *
    * @param {number} size The number of bytes to parse.
    * @returns {number} The parsed integer.
    */
    readInt(size = 1) {
        const value = this.readBytes(size);
        if (size === 4) return networkToHostLong(value);
        if (size === 2) return networkToHostShort(value);
        if (size === 1) return value[0];

        // what do we do here?
        return value;
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
        this.buffer.push(...bigIntToByteArray(value, size));
    }

    writeBytes(bytes = []) {
        this.buffer.push(...bytes);
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

        const length = CBOR.#readLength(additionalInformation, data);
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
                return byteArrayToString(result);
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
