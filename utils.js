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

export function base64urlEncode(data, quote=false) {
    if (Array.isArray(data) || ArrayBuffer.isView(a)) {
        data = byteArrayToString(data);
    }

    return btoa(data ?? "").replace(/\+/g, '-').replace(/\//g, '_');
}

export function base64urlDecode(data) {
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


