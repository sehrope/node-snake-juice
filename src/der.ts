// Minimal DER encoder, only what is needed to build a self signed certificate.

function encodeLength(length: number): Buffer {
    if (length < 0x80) {
        return Buffer.from([length]);
    }
    const bytes: number[] = [];
    for (let n = length; n > 0; n = Math.floor(n / 256)) {
        bytes.unshift(n & 0xff);
    }
    return Buffer.from([0x80 | bytes.length, ...bytes]);
}

export function tlv(tag: number, value: Buffer): Buffer {
    return Buffer.concat([Buffer.from([tag]), encodeLength(value.length), value]);
}

export function sequence(...items: Buffer[]): Buffer {
    return tlv(0x30, Buffer.concat(items));
}

export function set(...items: Buffer[]): Buffer {
    return tlv(0x31, Buffer.concat(items));
}

// value is an unsigned big-endian number; leading zeros are dropped but one is
// kept if needed to keep the high bit clear
export function integer(value: Buffer): Buffer {
    let start = 0;
    while (start < value.length - 1 && value[start] === 0 && (value[start + 1] & 0x80) === 0) {
        start++;
    }
    return tlv(0x02, value.subarray(start));
}

export function octetString(value: Buffer): Buffer {
    return tlv(0x04, value);
}

export function bitString(value: Buffer): Buffer {
    // Leading byte is the number of unused bits in the last byte
    return tlv(0x03, Buffer.concat([Buffer.from([0]), value]));
}

export function oidBytes(oid: string): Buffer {
    const parts = oid.split('.').map(Number);
    const bytes = [40 * parts[0] + parts[1]];
    for (const part of parts.slice(2)) {
        const encoded = [part & 0x7f];
        for (let n = Math.floor(part / 128); n > 0; n = Math.floor(n / 128)) {
            encoded.unshift(0x80 | (n & 0x7f));
        }
        bytes.push(...encoded);
    }
    return Buffer.from(bytes);
}

export function oid(oid: string): Buffer {
    return tlv(0x06, oidBytes(oid));
}

export function time(date: Date): Buffer {
    const iso = date.toISOString();
    const value = iso.slice(0, 4) + iso.slice(5, 7) + iso.slice(8, 10)
        + iso.slice(11, 13) + iso.slice(14, 16) + iso.slice(17, 19) + 'Z';
    const year = date.getUTCFullYear();
    // RFC 5280 4.1.2.5: UTCTime through 2049, GeneralizedTime otherwise
    if (year >= 1950 && year < 2050) {
        return tlv(0x17, Buffer.from(value.slice(2), 'latin1'));
    }
    return tlv(0x18, Buffer.from(value, 'latin1'));
}

export const NULL = Buffer.from([0x05, 0x00]);
export const TRUE = Buffer.from([0x01, 0x01, 0xff]);
