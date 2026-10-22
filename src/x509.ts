import crypto = require('crypto');
import net = require('net');
import {
    tlv,
    sequence,
    set,
    integer,
    octetString,
    bitString,
    oidBytes,
    oid,
    time,
    NULL,
    TRUE,
} from './der';
import { DigestAlgorithmName } from './util';

const ATTRIBUTE_OIDS: { [name: string]: string } = {
    commonName: '2.5.4.3',
    countryName: '2.5.4.6',
    localityName: '2.5.4.7',
    stateOrProvinceName: '2.5.4.8',
    organizationName: '2.5.4.10',
    organizationalUnitName: '2.5.4.11',
};

const SIGNATURE_OIDS: { [name: string]: string } = {
    sha1: '1.2.840.113549.1.1.5',
    sha256: '1.2.840.113549.1.1.11',
};

const OID_BASIC_CONSTRAINTS = '2.5.29.19';
const OID_KEY_USAGE = '2.5.29.15';
const OID_SUBJECT_ALT_NAME = '2.5.29.17';

const SAN_TYPE_IP_ADDRESS = 7;
const SAN_TYPE_REGISTERED_ID = 8;

export interface CertificateAttribute {
    name: string;
    value: string;
}

export interface CertificateAltName {
    type: number;
    value: string;
}

export interface CertificateOptions {
    keyPair: crypto.KeyPairKeyObjectResult;
    serialNumber: string;
    notBefore: Date;
    notAfter: Date;
    attributes: CertificateAttribute[];
    altNames: CertificateAltName[];
    digestAlgorithm: DigestAlgorithmName;
}

function distinguishedName(attributes: CertificateAttribute[]): Buffer {
    return sequence(...attributes.map(({ name, value }) => {
        // RFC 5280 requires PrintableString for countryName and recommends
        // UTF8String for the rest
        const encoded = name === 'countryName'
            ? tlv(0x13, Buffer.from(value, 'latin1'))
            : tlv(0x0c, Buffer.from(value, 'utf8'));
        return set(sequence(oid(ATTRIBUTE_OIDS[name]), encoded));
    }));
}

function ipv4Bytes(ip: string): number[] {
    return ip.split('.').map(Number);
}

function ipAddressBytes(ip: string): Buffer {
    if (net.isIPv4(ip)) {
        return Buffer.from(ipv4Bytes(ip));
    }
    if (!net.isIPv6(ip)) {
        throw new Error('Invalid IP address: ' + ip);
    }
    const [head, tail] = ip.split('::');
    const toBytes = (part: string) => !part ? [] : part.split(':').reduce((bytes: number[], group) => {
        // Trailing dotted IPv4, e.g. ::ffff:10.0.0.1
        if (group.includes('.')) {
            return bytes.concat(ipv4Bytes(group));
        }
        const n = parseInt(group, 16);
        return bytes.concat([n >> 8, n & 0xff]);
    }, []);
    const headBytes = toBytes(head);
    const tailBytes = toBytes(tail);
    const zeros = new Array(16 - headBytes.length - tailBytes.length).fill(0);
    return Buffer.from([...headBytes, ...zeros, ...tailBytes]);
}

function generalName(altName: CertificateAltName): Buffer {
    let value: Buffer;
    if (altName.type === SAN_TYPE_IP_ADDRESS) {
        value = ipAddressBytes(altName.value);
    } else if (altName.type === SAN_TYPE_REGISTERED_ID) {
        value = oidBytes(altName.value);
    } else {
        value = Buffer.from(altName.value, 'latin1');
    }
    return tlv(0x80 | altName.type, value);
}

function extension(id: string, value: Buffer): Buffer {
    return sequence(oid(id), octetString(value));
}

export function createCertificate(opts: CertificateOptions): Buffer {
    const signatureOid = SIGNATURE_OIDS[opts.digestAlgorithm];
    if (!signatureOid) {
        throw new Error('Invalid digest algorithm: ' + opts.digestAlgorithm);
    }
    const signatureAlgorithm = sequence(oid(signatureOid), NULL);
    const name = distinguishedName(opts.attributes);
    const extensions = [
        extension(OID_BASIC_CONSTRAINTS, sequence(TRUE)),
        // digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment
        // and keyCertSign, with the 2 trailing bits unused
        extension(OID_KEY_USAGE, tlv(0x03, Buffer.from([0x02, 0xf4]))),
    ];
    if (opts.altNames.length > 0) {
        extensions.push(extension(OID_SUBJECT_ALT_NAME, sequence(...opts.altNames.map(generalName))));
    }
    const tbsCertificate = sequence(
        // version v3
        tlv(0xa0, integer(Buffer.from([2]))),
        integer(Buffer.from(opts.serialNumber, 'hex')),
        signatureAlgorithm,
        name,
        sequence(time(opts.notBefore), time(opts.notAfter)),
        name,
        opts.keyPair.publicKey.export({ type: 'spki', format: 'der' }),
        tlv(0xa3, sequence(...extensions)),
    );
    const signature = crypto.sign(opts.digestAlgorithm, tbsCertificate, opts.keyPair.privateKey);
    return sequence(tbsCertificate, signatureAlgorithm, bitString(signature));
}

// node-forge, used before, wrote PEM with CRLF line endings
export function toCrlf(pem: string): string {
    return pem.replace(/\r?\n/g, '\r\n');
}

export function certificateToPem(der: Buffer): string {
    const lines = der.toString('base64').match(/.{1,64}/g);
    return toCrlf('-----BEGIN CERTIFICATE-----\n' + lines.join('\n') + '\n-----END CERTIFICATE-----\n');
}
