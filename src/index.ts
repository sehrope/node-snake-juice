import forge = require('node-forge');
import {
    toPositiveHex,
    DigestAlgorithmName,
    getDigestAlgorithm,
    pkiRsaGenerateKeyPairAsync,
    pkiCertificateToAsn1,
} from './util';

export enum SubjectAltNameType {
    OTHER_NAME = 0,
    RFC_822_NAME = 1,
    DNS_NAME = 2,
    X400_ADDRESS = 3,
    DIRECTORY_NAME = 4,
    EDI_PARTY_NAME = 5,
    URI = 6,
    IP_ADDRESS = 7,
    REGISTERED_ID = 8,
}


export interface KeyAndCert {
    privateKey: string;
    publicKey: string;
    certificate: string;
    fingerprint: string;
}

export interface Subject {
    commonName?: string;
    state?: string;
    country?: string;
    localityName?: string;
    organizationName?: string;
    organizationalUnitName?: string;
}

export interface SubjectAltName {
    type: SubjectAltNameType;
    value: string;
}

export interface GenerateOptions {
    keySizeInBits?: number;
    digestAlgorithm?: DigestAlgorithmName;
    validity?: {
        notBefore?: Date;
        days?: number;
    };
    subject?: Subject;
    subjectAltNames?: SubjectAltName[];
}

interface Attribute {
    name: string;
    value: string;
}

function subjectToAttributes(subject: Subject) {
    if (!subject) {
        return [];
    }
    const attributes: Attribute[] = [];
    if (subject.commonName) {
        attributes.push({
            name: 'commonName',
            value: subject.commonName,
        });
    }
    if (subject.state) {
        attributes.push({
            name: 'stateOrProvinceName',
            value: subject.state,
        });
    }
    if (subject.country) {
        attributes.push({
            name: 'countryName',
            value: subject.country,
        });
    }
    if (subject.localityName) {
        attributes.push({
            name: 'localityName',
            value: subject.localityName,
        });
    }
    if (subject.organizationName) {
        attributes.push({
            name: 'organizationName',
            value: subject.organizationName,
        });
    }
    if (subject.organizationalUnitName) {
        attributes.push({
            name: 'organizationalUnitName',
            value: subject.organizationalUnitName,
        });
    }
    return attributes;
}

const DEFAULT_VALIDITY_DAYS = 10 * 365;

async function generate(commonName: string, keySizeInBits?: number): Promise<KeyAndCert>;
async function generate(subjectAltNames: string[], keySizeInBits?: number): Promise<KeyAndCert>;
async function generate(opts: GenerateOptions): Promise<KeyAndCert>;
async function generate(opts: GenerateOptions | string | string[], keySizeInBits?: number): Promise<KeyAndCert> {
    if (typeof (opts) === 'string') {
        const commonName = opts;
        opts = {
            keySizeInBits,
            subject: {
                commonName,
            },
            subjectAltNames: [{
                type: SubjectAltNameType.DNS_NAME,
                value: commonName,
            }],
        };
    } else if (Array.isArray(opts)) {
        opts = {
            keySizeInBits,
            subjectAltNames: opts.map((subjectAltName) => ({
                type: SubjectAltNameType.DNS_NAME,
                value: subjectAltName,
            })),
        };
    }
    const hasCommonName = opts.subject && !!opts.subject.commonName;
    const hasSubjectAltNames = (opts.subjectAltNames || []).length > 0;
    if (!hasCommonName && !hasSubjectAltNames) {
        throw new Error('Either a commonName or subjectAltName is required');
    }
    keySizeInBits = opts.keySizeInBits || 2048;
    const validity = opts.validity || {};
    const notBefore = validity.notBefore || new Date();
    const notAfter = new Date();
    notAfter.setDate(notBefore.getDate() + (validity.days || DEFAULT_VALIDITY_DAYS));
    const attributes: Attribute[] = subjectToAttributes(opts.subject);
    const extensions: any[] = [];
    extensions.push({
        name: 'basicConstraints',
        cA: true,
    });
    extensions.push({
        name: 'keyUsage',
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true,
    });
    if (opts.subjectAltNames && opts.subjectAltNames.length > 0) {
        extensions.push({
            name: 'subjectAltName',
            altNames: opts.subjectAltNames,
        });
    }
    const keyPair = await pkiRsaGenerateKeyPairAsync(keySizeInBits);
    const algorithm = getDigestAlgorithm(opts.digestAlgorithm);
    const cert = forge.pki.createCertificate();
    cert.serialNumber = toPositiveHex(forge.util.bytesToHex(forge.random.getBytesSync(9)));
    cert.validity.notBefore = notBefore;
    cert.validity.notAfter = notAfter;
    cert.publicKey = keyPair.publicKey;
    cert.setSubject(attributes);
    cert.setIssuer(attributes);
    cert.setExtensions(extensions);
    cert.sign(keyPair.privateKey, algorithm);
    const fingerprint = forge.md.sha1
        .create()
        .update(forge.asn1.toDer(pkiCertificateToAsn1(cert)).getBytes())
        .digest()
        .toHex()
        .match(/.{2}/g)
        .join(':');

    return {
        privateKey: forge.pki.privateKeyToPem(keyPair.privateKey),
        publicKey: forge.pki.publicKeyToPem(keyPair.publicKey),
        certificate: forge.pki.certificateToPem(cert),
        fingerprint,
    };
}

export const SnakeJuice = {
    generate,
};
