import crypto = require('crypto');
import {
    toPositiveHex,
    DigestAlgorithmName,
    generateRsaKeyPairAsync,
} from './util';
import {
    createCertificate,
    certificateToPem,
    toCrlf,
} from './x509';

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

function subjectToAttributes(subject: Subject | undefined) {
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
    const notAfter = new Date(notBefore.getTime());
    notAfter.setUTCDate(notAfter.getUTCDate() + (validity.days || DEFAULT_VALIDITY_DAYS));
    const attributes: Attribute[] = subjectToAttributes(opts.subject);
    const keyPair = await generateRsaKeyPairAsync(keySizeInBits);
    const certificate = createCertificate({
        keyPair,
        serialNumber: toPositiveHex(crypto.randomBytes(9).toString('hex')),
        notBefore,
        notAfter,
        attributes,
        altNames: opts.subjectAltNames || [],
        digestAlgorithm: opts.digestAlgorithm || 'sha256',
    });
    const fingerprint = crypto.createHash('sha1')
        .update(certificate)
        .digest('hex')
        .match(/.{2}/g)!
        .join(':');

    return {
        privateKey: toCrlf(keyPair.privateKey.export({ type: 'pkcs1', format: 'pem' }) as string),
        publicKey: toCrlf(keyPair.publicKey.export({ type: 'spki', format: 'pem' }) as string),
        certificate: certificateToPem(certificate),
        fingerprint,
    };
}

export const SnakeJuice = {
    generate,
};
