import { SnakeJuice, SubjectAltNameType, KeyAndCert } from '../src';
import assert = require('assert');
import crypto = require('crypto');

const SAN_PREFIXES: { [type: number]: string } = {
    [SubjectAltNameType.RFC_822_NAME]: 'email',
    [SubjectAltNameType.DNS_NAME]: 'DNS',
    [SubjectAltNameType.URI]: 'URI',
    [SubjectAltNameType.IP_ADDRESS]: 'IP Address',
};

function parseCertificate(keyAndCert: KeyAndCert) {
    const certificate = new crypto.X509Certificate(keyAndCert.certificate);
    assert.ok(certificate.verify(certificate.publicKey));
    assert.ok(certificate.checkPrivateKey(crypto.createPrivateKey(keyAndCert.privateKey)));
    return certificate;
}

function getCommonName(keyAndCert: KeyAndCert) {
    const subject = parseCertificate(keyAndCert).subject || '';
    const line = subject.split('\n').find((line) => line.startsWith('CN='));
    return line && line.substring('CN='.length);
}

function checkHasCommonName(keyAndCert: KeyAndCert, expectedCommonName: string) {
    assert.equal(getCommonName(keyAndCert), expectedCommonName);
}

function checkHasNoCommonName(keyAndCert: KeyAndCert) {
    assert.equal(getCommonName(keyAndCert), undefined);
}

function checkHasSubjectAltName(keyAndCert: KeyAndCert, expectedType: SubjectAltNameType, expectedName: string) {
    const { subjectAltName } = parseCertificate(keyAndCert);
    assert.ok(subjectAltName);
    assert.ok(subjectAltName.split(', ').includes(SAN_PREFIXES[expectedType] + ':' + expectedName));
}

describe('generate(...)', () => {
    it('should create a keyAndCert with a single name', async () => {
        const keyAndCert = await SnakeJuice.generate('a.example.com');
        assert.ok(keyAndCert.privateKey);
        assert.ok(keyAndCert.publicKey);
        assert.ok(keyAndCert.certificate);
        assert.ok(keyAndCert.fingerprint);
        checkHasCommonName(keyAndCert, 'a.example.com');
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'a.example.com');
    });

    it('should create a keyAndCert with a list of subjectAltNames as DNS entries', async () => {
        const keyAndCert = await SnakeJuice.generate([
            'a.example.com',
            'b.example.com',
            'c.example.com',
        ]);
        assert.ok(keyAndCert.privateKey);
        assert.ok(keyAndCert.publicKey);
        assert.ok(keyAndCert.certificate);
        assert.ok(keyAndCert.fingerprint);
        checkHasNoCommonName(keyAndCert);
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'a.example.com');
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'b.example.com');
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'c.example.com');
    });

    it('should create a keyAndCert with a list of subjectAltNames as DNS entries and a keysize', async () => {
        const keyAndCert = await SnakeJuice.generate([
            'a.example.com',
            'b.example.com',
            'c.example.com',
        ], 1024);
        assert.ok(keyAndCert.privateKey);
        assert.ok(keyAndCert.publicKey);
        assert.ok(keyAndCert.certificate);
        assert.ok(keyAndCert.fingerprint);
        checkHasNoCommonName(keyAndCert);
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'a.example.com');
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'b.example.com');
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'c.example.com');
    });

    it('should create a keyAndCert with a full option set', async () => {
        const notBefore = new Date('2018-01-01T12:00:00Z');
        const days = 10;
        const keyAndCert = await SnakeJuice.generate({
            keySizeInBits: 1024,
            digestAlgorithm: 'sha1',
            validity: {
                notBefore,
                days,
            },
            subjectAltNames: [
                {
                    type: SubjectAltNameType.DNS_NAME,
                    value: 'a.example.com',
                },
                {
                    type: SubjectAltNameType.DNS_NAME,
                    value: 'b.example.com',
                },
                {
                    type: SubjectAltNameType.IP_ADDRESS,
                    value: '10.20.30.40',
                },
            ],
        });
        assert.ok(keyAndCert.privateKey);
        assert.ok(keyAndCert.publicKey);
        assert.ok(keyAndCert.certificate);
        assert.ok(keyAndCert.fingerprint);
        checkHasNoCommonName(keyAndCert);
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'a.example.com');
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.DNS_NAME, 'b.example.com');
        checkHasSubjectAltName(keyAndCert, SubjectAltNameType.IP_ADDRESS, '10.20.30.40');
        const { validFrom, validTo } = parseCertificate(keyAndCert);
        assert.equal(new Date(validFrom).toISOString(), '2018-01-01T12:00:00.000Z');
        assert.equal(new Date(validTo).toISOString(), '2018-01-11T12:00:00.000Z');
    });
});
