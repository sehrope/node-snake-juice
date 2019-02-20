import { SnakeJuice, SubjectAltNameType, KeyAndCert } from '../src';
import assert = require('assert');
import forge = require('node-forge');

function checkHasCommonName(keyAndCert: KeyAndCert, expectedCommonName: string) {
    const certificate = forge.pki.certificateFromPem(keyAndCert.certificate)
    assert.ok(certificate.subject);
    const attribute = certificate.subject.getField('CN');
    assert.ok(attribute);
    const commonName = attribute.value;
    assert.equal(commonName, expectedCommonName);
}

function checkHasNoCommonName(keyAndCert: KeyAndCert) {
    const certificate = forge.pki.certificateFromPem(keyAndCert.certificate)
    assert.ok(certificate.subject);
    const attribute = certificate.subject.getField('CN');
    assert.ok(!attribute);
}

function checkHasSubjectAltName(keyAndCert: KeyAndCert, expectedType: SubjectAltNameType, expectedName: string) {
    const certificate = forge.pki.certificateFromPem(keyAndCert.certificate)
    assert.ok(certificate.subject);
    const extension = certificate.getExtension('subjectAltName');
    assert.ok(extension);
    const { altNames } = extension as any;
    assert.ok(altNames.some((altName) => {
        return altName.type === expectedType && altName.value === expectedName;
    }));
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
    });
});
