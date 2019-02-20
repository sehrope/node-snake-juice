import forge = require('node-forge');

export function pkiRsaGenerateKeyPairAsync(keySizeInBits: number): Promise<forge.pki.rsa.KeyPair> {
    return new Promise((resolve, reject) => {
        forge.pki.rsa.generateKeyPair({
            bits: keySizeInBits,
        }, (err, keyPair) => {
            if (err) {
                return reject(err);
            }
            return resolve(keyPair);
        });
    });
}

export function pkiCertificateToAsn1(cert: forge.pki.Certificate): forge.asn1.Asn1 {
    return (forge.pki as any).certificateToAsn1(cert);
}

// a hexString is considered negative if it's most significant bit is 1
// because serial numbers use ones' complement notation
// this RFC in section 4.1.2.2 requires serial numbers to be positive
// http://www.ietf.org/rfc/rfc5280.txt
export function toPositiveHex(hexString: string) {
    var mostSiginficativeHexAsInt = parseInt(hexString[0], 16);
    if (mostSiginficativeHexAsInt < 8) {
        return hexString;
    }
    mostSiginficativeHexAsInt -= 8;
    return mostSiginficativeHexAsInt.toString() + hexString.substring(1);
}

export type DigestAlgorithmName = 'sha1' | 'sha256';

export function getDigestAlgorithm(name: DigestAlgorithmName = 'sha256') {
    if (name === 'sha1') {
        return forge.md.sha1.create();
    } else if (name === 'sha256') {
        return forge.md.sha256.create();
    }
    throw new Error('Invalid digest algorithm: ' + name);
}
