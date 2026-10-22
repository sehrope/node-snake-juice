import crypto = require('crypto');

export function generateRsaKeyPairAsync(keySizeInBits: number): Promise<crypto.KeyPairKeyObjectResult> {
    return new Promise((resolve, reject) => {
        crypto.generateKeyPair('rsa', {
            modulusLength: keySizeInBits,
        }, (err, publicKey, privateKey) => {
            if (err) {
                return reject(err);
            }
            return resolve({ publicKey, privateKey });
        });
    });
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
