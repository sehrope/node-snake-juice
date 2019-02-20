# snake-juice

[![NPM](https://nodei.co/npm/snake-juice.png?downloads=true&downloadRank=true&stars=true)](https://nodei.co/npm/snake-juice/)

[![Build Status](https://travis-ci.org/sehrope/node-snake-juice.svg?branch=master)](https://travis-ci.org/sehrope/node-snake-juice)

# Overview
Generate self signed TLS certificates (i.e. "snake oil).

* [Install](#install)
* [Usage](#usage)
* [Features](#features)
* [Building and Testing](#building-and-testing)
* [License](#license)

# Install

    $ npm install snake-juice --save

# Dependencies

* [node-forge](https://www.npmjs.com/package/node-forge)

# Features
* Simple interface for generating self signed certificates.
* Allows specifying either the commonName or a list of subjectAltNames
* Customize the RSA key size (default 2048)
* Customize the signature algorithm (default SHA-256)
* Customize the duration of the certificate (default 10 years)
* TypeScript declarations for simplified usage

# Usage
## Import
```typescript
import { SnakeJuice } from 'snake-juice';
```

## Returns
```typescript
interface KeyAndCert {
    privateKey: string;
    publicKey: string;
    certificate: string;
    fingerprint: string;
}
```

## Create with a common name and single subjectAltName
```typescript
const keyAndCert = await SnakeJuice.generate('dummy.example.com');
```

## Create with multiple subjectAltNames
```typescript
const keyAndCert = await SnakeJuice.generate([
    'a.example.com',
    'b.example.com',
    'c.example.com',
]);
```

## Create with multiple subjectAltNames and a custom key size
```typescript
// Warning: This could take a while (>10 seconds) to run
const keyAndCert = await SnakeJuice.generate([
    'a.example.com',
    'b.example.com',
    'c.example.com',
], 4096);
```

## Create with a lot of customzied options
```typescript
const keyAndCert = await SnakeJuice.generate({
    // Too small for real usage but fine for testing
    keySizeInBits: 1024,
    // Override to SHA1
    digestAlgorithm: 'sha1',
    // Custom
    validity: {
        // Override starting effective date
        notBefore: new Date('2018-01-01T12:00:00Z')
        // Override number of days that cert will be valid
        days: 1000,
    },
    // Explicit list of subjectAltNames
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
            // Can even specify non-DNS types
            type: SubjectAltNameType.IP_ADDRESS,
            value: '10.20.30.40',
        },
    ],
});
```

# Building and Testing
To build the module run:

    $ make

Then, to run the tests run:

    $ make test

# License
ISC. See the file [LICENSE](LICENSE).

# Credits
The real lifting is done by node-forge. Also, looking through the code for [selfsigned](https://www.npmjs.com/package/selfsigned) helped out a lot as well.
 