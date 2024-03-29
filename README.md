# CRYSTALS-Dilithium (Javascript implementation)

[![npm version](https://badge.fury.io/js/%40asanrom%2Fdilithium.svg)](https://badge.fury.io/js/%40asanrom%2Fdilithium)

Javascript implementation of post-quantum signature algorithm: [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium).

Note: This is an experimental implementation. I do not recommend using it in production until the algorithm is standarized.

## Installation

If you are using a npm managed project use:

```
npm install @asanrom/dilithium
```

If you are using it in the browser, download the minified file from the [Releases](https://github.com/AgustinSRG/crystals-dilithium-js/tags) section and import it to your html:

```html
<script type="text/javascript" src="/path/to/dilithium.js"></script>
```

The browser library exports all artifacts to the window global: `DilithiumAlgorithm`

## Usage

```ts
import { DilithiumKeyPair, DilithiumLevel, DilithiumLevelNumber, DilithiumSignature } from "@asanrom/dilithium";

const level = DilithiumLevel.get(2); // Get the security level config (2, 3, or 5)

// Generate a key pair
const keyPair = DilithiumKeyPair.generate(level);

// Get the private key
const privateKey = keyPair.getPrivateKey();

// Sign a message
const message = new Uint8Array(Buffer.from("Joy!", "utf8"));
const signature = privateKey.sign(message);

// Get the public key
const publicKey = keyPair.getPublicKey();

// Validate signature
const valid = publicKey.verifySignature(message, signature);
```

## Documentation

 - [Library documentation (Auto-generated)](https://agustinsrg.github.io/crystals-dilithium-js/)
 - [Test in the browser](https://agustinsrg.github.io/crystals-dilithium-js/test.html)
