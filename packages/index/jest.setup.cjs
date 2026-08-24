const { Crypto } = require("@peculiar/webcrypto");

globalThis.crypto = new Crypto();
