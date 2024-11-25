// Decrypt the private key from server.js

const https = require('https');
const crypto = require('crypto');
const { privateKey } = require('../c2_server/server');

// const attackerPrivateKey = ;

function decryptPrivateKey(encrypted) {
    const buffer = Buffer.from(encrypted, 'base64');
    const decrypted = crypto.decryptedPK(
        {
            key: privateKey,
        },
        buffer
    );
    return decrypted.toString('uft8');
}

modules.exports = { decrypted };