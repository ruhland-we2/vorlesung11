// jwt JSON-Web-Ticket in Action
// Web Engineering and XML-Applications
// npm i express
// npm i jsonwebtoken
// npm i node-rsa
// npm i base-64
// npm i crypto-js

const express = require("express");
const jwt = require("jsonwebtoken");
const NodeRSA = require('node-rsa');
const base64 = require('base-64');
const fs = require('fs');
const CryptoJS = require('crypto-js');

const app = express()
//const key = new NodeRSA({b: 512})
//key.generateKeyPair()
//onst publickey = key.exportKey('pkcs8-public-pem')
//const privatekey = key.exportKey('pkcs1-pem')
const publickey = fs.readFileSync('./openssl/public.pem','utf-8')
const privatekey = fs.readFileSync('./openssl/private.pem','utf-8')

const port = 3000;

function getFingerprintHash(req){
    let fingerprint = {
        host: req.get("Host"),
        agent: req.get('User-Agent'),
        accept: req.get('Accept'),
        accept_encoding: req.get('Accept-Encoding'),
        accept_language: req.get('Accept-Language')
    };
    return CryptoJS.SHA256(JSON.stringify(fingerprint)).toString();
}

function isAuthenticated(req, res, next) {
    if (typeof req.headers.authorization !== "undefined") {
        // retrieve the authorization header and parse out the
        // JWT using the split function
        let token = req.headers.authorization.split(" ")[1];
        // Here we validate that the JSON Web Token is valid and has been 
        // created using the same private pass phrase
        jwt.verify(token, privatekey, { algorithm: "HS256" }, (err, user) => {
            // if there has been an error...
            if (err) {  
                // shut them out!
                res.status(500).json({ error: "Not Authorized" });
                throw new Error("Not Authorized");
            }
            let payload = token.split(".")[1];
            let payload_obj = JSON.parse(base64.decode(payload));
            let fingerprint_hash = getFingerprintHash(req);
            let payload_hash = payload_obj.body.hash;

            if ( payload_hash !== fingerprint_hash ){  
                res.status(500).json({ error: "Not Authorized Agent" });
                throw new Error("Not Authorized Agent");
            }

            // if the JWT is valid, allow them to hit
            // the intended endpoint
            return next();
        });
    } else {
        // No authorization header exists on the incoming
        // request, return not authorized and throw a new error 
        res.status(500).json({ error: "Not Authorized" });
        throw new Error("Not Authorized");
    }
}

// for the index.html
app.use("/", express.static(__dirname + ''));

app.get('/secret', isAuthenticated, (req,res) => {
    res.json({"message": "THIS IS SUPER SECRET!"})
})

app.get('/readme', (req,res) => {
    res.json({"message": "This is open to the world"})
})

app.get('/jwt', (req,res) => {
    let payload = {
            "hash": getFingerprintHash(req)
        };
    let token = jwt.sign({ "body" : payload}, privatekey, {algorithm: 'HS256', expiresIn: '24h'})
    res.json({"jwt": token});
})

app.listen(port,
    () => console.log(`Simple Express App listening on port ${port}`))