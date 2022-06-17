// jwt JSON-Web-Ticket in Action
// Web Engineering and XML-Applications
// npm i -D express
// npm i -D jsonwebtoken
// npm i -D node-rsa
// npm i -D base-64

const express = require("express")
const jwt = require("jsonwebtoken")
const NodeRSA = require('node-rsa')
const base64 = require('base-64')
const fs = require('fs')

const app = express()
const key = new NodeRSA({b: 512})
key.generateKeyPair()
const publickey = key.exportKey('pkcs8-public-pem')
const privatekey = key.exportKey('pkcs1-pem')
//const publickey = fs.readFileSync('./openssl/public.pem','utf-8')
//const privatekey = fs.readFileSync('./openssl/private.pem','utf-8')

const port = 3000

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
            let actual_ip = req.ip;
            let actual_agent = req.get('User-Agent');

            if ( payload_obj.body.ipaddress !== actual_ip || payload_obj.body.agent !== actual_agent ){  
                res.status(500).json({ error: "Not Authorized Agent or IP" });
                throw new Error("Not Authorized Agent or IP");
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
            "username": "kruhland",
            "ipaddress": req.ip,
            "agent": req.get('User-Agent')
        }
    let token = jwt.sign({ "body" : payload}, privatekey, {algorithm: 'HS256', expiresIn: '24h'})
    res.json({"jwt": token});
})

app.listen(port,
    () => console.log(`Simple Express App listening on port ${port}`))