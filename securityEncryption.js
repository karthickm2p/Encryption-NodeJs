"use strict";
const request = require('request-promise')
const crypto = require('crypto')
const fs    = require('fs')
const path  = require('path')

class Encryption {
    constructor() {
        this.refNo = this.generateRefNo()
        this.sessionKey = this.generateToken()
    }

    generateDigitalSignedToken (requestData) {
        const privateKeyWalrus = './walrus.pem'
        const privateKey = fs.readFileSync(path.resolve(__dirname, privateKeyWalrus),
            { encoding: 'utf8'})
        const signer = crypto.createSign('sha1WithRSAEncryption')
        signer.update(requestData)
        return signer.sign(privateKey, 'base64')
    }

    encryptData (requestData) {
        const cipher = crypto.createCipheriv('aes-128-cbc', this.sessionKey, this.refNo)
        cipher.setAutoPadding(true)
        let encrypted = cipher.update(requestData, 'utf8', 'base64')
        encrypted += cipher.final('base64')
        return encrypted
    }

    encryptBusEntity(entity) {
        return this.encryptKey(entity)
    }

    encryptKey (str) {
        const publicKeyM2P = './m2p.pub'
        const publicKey = fs.readFileSync(path.resolve(__dirname, publicKeyM2P),
            { encoding: 'utf8' })
        return crypto.publicEncrypt({ key:publicKey,
            padding:crypto.constants.RSA_PKCS1_PADDING
        }, str).toString('base64')
    }
    verifyHash() {
    }

    decodeResponse (response) {
        let refNo = response.headers.refNo
        let key = response.headers.key
        let entity = response.headers.entity
        let hash = response.headers.hash
        let body = response.body

        let decryptedKey = this.decryptSessionKey(Buffer.from(key, 'base64'))
        let decryptedBody = this.decryptMessage(Buffer.from(body, 'base64'), decryptedKey, refNo)
        console.log(decryptedKey)
        console.log(decryptedBody.toString('utf8'))
    }

    decryptMessage (responseData, sessionKey, refNo) {
        const decipher = crypto.createDecipheriv('aes-128-cbc', sessionKey, refNo)
        decipher.setAutoPadding(true)
        let decrypted = decipher.update(responseData)
        decrypted += decipher.final('utf8')
        return decrypted
    }

    decryptSessionKey (encSessionKey) {
        const privateKeyWalrus = './walrus.pem'
        const privateKey = fs.readFileSync(path.resolve(__dirname, privateKeyWalrus),
            { encoding: 'utf8' })
        return crypto.privateDecrypt({ key: privateKey,
            padding:crypto.constants.RSA_PKCS1_PADDING
        }, encSessionKey)
    }

    generateToken() {
        return crypto.randomBytes(16)
    }

    generateRefNo() {
        return (Math.random()+' ').substring(2,10)+(Math.random()+' ').substring(2,10)
    }

    buildRequest (requestData, busEntity) {
        return  {
            "body": this.encryptData(requestData),
            "token": this.generateDigitalSignedToken(requestData),
            "entity": this.encryptBusEntity(Buffer.from(busEntity)),
            "key": this.encryptKey(this.sessionKey),
            "refNo": this.refNo
        }
    }
}
async function test() {
    try {
        let enc = new Encryption()
        let cardDetailsUrl = 'https://ssltest.yappay.in/Yappay/' + 'business-entity-manager/getCardList'
        let headers = {
            'Content-Type': 'application/json',
            'Authorization': 'Basic YWRtaW46YWRtaW4=',
            'Tenant': 'EQWALRUS'
        }
        let jsonData = {
            "entityId": "0006835587"
        }
        let encodedRequest = enc.buildRequest(JSON.stringify(jsonData), 'EQWALRUS')
        let options  =  {
            method: "POST",
            uri: cardDetailsUrl,
            body: encodedRequest,
            json: true,
            headers: headers
        }

        let encodedResponse = await request(options)
        let response = enc.decodeResponse(encodedResponse)
        console.log(response)
    } catch(e) {
        console.log(e)
    }
}

test()

/*
   - Encrypt constructed JSON string with the Symmetric key - generateToken()
   - Encrypt the generated Symmetric key with YAP's public key

   - Sign constructed JSON with YAP's public Key - output to Base64
   - Encrypt the Business EntityId using YAP's public Key

*/