const fs = require('fs');
const crypto = require('crypto');
const ursa = require('ursa');


const musePrivateKey = fs.readFileSync('./keys/bussiness.pkcs8', 'utf8');
const musePublicKey = fs.readFileSync('./keys/bussiness.pub');
const m2pPrivateKey = fs.readFileSync('./keys/m2p.pkcs8', 'utf8');
const m2pPublicKey = fs.readFileSync('./keys/m2p.pub');

function m2pEncryptRequest(request) {
    // console.log("inside m2pEncryptRequest : ", request);
    const requestModified = JSON.stringify(request);
    // ref no
    const refNo = '1234123412341234'; //crypto.randomBytes(8).toString('hex');
    const encryptionKey = crypto.randomBytes(16).toString('hex'); //.toString('hex')
    // console.log("inside m2pEncryptRequest/encryptionKey : ", encryptionKey);
    // const encryptionKey = '1234123412341234'; //.toString('hex')

    // step 1
    const cipher = crypto.createCipheriv('aes-256-cbc', Buffer.from(encryptionKey), Buffer.from(refNo));
    cipher.setAutoPadding(true);

    let encrypted = cipher.update(requestModified, 'utf8', 'base64');

    encrypted += cipher.final('base64'); //Buffer.concat([ encrypted, cipher.final('base64') ]);

    // body
    const body = encrypted; //encrypted.toString('base64');

    // token
    const sign = ursa.createPrivateKey(musePrivateKey);
    // TODO, encrypted body or requestModified?, as in doc it's written "constructed JSON"
    const token = sign.hashAndSign('sha1', requestModified, 'utf8', 'base64');

    // key
    const publicKey = ursa.createPublicKey(m2pPublicKey);
    // console.log("type of publicKey : ", typeof publicKey);
    const key = publicKey.encrypt(encryptionKey, 'utf8', 'base64', ursa.RSA_PKCS1_PADDING);

    // entity
    const entityName = 'MUSE';
    const entity = publicKey.encrypt(entityName, 'utf8', 'base64', ursa.RSA_PKCS1_PADDING);

    var temp = JSON.stringify({ token, body, entity, refNo, key });
    // return JSON.stringify({ token, body, entity, refNo, key });

    let encryptedData = {token, body, entity, refNo, key };

    // console.log("encryptedData ", encryptedData);
    // let encryptionKeyhex = encryptionKey.toString('hex');

    let decryptedData = m2pDencryptRequest(encryptedData);
    return  {decryptedData, encryptionKey, encryptedData: {token, body, entity, refNo, key,}};
}

function m2pDencryptRequest(request) {
    let {token, body, entity, refNo, key } = request;
    // console.log("body, ", body);

    let privateKeyDec = ursa.createPrivateKey(m2pPrivateKey);
    // console.log("m2pDencryptRequest/type of publicKeyDec : ", typeof publicKeyDec);
    let encryptionKeyDec = privateKeyDec.decrypt(key, 'base64', 'binary', ursa.RSA_PKCS1_PADDING);
    let entityDec = privateKeyDec.decrypt(entity, 'base64', 'utf8', ursa.RSA_PKCS1_PADDING);

    // console.log("encryptionKeyDec ", Buffer.from(encryptionKeyDec));
    //
    const decipher = crypto.createDecipheriv('aes-256-cbc', encryptionKeyDec, Buffer.from(refNo));
    decipher.setAutoPadding(true);

    let decrypted = decipher.update(body, 'base64', 'utf8');

    decrypted += decipher.final('utf8'); //Buffer.concat([ encrypted, cipher.final('base64') ]);

    const publicKey = ursa.createPublicKey(musePublicKey);
    const verify = publicKey.hashAndVerify('sha1', Buffer.from(decrypted), token, 'base64');
    // console.log('tokensVerification: ' + verify);

    return {encryptionKeyDec, decrypted, verify, entityDec, refNo};
}

function encryptPostReq() {
    // console.log("inside encryptPostReq");
    const request = {
        entityId: 'conzumex001'
    };

    try {
        return m2pEncryptRequest(request);
    } catch (error) {
        console.log("error : ", error);
    }
}

console.log(encryptPostReq());
