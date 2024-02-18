const aws = require('aws-sdk');

const crypto = require('crypto');

const kmsClient = new aws.KMS();

function encrypt(buffer) {
    return new Promise((resolve, reject) => {
        const params = {
            KeyId: 'key-id', // The identifier of the CMK to use for encryption. You can use the key ID or Amazon Resource Name (ARN) of the CMK, or the name or ARN of an alias that refers to the CMK.
            Plaintext: buffer// The data to encrypt.
        };
        kmsClient.encrypt(params, (err, data) => {
            if (err) {
                console.log(err, err.stack);
                reject(err);
            } else {
                console.log(data);
                resolve(data.CiphertextBlob);
            }
        });
    });
}

function decrypt(buffer) {
    return new Promise((resolve, reject) => {
        const params = {
            CiphertextBlob: buffer// The data to encrypt.
        };
        kmsClient.decrypt(params, (err, data) => {
            if (err) {
                console.log(err, err.stack);
                reject(err);
            } else {
                console.log(data);
                resolve(data.Plaintext);
            }
        });
    });
}

function generateDataKey() {
    return new Promise((resolve, reject) => {
        const params = {
            KeyId: 'b4d237d5-e595-47db-9aec-771cb25a682f', // The identifier of the CMK to use to encrypt the data key. You can use the key ID or Amazon Resource Name (ARN) of the CMK, or the name or ARN of an alias that refers to the CMK.
            KeySpec: 'AES_256'// Specifies the type of data key to return.
        };
        kmsClient.generateDataKey(params, (err, data) => {
            if (err) {
                console.log(err, err.stack);
                reject(err);
            } else {
                console.log(data);
                resolve(data);
            }
        });
    });
}

function encryptAES(key, initVector, message) {
    const algorithm = 'AES-256-CBC';

    // const iv = new Buffer('00000000000000000000000000000000', 'hex');

    // generate 16 bytes of random data
    // const initVector = crypto.randomBytes(16);
    // console.log("Init vector: ", initVector.toString("hex"));

    // protected data
    //const message = "api-commons/getTimestamp";

    // secret key generate 32 bytes of random data
    // const Securitykey = crypto.randomBytes(32);

    // the cipher function
    const cipher = crypto.createCipheriv(algorithm, key, initVector);

    // encrypt the message
    // input encoding
    // output encoding
    let encryptedData = cipher.update(message, "utf-8", "hex");

    encryptedData += cipher.final("hex");
    
    console.log('Encrypted data: ', encryptedData);

    return encryptedData;
/*
    return encryptedData;

    encryptor = crypto.createCipheriv(algorithm, key, iv);
    encryptor.write(strBuffer);
    encryptor.end();

    const cipher_text = encryptor.read();
    console.log(cipher_text);

    return cipher_text;
    */
}

function decryptAES(key, initVector, encryptedData) {
    const algorithm = 'AES-256-CBC';

    // const iv = new Buffer('00000000000000000000000000000000', 'hex');

    // the decipher function
    const decipher = crypto.createDecipheriv(algorithm, key, initVector);

    let decryptedData = decipher.update(encryptedData, "hex", "utf-8");

    decryptedData += decipher.final("utf8");

    console.log("Decrypted message: " + decryptedData);

    return decryptedData;

    /*
    encryptor = crypto.createDecipheriv(algorithm, key, iv);
    encryptor.write(buffer);
    encryptor.end();

    const cipher_text = encryptor.read();
    console.log(cipher_text);

    return cipher_text;
    */
}

/*
generateDataKey().then(data => decrypt(data.CiphertextBlob)).then(data => {
    const buffer = decryptAES(data.Plaintext, encryptAES(data.Plaintext, new Buffer('abc','utf-8')));
    console.log(buffer.toString('utf-8'));
});


encrypt(new Buffer('abc','utf-8')).then(decrypt).then(plaintext => {
    console.log(plaintext.toString('utf-8'));
});
*/

exports.handler = async function (event, context) {

    const target = "my-target-name";  
    console.log("EVENT: \n" + JSON.stringify(event, null, 2));
    
    const keyData = await generateDataKey();
//    .then(result => console.log(`Result: ${JSON.stringify(result)}`))
//    .catch(err => console.error(`Error retrieving Data key: ${JSON.stringify(err)}`));
    
    const encryptionKey = keyData.Plaintext;
    console.log("Encryption type: ", typeof encryptionKey)
    console.log("Encryption Key: ", encryptionKey);
    console.log("Json: ", JSON.stringify(encryptionKey));
    console.log("key Data: ", JSON.stringify(keyData));


    // generate 16 bytes of random data
    const initVector = crypto.randomBytes(16);
    console.log("Init vector: ", initVector.toString("hex"));

    let encryptedData = encryptAES(encryptionKey, initVector, target);

    let decryptedData = decryptAES(encryptionKey, initVector, encryptedData);

    let responseBody = JSON.stringify({"target":target, "encryptedData":encryptedData, "decryptedData": decryptedData});
  
    return {
        "statusCode": 200,
        "headers": {
            "Content-Type": "application/json"
        },
        "isBase64Encoded": false,
        "body": responseBody
    };
};
