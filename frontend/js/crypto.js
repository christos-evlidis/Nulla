

const crypto = {};


crypto.generateUserId = function() {
    const array = new Uint8Array(32);
    window.crypto.getRandomValues(array);

    return btoa(String.fromCharCode(...array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}


crypto.generateSignKeyPair = async function() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        true,
        ['sign', 'verify']
    );


    const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
    
    return {
        keyPair,
        publicKeyJwk,
        privateKeyJwk
    };
}


crypto.generateDHKeyPair = async function() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        ['deriveKey', 'deriveBits']
    );


    const publicKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.publicKey);
    const privateKeyJwk = await window.crypto.subtle.exportKey('jwk', keyPair.privateKey);
    
    return {
        keyPair,
        publicKeyJwk,
        privateKeyJwk
    };
}


crypto.signData = async function(privateKey, data) {
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    
    const signature = await window.crypto.subtle.sign(
        {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        privateKey,
        dataBuffer
    );


    return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}


crypto.verifySignature = async function(publicKeyJwk, data, signature) {
    try {

        const publicKey = await window.crypto.subtle.importKey(
            'jwk',
            publicKeyJwk,
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false,
            ['verify']
        );


        const signatureBuffer = Uint8Array.from(
            atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );

        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);

        return await window.crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            publicKey,
            signatureBuffer,
            dataBuffer
        );
    } catch (error) {
        return false;
    }
}


crypto.createCanonicalPayload = function(version, chatId, userA, userB, nonce, dhPublicKeyJwk) {

    const x = dhPublicKeyJwk.x;
    const y = dhPublicKeyJwk.y;
    

    const xBytes = Uint8Array.from(
        atob(x.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );
    const yBytes = Uint8Array.from(
        atob(y.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );
    

    if (xBytes.length !== 32 || yBytes.length !== 32) {
        throw new Error('Invalid ECDH public key: coordinates must be 32 bytes for P-256');
    }
    

    const pubKeyRaw = new Uint8Array(65);
    pubKeyRaw[0] = 0x04;
    pubKeyRaw.set(xBytes, 1);
    pubKeyRaw.set(yBytes, 33);
    

    const pubKeyBase64 = btoa(String.fromCharCode(...pubKeyRaw))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    

    return `${version}|${chatId}|${userA}|${userB}|${nonce}|${pubKeyBase64}`;
}


crypto.signCanonicalPayload = async function(privateKey, version, chatId, userA, userB, nonce, dhPublicKeyJwk) {
    const canonicalPayload = this.createCanonicalPayload(version, chatId, userA, userB, nonce, dhPublicKeyJwk);
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(canonicalPayload);
    
    const signature = await window.crypto.subtle.sign(
        {
            name: 'ECDSA',
            hash: 'SHA-256'
        },
        privateKey,
        dataBuffer
    );


    return btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}


crypto.verifyCanonicalPayload = async function(publicKeyJwk, version, chatId, userA, userB, nonce, dhPublicKeyJwk, signature) {
    try {

        if (!publicKeyJwk || typeof publicKeyJwk !== 'object') {
            throw new Error('publicKeyJwk must be an object');
        }
        
        if (!publicKeyJwk.kty || !publicKeyJwk.crv || !publicKeyJwk.x || !publicKeyJwk.y) {
            throw new Error('publicKeyJwk missing required JWK fields');
        }
        

        const publicKey = await window.crypto.subtle.importKey(
            'jwk',
            publicKeyJwk,
            {
                name: 'ECDSA',
                namedCurve: 'P-256'
            },
            false,
            ['verify']
        );


        const canonicalPayload = this.createCanonicalPayload(version, chatId, userA, userB, nonce, dhPublicKeyJwk);
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(canonicalPayload);


        const signatureBuffer = Uint8Array.from(
            atob(signature.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );

        return await window.crypto.subtle.verify(
            {
                name: 'ECDSA',
                hash: 'SHA-256'
            },
            publicKey,
            signatureBuffer,
            dataBuffer
        );
    } catch (error) {
        return false;
    }
}


crypto.deriveSharedSecret = async function(privateKey, publicKeyJwk) {

    const cleanPublicKeyJwk = {
        kty: publicKeyJwk.kty,
        crv: publicKeyJwk.crv,
        x: publicKeyJwk.x,
        y: publicKeyJwk.y
    };
    if (publicKeyJwk.ext !== undefined) {
        cleanPublicKeyJwk.ext = publicKeyJwk.ext;
    }

    


    const publicKey = await window.crypto.subtle.importKey(
        'jwk',
        cleanPublicKeyJwk,
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        false,
        []
    );


    const sharedSecret = await window.crypto.subtle.deriveBits(
        {
            name: 'ECDH',
            public: publicKey
        },
        privateKey,
        256
    );

    return new Uint8Array(sharedSecret);
}


crypto.hkdfExtract = async function(salt, ikm) {

    const key = await window.crypto.subtle.importKey(
        'raw',
        salt,
        { name: 'HMAC', hash: 'SHA-256' },
        false,
        ['sign']
    );
    
    const hmac = await window.crypto.subtle.sign('HMAC', key, ikm);
    return new Uint8Array(hmac);
}


crypto.hkdfExpand = async function(prk, info, length) {
    const hashLen = 32;
    const n = Math.ceil(length / hashLen);
    const okm = new Uint8Array(n * hashLen);
    
    const encoder = new TextEncoder();
    const infoBytes = encoder.encode(info);
    
    let prevT = new Uint8Array(0);
    
    for (let i = 0; i < n; i++) {


        const hmacInput = new Uint8Array(prevT.length + infoBytes.length + 1);
        if (prevT.length > 0) {
            hmacInput.set(prevT, 0);
        }
        hmacInput.set(infoBytes, prevT.length);
        hmacInput[hmacInput.length - 1] = i + 1;
        
        const key = await window.crypto.subtle.importKey(
            'raw',
            prk,
            { name: 'HMAC', hash: 'SHA-256' },
            false,
            ['sign']
        );
        
        const hmac = await window.crypto.subtle.sign('HMAC', key, hmacInput);
        prevT = new Uint8Array(hmac);
        okm.set(prevT, i * hashLen);
    }
    
    return okm.slice(0, length);
}


crypto.deriveSessionKeys = async function(sharedSecret, chatId, userA, userB, isUserA) {

    const sortedUsers = [userA, userB].sort();
    const minId = sortedUsers[0];
    const maxId = sortedUsers[1];
    

    const saltString = `nulla-v1|${chatId}|${minId}|${maxId}`;
    const saltBytes = new TextEncoder().encode(saltString);
    const saltHash = await window.crypto.subtle.digest('SHA-256', saltBytes);
    const salt = new Uint8Array(saltHash);
    

    const prk = await this.hkdfExtract(salt, sharedSecret);
    

    const direction = isUserA ? 'A->B' : 'B->A';
    const reverseDirection = isUserA ? 'B->A' : 'A->B';
    

    const kSendInfo = `nulla-v1 chat:${chatId} ${direction}`;
    const kSendBytes = await this.hkdfExpand(prk, kSendInfo, 32);
    

    const kRecvInfo = `nulla-v1 chat:${chatId} ${reverseDirection}`;
    const kRecvBytes = await this.hkdfExpand(prk, kRecvInfo, 32);
    

    const sessionIdInfo = `nulla-v1 chat:${chatId} session_id`;
    const sessionIdBytes = await this.hkdfExpand(prk, sessionIdInfo, 16);
    



    const kSend = await window.crypto.subtle.importKey(
        'raw',
        kSendBytes,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
    );
    

    const kRecv = await window.crypto.subtle.importKey(
        'raw',
        kRecvBytes,
        { name: 'AES-GCM', length: 256 },
        true,
        ['decrypt', 'encrypt']
    );
    

    const sessionId = btoa(String.fromCharCode(...sessionIdBytes))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    return { kSend, kRecv, sessionId };
}


crypto.encryptMessage = async function(chatKey, plaintext, chatId, direction) {
    const encoder = new TextEncoder();
    const plaintextBuffer = encoder.encode(plaintext);
    

    const { noncePrefix, counter } = await storage.getAndIncrementNonceCounter(chatId, direction);
    

    const prefixBytes = Uint8Array.from(
        atob(noncePrefix.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );
    

    const counterBytes = new Uint8Array(8);
    let counterValue = counter;
    for (let i = 7; i >= 0; i--) {
        counterBytes[i] = counterValue & 0xff;
        counterValue = Math.floor(counterValue / 256);
    }
    

    const iv = new Uint8Array(12);
    iv.set(prefixBytes, 0);
    iv.set(counterBytes, 4);
    

    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        chatKey,
        plaintextBuffer
    );


    return {
        iv: btoa(String.fromCharCode(...iv))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, ''),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
    };
}


crypto.decryptMessage = async function(chatKey, iv, ciphertext) {
    try {

        const ivBuffer = Uint8Array.from(
            atob(iv.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );
        
        const ciphertextBuffer = Uint8Array.from(
            atob(ciphertext.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );


        const plaintextBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer
            },
            chatKey,
            ciphertextBuffer
        );

        const decoder = new TextDecoder();
        return decoder.decode(plaintextBuffer);
    } catch (error) {
        throw new Error('Failed to decrypt message');
    }
}


crypto.encryptBinary = async function(chatKey, binaryData, chatId, direction) {

    const { noncePrefix, counter } = await storage.getAndIncrementNonceCounter(chatId, direction);
    

    const prefixBytes = Uint8Array.from(
        atob(noncePrefix.replace(/-/g, '+').replace(/_/g, '/')),
        c => c.charCodeAt(0)
    );
    

    const counterBytes = new Uint8Array(8);
    let counterValue = counter;
    for (let i = 7; i >= 0; i--) {
        counterBytes[i] = counterValue & 0xff;
        counterValue = Math.floor(counterValue / 256);
    }
    

    const iv = new Uint8Array(12);
    iv.set(prefixBytes, 0);
    iv.set(counterBytes, 4);
    

    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        chatKey,
        binaryData
    );



    function uint8ArrayToBase64(array) {
        let binary = '';
        const len = array.length;
        for (let i = 0; i < len; i++) {
            binary += String.fromCharCode(array[i]);
        }
        return btoa(binary);
    }
    
    const ivBase64 = uint8ArrayToBase64(iv)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    const ciphertextArray = new Uint8Array(ciphertext);
    const ciphertextBase64 = uint8ArrayToBase64(ciphertextArray)
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    

    return {
        iv: ivBase64,
        ciphertext: ciphertextBase64
    };
}


crypto.decryptBinary = async function(chatKey, iv, ciphertext) {
    try {

        const ivBuffer = Uint8Array.from(
            atob(iv.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );
        
        const ciphertextBuffer = Uint8Array.from(
            atob(ciphertext.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );


        const plaintextBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer
            },
            chatKey,
            ciphertextBuffer
        );

        return new Uint8Array(plaintextBuffer);
    } catch (error) {
        throw new Error('Failed to decrypt file');
    }
}


crypto.createAccount = async function() {
    const userId = this.generateUserId();
    const signKeys = await this.generateSignKeyPair();
    const dhKeys = await this.generateDHKeyPair();

    return {
        userId,
        signKeyPair: signKeys.keyPair,
        signPublicKeyJwk: signKeys.publicKeyJwk,
        signPrivateKeyJwk: signKeys.privateKeyJwk,
        dhKeyPair: dhKeys.keyPair,
        dhPublicKeyJwk: dhKeys.publicKeyJwk,
        dhPrivateKeyJwk: dhKeys.privateKeyJwk,
        createdAt: Date.now()
    };
}


crypto.importSignKeyPair = async function(publicKeyJwk, privateKeyJwk) {
    const publicKey = await window.crypto.subtle.importKey(
        'jwk',
        publicKeyJwk,
        {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        true,
        ['verify']
    );
    
    const privateKey = await window.crypto.subtle.importKey(
        'jwk',
        privateKeyJwk,
        {
            name: 'ECDSA',
            namedCurve: 'P-256'
        },
        true,
        ['sign']
    );
    
    return { publicKey, privateKey };
}


crypto.importDHKeyPair = async function(publicKeyJwk, privateKeyJwk) {
    const publicKey = await window.crypto.subtle.importKey(
        'jwk',
        publicKeyJwk,
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        []
    );
    
    const privateKey = await window.crypto.subtle.importKey(
        'jwk',
        privateKeyJwk,
        {
            name: 'ECDH',
            namedCurve: 'P-256'
        },
        true,
        ['deriveKey', 'deriveBits']
    );
    
    return { publicKey, privateKey };
}


crypto.deriveKeyFromPin = async function(pin) {
    const encoder = new TextEncoder();
    const pinBuffer = encoder.encode(pin);
    

    const salt = encoder.encode('nulla-export-salt-v1');
    

    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        pinBuffer,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    

    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 100000,
            hash: 'SHA-256'
        },
        baseKey,
        256
    );
    

    return await window.crypto.subtle.importKey(
        'raw',
        derivedBits,
        {
            name: 'AES-GCM',
            length: 256
        },
        false,
        ['encrypt', 'decrypt']
    );
}


crypto.encryptWithPin = async function(pin, data) {
    const key = await this.deriveKeyFromPin(pin);
    const encoder = new TextEncoder();
    const dataBuffer = encoder.encode(data);
    

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    

    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv
        },
        key,
        dataBuffer
    );
    

    return {
        iv: btoa(String.fromCharCode(...iv))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, ''),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
    };
}


crypto.decryptWithPin = async function(pin, iv, ciphertext) {
    try {
        const key = await this.deriveKeyFromPin(pin);
        

        const ivBuffer = Uint8Array.from(
            atob(iv.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );
        
        const ciphertextBuffer = Uint8Array.from(
            atob(ciphertext.replace(/-/g, '+').replace(/_/g, '/')),
            c => c.charCodeAt(0)
        );
        

        const plaintextBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer
            },
            key,
            ciphertextBuffer
        );
        
        const decoder = new TextDecoder();
        return decoder.decode(plaintextBuffer);
    } catch (error) {
        throw new Error('Failed to decrypt data. Invalid PIN or corrupted file.');
    }
}


crypto.generateRecoveryKey = function() {


    const array = new Uint8Array(23);
    window.crypto.getRandomValues(array);

    return btoa(String.fromCharCode(...array))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}


crypto.deriveExportKey = async function(recoveryKey, salt) {
    if (!recoveryKey || typeof recoveryKey !== 'string') {
        throw new Error('Recovery key must be a non-empty string');
    }
    
    const encoder = new TextEncoder();
    const recoveryKeyBuffer = encoder.encode(recoveryKey);
    
    if (recoveryKeyBuffer.length === 0) {
        throw new Error('Recovery key cannot be empty');
    }

    const baseKey = await window.crypto.subtle.importKey(
        'raw',
        recoveryKeyBuffer,
        'PBKDF2',
        false,
        ['deriveBits', 'deriveKey']
    );
    


    const derivedBits = await window.crypto.subtle.deriveBits(
        {
            name: 'PBKDF2',
            salt: salt,
            iterations: 1000000,
            hash: 'SHA-256'
        },
        baseKey,
        256
    );
    

    return await window.crypto.subtle.importKey(
        'raw',
        derivedBits,
        {
            name: 'AES-GCM',
            length: 256
        },
        false,
        ['encrypt', 'decrypt']
    );
}


crypto.encryptSeedWithRecoveryKey = async function(recoveryKey, seedData, metadata) {

    const salt = window.crypto.getRandomValues(new Uint8Array(16));
    const saltBase64url = btoa(String.fromCharCode(...salt))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    

    const exportKey = await this.deriveExportKey(recoveryKey, salt);
    
    const encoder = new TextEncoder();
    const seedBuffer = encoder.encode(seedData);
    

    const iv = window.crypto.getRandomValues(new Uint8Array(12));
    

    const aadObject = {
        version: metadata.version,
        kdf: metadata.kdf.algorithm,
        hash: metadata.kdf.hash,
        iterations: metadata.kdf.iterations,
        salt: saltBase64url,
        alg: metadata.encryption.algorithm
    };
    const aadString = JSON.stringify(aadObject);
    const aadBuffer = encoder.encode(aadString);
    

    const ciphertext = await window.crypto.subtle.encrypt(
        {
            name: 'AES-GCM',
            iv: iv,
            additionalData: aadBuffer
        },
        exportKey,
        seedBuffer
    );
    

    return {
        salt: saltBase64url,
        iv: btoa(String.fromCharCode(...iv))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, ''),
        ciphertext: btoa(String.fromCharCode(...new Uint8Array(ciphertext)))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '')
    };
}


crypto.decryptSeedWithRecoveryKey = async function(recoveryKey, encryptedData) {
    if (!recoveryKey || typeof recoveryKey !== 'string') {
        throw new Error('Recovery key must be a non-empty string');
    }
    
    recoveryKey = recoveryKey.trim().replace(/\s+/g, '');
    
    if (recoveryKey.length === 0) {
        throw new Error('Recovery key cannot be empty');
    }
    
    const { salt, iv, ciphertext, kdf, encryption } = encryptedData;
    

    let saltBase64 = salt.replace(/-/g, '+').replace(/_/g, '/');
    while (saltBase64.length % 4 !== 0) {
        saltBase64 += '=';
    }
    const saltBinary = atob(saltBase64);
    const saltBuffer = new Uint8Array(saltBinary.length);
    for (let i = 0; i < saltBinary.length; i++) {
        saltBuffer[i] = saltBinary.charCodeAt(i);
    }
    const exportKey = await this.deriveExportKey(recoveryKey, saltBuffer);
    
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    

    const aadObject = {
        version: encryptedData.version,
        kdf: kdf.algorithm,
        hash: kdf.hash,
        iterations: kdf.iterations,
        salt: salt,
        alg: encryption.algorithm
    };
    
    if (!kdf || !encryption || !salt || !iv || !ciphertext) {
        throw new Error('Missing required encryption parameters');
    }
    const aadString = JSON.stringify(aadObject);
    const aadBuffer = encoder.encode(aadString);
    

    let ivBase64 = iv.replace(/-/g, '+').replace(/_/g, '/');
    while (ivBase64.length % 4 !== 0) {
        ivBase64 += '=';
    }
    const ivBinary = atob(ivBase64);
    const ivBuffer = new Uint8Array(ivBinary.length);
    for (let i = 0; i < ivBinary.length; i++) {
        ivBuffer[i] = ivBinary.charCodeAt(i);
    }
    
    let ciphertextBase64 = ciphertext.replace(/-/g, '+').replace(/_/g, '/');
    while (ciphertextBase64.length % 4 !== 0) {
        ciphertextBase64 += '=';
    }
    const ciphertextBinary = atob(ciphertextBase64);
    const ciphertextBuffer = new Uint8Array(ciphertextBinary.length);
    for (let i = 0; i < ciphertextBinary.length; i++) {
        ciphertextBuffer[i] = ciphertextBinary.charCodeAt(i);
    }
    

    try {
        const plaintextBuffer = await window.crypto.subtle.decrypt(
            {
                name: 'AES-GCM',
                iv: ivBuffer,
                additionalData: aadBuffer
            },
            exportKey,
            ciphertextBuffer
        );
        

        const seedData = JSON.parse(decoder.decode(plaintextBuffer));
        return seedData;
    } catch (error) {
        if (error.name === 'OperationError') {
            throw new Error('Decryption failed: The seed lock string is incorrect, or the encrypted data has been corrupted. Please verify you are using the correct seed lock string that was shown when you exported the account.');
        }
        throw error;
    }
}

