

const storage = {
    DB_NAME: 'AnonymousChatDB',
    DB_VERSION: 5,
    STORE_NAME: 'account',
    db: null,
    currentAccount: null
};


storage.initDB = async function() {
    return new Promise((resolve, reject) => {
        const request = indexedDB.open(this.DB_NAME, this.DB_VERSION);

        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            this.db = request.result;
            resolve(this.db);
        };

        request.onupgradeneeded = (event) => {
            const database = event.target.result;
            if (!database.objectStoreNames.contains(this.STORE_NAME)) {
                database.createObjectStore(this.STORE_NAME, { keyPath: 'id' });
            }

            if (!database.objectStoreNames.contains('trustedKeys')) {
                database.createObjectStore('trustedKeys', { keyPath: 'userId' });
            }

            if (!database.objectStoreNames.contains('sessionKeys')) {
                database.createObjectStore('sessionKeys', { keyPath: 'chatId' });
            }

            if (!database.objectStoreNames.contains('nonces')) {
                database.createObjectStore('nonces', { keyPath: 'nonceKey' });
            }

            if (!database.objectStoreNames.contains('nonceCounters')) {
                database.createObjectStore('nonceCounters', { keyPath: 'counterKey' });
            }

            if (!database.objectStoreNames.contains('decryptedMessages')) {
                database.createObjectStore('decryptedMessages', { keyPath: 'messageKey' });
            }
        };
    });
}


storage.getAccount = async function() {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction([this.STORE_NAME], 'readonly');
        const store = transaction.objectStore(this.STORE_NAME);
        const request = store.get('account');

        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const result = request.result;


            if (!result || result === undefined || result === null) {
                resolve(null);
            } else {
                resolve(result);
            }
        };
    });
}


storage.saveAccount = async function(accountData) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction([this.STORE_NAME], 'readwrite');
        const store = transaction.objectStore(this.STORE_NAME);
        const request = store.put({ id: 'account', ...accountData });

        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}


storage.hasAccount = async function() {
    try {
        const account = await this.getAccount();
        

        if (!account) {
            return false;
        }
        
        if (typeof account !== 'object') {
            return false;
        }
        
        if (!account.userId) {
            return false;
        }
        
        if (typeof account.userId !== 'string') {
            return false;
        }
        
        if (account.userId.trim().length === 0) {
            return false;
        }
        
        return true;
    } catch (error) {
        return false;
    }
}


storage.deleteAccount = async function() {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {

        const stores = [this.STORE_NAME, 'trustedKeys', 'sessionKeys', 'nonces'];
        const transaction = this.db.transaction(stores, 'readwrite');
        
        let completed = 0;
        let hasError = false;
        

        const accountStore = transaction.objectStore(this.STORE_NAME);
        const accountRequest = accountStore.delete('account');
        accountRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(accountRequest.error);
            }
        };
        accountRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
        

        const trustedKeysStore = transaction.objectStore('trustedKeys');
        const trustedKeysRequest = trustedKeysStore.clear();
        trustedKeysRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(trustedKeysRequest.error);
            }
        };
        trustedKeysRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
        

        const sessionKeysStore = transaction.objectStore('sessionKeys');
        const sessionKeysRequest = sessionKeysStore.clear();
        sessionKeysRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(sessionKeysRequest.error);
            }
        };
        sessionKeysRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
        

        const noncesStore = transaction.objectStore('nonces');
        const noncesRequest = noncesStore.clear();
        noncesRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(noncesRequest.error);
            }
        };
        noncesRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
    });
}


storage.clearAll = async function() {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {

        const stores = [this.STORE_NAME, 'trustedKeys', 'sessionKeys', 'nonces', 'decryptedMessages'];
        const transaction = this.db.transaction(stores, 'readwrite');
        
        let completed = 0;
        let hasError = false;
        

        const accountStore = transaction.objectStore(this.STORE_NAME);
        const accountRequest = accountStore.clear();
        accountRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(accountRequest.error);
            }
        };
        accountRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
        

        const trustedKeysStore = transaction.objectStore('trustedKeys');
        const trustedKeysRequest = trustedKeysStore.clear();
        trustedKeysRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(trustedKeysRequest.error);
            }
        };
        trustedKeysRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
        

        const sessionKeysStore = transaction.objectStore('sessionKeys');
        const sessionKeysRequest = sessionKeysStore.clear();
        sessionKeysRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(sessionKeysRequest.error);
            }
        };
        sessionKeysRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
        

        const noncesStore = transaction.objectStore('nonces');
        const noncesRequest = noncesStore.clear();
        noncesRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(noncesRequest.error);
            }
        };
        noncesRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
        

        const decryptedMessagesStore = transaction.objectStore('decryptedMessages');
        const decryptedMessagesRequest = decryptedMessagesStore.clear();
        decryptedMessagesRequest.onerror = () => {
            if (!hasError) {
                hasError = true;
                reject(decryptedMessagesRequest.error);
            }
        };
        decryptedMessagesRequest.onsuccess = () => {
            completed++;
            if (completed === stores.length && !hasError) {
                this.currentAccount = null;
                resolve();
            }
        };
    });
}


storage.exportAll = async function(recoveryKey) {
    if (!this.db) await this.initDB();
    
    return new Promise(async (resolve, reject) => {
        try {

            const stores = [this.STORE_NAME, 'trustedKeys', 'sessionKeys', 'nonces', 'nonceCounters', 'decryptedMessages'];
            const transaction = this.db.transaction(stores, 'readonly');
            

            const accountStore = transaction.objectStore(this.STORE_NAME);
            const accountRequest = accountStore.getAll();
            
            accountRequest.onerror = () => reject(accountRequest.error);
            accountRequest.onsuccess = async () => {
                try {
                    const accountData = accountRequest.result.find(item => item.id === 'account');
                    if (!accountData) {
                        throw new Error('No account data found to export');
                    }
                    

                    const trustedKeysStore = transaction.objectStore('trustedKeys');
                    const trustedKeysRequest = trustedKeysStore.getAll();
                    
                    trustedKeysRequest.onerror = () => reject(trustedKeysRequest.error);
                    trustedKeysRequest.onsuccess = async () => {
                        try {
                            const trustedKeys = trustedKeysRequest.result;
                            

                            const sessionKeysStore = transaction.objectStore('sessionKeys');
                            const sessionKeysRequest = sessionKeysStore.getAll();
                            
                            sessionKeysRequest.onerror = () => reject(sessionKeysRequest.error);
                            sessionKeysRequest.onsuccess = async () => {
                                try {
                                    const sessionKeys = sessionKeysRequest.result;
                                    

                                    const noncesStore = transaction.objectStore('nonces');
                                    const noncesRequest = noncesStore.getAll();
                                    
                                    noncesRequest.onerror = () => reject(noncesRequest.error);
                                    noncesRequest.onsuccess = async () => {
                                        try {
                                            const nonces = noncesRequest.result;
                                            

                                            const nonceCountersStore = transaction.objectStore('nonceCounters');
                                            const nonceCountersRequest = nonceCountersStore.getAll();
                                            
                                            nonceCountersRequest.onerror = () => reject(nonceCountersRequest.error);
                                            nonceCountersRequest.onsuccess = async () => {
                                                try {
                                                    const nonceCounters = nonceCountersRequest.result;
                                                    

                                                    const decryptedMessagesStore = transaction.objectStore('decryptedMessages');
                                                    const decryptedMessagesRequest = decryptedMessagesStore.getAll();
                                                    
                                                    decryptedMessagesRequest.onerror = () => reject(decryptedMessagesRequest.error);
                                                    decryptedMessagesRequest.onsuccess = async () => {
                                                        try {
                                                            const decryptedMessages = decryptedMessagesRequest.result;
                                                            

                                                            const autoDeleteDuration = this.getAutoDeleteDuration();
                                                            const theme = this.getTheme();
                                                            

                                                            const allData = {
                                                                account: {
                                                                    userId: accountData.userId,
                                                                    signPublicKeyJwk: accountData.signPublicKeyJwk,
                                                                    signPrivateKeyJwk: accountData.signPrivateKeyJwk,
                                                                    dhPublicKeyJwk: accountData.dhPublicKeyJwk,
                                                                    dhPrivateKeyJwk: accountData.dhPrivateKeyJwk,
                                                                    createdAt: accountData.createdAt
                                                                },
                                                                trustedKeys: trustedKeys,
                                                                sessionKeys: sessionKeys,
                                                                nonces: nonces,
                                                                nonceCounters: nonceCounters,
                                                                decryptedMessages: decryptedMessages,
                                                                autoDeleteDuration: autoDeleteDuration,
                                                                theme: theme
                                                            };
                                                            

                                                            const seedJsonString = JSON.stringify(allData);
                                                            

                                                            const metadata = {
                                                                version: 1,
                                                                kdf: {
                                                                    algorithm: 'PBKDF2',
                                                                    hash: 'SHA-256',
                                                                    iterations: 1000000,
                                                                    salt: ''
                                                                },
                                                                encryption: {
                                                                    algorithm: 'AES-GCM'
                                                                }
                                                            };
                                                            


                                                            const encrypted = await crypto.encryptSeedWithRecoveryKey(recoveryKey, seedJsonString, metadata);
                                                            

                                                            const exportPackage = {
                                                                version: metadata.version,
                                                                exportDate: new Date().toISOString(),
                                                                kdf: {
                                                                    algorithm: metadata.kdf.algorithm,
                                                                    hash: metadata.kdf.hash,
                                                                    iterations: metadata.kdf.iterations,
                                                                    salt: encrypted.salt
                                                                },
                                                                encryption: {
                                                                    algorithm: metadata.encryption.algorithm,
                                                                    iv: encrypted.iv,
                                                                    ciphertext: encrypted.ciphertext
                                                                }
                                                            };
                                                            

                                                            const exportJsonString = JSON.stringify(exportPackage, null, 2);
                                                            

                                                            const blob = new Blob([exportJsonString], { type: 'application/json' });
                                                            const url = URL.createObjectURL(blob);
                                                            const a = document.createElement('a');
                                                            a.href = url;
                                                            a.download = `nulla-account-${Date.now()}.nulla`;
                                                            document.body.appendChild(a);
                                                            a.click();
                                                            document.body.removeChild(a);
                                                            URL.revokeObjectURL(url);
                                                            
                                                            resolve();
                                                        } catch (error) {
                                                            reject(error);
                                                        }
                                                    };
                                                } catch (error) {
                                                    reject(error);
                                                }
                                            };
                                        } catch (error) {
                                            reject(error);
                                        }
                                    };
                                } catch (error) {
                                    reject(error);
                                }
                            };
                        } catch (error) {
                            reject(error);
                        }
                    };
                } catch (error) {
                    reject(error);
                }
            };
        } catch (error) {
            reject(error);
        }
    });
}


storage.importAll = async function(recoveryKey, fileContent) {
    if (!this.db) await this.initDB();
    
    return new Promise(async (resolve, reject) => {
        try {

            const exportPackage = JSON.parse(fileContent);
            

            if (!exportPackage.version || !exportPackage.kdf || !exportPackage.encryption) {
                throw new Error('Invalid export file format');
            }
            

            const encryptedData = {
                version: exportPackage.version,
                kdf: exportPackage.kdf,
                encryption: exportPackage.encryption,
                salt: exportPackage.kdf.salt,
                iv: exportPackage.encryption.iv,
                ciphertext: exportPackage.encryption.ciphertext
            };
            
            const allData = await crypto.decryptSeedWithRecoveryKey(recoveryKey, encryptedData);
            

            if (!allData.account || !allData.account.userId) {
                throw new Error('Invalid decrypted data structure');
            }
            

            await this.clearAll();
            

            const accountStore = this.db.transaction([this.STORE_NAME], 'readwrite').objectStore(this.STORE_NAME);
            await new Promise((resolve, reject) => {
                const request = accountStore.put({
                    id: 'account',
                    userId: allData.account.userId,
                    signPublicKeyJwk: allData.account.signPublicKeyJwk,
                    signPrivateKeyJwk: allData.account.signPrivateKeyJwk,
                    dhPublicKeyJwk: allData.account.dhPublicKeyJwk,
                    dhPrivateKeyJwk: allData.account.dhPrivateKeyJwk,
                    createdAt: allData.account.createdAt
                });
                request.onsuccess = () => resolve();
                request.onerror = () => reject(request.error);
            });
            

            if (allData.trustedKeys && allData.trustedKeys.length > 0) {
                const trustedKeysStore = this.db.transaction(['trustedKeys'], 'readwrite').objectStore('trustedKeys');
                for (const key of allData.trustedKeys) {
                    await new Promise((resolve, reject) => {
                        const request = trustedKeysStore.put(key);
                        request.onsuccess = () => resolve();
                        request.onerror = () => reject(request.error);
                    });
                }
            }
            

            if (allData.sessionKeys && allData.sessionKeys.length > 0) {
                const sessionKeysStore = this.db.transaction(['sessionKeys'], 'readwrite').objectStore('sessionKeys');
                for (const key of allData.sessionKeys) {
                    await new Promise((resolve, reject) => {
                        const request = sessionKeysStore.put(key);
                        request.onsuccess = () => resolve();
                        request.onerror = () => reject(request.error);
                    });
                }
            }
            

            if (allData.nonces && allData.nonces.length > 0) {
                const noncesStore = this.db.transaction(['nonces'], 'readwrite').objectStore('nonces');
                for (const nonce of allData.nonces) {
                    await new Promise((resolve, reject) => {
                        const request = noncesStore.put(nonce);
                        request.onsuccess = () => resolve();
                        request.onerror = () => reject(request.error);
                    });
                }
            }
            

            if (allData.nonceCounters && allData.nonceCounters.length > 0) {
                const nonceCountersStore = this.db.transaction(['nonceCounters'], 'readwrite').objectStore('nonceCounters');
                for (const counter of allData.nonceCounters) {
                    await new Promise((resolve, reject) => {
                        const request = nonceCountersStore.put(counter);
                        request.onsuccess = () => resolve();
                        request.onerror = () => reject(request.error);
                    });
                }
            }
            

            if (allData.decryptedMessages && allData.decryptedMessages.length > 0) {
                const decryptedMessagesStore = this.db.transaction(['decryptedMessages'], 'readwrite').objectStore('decryptedMessages');
                for (const message of allData.decryptedMessages) {
                    await new Promise((resolve, reject) => {
                        const request = decryptedMessagesStore.put(message);
                        request.onsuccess = () => resolve();
                        request.onerror = () => reject(request.error);
                    });
                }
            }
            

            if (allData.autoDeleteDuration) {
                this.saveAutoDeleteDuration(allData.autoDeleteDuration);
            }
            

            if (allData.theme) {
                this.saveTheme(allData.theme);
            }
            

            this.currentAccount = null;
            
            resolve();
        } catch (error) {
            reject(error);
        }
    });
}


storage.storeTrustedSigningKey = async function(userId, signPublicKeyJwk) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['trustedKeys'], 'readwrite');
        const store = transaction.objectStore('trustedKeys');
        const request = store.put({
            userId: userId,
            signPublicKeyJwk: signPublicKeyJwk,
            storedAt: new Date().toISOString()
        });
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}


storage.getTrustedSigningKey = async function(userId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['trustedKeys'], 'readonly');
        const store = transaction.objectStore('trustedKeys');
        const request = store.get(userId);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const result = request.result;
            resolve(result ? result.signPublicKeyJwk : null);
        };
    });
}


storage.initNonceCounters = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['nonceCounters'], 'readwrite');
        const store = transaction.objectStore('nonceCounters');
        

        const sendPrefix = window.crypto.getRandomValues(new Uint8Array(4));
        const sendPrefixBase64 = btoa(String.fromCharCode(...sendPrefix))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        

        const recvPrefix = window.crypto.getRandomValues(new Uint8Array(4));
        const recvPrefixBase64 = btoa(String.fromCharCode(...recvPrefix))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        

        const sendKey = `${chatId}_send`;
        const recvKey = `${chatId}_recv`;
        
        const sendRequest = store.put({
            counterKey: sendKey,
            chatId: chatId,
            direction: 'send',
            noncePrefix: sendPrefixBase64,
            counter: 0
        });
        
        sendRequest.onsuccess = () => {
            const recvRequest = store.put({
                counterKey: recvKey,
                chatId: chatId,
                direction: 'recv',
                noncePrefix: recvPrefixBase64,
                counter: 0
            });
            
            recvRequest.onsuccess = () => resolve();
            recvRequest.onerror = () => reject(recvRequest.error);
        };
        
        sendRequest.onerror = () => reject(sendRequest.error);
    });
}


storage.getAndIncrementNonceCounter = async function(chatId, direction) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['nonceCounters'], 'readwrite');
        const store = transaction.objectStore('nonceCounters');
        const counterKey = `${chatId}_${direction}`;
        
        const request = store.get(counterKey);
        
        request.onsuccess = () => {
            let counterData = request.result;
            

            if (!counterData) {
                const prefix = window.crypto.getRandomValues(new Uint8Array(4));
                const prefixBase64 = btoa(String.fromCharCode(...prefix))
                    .replace(/\+/g, '-')
                    .replace(/\//g, '_')
                    .replace(/=/g, '');
                
                counterData = {
                    counterKey: counterKey,
                    chatId: chatId,
                    direction: direction,
                    noncePrefix: prefixBase64,
                    counter: 0
                };
            }
            

            const currentCounter = counterData.counter;
            counterData.counter = currentCounter + 1;
            

            const updateRequest = store.put(counterData);
            
            updateRequest.onsuccess = () => {
                resolve({
                    noncePrefix: counterData.noncePrefix,
                    counter: currentCounter
                });
            };
            
            updateRequest.onerror = () => reject(updateRequest.error);
        };
        
        request.onerror = () => reject(request.error);
    });
}


storage.storeSessionKeys = async function(chatId, kSend, kRecv, sessionId, isEstablished = false) {
    if (!this.db) await this.initDB();
    

    const kSendJwk = await window.crypto.subtle.exportKey('jwk', kSend);
    const kRecvJwk = await window.crypto.subtle.exportKey('jwk', kRecv);
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['sessionKeys'], 'readwrite');
        const store = transaction.objectStore('sessionKeys');
        const request = store.put({
            chatId: chatId,
            kSendJwk: kSendJwk,
            kRecvJwk: kRecvJwk,
            sessionId: sessionId,
            isEstablished: isEstablished,
            storedAt: new Date().toISOString()
        });
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}


storage.getSessionKeys = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['sessionKeys'], 'readonly');
        const store = transaction.objectStore('sessionKeys');
        const request = store.get(chatId);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = async () => {
            const result = request.result;
            if (!result || !result.kSendJwk || !result.kRecvJwk) {
                resolve(null);
                return;
            }
            
            try {

                const kSendJwk = { ...result.kSendJwk };
                delete kSendJwk.key_ops;
                
                const kRecvJwk = { ...result.kRecvJwk };
                delete kRecvJwk.key_ops;
                


                const kSend = await window.crypto.subtle.importKey(
                    'jwk',
                    kSendJwk,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['encrypt', 'decrypt']
                );
                

                const kRecv = await window.crypto.subtle.importKey(
                    'jwk',
                    kRecvJwk,
                    { name: 'AES-GCM', length: 256 },
                    false,
                    ['decrypt', 'encrypt']
                );
                
                resolve({
                    kSend: kSend,
                    kRecv: kRecv,
                    sessionId: result.sessionId,
                    isEstablished: result.isEstablished || false
                });
            } catch (error) {
                resolve(null);
            }
        };
    });
}


storage.markSessionEstablished = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['sessionKeys'], 'readwrite');
        const store = transaction.objectStore('sessionKeys');
        const getRequest = store.get(chatId);
        
        getRequest.onerror = () => reject(getRequest.error);
        getRequest.onsuccess = async () => {
            const result = getRequest.result;
            if (!result) {
                reject(new Error('Session keys not found'));
                return;
            }
            
            result.isEstablished = true;
            const putRequest = store.put(result);
            putRequest.onerror = () => reject(putRequest.error);
            putRequest.onsuccess = async () => {

                try {
                    await this.initNonceCounters(chatId);
                    resolve();
                } catch (error) {
                    reject(error);
                }
            };
        };
    });
}


storage.storeNonce = async function(chatId, fromUserId, nonce) {
    if (!this.db) await this.initDB();
    
    const nonceKey = `${chatId}:${fromUserId}:${nonce}`;
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['nonces'], 'readwrite');
        const store = transaction.objectStore('nonces');
        const request = store.put({
            nonceKey: nonceKey,
            timestamp: Date.now()
        });
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}


storage.hasNonceBeenUsed = async function(chatId, fromUserId, nonce) {
    if (!this.db) await this.initDB();
    
    const nonceKey = `${chatId}:${fromUserId}:${nonce}`;
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['nonces'], 'readonly');
        const store = transaction.objectStore('nonces');
        const request = store.get(nonceKey);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            resolve(request.result !== undefined);
        };
    });
}


storage.cleanupNoncesForChat = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['nonces'], 'readwrite');
        const store = transaction.objectStore('nonces');
        const request = store.openCursor();
        
        request.onerror = () => reject(request.error);
        request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {

                if (cursor.value.nonceKey.startsWith(chatId + ':')) {
                    cursor.delete();
                }
                cursor.continue();
            } else {
                resolve();
            }
        };
    });
}


storage.saveDecryptedMessage = async function(chatId, msgId, decryptedData) {
    if (!this.db) await this.initDB();
    
    const messageKey = `${chatId}_${msgId}`;
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['decryptedMessages'], 'readwrite');
        const store = transaction.objectStore('decryptedMessages');
        const request = store.put({
            messageKey: messageKey,
            chatId: chatId,
            msgId: msgId,
            decryptedData: decryptedData,
            cachedAt: Date.now()
        });
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}


storage.getDecryptedMessage = async function(chatId, msgId) {
    if (!this.db) await this.initDB();
    
    const messageKey = `${chatId}_${msgId}`;
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['decryptedMessages'], 'readonly');
        const store = transaction.objectStore('decryptedMessages');
        const request = store.get(messageKey);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => {
            const result = request.result;
            resolve(result ? result.decryptedData : null);
        };
    });
}


storage.getCachedMessagesForChat = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['decryptedMessages'], 'readonly');
        const store = transaction.objectStore('decryptedMessages');
        const request = store.openCursor();
        const cachedMessages = {};
        
        request.onerror = () => reject(request.error);
        request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                if (cursor.value.chatId === chatId) {
                    cachedMessages[cursor.value.msgId] = cursor.value.decryptedData;
                }
                cursor.continue();
            } else {
                resolve(cachedMessages);
            }
        };
    });
}


storage.clearCachedMessagesForChat = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['decryptedMessages'], 'readwrite');
        const store = transaction.objectStore('decryptedMessages');
        const request = store.openCursor();
        
        request.onerror = () => reject(request.error);
        request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                if (cursor.value.chatId === chatId) {
                    cursor.delete();
                }
                cursor.continue();
            } else {
                resolve();
            }
        };
    });
}


storage.deleteTrustedSigningKey = async function(userId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['trustedKeys'], 'readwrite');
        const store = transaction.objectStore('trustedKeys');
        const request = store.delete(userId);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}


storage.deleteSessionKeys = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['sessionKeys'], 'readwrite');
        const store = transaction.objectStore('sessionKeys');
        const request = store.delete(chatId);
        
        request.onerror = () => reject(request.error);
        request.onsuccess = () => resolve();
    });
}


storage.deleteNonceCounters = async function(chatId) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['nonceCounters'], 'readwrite');
        const store = transaction.objectStore('nonceCounters');
        const request = store.openCursor();
        
        request.onerror = () => reject(request.error);
        request.onsuccess = (event) => {
            const cursor = event.target.result;
            if (cursor) {
                if (cursor.value.chatId === chatId) {
                    cursor.delete();
                }
                cursor.continue();
            } else {
                resolve();
            }
        };
    });
}


storage.saveAutoDeleteDuration = function(duration) {
    localStorage.setItem('autoDeleteDuration', duration);
}


storage.getAutoDeleteDuration = function() {
    return localStorage.getItem('autoDeleteDuration') || 'off';
}


storage.saveTheme = function(theme) {
    localStorage.setItem('theme', theme);
}


storage.getTheme = function() {
    return localStorage.getItem('theme') || 'dark';
}


storage.deleteCachedMessage = async function(messageKey) {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['decryptedMessages'], 'readwrite');
        const store = transaction.objectStore('decryptedMessages');
        const request = store.delete(messageKey);
        
        request.onsuccess = () => resolve();
        request.onerror = () => reject(request.error);
    });
}


storage.getAllCachedMessages = async function() {
    if (!this.db) await this.initDB();
    
    return new Promise((resolve, reject) => {
        const transaction = this.db.transaction(['decryptedMessages'], 'readonly');
        const store = transaction.objectStore('decryptedMessages');
        const request = store.getAll();
        
        request.onsuccess = () => resolve(request.result || []);
        request.onerror = () => reject(request.error);
    });
}

