

const api = {
    API_BASE_URL: (window.API_BASE_URL || window.location.origin) + '/api',
    sessionToken: null
};


api.authenticate = async function() {

    let account = storage.currentAccount;
    if (!account) {
        const accountData = await storage.getAccount();
        if (!accountData) {
            throw new Error('No account found');
        }

        const signKeys = await crypto.importSignKeyPair(
            accountData.signPublicKeyJwk,
            accountData.signPrivateKeyJwk
        );
        const dhKeys = await crypto.importDHKeyPair(
            accountData.dhPublicKeyJwk,
            accountData.dhPrivateKeyJwk
        );
        account = {
            ...accountData,
            signKeyPair: {
                publicKey: signKeys.publicKey,
                privateKey: signKeys.privateKey
            },
            dhKeyPair: {
                publicKey: dhKeys.publicKey,
                privateKey: dhKeys.privateKey
            }
        };
        storage.currentAccount = account;
    }
    
    try {

        const challengeResponse = await fetch(`${this.API_BASE_URL}/auth/challenge`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ userId: account.userId })
        });
        
        if (!challengeResponse.ok) {
            if (typeof window.showConnectionLost === 'function') {
                window.showConnectionLost();
            }
            throw new Error('Failed to get challenge');
        }
        
        const { nonce } = await challengeResponse.json();
        

        const signature = await crypto.signData(account.signKeyPair.privateKey, nonce);
        

        const authResponse = await fetch(`${this.API_BASE_URL}/auth/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                userId: account.userId,
                nonce,
                signature
            })
        });
        
        if (!authResponse.ok) {
            if (typeof window.showConnectionLost === 'function') {
                window.showConnectionLost();
            }
            throw new Error('Authentication failed');
        }
        
        const { token } = await authResponse.json();
        this.sessionToken = token;
        return token;
    } catch (error) {

        if (error instanceof TypeError || error.name === 'NetworkError') {
            if (typeof window.showConnectionLost === 'function') {
                window.showConnectionLost();
            }
        }
        throw error;
    }
}


api.apiRequest = async function(endpoint, options = {}) {
    try {

        if (!this.sessionToken) {
            await this.authenticate();
        }
        
        const url = `${this.API_BASE_URL}${endpoint}`;
        const headers = {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${this.sessionToken}`,
            ...options.headers
        };
        
        const response = await fetch(url, {
            ...options,
            headers
        });
        

        if (response.status === 401) {
            this.sessionToken = null;
            await this.authenticate();
            return this.apiRequest(endpoint, options);
        }
        
        if (!response.ok) {
            const error = await response.json().catch(() => ({ message: 'Request failed' }));

            const errorMessage = error.error || error.message || 'Request failed';
            

            const skipConnectionLostErrors = [
                'Other user is not online. Key exchange requires both users to be connected.'
            ];
            

            const shouldSkipConnectionLost = skipConnectionLostErrors.some(skipError => 
                errorMessage.includes(skipError) || skipError.includes(errorMessage)
            );
            
            if (!shouldSkipConnectionLost) {

                if (typeof window.showConnectionLost === 'function') {
                    window.showConnectionLost();
                }
            }
            
            throw new Error(errorMessage);
        }
        
        return response.json();
    } catch (error) {


        if (error instanceof TypeError || error.name === 'NetworkError') {
            if (typeof window.showConnectionLost === 'function') {
                window.showConnectionLost();
            }
        }
        throw error;
    }
}


api.registerUser = async function() {
    let account = storage.currentAccount;
    if (!account) {
        const accountData = await storage.getAccount();
        if (!accountData) {
            throw new Error('No account found');
        }

        const signKeys = await crypto.importSignKeyPair(
            accountData.signPublicKeyJwk,
            accountData.signPrivateKeyJwk
        );
        const dhKeys = await crypto.importDHKeyPair(
            accountData.dhPublicKeyJwk,
            accountData.dhPrivateKeyJwk
        );
        account = {
            ...accountData,
            signKeyPair: {
                publicKey: signKeys.publicKey,
                privateKey: signKeys.privateKey
            },
            dhKeyPair: {
                publicKey: dhKeys.publicKey,
                privateKey: dhKeys.privateKey
            }
        };
        storage.currentAccount = account;
    }
    
    try {

        const response = await fetch(`${this.API_BASE_URL}/register`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                userId: account.userId,
                signPublicKeyJwk: account.signPublicKeyJwk,
                dhPublicKeyJwk: account.dhPublicKeyJwk
            })
        });
        
        if (!response.ok) {
            if (typeof window.showConnectionLost === 'function') {
                window.showConnectionLost();
            }
            const error = await response.json().catch(() => ({ message: 'Registration failed' }));
            throw new Error(error.message || 'Registration failed');
        }
        
        return response.json();
    } catch (error) {

        if (error instanceof TypeError || error.name === 'NetworkError') {
            if (typeof window.showConnectionLost === 'function') {
                window.showConnectionLost();
            }
        }
        throw error;
    }
}


api.sendContactRequest = async function(contactString) {
    return this.apiRequest('/contacts/request', {
        method: 'POST',
        body: JSON.stringify({
            toUserId: contactString
        })
    });
}


api.getIncomingRequests = async function() {
    return this.apiRequest('/contacts/requests/incoming');
}


api.getOutgoingRequests = async function() {
    return this.apiRequest('/contacts/requests/outgoing');
}


api.acceptContactRequest = async function(requestId) {
    return this.apiRequest(`/contacts/requests/${requestId}/accept`, {
        method: 'POST'
    });
}


api.rejectContactRequest = async function(requestId) {
    return this.apiRequest(`/contacts/requests/${requestId}/reject`, {
        method: 'POST'
    });
}


api.getChats = async function() {
    return this.apiRequest('/chats');
}


api.getChatMessages = async function(chatId) {
    return this.apiRequest(`/chats/${chatId}/messages`);
}


api.deleteChat = async function(chatId) {
    return this.apiRequest(`/chats/${chatId}`, {
        method: 'DELETE'
    });
}


api.deleteAccount = async function() {
    return this.apiRequest('/account/delete', {
        method: 'DELETE'
    });
};


