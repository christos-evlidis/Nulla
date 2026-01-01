

let currentView = 'main';


const landingPage = document.getElementById('landing-page');
const container = document.querySelector('.container');
const signUpBtn = document.getElementById('sign-up-btn');

const mainView = document.getElementById('main-view');
const contactsView = document.getElementById('contacts-view');
const chatView = document.getElementById('chat-view');
const settingsView = document.getElementById('settings-view');
const contactsIdentifier = document.getElementById('contacts-identifier');
const contactsCopyBtn = document.getElementById('contacts-copy-btn');
const contactsContactInput = document.getElementById('contacts-contact-input');
const contactsSendBtn = document.getElementById('contacts-send-btn');

const noAccountDiv = document.getElementById('no-account');
const hasAccountDiv = document.getElementById('has-account');
const createAccountBtn = document.getElementById('create-account-btn');
const copyContactBtn = document.getElementById('copy-contact-btn');
const backToContactsBtn = document.getElementById('back-to-contacts-btn');

const contactStringInput = document.getElementById('contact-string-input');
const sendRequestBtn = document.getElementById('send-request-btn');
const incomingRequestsList = document.getElementById('incoming-requests-list');
const chatsList = document.getElementById('chats-list');

const chatTitle = document.getElementById('chat-title');
const messagesList = document.getElementById('messages-list');
const messageInput = document.getElementById('message-input');
const sendMessageBtn = document.getElementById('send-message-btn');



const titleHoverText = document.getElementById('title-hover-text');
const thirdHoverText = document.getElementById('third-hover-text');
const signUpTitle = document.querySelector('.landing-content h1');
const navTitleHoverText = document.getElementById('nav-title-hover-text');
const navTitle = document.querySelector('.nav-title');
const logoutLink = document.getElementById('logout-link');
const logoutTooltip = document.getElementById('logout-tooltip');
const exportSeedBtn = document.getElementById('export-seed-btn');
const mainExportSeedBtn = document.getElementById('main-export-seed-btn');
const exportAccountBtn = document.getElementById('export-account-btn');
const importAccountBtn = document.getElementById('import-account-btn');
const landingImportSeedBtn = document.getElementById('landing-import-seed-btn');
const deleteMyDataBtn = document.getElementById('delete-my-data-btn');





function showView(viewName) {

    mainView.classList.add('hidden');
    contactsView.classList.add('hidden');
    chatView.classList.add('hidden');
    if (settingsView) settingsView.classList.add('hidden');
    

    document.querySelectorAll('.nav-link').forEach(link => {
        link.classList.remove('active');
    });
    

    currentView = viewName;
    switch (viewName) {
        case 'main':
            mainView.classList.remove('hidden');
            document.querySelector('.nav-link[data-view="main"]')?.classList.add('active');
            loadMainView();
            break;
        case 'contacts':
            contactsView.classList.remove('hidden');
            document.querySelector('.nav-link[data-view="contacts"]')?.classList.add('active');

            loadContactsView();

            const inboxView = document.getElementById('inbox-view');
            const contactRequestsView = document.getElementById('contact-requests-view');
            if (inboxView && !inboxView.classList.contains('hidden')) {
                loadInboxChats();
            } else if (contactRequestsView && !contactRequestsView.classList.contains('hidden')) {
                loadContactRequests();
            }
            break;
        case 'settings':
            if (settingsView) {
                settingsView.classList.remove('hidden');
                document.querySelector('.nav-link[data-view="settings"]')?.classList.add('active');
                loadSettingsView();
            }
            break;
        case 'chat':
            chatView.classList.remove('hidden');
            break;
    }
}


async function restoreAccountKeys(accountData) {

    const signKeys = await crypto.importSignKeyPair(
        accountData.signPublicKeyJwk,
        accountData.signPrivateKeyJwk
    );
    const dhKeys = await crypto.importDHKeyPair(
        accountData.dhPublicKeyJwk,
        accountData.dhPrivateKeyJwk
    );
    
    return {
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
}


async function loadLandingPage() {

    try {
        const hasAccount = await storage.hasAccount();
        if (signUpBtn) {
            if (hasAccount) {
                signUpBtn.textContent = 'continue as';
            } else {
                signUpBtn.textContent = 'sign up';
            }
        }
    } catch (error) {
        if (signUpBtn) {
            signUpBtn.textContent = 'sign up';
        }
    }
}


async function loadMainView() {
    const hasAccount = await storage.hasAccount();
    
    if (hasAccount) {
        const accountData = await storage.getAccount();

        const account = await restoreAccountKeys(accountData);

        storage.currentAccount = account;
        
        if (noAccountDiv) {
            noAccountDiv.classList.add('hidden');
        }
        if (hasAccountDiv) {
            hasAccountDiv.classList.remove('hidden');
        }
        


    } else {
        if (noAccountDiv) {
            noAccountDiv.classList.remove('hidden');
        }
        if (hasAccountDiv) {
            hasAccountDiv.classList.add('hidden');
        }
    }
}


async function loadAccountView() {
    await loadMainView();
}


async function handleSignUp() {

    landingPage.classList.add('hidden');
    container.classList.remove('hidden');
    

    const hasAccount = await storage.hasAccount();
    
    if (hasAccount) {

        await handleContinueAs();
    } else {

        await handleCreateAccount();
    }
}


async function handleContinueAs() {

    landingPage.classList.add('hidden');
    container.classList.remove('hidden');
    

    await loadMainView();
    

    try {
        if (!api.sessionToken || isTokenExpired(api.sessionToken)) {
            await api.authenticate();
        }

        ws.connectWebSocket();
    } catch (error) {
    }
    
    showView('main');
}


function isTokenExpired(token) {
    if (!token) return true;
    try {

        const parts = token.split('.');
        if (parts.length !== 3) return true;
        

        const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')));
        

        if (payload.exp && payload.exp * 1000 < Date.now()) {
            return true;
        }
        return false;
    } catch (error) {

        return true;
    }
}


async function handleCreateAccount() {

    const wasButtonEnabled = createAccountBtn ? !createAccountBtn.disabled : true;
    if (createAccountBtn) {
        createAccountBtn.disabled = true;
        createAccountBtn.textContent = 'Creating...';
    }
    
    try {

        const account = await crypto.createAccount();
        

        await storage.saveAccount({
            userId: account.userId,
            signPublicKeyJwk: account.signPublicKeyJwk,
            signPrivateKeyJwk: account.signPrivateKeyJwk,
            dhPublicKeyJwk: account.dhPublicKeyJwk,
            dhPrivateKeyJwk: account.dhPrivateKeyJwk,
            createdAt: account.createdAt
        });
        

        storage.currentAccount = account;
        

        try {
            await api.registerUser();
            

            await api.authenticate();
            

            ws.connectWebSocket();
            

        } catch (error) {
            try {
                await storage.deleteAccount();
                storage.currentAccount = null;
            } catch (deleteError) {
            }
            

            if (typeof window.showConnectionLost === 'function') {
                window.showConnectionLost('Account creation failed because connection to server lost. Please reload the page and try again.', 'Account Creation Failed');
            }
            return;
        }
        

        await loadMainView();
        

        showView('main');
    } catch (error) {
showView('main');
        if (noAccountDiv) {
            noAccountDiv.classList.remove('hidden');
        }
        if (hasAccountDiv) {
            hasAccountDiv.classList.add('hidden');
        }
    } finally {

        if (createAccountBtn) {
            createAccountBtn.disabled = !wasButtonEnabled;
            createAccountBtn.textContent = 'Create Account';
        }
    }
}


async function handleCopyContact() {
    const account = storage.currentAccount || await storage.getAccount();
    if (!account) return;
    
    try {
        await navigator.clipboard.writeText(account.userId);

    } catch (error) {

        const textArea = document.createElement('textarea');
        textArea.value = account.userId;
        textArea.style.position = 'fixed';
        textArea.style.opacity = '0';
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');

        } catch (err) {

        }
        document.body.removeChild(textArea);
    }
}


async function loadContactsView() {

    const account = storage.currentAccount || await storage.getAccount();
    if (account && contactsIdentifier) {
        contactsIdentifier.value = account.userId;
    }
    


    renderIncomingRequests([]);
    renderChats([]);
}


async function loadInboxChats() {
    const inboxChatsList = document.getElementById('inbox-chats-list');
    if (!inboxChatsList) return;
    
    try {
        const chats = await api.getChats();
        if (chats && Array.isArray(chats)) {
            if (chats.length === 0) {
                inboxChatsList.innerHTML = '<p class="inbox-chat-empty">No active chats</p>';
            } else {
                inboxChatsList.innerHTML = '';
                
                chats.forEach((chat, index) => {

                    const otherUserId = chat.otherUserId;
                    
                    if (!otherUserId) {
return;
                    }
                    
                    const chatBox = renderInboxChatBox(chat.chatId, otherUserId);
                    inboxChatsList.appendChild(chatBox);
                    

                    if (index === 0) {
                        chatBox.classList.add('selected');
                        displayInboxChat(chat.chatId, otherUserId);
                    }
                });
            }
        } else {
            inboxChatsList.innerHTML = '<p class="inbox-chat-empty">No active chats</p>';
        }
    } catch (error) {
inboxChatsList.innerHTML = '<p class="inbox-chat-empty">No active chats</p>';
    }
}


let currentChatId = null;
let currentOtherUserId = null;

const chatMessagesCache = {};

async function displayInboxChat(chatId, otherUserId) {
    const chatDisplay = document.getElementById('inbox-chat-display');
    if (!chatDisplay) return;
    

    hideTypingIndicator();
    

    if (currentChatId && currentChatId !== chatId) {
        const messagesList = document.getElementById('inbox-chat-messages');
        if (messagesList) {
            chatMessagesCache[currentChatId] = messagesList.innerHTML;
        }
    }
    
    currentChatId = chatId;
    currentOtherUserId = otherUserId;
    

    const emptyMsg = chatDisplay.querySelector('.inbox-chat-empty');
    if (emptyMsg) {
        emptyMsg.textContent = 'Loading messages...';
    }
    
    const messagesContainer = document.getElementById('inbox-chat-messages-container');
    const messagesList = document.getElementById('inbox-chat-messages');
    const userIdEl = document.getElementById('inbox-chat-user-id');
    
    try {
        if (!otherUserId) {
            if (emptyMsg) emptyMsg.textContent = 'Select a chat to view messages';
            if (messagesContainer) messagesContainer.classList.add('hidden');
            return;
        }
        

        if (emptyMsg) emptyMsg.style.display = 'none';
        if (messagesContainer) messagesContainer.classList.remove('hidden');
        if (userIdEl) userIdEl.textContent = otherUserId;
        

        if (messagesList) {
            messagesList.innerHTML = '';
        }
        

        let loadingElement = messagesContainer?.querySelector('.inbox-chat-loading');
        if (!loadingElement && messagesContainer) {
            loadingElement = document.createElement('div');
            loadingElement.className = 'inbox-chat-loading';
            loadingElement.innerHTML = `
                <div class="inbox-chat-loading-spinner"></div>
                <div class="inbox-chat-loading-text">Decrypting...</div>
            `;
            messagesContainer.appendChild(loadingElement);
        }
        if (loadingElement) {
            loadingElement.style.display = 'flex';
        }
        

        try {
            const messagesResponse = await api.getChatMessages(chatId);
            const encryptedMessages = messagesResponse.messages || [];
            

            const cachedMessages = await storage.getCachedMessagesForChat(chatId);
            
            if (encryptedMessages.length === 0) {

                const cachedMessageIds = Object.keys(cachedMessages);
                if (cachedMessageIds.length > 0) {

                    const allMessages = Object.values(cachedMessages);
                    allMessages.sort((a, b) => a.timestamp - b.timestamp);
                    
                    if (messagesList) {
                        messagesList.innerHTML = '';
                        allMessages.forEach(msg => {
                            if (msg.isFile) {

                                if (msg.fileData && !msg.fileDataUrl) {
                                    const blob = new Blob([msg.fileData], { type: msg.fileType });
                                    msg.fileDataUrl = URL.createObjectURL(blob);
                                }
                                addFileMessageToUI(
                                    msg.fileName,
                                    msg.fileType,
                                    msg.fileSize,
                                    msg.isSent,
                                    msg.isImage,
                                    msg.fileDataUrl
                                );
                            } else {
                                addMessageToUI(msg.text, msg.isSent);
                            }
                        });
                        chatMessagesCache[chatId] = messagesList.innerHTML;
                    }

                    if (loadingElement) {
                        loadingElement.style.display = 'none';
                    }
                } else {
                    if (messagesList) {
                        messagesList.innerHTML = '<p class="inbox-chat-empty">No messages yet. Start the conversation!</p>';
                    }

                    if (loadingElement) {
                        loadingElement.style.display = 'none';
                    }
                }
            } else {

                const sessionKeys = await storage.getSessionKeys(chatId);
                if (!sessionKeys || !sessionKeys.isEstablished) {
const cachedMessageIds = Object.keys(cachedMessages);
                    if (cachedMessageIds.length > 0) {
                        const allMessages = Object.values(cachedMessages);
                        allMessages.sort((a, b) => a.timestamp - b.timestamp);
                        
                        if (messagesList) {
                            messagesList.innerHTML = '';
                            allMessages.forEach(msg => {
                                if (msg.isFile) {
                                    if (msg.fileData && !msg.fileDataUrl) {
                                        const blob = new Blob([msg.fileData], { type: msg.fileType });
                                        msg.fileDataUrl = URL.createObjectURL(blob);
                                    }
                                    addFileMessageToUI(
                                        msg.fileName,
                                        msg.fileType,
                                        msg.fileSize,
                                        msg.isSent,
                                        msg.isImage,
                                        msg.fileDataUrl
                                    );
                                } else {
                                    addMessageToUI(msg.text, msg.isSent);
                                }
                            });
                            chatMessagesCache[chatId] = messagesList.innerHTML;
                        }
                    } else {
                        if (messagesList) {
                            messagesList.innerHTML = '<p class="inbox-chat-empty">Cannot decrypt messages - session keys not available</p>';
                        }
                    }

                    if (loadingElement) {
                        loadingElement.style.display = 'none';
                    }
                    return;
                }
                


                let account = storage.currentAccount;
                if (!account) {
                    const accountData = await storage.getAccount();
                    if (accountData) {
                        account = await restoreAccountKeys(accountData);
                        storage.currentAccount = account;
                    }
                }
                
                if (!account || !account.userId) {
return;
                }
                

                const messagesToProcess = encryptedMessages.slice(-20);
                

                const allDecryptedMessages = Object.values(cachedMessages).map(msg => ({ ...msg }));
                

                const newMessages = messagesToProcess.filter(msg => !cachedMessages[msg.msgId]);
                


                const yieldToUI = () => new Promise(resolve => {
                    if (window.requestAnimationFrame) {
                        window.requestAnimationFrame(() => setTimeout(resolve, 0));
                    } else {
                        setTimeout(resolve, 0);
                    }
                });
                

                for (let i = 0; i < newMessages.length; i++) {
                    const msg = newMessages[i];
                    

                    if (i > 0) {
                        await yieldToUI();
                    }
                    
                    try {
                        
                        



                        if (msg.sessionId === sessionKeys.sessionId) {

                            const isSent = msg.senderId === account.userId;
                            const decryptKey = isSent ? sessionKeys.kSend : sessionKeys.kRecv;
                            
                            
                            let decryptedMessage = null;
                            

                            if (msg.isFile && msg.encryptedMetadata) {

                                const metadataJson = await crypto.decryptMessage(
                                    decryptKey,
                                    msg.encryptedMetadata.iv,
                                    msg.encryptedMetadata.ciphertext
                                );
                                const metadata = JSON.parse(metadataJson);
                                

                                await new Promise(resolve => setTimeout(resolve, 0));
                                

                                const fileData = await crypto.decryptBinary(
                                    decryptKey,
                                    msg.iv,
                                    msg.ciphertext
                                );
                                

                                await new Promise(resolve => setTimeout(resolve, 0));
                                

                                const blob = new Blob([fileData], { type: metadata.fileType });
                                const fileDataUrl = URL.createObjectURL(blob);
                                


                                decryptedMessage = {
                                    isFile: true,
                                    fileName: metadata.fileName,
                                    fileType: metadata.fileType,
                                    fileSize: metadata.fileSize,
                                    isImage: metadata.isImage,
                                    fileData: fileData.buffer,
                                    fileDataUrl: fileDataUrl,
                                    isSent: isSent,
                                    timestamp: new Date(msg.timestamp),
                                    msgId: msg.msgId
                                };
                            } else {

                                const decrypted = await crypto.decryptMessage(
                                    decryptKey,
                                    msg.iv,
                                    msg.ciphertext
                                );
                                

                                await yieldToUI();
                                
                                

                                decryptedMessage = {
                                    text: decrypted,
                                    isSent: isSent,
                                    timestamp: new Date(msg.timestamp),
                                    msgId: msg.msgId
                                };
                            }
                            

                            if (decryptedMessage) {

                                await storage.saveDecryptedMessage(chatId, msg.msgId, decryptedMessage);
                                allDecryptedMessages.push(decryptedMessage);
                            }
                        } else {
}
                    } catch (error) {
}
                }
                

                allDecryptedMessages.sort((a, b) => a.timestamp - b.timestamp);
                
                

                if (messagesList) {
                    messagesList.innerHTML = '';
                    allDecryptedMessages.forEach(msg => {
                        if (msg.isFile) {

                            if (msg.fileData && !msg.fileDataUrl) {
                                const blob = new Blob([msg.fileData], { type: msg.fileType });
                                msg.fileDataUrl = URL.createObjectURL(blob);
                            }
                            addFileMessageToUI(
                                msg.fileName,
                                msg.fileType,
                                msg.fileSize,
                                msg.isSent,
                                msg.isImage,
                                msg.fileDataUrl
                            );
                        } else {
                            addMessageToUI(msg.text, msg.isSent);
                        }
                    });
                    

                    chatMessagesCache[chatId] = messagesList.innerHTML;
                }

                if (loadingElement) {
                    loadingElement.style.display = 'none';
                }
            }
        } catch (error) {
if (messagesList) {
                messagesList.innerHTML = '<p class="inbox-chat-empty">Failed to load messages</p>';
            }

            if (loadingElement) {
                loadingElement.style.display = 'none';
            }
        }
        

        setupChatInput();
        

        setupDeleteButton(chatId, otherUserId);
        setupReloadButton(chatId, otherUserId);
    } catch (error) {
if (emptyMsg) emptyMsg.textContent = 'Failed to load messages';
        if (messagesContainer) messagesContainer.classList.add('hidden');

        const loadingElement = messagesContainer?.querySelector('.inbox-chat-loading');
        if (loadingElement) {
            loadingElement.style.display = 'none';
        }
    }
}


let chatInputHandler = null;
let chatSendHandler = null;
let chatTypingHandler = null;
let chatUploadHandler = null;
let chatFileInputHandler = null;
let typingIndicatorTimeout = null;
let lastTypingIndicatorSent = 0;
const TYPING_INDICATOR_INTERVAL = 500;


async function handleDeleteChat(chatId, otherUserId) {
    if (!confirm('Are you sure you want to delete this chat? This will permanently delete all messages and cannot be undone.')) {
        return;
    }
    
    try {

        await api.deleteChat(chatId);
        

        await storage.clearCachedMessagesForChat(chatId);
        await storage.deleteTrustedSigningKey(otherUserId);
        await storage.deleteSessionKeys(chatId);
        await storage.deleteNonceCounters(chatId);
        

        delete chatMessagesCache[chatId];
        

        if (currentChatId === chatId) {
            currentChatId = null;
            currentOtherUserId = null;
            
            const messagesContainer = document.getElementById('inbox-chat-messages-container');
            const emptyMsg = document.getElementById('inbox-chat-display')?.querySelector('.inbox-chat-empty');
            
            if (messagesContainer) {
                messagesContainer.classList.add('hidden');
            }
            if (emptyMsg) {
                emptyMsg.style.display = 'block';
                emptyMsg.textContent = 'Select a chat to view messages';
            }
        }
        

        await loadInboxChats();
        
    } catch (error) {
alert('Failed to delete chat. Please try again.');
    }
}


function setupDeleteButton(chatId, otherUserId) {
    const deleteBtn = document.getElementById('inbox-chat-delete-btn');
    if (!deleteBtn) return;
    

    const oldHandler = deleteBtn._deleteHandler;
    if (oldHandler) {
        deleteBtn.removeEventListener('click', oldHandler);
    }
    

    const deleteHandler = (e) => {
        e.preventDefault();
        e.stopPropagation();
        handleDeleteChat(chatId, otherUserId);
    };
    

    deleteBtn._deleteHandler = deleteHandler;
    deleteBtn.addEventListener('click', deleteHandler);
}

function setupReloadButton(chatId, otherUserId) {
    const reloadBtn = document.getElementById('inbox-chat-reload-btn');
    if (!reloadBtn) return;
    

    const oldHandler = reloadBtn._reloadHandler;
    if (oldHandler) {
        reloadBtn.removeEventListener('click', oldHandler);
    }
    

    const reloadHandler = (e) => {
        e.preventDefault();
        e.stopPropagation();

        delete chatMessagesCache[chatId];

        displayInboxChat(chatId, otherUserId);
    };
    

    reloadBtn._reloadHandler = reloadHandler;
    reloadBtn.addEventListener('click', reloadHandler);
}

function setupChatInput() {
    const input = document.getElementById('inbox-chat-input');
    const sendBtn = document.getElementById('inbox-chat-send-btn');
    const uploadBtn = document.getElementById('inbox-chat-upload-btn');
    const fileInput = document.getElementById('inbox-chat-file-input');
    
    
    if (!input || !sendBtn || !uploadBtn || !fileInput) {
return;
    }
    

    if (chatInputHandler) {
        input.removeEventListener('keypress', chatInputHandler);
    }
    if (chatSendHandler) {
        sendBtn.removeEventListener('click', chatSendHandler);
    }
    if (chatTypingHandler) {
        input.removeEventListener('input', chatTypingHandler);
    }
    if (chatUploadHandler) {
        uploadBtn.removeEventListener('click', chatUploadHandler);
    }
    if (chatFileInputHandler) {
        fileInput.removeEventListener('change', chatFileInputHandler);
    }
    

    chatInputHandler = async (e) => {
        if (e.key === 'Enter') {
            e.preventDefault();
            await handleSendMessage();
        }
    };
    
    chatSendHandler = async (e) => {
        e.preventDefault();
        e.stopPropagation();
        try {
            await handleSendMessage();
        } catch (error) {
}
    };
    
    chatTypingHandler = () => {
        sendTypingIndicator();
    };
    
    chatUploadHandler = () => {
        fileInput.click();
    };
    
    chatFileInputHandler = async (e) => {
        const file = e.target.files[0];
        if (file) {
            await handleFileUpload(file);

            e.target.value = '';
        }
    };
    

    input.addEventListener('keypress', chatInputHandler);
    input.addEventListener('input', chatTypingHandler);
    sendBtn.addEventListener('click', chatSendHandler);
    uploadBtn.addEventListener('click', chatUploadHandler);
    fileInput.addEventListener('change', chatFileInputHandler);
    
}

function sendTypingIndicator() {
    if (!currentChatId) {
        return;
    }
    
    const now = Date.now();

    if (now - lastTypingIndicatorSent < TYPING_INDICATOR_INTERVAL) {

        if (typingIndicatorTimeout) {
            clearTimeout(typingIndicatorTimeout);
        }
        typingIndicatorTimeout = setTimeout(() => {
            sendTypingIndicator();
        }, TYPING_INDICATOR_INTERVAL - (now - lastTypingIndicatorSent));
        return;
    }
    

    if (window.ws && window.ws.sendWebSocketMessage) {
        window.ws.sendWebSocketMessage('typing', {
            chatId: currentChatId
        });
        lastTypingIndicatorSent = now;
    }
    

    if (typingIndicatorTimeout) {
        clearTimeout(typingIndicatorTimeout);
        typingIndicatorTimeout = null;
    }
}

async function handleFileUpload(file) {
    if (!currentChatId) {
alert('No chat selected');
        return;
    }
    
    try {

        const sessionKeys = await storage.getSessionKeys(currentChatId);
        if (!sessionKeys || !sessionKeys.isEstablished) {
alert('Session not established. Please wait for the connection to be established.');
            return;
        }
        

        const fileBuffer = await file.arrayBuffer();
        const fileData = new Uint8Array(fileBuffer);
        

        const encrypted = await crypto.encryptBinary(sessionKeys.kSend, fileData, currentChatId, 'send');
        

        const isImage = file.type.startsWith('image/');
        

        const messagePayload = JSON.stringify({
            type: 'file',
            fileName: file.name,
            fileType: file.type,
            fileSize: file.size,
            isImage: isImage
        });
        

        const encryptedMetadata = await crypto.encryptMessage(sessionKeys.kSend, messagePayload, currentChatId, 'send');
        

        if (!window.ws || !window.ws.sendWebSocketMessage) {
alert('WebSocket not connected. Please refresh the page.');
            return;
        }
        
        const sent = window.ws.sendWebSocketMessage('send_message', {
            chatId: currentChatId,
            sessionId: sessionKeys.sessionId,
            encryptedMessage: encrypted,
            encryptedMetadata: encryptedMetadata,
            isFile: true
        });
        
        if (!sent) {
alert('Failed to send file. WebSocket not connected.');
            return;
        }
        

        hideTypingIndicator();
        

        addFileMessageToUI(file.name, file.type, file.size, true, isImage);
    } catch (error) {
alert('Failed to send file: ' + error.message);
    }
}

async function handleSendMessage() {
    const input = document.getElementById('inbox-chat-input');
    if (!input) {
return;
    }
    
    if (!currentChatId) {
alert('No chat selected');
        return;
    }
    
    const text = input.value.trim();
    if (!text) {
        return;
    }
    

    if (typingIndicatorTimeout) {
        clearTimeout(typingIndicatorTimeout);
        typingIndicatorTimeout = null;
    }
    lastTypingIndicatorSent = 0;
    
    
    try {

        const sessionKeys = await storage.getSessionKeys(currentChatId);
        if (!sessionKeys || !sessionKeys.isEstablished) {
alert('Session not established. Please wait for the connection to be established.');
            return;
        }
        
        

        const encrypted = await crypto.encryptMessage(sessionKeys.kSend, text, currentChatId, 'send');
        
        

        if (!window.ws || !window.ws.sendWebSocketMessage) {
alert('WebSocket not connected. Please refresh the page.');
            return;
        }
        
        const sent = window.ws.sendWebSocketMessage('send_message', {
            chatId: currentChatId,
            sessionId: sessionKeys.sessionId,
            encryptedMessage: encrypted
        });
        
        
        if (!sent) {
alert('Failed to send message. WebSocket not connected.');
            return;
        }
        

        input.value = '';
        

        hideTypingIndicator();
        

        addMessageToUI(text, true);
    } catch (error) {
alert('Failed to send message: ' + error.message);
    }
}

function addMessageToUI(text, isSent) {
    const messagesList = document.getElementById('inbox-chat-messages');
    if (!messagesList) return;
    

    const emptyMsg = messagesList.querySelector('.inbox-chat-empty');
    if (emptyMsg) emptyMsg.remove();
    
    const messageEl = document.createElement('div');
    messageEl.className = `inbox-chat-message ${isSent ? 'sent' : 'received'}`;
    messageEl.textContent = text;
    messagesList.appendChild(messageEl);
    

    if (currentChatId) {
        chatMessagesCache[currentChatId] = messagesList.innerHTML;
    }
    

    messagesList.scrollTop = messagesList.scrollHeight;
}

function addFileMessageToUI(fileName, fileType, fileSize, isSent, isImage, fileDataUrl = null) {
    const messagesList = document.getElementById('inbox-chat-messages');
    if (!messagesList) return;
    

    const emptyMsg = messagesList.querySelector('.inbox-chat-empty');
    if (emptyMsg) emptyMsg.remove();
    
    const messageEl = document.createElement('div');
    messageEl.className = `inbox-chat-message ${isSent ? 'sent' : 'received'} inbox-chat-file-message`;
    
    if (isImage && fileDataUrl) {

        const img = document.createElement('img');
        img.src = fileDataUrl;
        img.className = 'inbox-chat-file-image';
        img.alt = fileName;
        messageEl.appendChild(img);
        

        const fileInfo = document.createElement('div');
        fileInfo.className = 'inbox-chat-file-info';
        
        const fileInfoLeft = document.createElement('div');
        fileInfoLeft.className = 'inbox-chat-file-info-left';
        
        const fileNameEl = document.createElement('div');
        fileNameEl.className = 'inbox-chat-file-name';
        fileNameEl.textContent = fileName;
        fileInfoLeft.appendChild(fileNameEl);
        
        fileInfo.appendChild(fileInfoLeft);
        
        if (fileDataUrl) {
            const downloadLink = document.createElement('a');
            downloadLink.href = fileDataUrl;
            downloadLink.download = fileName;
            downloadLink.className = 'inbox-chat-file-download';
            downloadLink.title = 'Download';
            downloadLink.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512" class="download-icon">
                    <path d="M169.4 470.6c12.5 12.5 32.8 12.5 45.3 0l160-160c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L224 370.8 224 64c0-17.7-14.3-32-32-32s-32 14.3-32 32l0 306.7L54.6 265.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3l160 160z"/>
                </svg>
            `;
            fileInfo.appendChild(downloadLink);
        }
        
        messageEl.appendChild(fileInfo);
    } else {

        const fileInfo = document.createElement('div');
        fileInfo.className = 'inbox-chat-file-info';
        
        const fileInfoLeft = document.createElement('div');
        fileInfoLeft.className = 'inbox-chat-file-info-left';
        
        const fileNameEl = document.createElement('div');
        fileNameEl.className = 'inbox-chat-file-name';
        fileNameEl.textContent = fileName;
        fileInfoLeft.appendChild(fileNameEl);
        
        const fileSizeEl = document.createElement('div');
        fileSizeEl.className = 'inbox-chat-file-size';
        fileSizeEl.textContent = formatFileSize(fileSize);
        fileInfoLeft.appendChild(fileSizeEl);
        
        fileInfo.appendChild(fileInfoLeft);
        
        if (fileDataUrl) {
            const downloadLink = document.createElement('a');
            downloadLink.href = fileDataUrl;
            downloadLink.download = fileName;
            downloadLink.className = 'inbox-chat-file-download';
            downloadLink.title = 'Download';
            downloadLink.innerHTML = `
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512" class="download-icon">
                    <path d="M169.4 470.6c12.5 12.5 32.8 12.5 45.3 0l160-160c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L224 370.8 224 64c0-17.7-14.3-32-32-32s-32 14.3-32 32l0 306.7L54.6 265.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3l160 160z"/>
                </svg>
            `;
            fileInfo.appendChild(downloadLink);
        }
        
        messageEl.appendChild(fileInfo);
    }
    
    messagesList.appendChild(messageEl);
    

    if (currentChatId) {
        chatMessagesCache[currentChatId] = messagesList.innerHTML;
    }
    

    messagesList.scrollTop = messagesList.scrollHeight;
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}


function renderInboxChatBox(chatId, otherUserId) {
    const box = document.createElement('div');
    box.className = 'inbox-chat-box';
    box.dataset.chatId = chatId;
    
    const userEl = document.createElement('div');
    userEl.className = 'inbox-chat-user';
    userEl.textContent = otherUserId;
    userEl.title = otherUserId;
    box.appendChild(userEl);
    

    box.addEventListener('click', () => {

        if (box.classList.contains('selected') && currentChatId === chatId) {
            return;
        }
        

        document.querySelectorAll('.inbox-chat-box').forEach(b => b.classList.remove('selected'));

        box.classList.add('selected');

        displayInboxChat(chatId, otherUserId);
    });
    
    return box;
}


function renderIncomingRequests(requests) {
    if (!incomingRequestsList) return;
    
    if (requests.length === 0) {
        incomingRequestsList.innerHTML = '<p class="empty-state">No incoming requests</p>';
        return;
    }
    
    incomingRequestsList.innerHTML = requests.map(req => `
        <div class="request-item">
            <div class="request-info">
                <span class="request-id">${req.fromUserId}</span>
                <span class="request-time">${new Date(req.timestamp).toLocaleString()}</span>
            </div>
            <div class="request-actions">
                <button class="btn btn-success" onclick="handleAcceptRequest('${req.id}')">Accept</button>
                <button class="btn btn-danger" onclick="handleRejectRequest('${req.id}')">Reject</button>
            </div>
        </div>
    `).join('');
}


function renderChats(chats) {
    if (!chatsList) return;
    
    if (chats.length === 0) {
        chatsList.innerHTML = '<p class="empty-state">No active chats</p>';
        return;
    }
    
    chatsList.innerHTML = chats.map(chat => `
        <div class="chat-item" onclick="openChat('${chat.chatId}', '${chat.otherUserId}')">
            <div class="chat-info">
                <span class="chat-id">${chat.otherUserId.substring(0, 16)}...</span>
                <span class="chat-preview">${chat.lastMessage || 'No messages'}</span>
            </div>
            <span class="chat-time">${chat.lastMessageTime ? new Date(chat.lastMessageTime).toLocaleString() : ''}</span>
        </div>
    `).join('');
}


async function handleSendRequest() {
    const contactString = contactStringInput.value.trim();
    
    if (!contactString) {

        return;
    }
    
    if (contactString.length < 32) {

        return;
    }
    
    try {
        sendRequestBtn.disabled = true;
        sendRequestBtn.textContent = 'Sending...';
        


        

        contactStringInput.value = '';
    } catch (error) {
} finally {
        sendRequestBtn.disabled = false;
        sendRequestBtn.textContent = 'Send Request';
    }
}


async function handleContactsSendRequest() {
    const contactString = contactsContactInput?.value.trim();
    
    if (!contactString) {

        return;
    }
    
    if (contactString.length < 32) {

        return;
    }
    
    try {
        if (contactsSendBtn) {
            contactsSendBtn.disabled = true;
            contactsSendBtn.style.opacity = '0.5';
        }
        

        await api.sendContactRequest(contactString);
        

        if (contactsContactInput) {
            contactsContactInput.value = '';
        }
        

        const contactRequestsView = document.getElementById('contact-requests-view');
        if (contactRequestsView && !contactRequestsView.classList.contains('hidden')) {
            loadContactRequests();
        }
    } catch (error) {
} finally {
        if (contactsSendBtn) {
            contactsSendBtn.disabled = false;
            contactsSendBtn.style.opacity = '1';
        }
    }
}


async function handleAcceptRequest(requestId) {
    try {
        const result = await api.acceptContactRequest(requestId);

        


        if (result && (result.initiator === true || result.initiator === 'true') && result.chatId) {

            let account = storage.currentAccount;
            if (!account) {
                const accountData = await storage.getAccount();
                if (!accountData) {
                    throw new Error('Account not available');
                }
                account = await restoreAccountKeys(accountData);
                storage.currentAccount = account;
            }
            

            let otherUserId = null;
            try {
                const requests = await api.getIncomingRequests();
                const request = requests.find(r => r.id === requestId || r.requestId === requestId);
                if (request && request.fromUserId) {
                    otherUserId = request.fromUserId;
                }
            } catch (error) {
}
            

            if (!otherUserId) {
                const currentUserId = account.userId;
                const parts = result.chatId.split('_');

                let foundIndex = -1;
                for (let i = 0; i < parts.length; i++) {
                    const testId = parts.slice(0, i + 1).join('_');
                    if (testId === currentUserId) {
                        foundIndex = i;
                        break;
                    }
                }
                if (foundIndex >= 0) {
                    otherUserId = parts.slice(foundIndex + 1).join('_');
                } else {

                    for (let i = parts.length - 1; i >= 0; i--) {
                        const testId = parts.slice(i).join('_');
                        if (testId === currentUserId) {
                            otherUserId = parts.slice(0, i).join('_');
                            break;
                        }
                    }

                    if (!otherUserId) {
                        otherUserId = parts[0];
                    }
                }
            }
            
            if (otherUserId) {
                await initiateKeyExchange(result.chatId, otherUserId);
            } else {
}
        }
        


    } catch (error) {
const errorMessage = error.message || '';
        if (errorMessage.includes('not online') || errorMessage.includes('Other user is not online')) {

            showRequestError(requestId, 'User must be online for handshake to initiate');
        } else {

        }
    }
}


async function initiateKeyExchange(chatId, otherUserId) {
    try {

        let account = storage.currentAccount;
        if (!account) {
            const accountData = await storage.getAccount();
            if (!accountData) {
                throw new Error('Account not available');
            }
            account = await restoreAccountKeys(accountData);
            storage.currentAccount = account;
        }
        

        if (!account.signKeyPair || !account.signKeyPair.privateKey) {
            throw new Error('Signing key not available');
        }
        


        if (!otherUserId) {
            const currentUserId = account.userId;
            const parts = chatId.split('_');

            let foundIndex = -1;
            for (let i = 0; i < parts.length; i++) {
                const testId = parts.slice(0, i + 1).join('_');
                if (testId === currentUserId) {
                    foundIndex = i;
                    break;
                }
            }
            if (foundIndex >= 0) {
                otherUserId = parts.slice(foundIndex + 1).join('_');
            } else {


                for (let i = parts.length - 1; i >= 0; i--) {
                    const testId = parts.slice(i).join('_');
                    if (testId === currentUserId) {
                        otherUserId = parts.slice(0, i).join('_');
                        break;
                    }
                }

                if (!otherUserId) {
                    otherUserId = parts[0];
                }
            }
        }
        
        if (!otherUserId) {
            throw new Error('Could not determine otherUserId');
        }
        
        const currentUserId = account.userId;
        

        const sortedUsers = [currentUserId, otherUserId].sort();
        const userA = sortedUsers[0];
        const userB = sortedUsers[1];
        const isUserA = currentUserId === userA;
        

        const dhKeyPair = await crypto.generateDHKeyPair();
        

        const nonce = new Uint8Array(16);
        window.crypto.getRandomValues(nonce);
        const nonceBase64 = btoa(String.fromCharCode(...nonce))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        

        const version = 'nulla-v1';
        

        const signature = await crypto.signCanonicalPayload(
            account.signKeyPair.privateKey,
            version,
            chatId,
            userA,
            userB,
            nonceBase64,
            dhKeyPair.publicKeyJwk
        );
        

        if (!window.pendingKeyExchanges) {
            window.pendingKeyExchanges = {};
        }
        window.pendingKeyExchanges[chatId] = {
            dhPrivateKey: dhKeyPair.keyPair.privateKey,
            nonce: nonceBase64,
            otherUserId: otherUserId,
            isUserA: isUserA,
            version: version
        };
        

        ws.sendWebSocketMessage('dh_init', {
            chatId: chatId,
            toUserId: otherUserId,
            dhPublicKeyJwk: dhKeyPair.publicKeyJwk,
            nonce: nonceBase64,
            signature: signature,
            version: version
        });
        
    } catch (error) {
}
}


async function handleDHInit(message) {
    try {
        let { chatId, fromUserId, dhPublicKeyJwk, nonce, signature, signPublicKeyJwk, version } = message;
        

        if (typeof signPublicKeyJwk === 'string') {
            try {
                signPublicKeyJwk = JSON.parse(signPublicKeyJwk);
            } catch (e) {
throw new Error('Invalid signPublicKeyJwk format');
            }
        }
        

        let account = storage.currentAccount;
        if (!account) {
            const accountData = await storage.getAccount();
            if (!accountData) {
                throw new Error('Account not available');
            }
            account = await restoreAccountKeys(accountData);
            storage.currentAccount = account;
        }
        

        if (!account.signKeyPair || !account.signKeyPair.privateKey) {
            const accountData = await storage.getAccount();
            if (accountData) {
                account = await restoreAccountKeys(accountData);
                storage.currentAccount = account;
            }
            if (!account.signKeyPair || !account.signKeyPair.privateKey) {
                throw new Error('Signing key not available');
            }
        }
        


        const otherUserId = fromUserId;
        if (!otherUserId) {
            throw new Error('fromUserId not provided in dh_init message');
        }
        
        const currentUserId = account.userId;
        

        const sortedUsers = [currentUserId, otherUserId].sort();
        const userA = sortedUsers[0];
        const userB = sortedUsers[1];
        const isUserA = currentUserId === userA;
        const protocolVersion = version || 'nulla-v1';
        

        const nonceUsed = await storage.hasNonceBeenUsed(chatId, fromUserId, nonce);
        if (nonceUsed) {
throw new Error('Replay attack detected');
        }
        

        await storage.storeNonce(chatId, fromUserId, nonce);
        

        let trustedKey = await storage.getTrustedSigningKey(fromUserId);
        
        if (!trustedKey) {

            await storage.storeTrustedSigningKey(fromUserId, signPublicKeyJwk);
            trustedKey = signPublicKeyJwk;
        } else {

            if (typeof trustedKey === 'string') {
                try {
                    trustedKey = JSON.parse(trustedKey);
                } catch (e) {
trustedKey = signPublicKeyJwk;
                    await storage.storeTrustedSigningKey(fromUserId, signPublicKeyJwk);
                }
            }
            

            if (JSON.stringify(trustedKey) !== JSON.stringify(signPublicKeyJwk)) {
await storage.storeTrustedSigningKey(fromUserId, signPublicKeyJwk);
                trustedKey = signPublicKeyJwk;
            }
        }
        

        if (!trustedKey) {
throw new Error('Invalid trusted signing key format');
        }
        if (typeof trustedKey !== 'object') {
throw new Error('Invalid trusted signing key format');
        }
        if (!trustedKey.kty || !trustedKey.crv || !trustedKey.x || !trustedKey.y) {
throw new Error('Invalid trusted signing key format');
        }
        

        const cleanTrustedKey = {
            kty: trustedKey.kty,
            crv: trustedKey.crv,
            x: trustedKey.x,
            y: trustedKey.y
        };

        if (trustedKey.ext !== undefined) {
            cleanTrustedKey.ext = trustedKey.ext;
        }
        if (trustedKey.key_ops && Array.isArray(trustedKey.key_ops)) {
            cleanTrustedKey.key_ops = trustedKey.key_ops;
        }
        

        const isValid = await crypto.verifyCanonicalPayload(
            cleanTrustedKey,
            protocolVersion,
            chatId,
            userA,
            userB,
            nonce,
            dhPublicKeyJwk,
            signature
        );
        
        if (!isValid) {
return;
        }
        

        const dhKeyPair = await crypto.generateDHKeyPair();
        

        const responseNonce = new Uint8Array(16);
        window.crypto.getRandomValues(responseNonce);
        const responseNonceBase64 = btoa(String.fromCharCode(...responseNonce))
            .replace(/\+/g, '-')
            .replace(/\//g, '_')
            .replace(/=/g, '');
        

        if (!account.signKeyPair || !account.signKeyPair.privateKey) {

            const accountData = await storage.getAccount();
            if (accountData) {
                account = await restoreAccountKeys(accountData);
                storage.currentAccount = account;
            }
            if (!account.signKeyPair || !account.signKeyPair.privateKey) {
                throw new Error('Signing key not available');
            }
        }
        

        const responseSignature = await crypto.signCanonicalPayload(
            account.signKeyPair.privateKey,
            protocolVersion,
            chatId,
            userA,
            userB,
            responseNonceBase64,
            dhKeyPair.publicKeyJwk
        );
        

        const sharedSecret = await crypto.deriveSharedSecret(dhKeyPair.keyPair.privateKey, dhPublicKeyJwk);
        

        const { kSend, kRecv, sessionId } = await crypto.deriveSessionKeys(
            sharedSecret,
            chatId,
            userA,
            userB,
            isUserA
        );
        

        await storage.storeSessionKeys(chatId, kSend, kRecv, sessionId, false);
        

        ws.sendWebSocketMessage('dh_response', {
            chatId: chatId,
            toUserId: fromUserId,
            dhPublicKeyJwk: dhKeyPair.publicKeyJwk,
            nonce: responseNonceBase64,
            signature: responseSignature,
            version: protocolVersion
        });
        


        
    } catch (error) {
}
}


async function handleDHResponse(message) {
    try {
        let { chatId, fromUserId, dhPublicKeyJwk, nonce, signature, signPublicKeyJwk, version } = message;
        

        if (typeof signPublicKeyJwk === 'string') {
            try {
                signPublicKeyJwk = JSON.parse(signPublicKeyJwk);
            } catch (e) {
throw new Error('Invalid signPublicKeyJwk format');
            }
        }
        
        const account = storage.currentAccount || await storage.getAccount();
        if (!account) {
            throw new Error('Account not available');
        }
        

        if (!window.pendingKeyExchanges || !window.pendingKeyExchanges[chatId]) {
            throw new Error('No pending key exchange found');
        }
        
        const pending = window.pendingKeyExchanges[chatId];
        const { dhPrivateKey, otherUserId: pendingOtherUserId, isUserA, version: pendingVersion } = pending;
        const protocolVersion = version || pendingVersion || 'nulla-v1';
        

        if (fromUserId !== pendingOtherUserId) {
            throw new Error('User ID mismatch in dh_response');
        }
        

        const nonceUsed = await storage.hasNonceBeenUsed(chatId, fromUserId, nonce);
        if (nonceUsed) {
throw new Error('Replay attack detected');
        }
        

        await storage.storeNonce(chatId, fromUserId, nonce);
        


        const otherUserId = pendingOtherUserId;
        if (!otherUserId) {
            throw new Error('otherUserId not found in pending key exchange');
        }
        
        const currentUserId = account.userId;
        

        const sortedUsers = [currentUserId, pendingOtherUserId].sort();
        const userA = sortedUsers[0];
        const userB = sortedUsers[1];
        

        let trustedKey = await storage.getTrustedSigningKey(fromUserId);
        
        if (!trustedKey) {

            await storage.storeTrustedSigningKey(fromUserId, signPublicKeyJwk);
            trustedKey = signPublicKeyJwk;
        } else {

            if (typeof trustedKey === 'string') {
                try {
                    trustedKey = JSON.parse(trustedKey);
                } catch (e) {
trustedKey = signPublicKeyJwk;
                    await storage.storeTrustedSigningKey(fromUserId, signPublicKeyJwk);
                }
            }
            

            if (JSON.stringify(trustedKey) !== JSON.stringify(signPublicKeyJwk)) {
await storage.storeTrustedSigningKey(fromUserId, signPublicKeyJwk);
                trustedKey = signPublicKeyJwk;
            }
        }
        

        if (!trustedKey) {
throw new Error('Invalid trusted signing key format');
        }
        if (typeof trustedKey !== 'object') {
throw new Error('Invalid trusted signing key format');
        }
        if (!trustedKey.kty || !trustedKey.crv || !trustedKey.x || !trustedKey.y) {
throw new Error('Invalid trusted signing key format');
        }
        

        const cleanTrustedKey = {
            kty: trustedKey.kty,
            crv: trustedKey.crv,
            x: trustedKey.x,
            y: trustedKey.y
        };

        if (trustedKey.ext !== undefined) {
            cleanTrustedKey.ext = trustedKey.ext;
        }
        if (trustedKey.key_ops && Array.isArray(trustedKey.key_ops)) {
            cleanTrustedKey.key_ops = trustedKey.key_ops;
        }
        

        const isValid = await crypto.verifyCanonicalPayload(
            cleanTrustedKey,
            protocolVersion,
            chatId,
            userA,
            userB,
            nonce,
            dhPublicKeyJwk,
            signature
        );
        
        if (!isValid) {
return;
        }
        

        const sharedSecret = await crypto.deriveSharedSecret(dhPrivateKey, dhPublicKeyJwk);
        

        const { kSend, kRecv, sessionId } = await crypto.deriveSessionKeys(
            sharedSecret,
            chatId,
            userA,
            userB,
            isUserA
        );
        

        await storage.storeSessionKeys(chatId, kSend, kRecv, sessionId, false);
        

        delete window.pendingKeyExchanges[chatId];
        

        const finishMessage = JSON.stringify({
            type: 'dh_finish',
            chatId: chatId,
            sessionId: sessionId,
            timestamp: Date.now()
        });

        await storage.initNonceCounters(chatId);
        const encryptedFinish = await crypto.encryptMessage(kSend, finishMessage, chatId, 'send');
        
        ws.sendWebSocketMessage('dh_finish', {
            chatId: chatId,
            toUserId: fromUserId,
            encryptedFinish: encryptedFinish
        });
        

        if (!window.pendingFinishes) {
            window.pendingFinishes = {};
        }
        window.pendingFinishes[chatId] = {
            sent: true,
            received: false
        };
        
    } catch (error) {
}
}


async function handleDHFinish(message) {
    try {
        const { chatId, fromUserId, encryptedFinish } = message;
        
        if (!encryptedFinish) {
return;
        }
        

        const sessionKeys = await storage.getSessionKeys(chatId);
        if (!sessionKeys || !sessionKeys.kRecv) {
return;
        }
        

        let finishMessage;
        try {
            const decrypted = await crypto.decryptMessage(
                sessionKeys.kRecv,
                encryptedFinish.iv,
                encryptedFinish.ciphertext
            );
            finishMessage = JSON.parse(decrypted);
        } catch (error) {
return;
        }
        

        if (finishMessage.type !== 'dh_finish' || finishMessage.chatId !== chatId) {
return;
        }
        

        if (!window.pendingFinishes) {
            window.pendingFinishes = {};
        }
        if (!window.pendingFinishes[chatId]) {
            window.pendingFinishes[chatId] = { sent: false, received: false };
        }
        
        window.pendingFinishes[chatId].received = true;
        

        if (!window.pendingFinishes[chatId].sent) {


            const otherUserId = fromUserId;
            if (!otherUserId) {
return;
            }
            

            const ourFinishMessage = JSON.stringify({
                type: 'dh_finish',
                chatId: chatId,
                sessionId: sessionKeys.sessionId,
                timestamp: Date.now()
            });
            const ourEncryptedFinish = await crypto.encryptMessage(sessionKeys.kSend, ourFinishMessage, chatId, 'send');
            
            ws.sendWebSocketMessage('dh_finish', {
                chatId: chatId,
                toUserId: otherUserId,
                encryptedFinish: ourEncryptedFinish
            });
            
            window.pendingFinishes[chatId].sent = true;
            


            await establishChatAfterKeyExchange(chatId);
        } else {


            await establishChatAfterKeyExchange(chatId);
        }
        
    } catch (error) {
}
}


async function establishChatAfterKeyExchange(chatId) {
    try {

        await storage.markSessionEstablished(chatId);
        

        const pendingEstablishment = window.pendingChatEstablishments?.[chatId];
        

        const response = await fetch(`${api.API_BASE_URL}/chats/establish`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${api.sessionToken}`
            },
            body: JSON.stringify({
                chatId: chatId,
                requestId: pendingEstablishment?.requestId,
                reverseRequestId: pendingEstablishment?.reverseRequestId
            })
        });
        
        if (!response.ok) {
            throw new Error('Failed to establish chat');
        }
        

        if (window.pendingFinishes) {
            delete window.pendingFinishes[chatId];
        }
        if (window.pendingChatEstablishments) {
            delete window.pendingChatEstablishments[chatId];
        }
        

        await storage.cleanupNoncesForChat(chatId);
        

        

        await loadContactRequests();
        await loadInboxChats();
        

        const contactsView = document.getElementById('contacts-view');
        if (contactsView && !contactsView.classList.contains('hidden')) {
            loadContactsView();
        }
        
    } catch (error) {
}
}


window.app = window.app || {};
window.app.onNewMessage = async function(message) {
    try {
        const { chatId, encryptedMessage, fromUserId, sessionId, msgId, timestamp, encryptedMetadata, isFile } = message;
        

        if (chatId !== currentChatId) {

            return;
        }
        

        const sessionKeys = await storage.getSessionKeys(chatId);
        if (!sessionKeys || !sessionKeys.isEstablished) {
return;
        }
        

        if (sessionId && sessionId !== sessionKeys.sessionId) {
return;
        }
        
        if (isFile && encryptedMetadata) {

            const metadataJson = await crypto.decryptMessage(
                sessionKeys.kRecv,
                encryptedMetadata.iv,
                encryptedMetadata.ciphertext
            );
            const metadata = JSON.parse(metadataJson);
            

            const fileData = await crypto.decryptBinary(
                sessionKeys.kRecv,
                encryptedMessage.iv,
                encryptedMessage.ciphertext
            );
            

            const blob = new Blob([fileData], { type: metadata.fileType });
            const fileDataUrl = URL.createObjectURL(blob);
            

            const decryptedMessage = {
                isFile: true,
                fileName: metadata.fileName,
                fileType: metadata.fileType,
                fileSize: metadata.fileSize,
                isImage: metadata.isImage,
                fileData: fileData.buffer,
                fileDataUrl: fileDataUrl,
                isSent: false,
                timestamp: new Date(timestamp),
                msgId: msgId
            };
            await storage.saveDecryptedMessage(chatId, msgId, decryptedMessage);
            

            addFileMessageToUI(
                metadata.fileName,
                metadata.fileType,
                metadata.fileSize,
                false,
                metadata.isImage,
                fileDataUrl
            );
        } else {

            const decrypted = await crypto.decryptMessage(
                sessionKeys.kRecv,
                encryptedMessage.iv,
                encryptedMessage.ciphertext
            );
            

            const decryptedMessage = {
                text: decrypted,
                isSent: false,
                timestamp: new Date(timestamp),
                msgId: msgId
            };
            await storage.saveDecryptedMessage(chatId, msgId, decryptedMessage);
            

            addMessageToUI(decrypted, false);
        }
        

        hideTypingIndicator();
    } catch (error) {
}
};

window.app.onTyping = function(message) {
    const { chatId, fromUserId } = message;
    

    if (chatId === currentChatId) {
        showTypingIndicator();
    }
};

window.app.onChatDeleted = async function(message) {
    try {
        const { chatId, deletedBy } = message;
        


        const otherUserId = deletedBy;
        

        await storage.clearCachedMessagesForChat(chatId);
        await storage.deleteTrustedSigningKey(otherUserId);
        await storage.deleteSessionKeys(chatId);
        await storage.deleteNonceCounters(chatId);
        

        delete chatMessagesCache[chatId];
        

        if (currentChatId === chatId) {
            currentChatId = null;
            currentOtherUserId = null;
            
            const messagesContainer = document.getElementById('inbox-chat-messages-container');
            const emptyMsg = document.getElementById('inbox-chat-display')?.querySelector('.inbox-chat-empty');
            
            if (messagesContainer) {
                messagesContainer.classList.add('hidden');
            }
            if (emptyMsg) {
                emptyMsg.style.display = 'block';
                emptyMsg.textContent = 'Select a chat to view messages';
            }
        }
        

        await loadInboxChats();
        
    } catch (error) {
}
};

let typingIndicatorDisplayTimeout = null;

function showTypingIndicator() {
    const messagesList = document.getElementById('inbox-chat-messages');
    if (!messagesList) return;
    

    let typingEl = document.getElementById('typing-indicator');
    
    if (!typingEl) {

        typingEl = document.createElement('div');
        typingEl.className = 'inbox-chat-typing-indicator';
        typingEl.id = 'typing-indicator';
        typingEl.innerHTML = '<span></span><span></span><span></span>';
        messagesList.appendChild(typingEl);
        

        messagesList.scrollTop = messagesList.scrollHeight;
    }
    


    if (typingIndicatorDisplayTimeout) {
        clearTimeout(typingIndicatorDisplayTimeout);
        typingIndicatorDisplayTimeout = null;
    }
}

function hideTypingIndicator() {
    const typingEl = document.getElementById('typing-indicator');
    if (typingEl) {
        typingEl.remove();
    }
    if (typingIndicatorDisplayTimeout) {
        clearTimeout(typingIndicatorDisplayTimeout);
        typingIndicatorDisplayTimeout = null;
    }
}

window.app.onContactRequestAccepted = async function(message) {

    if (message.chatId) {
        if (!window.pendingChatEstablishments) {
            window.pendingChatEstablishments = {};
        }
        window.pendingChatEstablishments[message.chatId] = {
            requestId: message.requestId,
            reverseRequestId: message.reverseRequestId || null
        };
    }
    


    let isInitiator = false;
    if (message.initiator === true || message.initiator === 'true') {

        isInitiator = true;
    } else {

        const account = storage.currentAccount || await storage.getAccount();
        if (account && message.initiator === account.userId) {
            isInitiator = true;
        }
    }
    

    if (isInitiator && message.chatId) {

        let otherUserId = null;
        try {
            const requests = await api.getIncomingRequests();
            const request = requests.find(r => 
                (r.id === message.requestId || r.requestId === message.requestId) ||
                (message.reverseRequestId && (r.id === message.reverseRequestId || r.requestId === message.reverseRequestId))
            );
            if (request && request.fromUserId) {
                otherUserId = request.fromUserId;
            }
        } catch (error) {
        }
        

        if (!otherUserId) {
            const account = storage.currentAccount || await storage.getAccount();
            if (account) {
                const currentUserId = account.userId;
                const parts = message.chatId.split('_');

                let foundIndex = -1;
                for (let i = 0; i < parts.length; i++) {
                    const testId = parts.slice(0, i + 1).join('_');
                    if (testId === currentUserId) {
                        foundIndex = i;
                        break;
                    }
                }
                if (foundIndex >= 0) {
                    otherUserId = parts.slice(foundIndex + 1).join('_');
                } else {

                    otherUserId = parts[0];
                }
            }
        }
        
        if (otherUserId) {
            await initiateKeyExchange(message.chatId, otherUserId);
        } else {
}
    }
    


    const contactRequestsView = document.getElementById('contact-requests-view');
    const inboxView = document.getElementById('inbox-view');
    
    if (contactRequestsView && !contactRequestsView.classList.contains('hidden')) {
        loadContactRequests();
    }
    
    if (inboxView && !inboxView.classList.contains('hidden')) {
        loadInboxChats();
    }
};

window.app.onContactRequest = function(message) {

    const contactRequestsView = document.getElementById('contact-requests-view');
    if (contactRequestsView && !contactRequestsView.classList.contains('hidden')) {
        loadContactRequests();
    }
};

window.app.onDHInit = handleDHInit;
window.app.onDHResponse = handleDHResponse;
window.app.onDHFinish = handleDHFinish;


async function handleRejectRequest(requestId) {
    try {
        await api.rejectContactRequest(requestId);

        

        loadContactRequests();
    } catch (error) {
}
}


async function openChat(chatId, otherUserId) {
    currentChatId = chatId;
    chatTitle.textContent = `Chat: ${otherUserId.substring(0, 16)}...`;
    showView('chat');
    

    await loadChatMessages(chatId);
}


async function loadChatMessages(chatId) {
    try {



        renderMessages([]);
    } catch (error) {
}
}


function renderMessages(messages) {
    if (messages.length === 0) {
        messagesList.innerHTML = '<p class="empty-state">No messages yet</p>';
        return;
    }
    
    messagesList.innerHTML = messages.map(msg => `
        <div class="message ${msg.isOwn ? 'message-own' : 'message-other'}">
            <div class="message-content">${escapeHtml(msg.text)}</div>
            <div class="message-time">${new Date(msg.timestamp).toLocaleTimeString()}</div>
        </div>
    `).join('');
    

    messagesList.scrollTop = messagesList.scrollHeight;
}




function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}


async function handleExportSeed() {
    try {

        if (exportSeedBtn) {
            exportSeedBtn.disabled = true;
            exportSeedBtn.textContent = 'Generating...';
        }
        if (mainExportSeedBtn) {
            mainExportSeedBtn.disabled = true;
            mainExportSeedBtn.textContent = 'Generating...';
        }
        if (exportAccountBtn) {
            exportAccountBtn.disabled = true;
            exportAccountBtn.textContent = 'Generating...';
        }
        

        if (typeof crypto.generateRecoveryKey !== 'function') {
            throw new Error('generateRecoveryKey function not available. Please refresh the page.');
        }
        const recoveryKey = crypto.generateRecoveryKey();
        

        const recoveryKeyMessage = `Write down the seed lock string below, you will need it to import your account seed later and decrypt your data. Without it, you cannot recover your account after logging out.\n\nSeed Lock String:\n${recoveryKey}\n\nContinue only if you have saved the seed lock string.`;
        
        const userConfirmed = confirm(recoveryKeyMessage);
        
        if (!userConfirmed) {

            if (exportSeedBtn) {
                exportSeedBtn.disabled = false;
                exportSeedBtn.textContent = 'Export Seed';
            }
            if (mainExportSeedBtn) {
                mainExportSeedBtn.disabled = false;
                mainExportSeedBtn.textContent = 'Export seed';
            }
            if (exportAccountBtn) {
                exportAccountBtn.disabled = false;
                exportAccountBtn.textContent = 'Export account';
            }

        return;
    }
    

        if (exportSeedBtn) {
            exportSeedBtn.textContent = 'Exporting...';
        }
        if (mainExportSeedBtn) {
            mainExportSeedBtn.textContent = 'Exporting...';
        }
        if (exportAccountBtn) {
            exportAccountBtn.textContent = 'Exporting...';
        }
        

        await storage.exportAll(recoveryKey);
        

    } catch (error) {
} finally {

        if (exportSeedBtn) {
            exportSeedBtn.disabled = false;
            exportSeedBtn.textContent = 'Export Seed';
        }
        if (mainExportSeedBtn) {
            mainExportSeedBtn.disabled = false;
            mainExportSeedBtn.textContent = 'Export seed';
        }
        if (exportAccountBtn) {
            exportAccountBtn.disabled = false;
            exportAccountBtn.textContent = 'Export account';
        }
    }
}


async function handleImportAccount() {
    try {

        if (importAccountBtn) {
            importAccountBtn.disabled = true;
            importAccountBtn.textContent = 'Selecting file...';
        }
        

        const fileInput = document.createElement('input');
        fileInput.type = 'file';
        fileInput.accept = '.nulla';
        fileInput.style.display = 'none';
        

        const file = await new Promise((resolve, reject) => {
            fileInput.onchange = (e) => {
                const file = e.target.files[0];
                if (file) {
                    resolve(file);
                } else {
                    reject(new Error('No file selected'));
                }
            };
            fileInput.oncancel = () => {
                reject(new Error('File selection cancelled'));
            };
            fileInput.click();
        });
        

        if (importAccountBtn) {
            importAccountBtn.textContent = 'Reading file...';
        }
        const fileContent = await new Promise((resolve, reject) => {
            const reader = new FileReader();
            reader.onload = (e) => resolve(e.target.result);
            reader.onerror = () => reject(new Error('Failed to read file'));
            reader.readAsText(file);
        });
        

        if (importAccountBtn) {
            importAccountBtn.textContent = 'Waiting for seed lock string...';
        }
        const seedLockString = prompt('Enter the seed lock string to decrypt the backup:');
        if (!seedLockString) {
            if (importAccountBtn) {
                importAccountBtn.disabled = false;
                importAccountBtn.textContent = 'Import account';
            }
            return;
        }
        

        if (importAccountBtn) {
            importAccountBtn.textContent = 'Decrypting...';
        }
        
        let decryptedData;
        try {
            const exportPackage = JSON.parse(fileContent);
            const encryptedData = {
                version: exportPackage.version,
                kdf: exportPackage.kdf,
                encryption: exportPackage.encryption,
                salt: exportPackage.kdf.salt,
                iv: exportPackage.encryption.iv,
                ciphertext: exportPackage.encryption.ciphertext
            };
            decryptedData = await crypto.decryptSeedWithRecoveryKey(seedLockString, encryptedData);
        } catch (error) {
            alert('Failed to decrypt backup. The seed lock string may be incorrect or the file may be corrupted.');
            if (importAccountBtn) {
                importAccountBtn.disabled = false;
                importAccountBtn.textContent = 'Import account';
            }
            return;
        }
        

        const existingAccount = await storage.getAccount();
        if (existingAccount) {

            const confirmed = confirm('WARNING: This action will replace the account that already exists on this device. All current data will be deleted and replaced with the imported backup.\n\nAre you sure you want to continue?');
            if (!confirmed) {
                if (importAccountBtn) {
                    importAccountBtn.disabled = false;
                    importAccountBtn.textContent = 'Import account';
                }
                return;
            }
        }
        

        if (importAccountBtn) {
            importAccountBtn.textContent = 'Importing...';
        }
        await storage.importAll(seedLockString, fileContent);
        

        alert('Account imported successfully! The page will reload.');
        window.location.reload();
        
    } catch (error) {
alert('Failed to import account: ' + (error.message || 'Unknown error'));
        if (importAccountBtn) {
            importAccountBtn.disabled = false;
            importAccountBtn.textContent = 'Import account';
        }
    }
}


async function handleDeleteMyData() {

    const confirmMessage = 'WARNING: This will permanently delete all your account data, including:\n\n' +
        '- All your messages\n' +
        '- All your contacts\n' +
        '- Your account identity\n' +
        '- All local and server data\n\n' +
        'This action CANNOT be undone. Are you absolutely sure you want to proceed?';
    
    if (!confirm(confirmMessage)) {
        return;
    }
    

    if (!confirm('Final confirmation: This will permanently delete everything. This action cannot be undone.')) {
        return;
    }
    
    try {

        if (typeof ws !== 'undefined' && ws.disconnectWebSocket) {
            ws.disconnectWebSocket();
        }
        

        if (typeof api !== 'undefined' && api.deleteAccount) {
            try {
                await api.deleteAccount();
            } catch (error) {
}
        }
        

        await storage.clearAll();
        

        localStorage.removeItem('autoDeleteDuration');
        localStorage.removeItem('theme');
        

        storage.currentAccount = null;
        

        if (typeof api !== 'undefined') {
            api.sessionToken = null;
        }
        

        if (container) {
            container.classList.add('hidden');
        }
        if (landingPage) {
            landingPage.classList.remove('hidden');
        }
        

        await loadLandingPage();
        
        alert('All your data has been permanently deleted. Your identity has been reset.');
    } catch (error) {
alert('An error occurred while deleting your data. Please try again.');
    }
}


async function handleLogout() {

    if (!confirm('Are you sure you want to logout and delete all local data? If you have not exported your account seed, you will lose access to your account forever.\n\n Continue only if you have exported your account seed.')) {
        return;
    }
    
    try {

        if (typeof ws !== 'undefined' && ws.disconnectWebSocket) {
            ws.disconnectWebSocket();
        }
        

        await storage.clearAll();
        

        localStorage.removeItem('autoDeleteDuration');
        localStorage.removeItem('theme');
        

        storage.currentAccount = null;
        

        if (typeof api !== 'undefined') {
            api.sessionToken = null;
        }
        

        if (container) {
            container.classList.add('hidden');
        }
        if (landingPage) {
            landingPage.classList.remove('hidden');
        }
        

        await loadLandingPage();
        

    } catch (error) {
}
}


async function init() {

    if (typeof storage === 'undefined') {
return;
    }
    


    const hasAccount = await storage.hasAccount();
    const isPastLanding = container && !container.classList.contains('hidden');
    const isLandingVisible = landingPage && !landingPage.classList.contains('hidden');
    

    if (hasAccount && isPastLanding && !isLandingVisible) {

        setupEventListeners();

        return;
    }
    

    await new Promise(resolve => setTimeout(resolve, 10));
    

    await loadLandingPage();
    

    setupEventListeners();
    

    setupHoverTyping();
    

    setupNavTitleHoverTyping();
    

    const savedTheme = storage.getTheme();
    applyTheme(savedTheme);
    

    setupLogoutTooltip();
    

    registerServiceWorker();
}


function renderRequestBox(request, isReceived) {
    const contactString = isReceived ? request.fromUserId : request.toUserId;
    const requestId = request.id || request.requestId;
    
    const box = document.createElement('div');
    box.className = 'contact-request-item';
    box.dataset.requestId = requestId;
    

    const rowContainer = document.createElement('div');
    rowContainer.style.display = 'flex';
    rowContainer.style.alignItems = 'center';
    rowContainer.style.gap = '12px';
    rowContainer.style.width = '100%';
    
    const contactStringEl = document.createElement('div');
    contactStringEl.className = 'contact-request-string';
    contactStringEl.textContent = contactString;
    contactStringEl.title = contactString;
    contactStringEl.style.flex = '1';
    contactStringEl.style.minWidth = '0';
    
    const buttonsContainer = document.createElement('div');
    buttonsContainer.className = 'contact-request-buttons';
    buttonsContainer.style.flexShrink = '0';
    
    if (isReceived) {

        const acceptBtn = document.createElement('button');
        acceptBtn.className = 'contact-request-btn contact-request-accept';
        acceptBtn.title = 'Accept';
        acceptBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 448 512" class="check-icon">
                <path d="M438.6 105.4c12.5 12.5 12.5 32.8 0 45.3l-256 256c-12.5 12.5-32.8 12.5-45.3 0l-128-128c-12.5-12.5-12.5-32.8 0-45.3s32.8-12.5 45.3 0L160 338.7 393.4 105.4c12.5-12.5 32.8-12.5 45.3 0z"/>
            </svg>
        `;
        acceptBtn.addEventListener('click', () => handleAcceptRequest(requestId));
        
        const rejectBtn = document.createElement('button');
        rejectBtn.className = 'contact-request-btn contact-request-reject';
        rejectBtn.title = 'Reject';
        rejectBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512" class="x-icon">
                <path d="M342.6 150.6c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L192 210.7 86.6 105.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L146.7 256 41.4 361.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L192 301.3 297.4 406.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3L237.3 256 342.6 150.6z"/>
            </svg>
        `;
        rejectBtn.addEventListener('click', () => handleRejectRequest(requestId));
        
        buttonsContainer.appendChild(acceptBtn);
        buttonsContainer.appendChild(rejectBtn);
    } else {

        const statusEl = document.createElement('div');
        statusEl.className = 'contact-request-status';
        statusEl.textContent = 'Pending';
        buttonsContainer.appendChild(statusEl);
    }
    

    rowContainer.appendChild(contactStringEl);
    rowContainer.appendChild(buttonsContainer);
    

    box.appendChild(rowContainer);
    
    return box;
}


function showRequestError(requestId, errorMessage) {

    const requestBox = document.querySelector(`.contact-request-item[data-request-id="${requestId}"]`);
    if (!requestBox) {
        return;
    }
    

    const existingError = requestBox.querySelector('.contact-request-error');
    if (existingError) {
        existingError.remove();
    }
    

    const errorEl = document.createElement('div');
    errorEl.className = 'contact-request-error';
    errorEl.textContent = errorMessage;
    

    const buttonsContainer = requestBox.querySelector('.contact-request-buttons');
    
    if (buttonsContainer && buttonsContainer.nextSibling) {

        requestBox.insertBefore(errorEl, buttonsContainer.nextSibling);
    } else {

        requestBox.appendChild(errorEl);
    }
    

    setTimeout(() => {
        if (errorEl.parentNode) {
            errorEl.remove();
        }
    }, 5000);
}


async function loadContactRequests() {
    const receivedRequestsList = document.getElementById('received-requests-list');
    const sentRequestsList = document.getElementById('sent-requests-list');
    
    if (!receivedRequestsList || !sentRequestsList) return;
    
    try {

        const receivedRequests = await api.getIncomingRequests();
        if (receivedRequests && Array.isArray(receivedRequests)) {
            if (receivedRequests.length === 0) {
                receivedRequestsList.innerHTML = '<p class="contact-request-empty">No requests received yet</p>';
            } else {
                receivedRequestsList.innerHTML = '';
                receivedRequests.forEach(request => {
                    receivedRequestsList.appendChild(renderRequestBox(request, true));
                });
            }
        } else {
            receivedRequestsList.innerHTML = '<p class="contact-request-empty">No requests received yet</p>';
        }
        

        const sentRequests = await api.getOutgoingRequests();
        if (sentRequests && Array.isArray(sentRequests)) {
            if (sentRequests.length === 0) {
                sentRequestsList.innerHTML = '<p class="contact-request-empty">No sent requests found</p>';
            } else {
                sentRequestsList.innerHTML = '';
                sentRequests.forEach(request => {
                    sentRequestsList.appendChild(renderRequestBox(request, false));
                });
            }
        } else {
            sentRequestsList.innerHTML = '<p class="contact-request-empty">No sent requests found</p>';
        }
    } catch (error) {
receivedRequestsList.innerHTML = '<p class="contact-request-empty">No requests received yet</p>';
        sentRequestsList.innerHTML = '<p class="contact-request-empty">No sent requests found</p>';
    }
}


function setupEventListeners() {

    const connectionLostOverlay = document.getElementById('connection-lost-overlay');
    if (connectionLostOverlay) {
        connectionLostOverlay.addEventListener('click', () => {
            window.location.reload();
        });
    }
    

    document.querySelectorAll('.nav-link[data-view]').forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            const viewName = link.getAttribute('data-view');
            if (viewName) {
                showView(viewName);
            }
        });
    });
    

    if (signUpBtn) {
        signUpBtn.removeEventListener('click', handleSignUp);
        signUpBtn.addEventListener('click', handleSignUp);
    }
    
    if (landingImportSeedBtn) {
        landingImportSeedBtn.removeEventListener('click', handleImportAccount);
        landingImportSeedBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            handleImportAccount();
        });
    }
    

    if (createAccountBtn) {
        createAccountBtn.removeEventListener('click', handleCreateAccount);
        createAccountBtn.addEventListener('click', handleCreateAccount);
    }
    if (copyContactBtn) {
        copyContactBtn.removeEventListener('click', handleCopyContact);
        copyContactBtn.addEventListener('click', handleCopyContact);
    }
    
    if (contactsCopyBtn) {
        contactsCopyBtn.removeEventListener('click', handleCopyContact);
        contactsCopyBtn.addEventListener('click', handleCopyContact);
    }
    
    if (contactsSendBtn) {
        contactsSendBtn.removeEventListener('click', handleContactsSendRequest);
        contactsSendBtn.addEventListener('click', handleContactsSendRequest);
    }
    
    const mainAddContactBtn = document.getElementById('main-add-contact-btn');
    if (mainAddContactBtn) {
        mainAddContactBtn.removeEventListener('click', () => showView('contacts'));
        mainAddContactBtn.addEventListener('click', () => showView('contacts'));
    }
    

    const inboxBtn = document.getElementById('inbox-btn');
    const contactRequestsBtn = document.getElementById('contact-requests-btn');
    const inboxView = document.getElementById('inbox-view');
    const contactRequestsView = document.getElementById('contact-requests-view');
    
    function handleButtonSelection(selectedBtn) {

        if (selectedBtn && selectedBtn.classList.contains('selected')) {
            return;
        }
        

        if (inboxBtn) inboxBtn.classList.remove('selected');
        if (contactRequestsBtn) contactRequestsBtn.classList.remove('selected');

        if (selectedBtn) selectedBtn.classList.add('selected');
        

        if (selectedBtn === inboxBtn) {
            if (inboxView) inboxView.classList.remove('hidden');
            if (contactRequestsView) contactRequestsView.classList.add('hidden');

            loadInboxChats();
        } else if (selectedBtn === contactRequestsBtn) {
            if (inboxView) inboxView.classList.add('hidden');
            if (contactRequestsView) contactRequestsView.classList.remove('hidden');

            loadContactRequests();
        }
    }
    
    function renderRequestBox(request, isReceived) {
        const contactString = isReceived ? request.fromUserId : request.toUserId;
        const requestId = request.id || request.requestId;
        
    const box = document.createElement('div');
    box.className = 'contact-request-item';
    box.dataset.requestId = requestId;
    

    const rowContainer = document.createElement('div');
    rowContainer.style.display = 'flex';
    rowContainer.style.alignItems = 'center';
    rowContainer.style.gap = '12px';
    rowContainer.style.width = '100%';
    
    const contactStringEl = document.createElement('div');
    contactStringEl.className = 'contact-request-string';
    contactStringEl.textContent = contactString;
    contactStringEl.title = contactString;
    contactStringEl.style.flex = '1';
    contactStringEl.style.minWidth = '0';
    
    const buttonsContainer = document.createElement('div');
    buttonsContainer.className = 'contact-request-buttons';
    buttonsContainer.style.flexShrink = '0';
    
    if (isReceived) {

        const acceptBtn = document.createElement('button');
        acceptBtn.className = 'contact-request-btn contact-request-accept';
        acceptBtn.title = 'Accept';
        acceptBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 448 512" class="check-icon">
                <path d="M438.6 105.4c12.5 12.5 12.5 32.8 0 45.3l-256 256c-12.5 12.5-32.8 12.5-45.3 0l-128-128c-12.5-12.5-12.5-32.8 0-45.3s32.8-12.5 45.3 0L160 338.7 393.4 105.4c12.5-12.5 32.8-12.5 45.3 0z"/>
            </svg>
        `;
        acceptBtn.addEventListener('click', () => handleAcceptRequest(requestId));
        
        const rejectBtn = document.createElement('button');
        rejectBtn.className = 'contact-request-btn contact-request-reject';
        rejectBtn.title = 'Reject';
        rejectBtn.innerHTML = `
            <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 384 512" class="x-icon">
                <path d="M342.6 150.6c12.5-12.5 12.5-32.8 0-45.3s-32.8-12.5-45.3 0L192 210.7 86.6 105.4c-12.5-12.5-32.8-12.5-45.3 0s-12.5 32.8 0 45.3L146.7 256 41.4 361.4c-12.5 12.5-12.5 32.8 0 45.3s32.8 12.5 45.3 0L192 301.3 297.4 406.6c12.5 12.5 32.8 12.5 45.3 0s12.5-32.8 0-45.3L237.3 256 342.6 150.6z"/>
            </svg>
        `;
        rejectBtn.addEventListener('click', () => handleRejectRequest(requestId));
        
        buttonsContainer.appendChild(acceptBtn);
        buttonsContainer.appendChild(rejectBtn);
    } else {

        const statusEl = document.createElement('div');
        statusEl.className = 'contact-request-status';
        statusEl.textContent = 'Pending';
        buttonsContainer.appendChild(statusEl);
    }
    

    rowContainer.appendChild(contactStringEl);
    rowContainer.appendChild(buttonsContainer);
    

    box.appendChild(rowContainer);
    
    return box;
    }
    

    if (inboxView) inboxView.classList.remove('hidden');
    if (contactRequestsView) contactRequestsView.classList.add('hidden');

    
    if (inboxBtn) {
        inboxBtn.removeEventListener('click', () => handleButtonSelection(inboxBtn));
        inboxBtn.addEventListener('click', () => handleButtonSelection(inboxBtn));
    }
    
    if (contactRequestsBtn) {
        contactRequestsBtn.removeEventListener('click', () => handleButtonSelection(contactRequestsBtn));
        contactRequestsBtn.addEventListener('click', () => handleButtonSelection(contactRequestsBtn));
    }
    
    if (contactsContactInput) {
        contactsContactInput.removeEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleContactsSendRequest();
            }
        });
        contactsContactInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') {
                handleContactsSendRequest();
            }
        });
    }
    
    if (backToContactsBtn) {
        backToContactsBtn.removeEventListener('click', () => showView('main'));
        backToContactsBtn.addEventListener('click', () => showView('main'));
    }
    
    if (sendRequestBtn) {
        sendRequestBtn.removeEventListener('click', handleSendRequest);
        sendRequestBtn.addEventListener('click', handleSendRequest);
    }
    if (contactStringInput) {
        contactStringInput.removeEventListener('keypress', handleContactInputEnter);
        contactStringInput.addEventListener('keypress', handleContactInputEnter);
    }
    
    if (sendMessageBtn) {
        sendMessageBtn.removeEventListener('click', handleSendMessage);
        sendMessageBtn.addEventListener('click', handleSendMessage);
    }
    if (messageInput) {
        messageInput.removeEventListener('keypress', handleMessageInputEnter);
        messageInput.addEventListener('keypress', handleMessageInputEnter);
    }
    
    if (logoutLink) {

        const oldHandler = logoutLink._logoutHandler;
        if (oldHandler) {
            logoutLink.removeEventListener('click', oldHandler);
        }
        

        const logoutHandler = (e) => {

            if (logoutTooltip && (logoutTooltip.contains(e.target) || e.target === logoutTooltip)) {
                return;
            }
            e.preventDefault();
            e.stopPropagation();
            handleLogout();
        };
        

        logoutLink._logoutHandler = logoutHandler;
        logoutLink.addEventListener('click', logoutHandler);
    } else {
}
    
    if (exportSeedBtn) {
        exportSeedBtn.removeEventListener('click', handleExportSeed);
        exportSeedBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            handleExportSeed();
        });
    }
    
    if (mainExportSeedBtn) {
        mainExportSeedBtn.removeEventListener('click', handleExportSeed);
        mainExportSeedBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            handleExportSeed();
        });
    }
    
    if (exportAccountBtn) {
        exportAccountBtn.removeEventListener('click', handleExportSeed);
        exportAccountBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            handleExportSeed();
        });
    }
    
    if (importAccountBtn) {
        importAccountBtn.removeEventListener('click', handleImportAccount);
        importAccountBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            handleImportAccount();
        });
    }
    

    setupAutoDeleteButtons();
    

    setupThemeButtons();
    

    if (deleteMyDataBtn) {
        deleteMyDataBtn.removeEventListener('click', handleDeleteMyData);
        deleteMyDataBtn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            handleDeleteMyData();
        });
    }
    

    window.handleAcceptRequest = handleAcceptRequest;
    window.handleRejectRequest = handleRejectRequest;
    window.openChat = openChat;
}



function typeText(element, text, speed = 30) {
    let index = 0;
    element.textContent = '';
    element.classList.add('visible');
    
    const interval = setInterval(() => {
        if (index < text.length) {
            element.textContent += text[index];
            index++;
        } else {
            clearInterval(interval);
        }
    }, speed);
    
    return interval;
}

function typeTextReverse(element, text, speed = 30) {
    let index = text.length;
    element.textContent = '';
    element.classList.add('visible');
    
    const interval = setInterval(() => {
        if (index > 0) {

            element.textContent = text.substring(index - 1);
            index--;
        } else {
            clearInterval(interval);
        }
    }, speed);
    
    return interval;
}

function setupHoverTyping() {
    function startHover() {

        document.documentElement.classList.add('nav-hovered');
        document.body.classList.add('nav-hovered');
    }
    
    function stopHover() {

        document.documentElement.classList.remove('nav-hovered');
        document.body.classList.remove('nav-hovered');
    }
    

    if (signUpTitle) {
        signUpTitle.addEventListener('mouseenter', startHover);
        signUpTitle.addEventListener('mouseleave', stopHover);
    }
    
    if (signUpBtn) {
        signUpBtn.addEventListener('mouseenter', startHover);
        signUpBtn.addEventListener('mouseleave', stopHover);
    }
    
    if (landingImportSeedBtn) {
        landingImportSeedBtn.addEventListener('mouseenter', startHover);
        landingImportSeedBtn.addEventListener('mouseleave', stopHover);
    }
}


let logoutTooltipShowHandler = null;
let logoutTooltipHideHandler = null;


function setupLogoutTooltip() {
    if (!logoutLink || !logoutTooltip) {
return;
    }
    

    if (logoutTooltipShowHandler) {
        logoutLink.removeEventListener('mouseenter', logoutTooltipShowHandler);
        logoutTooltip.removeEventListener('mouseenter', logoutTooltipShowHandler);
    }
    if (logoutTooltipHideHandler) {
        logoutLink.removeEventListener('mouseleave', logoutTooltipHideHandler);
        logoutTooltip.removeEventListener('mouseleave', logoutTooltipHideHandler);
    }
    
    let hideTimeout = null;
    
    logoutTooltipShowHandler = function() {

        if (hideTimeout) {
            clearTimeout(hideTimeout);
            hideTimeout = null;
        }

        logoutTooltip.classList.add('visible');
    };
    
    logoutTooltipHideHandler = function() {

        if (hideTimeout) {
            clearTimeout(hideTimeout);
        }

        hideTimeout = setTimeout(() => {
            logoutTooltip.classList.remove('visible');
            hideTimeout = null;
        }, 500);
    };
    

    logoutLink.addEventListener('mouseenter', logoutTooltipShowHandler);
    logoutLink.addEventListener('mouseleave', logoutTooltipHideHandler);
    

    logoutTooltip.addEventListener('mouseenter', logoutTooltipShowHandler);
    logoutTooltip.addEventListener('mouseleave', logoutTooltipHideHandler);
    

    logoutTooltip.addEventListener('click', (e) => {
        e.stopPropagation();
    });
    
}


function setupNavTitleHoverTyping() {
    if (!navTitle || !navTitleHoverText) return;
    
    const hoverText = 'An identity-less, end-to-end encrypted communication system.';
    let typingInterval = null;
    let hasTyped = false;
    let hoverTimeout = null;
    
    function startTyping() {

        const isLightTheme = document.body.classList.contains('light-theme');
        if (!isLightTheme) {

            document.documentElement.classList.add('nav-hovered');
            document.body.classList.add('nav-hovered');
        }
        

        if (hasTyped) return;
        
        hoverTimeout = setTimeout(() => {
            if (hasTyped) return;
            hasTyped = true;
            
            if (navTitleHoverText) {
                navTitleHoverText.classList.add('visible');
                typingInterval = typeText(navTitleHoverText, hoverText, 30);
            }
        }, 1000);
    }
    
    function stopTyping() {

        const isLightTheme = document.body.classList.contains('light-theme');
        if (!isLightTheme) {

            document.documentElement.classList.remove('nav-hovered');
            document.body.classList.remove('nav-hovered');
        }
        

        if (hoverTimeout) {
            clearTimeout(hoverTimeout);
            hoverTimeout = null;
        }
        


    }
    

    const navTitleWrapper = document.querySelector('.nav-title-wrapper');
    
    if (navTitle) {
        navTitle.addEventListener('mouseenter', startTyping);
        navTitle.addEventListener('mouseleave', stopTyping);
    }
    

    if (navTitleWrapper) {
        navTitleWrapper.addEventListener('mouseenter', startTyping);
        navTitleWrapper.addEventListener('mouseleave', stopTyping);
    }
}


function handleContactInputEnter(e) {
    if (e.key === 'Enter') {
        handleSendRequest();
    }
}

function handleMessageInputEnter(e) {
    if (e.key === 'Enter') {
        handleSendMessage();
    }
}


function loadSettingsView() {

    const savedDuration = storage.getAutoDeleteDuration();
    const buttons = document.querySelectorAll('.auto-delete-btn');
    buttons.forEach(btn => {
        btn.classList.remove('selected');
        if (btn.getAttribute('data-duration') === savedDuration) {
            btn.classList.add('selected');
        }
    });
    

    const savedTheme = storage.getTheme();
    const themeButtons = document.querySelectorAll('.theme-btn');
    themeButtons.forEach(btn => {
        btn.classList.remove('selected');
        if (btn.getAttribute('data-theme') === savedTheme) {
            btn.classList.add('selected');
        }
    });
}


async function handleAutoDeleteSelection(duration) {

    storage.saveAutoDeleteDuration(duration);
    

    const buttons = document.querySelectorAll('.auto-delete-btn');
    buttons.forEach(btn => {
        btn.classList.remove('selected');
        if (btn.getAttribute('data-duration') === duration) {
            btn.classList.add('selected');
        }
    });
    

    if (duration !== 'off') {
        await triggerAutoDeleteCleanup(parseInt(duration));
    }
}


async function triggerAutoDeleteCleanup(days) {

    if (!socket || socket.readyState !== WebSocket.OPEN) {
        return;
    }
    
    try {

        const allCachedMessages = await storage.getAllCachedMessages();
        
        if (!allCachedMessages || allCachedMessages.length === 0) {
            return;
        }
        

        const cutoffDate = new Date();
        cutoffDate.setDate(cutoffDate.getDate() - days);
        const cutoffTimestamp = cutoffDate.getTime();
        


        const messagesToDelete = [];
        for (const cached of allCachedMessages) {
            try {

                const parts = cached.messageKey.split('_');
                if (parts.length < 2) continue;
                
                const chatId = parts[0];
                const messageId = parts.slice(1).join('_');
                


                const decryptedData = cached.decryptedData;
                if (!decryptedData || !decryptedData.timestamp) {
                    continue;
                }
                

                const messageTimestamp = decryptedData.timestamp instanceof Date 
                    ? decryptedData.timestamp.getTime() 
                    : new Date(decryptedData.timestamp).getTime();
                
                if (messageTimestamp < cutoffTimestamp) {
                    messagesToDelete.push({
                        messageId: messageId,
                        chatId: chatId
                    });
                }
            } catch (e) {

                continue;
            }
        }
        
        if (messagesToDelete.length === 0) {
            return;
        }
        

        const messagesByChat = {};
        messagesToDelete.forEach(msg => {
            if (!messagesByChat[msg.chatId]) {
                messagesByChat[msg.chatId] = [];
            }
            messagesByChat[msg.chatId].push(msg.messageId);
        });
        

        for (const [chatId, messageIds] of Object.entries(messagesByChat)) {
            socket.send(JSON.stringify({
                type: 'delete_old_messages',
                chatId: chatId,
                messageIds: messageIds,
                days: days
            }));
        }
        
    } catch (error) {
}
}


async function handleAutoDeleteConfirmation(message) {
    const { chatId, messageIds } = message;
    

    if (messageIds && Array.isArray(messageIds)) {
        for (const messageId of messageIds) {
            const messageKey = `${chatId}_${messageId}`;
            await storage.deleteCachedMessage(messageKey);
        }
    }
    

    if (currentView === 'contacts') {
        const currentChatId = document.getElementById('inbox-chat-user-id')?.getAttribute('data-chat-id');
        if (currentChatId === chatId) {
            await displayInboxChat(chatId);
        }
    }
}


function setupAutoDeleteButtons() {
    const buttons = document.querySelectorAll('.auto-delete-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const duration = btn.getAttribute('data-duration');
            handleAutoDeleteSelection(duration);
        });
    });
}


function handleThemeSelection(theme) {

    storage.saveTheme(theme);
    

    const buttons = document.querySelectorAll('.theme-btn');
    buttons.forEach(btn => {
        btn.classList.remove('selected');
        if (btn.getAttribute('data-theme') === theme) {
            btn.classList.add('selected');
        }
    });
    

    applyTheme(theme);
}


function applyTheme(theme) {
    if (theme === 'light') {
        document.documentElement.classList.add('light-theme');
        document.body.classList.add('light-theme');
    } else {
        document.documentElement.classList.remove('light-theme');
        document.body.classList.remove('light-theme');
    }
}


function setupThemeButtons() {
    const buttons = document.querySelectorAll('.theme-btn');
    buttons.forEach(btn => {
        btn.addEventListener('click', (e) => {
            e.preventDefault();
            e.stopPropagation();
            const theme = btn.getAttribute('data-theme');
            handleThemeSelection(theme);
        });
    });
}


window.app.onWebSocketConnected = async function() {
    const duration = storage.getAutoDeleteDuration();
    if (duration !== 'off') {
        await triggerAutoDeleteCleanup(parseInt(duration));
    }
};


window.app.onAutoDeleteConfirmed = async function(message) {
    await handleAutoDeleteConfirmation(message);
};


function startApp() {
    if (typeof storage === 'undefined') {

        setTimeout(startApp, 10);
        return;
    }
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }
}


function registerServiceWorker() {
    if ('serviceWorker' in navigator) {
        window.addEventListener('load', () => {
            navigator.serviceWorker.register('/js/sw.js')
                .then((registration) => {
                })
                .catch((error) => {
});
        });
    }
}

startApp();

