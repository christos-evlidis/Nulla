

const WS_URL = (window.WS_URL || (window.location.protocol === 'https:' ? 'wss:' : 'ws:') + '//' + window.location.host) + '/ws';

let socket = null;
let reconnectAttempts = 0;
const MAX_RECONNECT_ATTEMPTS = 5;
let reconnectTimeout = null;
let isIntentionalDisconnect = false;


async function connectWebSocket() {
    if (socket && socket.readyState === WebSocket.OPEN) {
        return;
    }
    
    if (!api.sessionToken) {
        return;
    }
    

    if (socket) {
        socket.close();
    }
    

    const url = `${WS_URL}?token=${encodeURIComponent(api.sessionToken)}`;
    
    try {
        socket = new WebSocket(url);
    } catch (error) {
        showConnectionLost();
        return;
    }
    
    socket.onopen = () => {
        reconnectAttempts = 0;
        onWebSocketOpen();
    };
    
    socket.onclose = (event) => {
        onWebSocketClose();
        

        if (isIntentionalDisconnect) {
            isIntentionalDisconnect = false;
            reconnectAttempts = 0;
            hideConnectionLost();
            return;
        }
        

        if (event.code !== 1000) {

            if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
                showConnectionLost();
            } else {
                attemptReconnect();
            }
        } else {

            hideConnectionLost();
        }
    };
    
    socket.onerror = (error) => {
        showConnectionLost();
    };
    
    socket.onmessage = (event) => {
        try {
            const message = JSON.parse(event.data);
            handleWebSocketMessage(message);
        } catch (error) {
        }
    };
}


function disconnectWebSocket() {

    isIntentionalDisconnect = true;
    
    if (reconnectTimeout) {
        clearTimeout(reconnectTimeout);
        reconnectTimeout = null;
    }
    
    if (socket) {
        socket.close(1000, 'Normal closure');
        socket = null;
    }
    

    reconnectAttempts = 0;
}


function attemptReconnect() {
    if (reconnectAttempts >= MAX_RECONNECT_ATTEMPTS) {
        showConnectionLost();
        return;
    }
    
    reconnectAttempts++;
    const delay = Math.min(1000 * Math.pow(2, reconnectAttempts - 1), 30000);
    
    reconnectTimeout = setTimeout(() => {
        if (api.sessionToken) {
            connectWebSocket();
        } else {
            showConnectionLost();
        }
    }, delay);
}


function showConnectionLost(customMessage = null, customTitle = null) {
    const overlay = document.getElementById('connection-lost-overlay');
    if (overlay) {
        const title = overlay.querySelector('.box-title');
        const description = overlay.querySelector('.box-description');
        
        if (title && customTitle) {
            title.textContent = customTitle;
        } else if (title && !customTitle) {
            title.textContent = 'Connection Lost';
        }
        
        if (description && customMessage) {
            description.textContent = customMessage;
        } else if (description && !customMessage) {
            description.textContent = 'The connection to the server has been lost. Please reload the page to reconnect.';
        }
        
        overlay.classList.remove('hidden');
    }
}


function hideConnectionLost() {
    const overlay = document.getElementById('connection-lost-overlay');
    if (overlay) {
        overlay.classList.add('hidden');
    }
}


function onWebSocketOpen() {
    reconnectAttempts = 0;
    hideConnectionLost();
    if (window.app && window.app.onWebSocketConnected) {
        window.app.onWebSocketConnected();
    }
}


function onWebSocketClose() {
    if (window.app && window.app.onWebSocketDisconnected) {
        window.app.onWebSocketDisconnected();
    }
}


async function handleWebSocketMessage(message) {
    switch (message.type) {
        case 'connected':
            break;
            
        case 'contact_request':
            if (window.app && window.app.onContactRequest) {
                window.app.onContactRequest(message);
            }
            break;
            
        case 'contact_request_accepted':
            if (window.app && window.app.onContactRequestAccepted) {
                await window.app.onContactRequestAccepted(message);
            }
            break;
            
        case 'contact_request_rejected':
            if (window.app && window.app.onContactRequestRejected) {
                window.app.onContactRequestRejected(message);
            }
            break;
            
        case 'dh_init':
            if (window.app && window.app.onDHInit) {
                await window.app.onDHInit(message);
            }
            break;
            
        case 'dh_response':
            if (window.app && window.app.onDHResponse) {
                await window.app.onDHResponse(message);
            }
            break;
            
        case 'dh_finish':
            if (window.app && window.app.onDHFinish) {
                await window.app.onDHFinish(message);
            }
            break;
            
        case 'dh_init_sent':
        case 'dh_response_sent':
        case 'dh_finish_sent':

            break;
            
        case 'new_message':
            if (window.app && window.app.onNewMessage) {
                await window.app.onNewMessage(message);
            }
            break;
            
        case 'typing':
            if (window.app && window.app.onTyping) {
                window.app.onTyping(message);
            }
            break;
            
        case 'chat_deleted':
            if (window.app && window.app.onChatDeleted) {
                await window.app.onChatDeleted(message);
            }
            break;
            
        case 'auto_delete_confirmed':
            if (window.app && window.app.onAutoDeleteConfirmed) {
                await window.app.onAutoDeleteConfirmed(message);
            }
            break;
            
        case 'error':
            break;
            
        default:
    }
}


function sendWebSocketMessage(type, data) {
    if (!socket || socket.readyState !== WebSocket.OPEN) {
        return false;
    }
    
    try {
        const message = {
            type: type,
            ...data
        };
        socket.send(JSON.stringify(message));
        return true;
    } catch (error) {
        return false;
    }
}


const ws = {
    connectWebSocket,
    disconnectWebSocket,
    sendWebSocketMessage
};


if (typeof window !== 'undefined') {
    window.ws = ws;
    window.showConnectionLost = showConnectionLost;
}
