/* Sprint 4 UI paused: file kept for history, not active in CLI-only delivery. */
document.addEventListener('DOMContentLoaded', () => {
    const nodeIdShort = document.getElementById('node-id-short');
    const filesCount = document.getElementById('files-count');
    const peersCount = document.getElementById('peers-count');
    const pageTitle = document.getElementById('page-title');
    const dynamicContent = document.getElementById('dynamic-content');

    let currentView = 'view-status';
    let activePeerId = null;
    let peersCache = [];

    function showToast(message, type = 'ok') {
        const root = document.getElementById('toast-container');
        const item = document.createElement('div');
        item.className = `toast ${type}`;
        item.textContent = message;
        root.appendChild(item);
        setTimeout(() => item.remove(), 3000);
    }

    async function updateStatus() {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            if (data.status !== 'online') {
                nodeIdShort.textContent = 'offline';
                return;
            }
            nodeIdShort.textContent = `${data.node_id.substring(0, 12)}...`;
            filesCount.textContent = String(data.files_count);
            peersCount.textContent = String(data.peers_count);
        } catch (error) {
            console.error('Failed to fetch status:', error);
        }
    }

    async function updatePeers() {
        try {
            const response = await fetch('/api/peers');
            peersCache = await response.json();
            if (currentView === 'view-peers') {
                renderPeersTable();
            }
        } catch (error) {
            console.error('Failed to fetch peers:', error);
        }
    }

    function renderPeersTable() {
        const tableBody = document.getElementById('peers-table-body');
        if (!tableBody) return;

        if (!Array.isArray(peersCache) || peersCache.length === 0) {
            tableBody.innerHTML = '<tr><td colspan="4" style="text-align:center">No peers discovered yet.</td></tr>';
            return;
        }

        tableBody.innerHTML = peersCache.map((peer) => {
            const peerId = peer.node_id || '';
            const shortId = peerId.length > 16 ? `${peerId.substring(0, 16)}...` : peerId;
            const ip = peer.ip || '?';
            const port = peer.tcp_port || '?';
            return `
                <tr>
                    <td>${shortId}</td>
                    <td>${ip}:${port}</td>
                    <td><span class="status-indicator online"></span> Online</td>
                    <td>
                        <button class="action-btn" data-peer="${peerId}">Select</button>
                    </td>
                </tr>
            `;
        }).join('');

        tableBody.querySelectorAll('button[data-peer]').forEach((btn) => {
            btn.addEventListener('click', () => {
                activePeerId = btn.getAttribute('data-peer');
                showToast(`Peer selected: ${activePeerId.substring(0, 12)}...`);
            });
        });
    }

    async function addManualPeer() {
        const ipInput = document.getElementById('manual-peer-ip');
        const portInput = document.getElementById('manual-peer-port');
        if (!ipInput || !portInput) return;

        const ip = ipInput.value.trim();
        const port = parseInt(portInput.value || '7777', 10);
        if (!ip) {
            showToast('Provide an IP address', 'error');
            return;
        }

        try {
            const response = await fetch(`/api/peers/add?ip=${encodeURIComponent(ip)}&port=${port}`, { method: 'POST' });
            const data = await response.json();
            if (response.ok && data.status === 'ok') {
                showToast('Peer added');
                await updatePeers();
            } else {
                showToast(data.message || 'Failed to add peer', 'error');
            }
        } catch (error) {
            showToast('Local server error', 'error');
        }
    }

    function navSetup() {
        const navLinks = document.querySelectorAll('nav a');
        navLinks.forEach((link) => {
            link.addEventListener('click', (event) => {
                event.preventDefault();
                navLinks.forEach((item) => item.parentElement.classList.remove('active'));
                link.parentElement.classList.add('active');
                currentView = link.id;
                pageTitle.textContent = link.textContent;
                renderView(currentView);
            });
        });
    }

    function renderView(view) {
        if (view === 'view-status') {
            dynamicContent.innerHTML = `
                <div class="glass-card full-width">
                    <h3>Node Status</h3>
                    <p class="muted">Archipel node is running locally. P2P messaging and file transfer work without internet.</p>
                </div>
            `;
            return;
        }

        if (view === 'view-peers') {
            dynamicContent.innerHTML = `
                <div class="glass-card full-width">
                    <div class="card-header-flex">
                        <h3>Peers</h3>
                        <div class="inline-row">
                            <input id="manual-peer-ip" class="text-input" placeholder="Peer IP (ex: 192.168.1.20)">
                            <input id="manual-peer-port" class="text-input small" value="7777" type="number">
                            <button id="add-peer-btn" class="action-btn">Add Peer</button>
                        </div>
                    </div>
                    <table class="data-table">
                        <thead>
                            <tr><th>Node ID</th><th>Address</th><th>Status</th><th>Action</th></tr>
                        </thead>
                        <tbody id="peers-table-body"></tbody>
                    </table>
                </div>
            `;
            renderPeersTable();
            document.getElementById('add-peer-btn').addEventListener('click', addManualPeer);
            return;
        }

        if (view === 'view-p2p-chat') {
            dynamicContent.innerHTML = `
                <div class="glass-card full-width">
                    <h3>P2P Messages (offline capable)</h3>
                    <div class="form-grid">
                        <input id="chat-node-id" class="text-input" placeholder="Target node_id (optional if selected in Peers)">
                        <input id="chat-ip" class="text-input" placeholder="Target IP fallback (optional)">
                        <input id="chat-port" class="text-input small" type="number" value="7777" placeholder="Port">
                    </div>
                    <div class="chat-container">
                        <div class="chat-messages" id="p2p-chat-messages"></div>
                        <div class="chat-input-area">
                            <input type="text" id="p2p-chat-input" placeholder="Type a P2P message...">
                            <button id="p2p-chat-send">Send P2P</button>
                        </div>
                    </div>
                </div>
            `;
            setupP2PChat();
            return;
        }

        if (view === 'view-p2p-files') {
            dynamicContent.innerHTML = `
                <div class="glass-card full-width">
                    <h3>P2P File Transfer (offline capable)</h3>
                    <div class="form-grid">
                        <input id="file-node-id" class="text-input" placeholder="Target node_id (optional if selected in Peers)">
                        <input id="file-ip" class="text-input" placeholder="Target IP fallback (optional)">
                        <input id="file-port" class="text-input small" type="number" value="7777" placeholder="Port">
                        <input id="file-path" class="text-input" placeholder="Local file path on node machine (ex: C:\\temp\\test-envoi.txt)">
                        <button id="file-send-btn" class="action-btn">Send File</button>
                    </div>
                    <h4>Received files</h4>
                    <div id="received-files" class="file-list"></div>
                </div>
            `;
            setupP2PFiles();
            return;
        }

        if (view === 'view-gemini') {
            dynamicContent.innerHTML = `
                <div class="glass-card full-width">
                    <h3>Gemini Chat (internet required)</h3>
                    <div class="chat-container">
                        <div class="chat-messages" id="ai-chat-messages">
                            <div class="msg ai">Gemini ready. If API key is missing, start dashboard with --api-key.</div>
                        </div>
                        <div class="chat-input-area">
                            <input type="text" id="ai-chat-input" placeholder="Ask Gemini...">
                            <button id="ai-chat-send">Send AI</button>
                        </div>
                    </div>
                </div>
            `;
            setupAIChat();
        }
    }

    function appendMessage(containerId, text, type) {
        const container = document.getElementById(containerId);
        if (!container) return;
        const div = document.createElement('div');
        div.className = `msg ${type}`;
        div.textContent = text;
        container.appendChild(div);
        container.scrollTop = container.scrollHeight;
    }

    function setupP2PChat() {
        const input = document.getElementById('p2p-chat-input');
        const sendBtn = document.getElementById('p2p-chat-send');

        const send = async () => {
            const text = input.value.trim();
            if (!text) return;

            const nodeId = (document.getElementById('chat-node-id').value || activePeerId || '').trim();
            const ip = document.getElementById('chat-ip').value.trim();
            const port = parseInt(document.getElementById('chat-port').value || '7777', 10);

            appendMessage('p2p-chat-messages', text, 'user');
            input.value = '';

            const params = new URLSearchParams({ text, port: String(port) });
            if (nodeId) params.set('node_id', nodeId);
            if (ip) params.set('ip', ip);

            try {
                const response = await fetch(`/api/chat/send?${params.toString()}`, { method: 'POST' });
                const data = await response.json();
                if (response.ok && data.status === 'ok') {
                    appendMessage('p2p-chat-messages', 'P2P message sent.', 'ai');
                } else {
                    appendMessage('p2p-chat-messages', data.message || 'P2P send failed', 'error');
                }
            } catch (error) {
                appendMessage('p2p-chat-messages', 'Local server error', 'error');
            }
        };

        sendBtn.addEventListener('click', send);
        input.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') send();
        });
    }

    async function loadReceivedFiles() {
        const box = document.getElementById('received-files');
        if (!box) return;
        try {
            const response = await fetch('/api/files/received');
            const files = await response.json();
            if (!Array.isArray(files) || files.length === 0) {
                box.innerHTML = '<p class="muted">No received files yet.</p>';
                return;
            }
            box.innerHTML = files.map((item) => {
                const progress = `${item.chunks || 0}/${item.total_chunks || 0}`;
                const shortId = (item.file_id || '').substring(0, 12);
                return `<div class="file-row"><strong>${item.filename}</strong> <span>${progress}</span> <span>${shortId}...</span></div>`;
            }).join('');
        } catch (error) {
            box.innerHTML = '<p class="muted">Failed to load received files.</p>';
        }
    }

    function setupP2PFiles() {
        const btn = document.getElementById('file-send-btn');
        const filePathInput = document.getElementById('file-path');

        loadReceivedFiles();

        btn.addEventListener('click', async () => {
            const filepath = filePathInput.value.trim();
            if (!filepath) {
                showToast('Provide a file path', 'error');
                return;
            }

            const nodeId = (document.getElementById('file-node-id').value || activePeerId || '').trim();
            const ip = document.getElementById('file-ip').value.trim();
            const port = document.getElementById('file-port').value || '7777';

            const params = new URLSearchParams({
                filepath,
                port,
            });
            if (nodeId) params.set('node_id', nodeId);
            if (ip) params.set('ip', ip);

            try {
                btn.disabled = true;
                btn.textContent = 'Sending...';
                const response = await fetch(`/api/files/send?${params.toString()}`, { method: 'POST' });
                const data = await response.json();
                if (response.ok && data.status === 'ok') {
                    showToast(`File sent: ${data.filename}`);
                    await loadReceivedFiles();
                } else {
                    showToast(data.message || 'File transfer failed', 'error');
                }
            } catch (error) {
                showToast('Local server error', 'error');
            } finally {
                btn.disabled = false;
                btn.textContent = 'Send File';
            }
        });
    }

    function setupAIChat() {
        const input = document.getElementById('ai-chat-input');
        const sendBtn = document.getElementById('ai-chat-send');

        const send = async () => {
            const text = input.value.trim();
            if (!text) return;
            appendMessage('ai-chat-messages', text, 'user');
            input.value = '';

            appendMessage('ai-chat-messages', 'Gemini is thinking...', 'ai');
            try {
                const response = await fetch(`/api/ai?text=${encodeURIComponent(text)}`);
                const data = await response.json();

                const messages = document.getElementById('ai-chat-messages');
                const last = messages.lastElementChild;
                if (last && last.textContent === 'Gemini is thinking...') {
                    last.remove();
                }

                if (response.ok && data.status === 'ok') {
                    appendMessage('ai-chat-messages', data.response, 'ai');
                } else {
                    appendMessage('ai-chat-messages', data.message || 'Gemini error', 'error');
                }
            } catch (error) {
                appendMessage('ai-chat-messages', 'Local server error', 'error');
            }
        };

        sendBtn.addEventListener('click', send);
        input.addEventListener('keypress', (event) => {
            if (event.key === 'Enter') send();
        });
    }

    navSetup();
    renderView(currentView);
    updateStatus();
    updatePeers();

    setInterval(updateStatus, 3000);
    setInterval(updatePeers, 5000);
});
