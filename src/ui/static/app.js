document.addEventListener('DOMContentLoaded', () => {
    const nodeIdShort = document.getElementById('node-id-short');
    const filesCount = document.getElementById('files-count');
    const peersCount = document.getElementById('peers-count');
    const aiCheckbox = document.getElementById('ai-checkbox');

    // Polling Node Status
    async function updateStatus() {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();

            if (data.status === 'online') {
                nodeIdShort.textContent = data.node_id.substring(0, 12) + '...';
                filesCount.textContent = data.files_count;
                peersCount.textContent = data.peers_count;
                aiCheckbox.checked = data.ai_enabled;
            }
        } catch (error) {
            console.error('Failed to fetch status:', error);
        }
    }

    // Initialize
    updateStatus();
    setInterval(updateStatus, 3000);

    // View Switching
    const navLinks = document.querySelectorAll('nav a');
    const pageTitle = document.getElementById('page-title');
    const dynamicContent = document.getElementById('dynamic-content');

    navLinks.forEach(link => {
        link.addEventListener('click', (e) => {
            e.preventDefault();
            navLinks.forEach(l => l.parentElement.classList.remove('active'));
            link.parentElement.classList.add('active');

            const view = link.id;
            pageTitle.textContent = link.textContent;
            renderView(view);
        });
    });

    function renderView(view) {
        switch (view) {
            case 'view-status':
                dynamicContent.innerHTML = `
                    <div class="glass-card full-width">
                        <h3>Local Discovery</h3>
                        <div class="discovery-log" id="discovery-log">
                            Monitoring local network for Archipel nodes...
                        </div>
                    </div>
                `;
                break;
            case 'view-peers':
                dynamicContent.innerHTML = `
                    <div class="glass-card full-width">
                        <h3>Discovered Nodes</h3>
                        <p style="color: var(--text-secondary)">Scanning Wi-Fi Direct / Local Ad-Hoc networks...</p>
                        <table class="data-table">
                            <thead>
                                <tr><th>Node ID</th><th>IP Address</th><th>Status</th><th>Action</th></tr>
                            </thead>
                            <tbody id="peers-table-body">
                                <tr><td colspan="4" style="text-align:center">No peers discovered yet.</td></tr>
                            </tbody>
                        </table>
                    </div>
                `;
                break;
            case 'view-files':
                dynamicContent.innerHTML = `
                    <div class="glass-card full-width">
                        <h3>Local File Store</h3>
                        <div class="file-list" id="file-list">
                            <p style="color: var(--text-secondary)">No files in chunk store.</p>
                        </div>
                    </div>
                `;
                break;
            case 'view-chat':
                dynamicContent.innerHTML = `
                    <div class="chat-container glass-card">
                        <div class="chat-messages" id="chat-messages">
                            <div class="msg ai">Bienvenue sur Archipel. Je suis Gemini, votre assistant decentralise. Comment puis-je vous aider ?</div>
                        </div>
                        <div class="chat-input-area">
                            <input type="text" id="chat-input" placeholder="Ecrivez votre message ou utilisez /ask pour Gemini...">
                            <button id="chat-send">Envoyer</button>
                        </div>
                    </div>
                `;
                setupChat();
                break;
        }
    }

    function setupChat() {
        const input = document.getElementById('chat-input');
        const sendBtn = document.getElementById('chat-send');
        const messages = document.getElementById('chat-messages');

        function appendMessage(text, type) {
            const div = document.createElement('div');
            div.className = `msg ${type}`;
            div.textContent = text;
            messages.appendChild(div);
            messages.scrollTop = messages.scrollHeight;
        }

        input.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') sendBtn.click();
        });

        sendBtn.addEventListener('click', async () => {
            const text = input.value.trim();
            if (!text) return;

            appendMessage(text, 'user');
            input.value = '';

            if (text.startsWith('/ask')) {
                appendMessage('Gemini est en train de réfléchir', 'ai pensive');
                try {
                    const response = await fetch(`/api/ai?text=${encodeURIComponent(text)}`);

                    const pensive = document.querySelector('.pensive');
                    if (pensive) pensive.remove();

                    if (!response.ok) {
                        const errData = await response.json().catch(() => ({}));
                        appendMessage(`[Désolé] quota API dépassé (429). Réessayez dans 60 secondes.`, 'error');
                        return;
                    }

                    const data = await response.json();
                    if (data.status === 'ok') {
                        appendMessage(data.response, 'ai');
                    } else {
                        appendMessage(`Gemini: ${data.message || 'Réponse invalide'}`, 'ai');
                    }
                } catch (error) {
                    const pensive = document.querySelector('.pensive');
                    if (pensive) pensive.remove();
                    appendMessage("Connexion au serveur Archipel perdue.", 'error');
                }
            } else {
                appendMessage("Message envoyé en P2P (chiffré).", 'ai');
            }
        });
    }
});
