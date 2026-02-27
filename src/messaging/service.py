class MessagingService:
    def __init__(self) -> None:
        self._history: list[str] = []

    def send_encrypted_message(self, recipient_node_id: str, plaintext: str) -> str:
        # Placeholder until Sprint 2 handshake + AEAD is implemented.
        entry = f"to={recipient_node_id} msg={plaintext}"
        self._history.append(entry)
        return "queued"

    def history(self) -> list[str]:
        return list(self._history)
