"""Message history tracker for Archipel.

Maintains a sliding window of the last N messages to provide context
to the Gemini AI assistant.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import List


@dataclass
class MessageEntry:
    """A single message entry in the history.

    Attributes:
        sender_id: Hex node ID of the sender.
        text: Cleartext message content.
        timestamp: When the message was recorded.
        role: "user" or "model" (for Gemini responses).
    """
    sender_id: str
    text: str
    timestamp: datetime = field(default_factory=datetime.now)
    role: str = "user"


class MessageHistory:
    """Fixed-size buffer for conversation history."""

    def __init__(self, max_size: int = 20):
        self.max_size = max_size
        self.history: List[MessageEntry] = []

    def add_message(self, sender_id: str, text: str, role: str = "user"):
        """Add a message to the history, respecting the max size."""
        entry = MessageEntry(sender_id=sender_id, text=text, role=role)
        self.history.append(entry)
        if len(self.history) > self.max_size:
            self.history.pop(0)

    def get_context_for_ai(self) -> List[dict]:
        """Format history for Gemini API 'contents' field."""
        contents = []
        for entry in self.history:
            contents.append({
                "role": "user" if entry.role == "user" else "model",
                "parts": [{"text": entry.text}]
            })
        return contents

    def clear(self):
        """Clear all history."""
        self.history = []
