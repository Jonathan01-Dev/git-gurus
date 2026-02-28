"""Gemini AI Service for Archipel.

Handles communication with the Google Gemini API. Supports contextual
queries using message history and provides a graceful fallback if
offline (internet connection required for Gemini).
"""

import json
import logging
import httpx
from typing import List, Optional

logger = logging.getLogger("archipel.ai")


class GeminiService:
    """Service wrapper for Google Gemini API."""

    API_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent"

    def __init__(self, api_key: Optional[str] = None):
        """Initialise with an optional API key.

        Args:
            api_key: Google AI Studio API key.
        """
        self.api_key = api_key

    async def query(self, user_query: str, history_context: List[dict]) -> str:
        """Send a query to Gemini with conversation context.

        Args:
            user_query: The current question or command.
            history_context: List of previous messages in Gemini format.

        Returns:
            The AI response or an error message if offline/failed.
        """
        if not self.api_key:
            return "[AI] Error: Missing API Key. Use --api-key to provide one."

        # Prepare payload
        # Combine history with the new user query
        contents = list(history_context)
        contents.append({
            "role": "user",
            "parts": [{"text": user_query}]
        })

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 800,
            }
        }

        url = f"{self.API_URL}?key={self.api_key}"

        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                response = await client.post(
                    url,
                    headers={"Content-Type": "application/json"},
                    json=payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    try:
                        # Extract the first candidate's text
                        return result['candidates'][0]['content']['parts'][0]['text']
                    except (KeyError, IndexError):
                        return "[AI] Error: Unexpected API response format."
                else:
                    return f"[AI] Error: API returned status {response.status_code}. (Are you offline?)"

        except httpx.ConnectError:
            return "[AI] Error: Connection failed. Archipel nodes can communicate P2P without internet, but Gemini requires a connection."
        except Exception as e:
            return f"[AI] Error: {str(e)}"
