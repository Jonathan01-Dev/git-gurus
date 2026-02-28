"""Gemini AI service for Archipel."""

import os
from typing import List, Optional

import httpx


class GeminiService:
    """Service wrapper for Google Gemini API with model fallback."""

    API_ROOT = "https://generativelanguage.googleapis.com/v1beta/models"
    DEFAULT_MODELS = (
        "gemini-2.5-flash-lite",
        "gemma-3-27b-it",
        "gemini-2.5-flash",
        "gemini-2.0-flash",
    )

    def __init__(self, api_key: Optional[str] = None, model: Optional[str] = None):
        self.api_key = api_key
        self.model = model or os.getenv("ARCHIPEL_GEMINI_MODEL") or self.DEFAULT_MODELS[0]

    def _dedupe(self, ordered: list[str]) -> list[str]:
        seen = set()
        unique = []
        for item in ordered:
            if item and item not in seen:
                seen.add(item)
                unique.append(item)
        return unique

    def _candidate_models(self, available_models: list[str]) -> list[str]:
        preferred = self._dedupe([self.model, *self.DEFAULT_MODELS])
        if not available_models:
            return preferred

        available_set = set(available_models)
        ranked_available = [m for m in preferred if m in available_set]
        dynamic_tail = [m for m in available_models if m not in ranked_available]
        return ranked_available + dynamic_tail

    async def _fetch_available_models(self, client: httpx.AsyncClient) -> list[str]:
        """Return model ids that support generateContent for this API key."""
        if not self.api_key:
            return []
        url = f"{self.API_ROOT}?key={self.api_key}"
        try:
            response = await client.get(url, headers={"Content-Type": "application/json"})
            if response.status_code != 200:
                return []
            payload = response.json()
            items = payload.get("models", [])
            out = []
            for item in items:
                methods = item.get("supportedGenerationMethods", []) or []
                if "generateContent" not in methods:
                    continue
                name = item.get("name", "")
                # API returns names like: models/gemini-2.5-flash
                if name.startswith("models/"):
                    out.append(name.split("/", 1)[1])
            return self._dedupe(out)
        except Exception:
            # Non-fatal: if this lookup fails, static fallback still works.
            return []

    @staticmethod
    def _extract_text(payload: dict) -> Optional[str]:
        try:
            return payload["candidates"][0]["content"]["parts"][0]["text"]
        except (KeyError, IndexError, TypeError):
            return None

    async def query(self, user_query: str, history_context: List[dict]) -> str:
        if not self.api_key:
            return "[AI] Error: Missing API key. Start with --api-key."
        if not user_query.strip():
            return "[AI] Error: Empty prompt."

        contents = list(history_context)
        contents.append({"role": "user", "parts": [{"text": user_query}]})
        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 800,
            },
        }

        try:
            async with httpx.AsyncClient(timeout=20.0) as client:
                available_models = await self._fetch_available_models(client)
                model_not_found = False
                last_error = None

                for model in self._candidate_models(available_models):
                    url = f"{self.API_ROOT}/{model}:generateContent?key={self.api_key}"
                    response = await client.post(
                        url,
                        headers={"Content-Type": "application/json"},
                        json=payload,
                    )

                    if response.status_code == 200:
                        text = self._extract_text(response.json())
                        if text:
                            return text
                        return "[AI] Error: Unexpected API response format."

                    if response.status_code == 404:
                        model_not_found = True
                        continue

                    if response.status_code == 429:
                        return "[AI] Error: API quota exceeded (429)."

                    snippet = response.text[:180].replace("\n", " ")
                    last_error = f"[AI] Error: API returned status {response.status_code}. {snippet}"
                    break

                if model_not_found and not last_error:
                    return (
                        "[AI] Error: Gemini model not found for this API key. "
                        "Set ARCHIPEL_GEMINI_MODEL or use a currently available model."
                    )
                if last_error:
                    return last_error
                return "[AI] Error: Failed to query Gemini."
        except httpx.ConnectError:
            return (
                "[AI] Error: Connection failed. P2P features work offline, "
                "Gemini requires internet."
            )
        except httpx.TimeoutException:
            return "[AI] Error: Gemini request timed out."
        except Exception as exc:
            return f"[AI] Error: {exc}"
