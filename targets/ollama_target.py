"""
Target harness for a local Ollama-served LLM.

Handles sending prompts and maintaining conversation state, so attack
modules can run single-turn or multi-turn tests without worrying about
the underlying API.
"""

import requests


class OllamaTarget:
    def __init__(self, model: str, host: str = "http://localhost:11434"):
        self.model = model
        self.host = host.rstrip("/")
        self.history = []  # list of {"role": ..., "content": ...}

    def reset(self):
        """Clear conversation history — call between independent test cases."""
        self.history = []

    def send(self, prompt: str, role: str = "user") -> str:
        """
        Send a prompt to the model, appending to conversation history so
        multi-turn / memory-persistence attacks can be tested.
        """
        self.history.append({"role": role, "content": prompt})

        response = requests.post(
            f"{self.host}/api/chat",
            json={
                "model": self.model,
                "messages": self.history,
                "stream": False,
            },
            timeout=60,
        )
        response.raise_for_status()
        data = response.json()
        reply = data.get("message", {}).get("content", "")

        self.history.append({"role": "assistant", "content": reply})
        return reply

    def new_session(self):
        """
        Simulate a new session while keeping the model's underlying state
        (useful for testing cross-session memory persistence if the target
        app itself persists memory outside the chat history, e.g. to a file
        or database — see attacks/memory_poisoning.py).
        """
        self.reset()
