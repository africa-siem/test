"""
SIEM Africa - Agent (Module 3) - Package ai
Enrichissement IA des alertes via Ollama (qwen2.5:3b, llama3.2:3b).
"""
from ai.ollama_client import OllamaClient
from ai.parser import parse_ai_response
from ai.prompt import build_prompt
from ai.enricher import AIEnricher

__all__ = ["OllamaClient", "parse_ai_response", "build_prompt", "AIEnricher"]
