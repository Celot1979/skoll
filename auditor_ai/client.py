import os

from google import genai
from google.genai import types

from auditor_ai.config import DEFAULT_MODEL, RAPTOR_SYSTEM_PROMPT


class GeminiClient:
    def __init__(self, api_key=None):
        """
        Inicializa el cliente. Prioriza la clave pasada como argumento,
        si no, busca en las variables de entorno.
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")

        if not self.api_key:
            raise ValueError("No se ha proporcionado una API Key válida.")

        try:
            self.client = genai.Client(api_key=self.api_key)
        except Exception as e:
            raise RuntimeError(f"Error al inicializar el SDK de Gemini: {str(e)}")

    def iniciar_chat(self, model: str = DEFAULT_MODEL):
        config = types.GenerateContentConfig(
            system_instruction=RAPTOR_SYSTEM_PROMPT,
            temperature=0.3,
        )
        return self.client.chats.create(model=model, config=config)

    def analizar_codigo_stream(self, prompt_usuario: str, model: str = DEFAULT_MODEL):
        config = types.GenerateContentConfig(
            system_instruction=RAPTOR_SYSTEM_PROMPT,
            temperature=0.2,
        )
        return self.client.models.generate_content_stream(
            model=model,
            contents=prompt_usuario,
            config=config
        )
