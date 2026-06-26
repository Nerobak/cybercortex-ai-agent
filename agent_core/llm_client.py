from openai import OpenAI

from config import (
    OPENAI_BASE_URL,
    OPENAI_API_KEY,
    OPENAI_MODEL,
)

client = OpenAI(
    base_url=OPENAI_BASE_URL,
    api_key=OPENAI_API_KEY,
)

model = OPENAI_MODEL

def ask_agent(message: str) -> str:
    response = client.chat.completions.create(
        model=model,
        messages=[
            {
                "role": "system",
                "content": "You are a local cybersecurity AI assistant. Only assist with authorized security testing.",
            },
            {
                "role": "user",
                "content": message,
            },
        ],
    )

    return response.choices[0].message.content
