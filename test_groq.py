import os
from dotenv import load_dotenv
load_dotenv(".env")
import requests

key = os.getenv("GROQ_API_KEY", "")
print(f"API Key: {key[:10]}..." if key else "API KEY YOK!")

r = requests.post(
    "https://api.groq.com/openai/v1/chat/completions",
    headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
    json={
        "model": "llama-3.3-70b-versatile",
        "messages": [{"role": "user", "content": "Merhaba, 2+2 kac?"}],
        "max_tokens": 100,
    },
    timeout=15
)
print(f"Status: {r.status_code}")
print(f"Response: {r.text[:500]}")