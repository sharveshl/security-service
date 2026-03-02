from fastapi import FastAPI
from pydantic import BaseModel
from risk_engine import analyze_message

app = FastAPI()

class Message(BaseModel):
    text: str
    user_id: str

@app.post("/analyze")
def analyze(message: Message):
    result = analyze_message(message.text)
    return result