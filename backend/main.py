from fastapi import FastAPI

app = FastAPI()

@app.get("/")
def home():
    return {
        "message": "AI Destekli Phishing Tespit Platformu"
    }

@app.get("/analyze")
def analyze():
    return {
        "risk": 25,
        "status": "safe"
    }