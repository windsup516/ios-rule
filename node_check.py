from fastapi import FastAPI

app = FastAPI()

@app.get("/health")
def health():
    return {
        "success": True,
        "status": "node_ok",
        "message": "node service is reachable"
    }