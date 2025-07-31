from fastapi import FastAPI, Request
from .auth import (
    get_registration_options,
    verify_registration,
    get_authentication_options,
    verify_authentication,
)
from fastapi.responses import FileResponse
import os

app = FastAPI()

@app.get("/")
async def get_index_page():
    current_dir = os.path.dirname(os.path.abspath(__file__))
    index_path = os.path.join(current_dir, "index.html")
    return FileResponse(path=index_path, media_type="text/html")

@app.post("/register/options")
async def register_options(request: Request):
    body = await request.json()
    return get_registration_options(body["username"])

@app.post("/register/verify")
async def register_verify(request: Request):
    body = await request.json()
    verified = verify_registration(body["username"], body["response"])
    return {"status": "ok" if verified else "failed"}

@app.post("/login/options")
async def login_options(request: Request):
    body = await request.json()
    return get_authentication_options(body["username"])

@app.post("/login/verify")
async def login_verify(request: Request):
    body = await request.json()
    verified = verify_authentication(body["username"], body["response"])
    return {"status": "ok" if verified else "failed"}
