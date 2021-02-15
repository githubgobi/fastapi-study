from fastapi import Depends, FastAPI, Request, WebSocket, Query, HTTPException
from fastapi_jwt_auth.exceptions import AuthJWTException
from fastapi.responses import JSONResponse, HTMLResponse

from fastapi_jwt_auth import AuthJWT

from .dependencies import get_query_token, get_token_header
from .internal import admin
from .routers import items, users, auth

from typing import List
from sqlalchemy.orm import Session

from app import models, schemas, crud
from app.database import engine, SessionLocal

# app = FastAPI(dependencies=[Depends(get_query_token)])
app = FastAPI()


app.include_router(users.router)
app.include_router(items.router)
app.include_router(auth.router)
app.include_router(
    admin.router,
    prefix="/admin",
    tags=["admin"],
    dependencies=[Depends(get_token_header)],
    responses={418: {"description": "I'm a teapot"}},
)


@app.get("/")
async def root():
    # return {"message": "Hello Bigger Applications!"}
    return HTMLResponse(html)

@app.exception_handler(AuthJWTException)
def authjwt_exception_handler(request: Request, exc: AuthJWTException):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message}
    )    

# Web Socket Protecting


html = """
<!DOCTYPE html>
<html>
    <head>
        <title>Authorize</title>
    </head>
    <body>
        <h1>WebSocket Authorize</h1>
        <p>Token:</p>
        <textarea id="token" rows="4" cols="50"></textarea><br><br>
        <button onclick="websocketfun()">Send</button>
        <ul id='messages'>
        </ul>
        <script>
            const websocketfun = () => {
                let token = document.getElementById("token").value
                let ws = new WebSocket(`ws://127.0.0.1:8000/ws?token=${token}`)
                ws.onmessage = (event) => {
                    let messages = document.getElementById('messages')
                    let message = document.createElement('li')
                    let content = document.createTextNode(event.data)
                    message.appendChild(content)
                    messages.appendChild(message)
                }
            }
        </script>
    </body>
</html>
"""


@app.websocket('/ws')
async def websocket(websocket: WebSocket, token: str = Query(...), Authorize: AuthJWT = Depends()):
    await websocket.accept()
    try:
        Authorize.jwt_required("websocket",token=token)
        # Authorize.jwt_optional("websocket",token=token)
        # Authorize.jwt_refresh_token_required("websocket",token=token)
        # Authorize.fresh_jwt_required("websocket",token=token)
        await websocket.send_text("Successfully Login!")
        decoded_token = Authorize.get_raw_jwt(token)
        await websocket.send_text(f"Here your decoded token: {decoded_token}")
    except AuthJWTException as err:
        await websocket.send_text(err.message)
        await websocket.close()

def get_db():
    db = None
    try:
        db = SessionLocal()
        yield db
    finally:
        db.close()

@app.post("/customer", response_model=schemas.UserInfo)
def create_customer(user: schemas.UserCreate, db: Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Username already registered")
    return crud.create_user(db=db, user=user)

@app.get("/customer", response_model=List[schemas.UserList])
def customer_list(skip: int = 0, limit: int = 100, db: Session = Depends(get_db)):
    return crud.get_users(db, skip=skip, limit=limit);  

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=4000)    