from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, Request, Response, status
from fastapi.responses import RedirectResponse
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.templating import Jinja2Templates
from fastapi_users import BaseUserManager, exceptions
from fastapi_users.authentication import Authenticator, Strategy
from fastapi_users.schemas import BaseUserCreate

from app.db import User, create_db_and_tables
from app.schemas import UserCreate, UserRead, UserUpdate
from app.users import (
    auth_backend,
    current_active_user,
    current_user,
    fastapi_users,
    get_user_manager,
    user_authenticator,
)

templates = Jinja2Templates(directory="templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Not needed if you setup a migration system like Alembic
    await create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)

app.include_router(
    fastapi_users.get_auth_router(auth_backend), prefix="/auth/jwt", tags=["auth"]
)
app.include_router(
    fastapi_users.get_register_router(UserRead, UserCreate),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_reset_password_router(),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_verify_router(UserRead),
    prefix="/auth",
    tags=["auth"],
)
app.include_router(
    fastapi_users.get_users_router(UserRead, UserUpdate),
    prefix="/users",
    tags=["users"],
)


@app.get("/authenticated-route")
async def authenticated_route(user: User = Depends(current_active_user)):
    return {"message": f"Hello {user.email}!"}


@app.get("/")
async def index(request: Request, user: User = Depends(current_user)):
    if user is None:
        return RedirectResponse("/my-login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(name="index.html", request=request)


@app.get("/my-login")
async def login_get(request: Request, user: User = Depends(current_user)):
    if user is not None:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(name="login.html", request=request)


@app.post("/my-login")
async def login_post(
    request: Request,
    response: Response,
    user_manager: BaseUserManager = Depends(get_user_manager),
    strategy: Strategy = Depends(auth_backend.get_strategy),
    email: str = Form(...),
    password: str = Form(...),
):
    credentials = OAuth2PasswordRequestForm(username=email, password=password)
    user = await user_manager.authenticate(credentials)
    if user is None:
        extra = {"exceptions": "there is no user with this username and password"}
        return templates.TemplateResponse(
            name="login.html", request=request, context=extra
        )
    else:
        response = await auth_backend.login(strategy, user)
        await user_manager.on_after_login(user, request, response)
        redicrct = RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
        redicrct.raw_headers.extend(response.raw_headers)
        return redicrct


@app.get("/register")
async def register_get(request: Request, user: User = Depends(current_user)):
    if user is not None:
        return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(
        name="register.html",
        request=request,
    )


@app.post("/register")
async def register_post(
    request: Request,
    response: Response,
    user_manager: BaseUserManager = Depends(get_user_manager),
    email: str = Form(...),
    password: str = Form(...),
):
    user = None
    try:
        user = await user_manager.create(
            user_create=BaseUserCreate(email=email, password=password)
        )
        print(user)
    except exceptions.UserAlreadyExists:
        extra = {"exceptions": "UserAlreadyExists"}
        return templates.TemplateResponse(
            name="register.html", request=request, context=extra
        )
    return templates.TemplateResponse(
        name="login.html",
        request=request,
    )


def get_current_user_token():
    user_token = user_authenticator.current_user_token(active=True, verified=False)
    return user_token


@app.post("/logout")
async def logout_post(
    user_token: Authenticator = Depends(get_current_user_token),
    strategy: Strategy = Depends(auth_backend.get_strategy),
):
    print(user_token)
    # user, token = user_token
    # return await auth_backend.logout(strategy, user, token)
