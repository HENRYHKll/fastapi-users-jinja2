from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, Form, Request, Response, status
from fastapi.exceptions import HTTPException
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
    get_current_user_token,
    get_user_manager,
)

templates = Jinja2Templates(directory="templates")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Not needed if you setup a migration system like Alembic
    await create_db_and_tables()
    yield


app = FastAPI(lifespan=lifespan)


# 404 Redirect /
@app.exception_handler(404)
async def not_found_exception_handler(request: Request, exc: HTTPException):
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


@app.exception_handler(401)
async def unauthorized_exception_handler(request: Request, exc: HTTPException):
    return RedirectResponse("/", status_code=status.HTTP_303_SEE_OTHER)


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


async def auth_redirect(user: User = Depends(current_user)):
    if user is None:
        raise HTTPException(
            status_code=302, detail="Not authorized", headers={"Location": "/my-login"}
        )
    return user

def mixin_redirect(res: Response, path: str ='/'):
    redirect = RedirectResponse(path, status_code=status.HTTP_303_SEE_OTHER)
    redirect.raw_headers.extend(res.raw_headers)
    return redirect


@app.get("/")
async def index(request: Request, user: User = Depends(auth_redirect)):
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
        return mixin_redirect(res=response)


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


@app.post("/logout")
async def logout_post(
    user_token: Authenticator = Depends(get_current_user_token),
    strategy: Strategy = Depends(auth_backend.get_strategy),
):
    user, token = user_token
    response = await auth_backend.logout(strategy, user, token)
    return mixin_redirect(res=response, path= 'my-login')
