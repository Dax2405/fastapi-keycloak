from typing import Union, Annotated

from fastapi import FastAPI, Security
from .keycloak import get_current_user, oauth2_scheme, role_required


app = FastAPI()


@app.get("/")
@role_required(["user"])
def get_root():
    return {"Holi": "si"}


@app.get("/admin")
@role_required(["admin"])
def admin_route():
    return {"message": "Hi admin"}


@app.get("/super_admin")
@role_required(["super_admin"])
def super_admin_route():
    return {"message": "Hi super_admin"}
