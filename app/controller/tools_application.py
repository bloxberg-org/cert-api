import logging

from controller.errors.http_error import http_error_handler
from controller.errors.validation_error import validation_exception_handler
from fastapi import FastAPI, HTTPException
from starlette.middleware.cors import CORSMiddleware
from fastapi.exceptions import RequestValidationError
from controller.cert_tools.router import router as api_router

logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%m/%d/%Y %I:%M:%S %p")
logger = logging.getLogger(__name__)


tags_metadata = [
    {
        "name": "certificate",
        "description": "Creates, transacts, and signs a research object certificate on the bloxberg blockchain. Hashes must be generated client side for each desired file and provided in an array. Each hash corresponds to one research object certificate returned in a JSON object array."
    },
    {
        "name": "pdf",
        "description": "Accepts as input the response from the createBloxbergCertificate endpoint, for example a research object JSON array."
    },
    {
        "name": "research_object_v1",
        "description": "Returns Context JSON schema for Version 1 of Research Object Certificate"
    }

]

app = FastAPI(title="Research Object Certification", openapi_tags=tags_metadata, version="0.4.0")

origins = [
    "http://localhost:3001"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

app.add_exception_handler(HTTPException, http_error_handler)
app.add_exception_handler(RequestValidationError, validation_exception_handler)

