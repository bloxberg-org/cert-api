from fastapi import APIRouter
from controller.cert_tools import generate_unsigned_certificate, generate_pdf, generate_research_object_schema
from fastapi_simple_security import api_key_router

router = APIRouter()

router.include_router(api_key_router, prefix="/auth", tags=["_auth"])
router.include_router(generate_unsigned_certificate.router, tags=["_auth"])
router.include_router(generate_pdf.router, tags=["_auth"])
router.include_router(generate_research_object_schema.router)