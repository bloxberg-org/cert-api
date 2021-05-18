from typing import List, Optional
from functools import lru_cache
from fastapi import Depends, FastAPI, Request, HTTPException, status, BackgroundTasks
from fastapi.responses import FileResponse, Response, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
import logging
from fastapi import APIRouter
from os.path import join, dirname

import json




logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%m/%d/%Y %I:%M:%S %p")
logger = logging.getLogger(__name__)
router = APIRouter()



@router.get("/research_object_certificate_v1", tags=['research_object_v1'])
async def research_object_certificate_v1():
    schema = _load_json_schema("./schemas/research_object_certificate_v1.json")
    return schema





def _load_json_schema(filename):
    """ Loads the given schema file """

    relative_path = join('.', filename)
    absolute_path = join(dirname(__file__), relative_path)

    with open(absolute_path) as schema_file:
        return json.loads(schema_file.read())