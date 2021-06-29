from typing import List, Optional
from functools import lru_cache
from fastapi import Depends, FastAPI, Request, HTTPException, status, BackgroundTasks
from fastapi.responses import FileResponse, Response, JSONResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.encoders import jsonable_encoder
from fastapi_simple_security import api_key_security
from cert_tools import instantiate_v3_alpha_certificate_batch, create_v3_alpha_certificate_template
from pydantic import BaseModel, Field, Json
from urllib.error import HTTPError
import configargparse
import logging
from fastapi import APIRouter
import uuid
import io
import os
import httpx
import time
import json
import requests
import shutil

logging.basicConfig(format="%(asctime)s %(message)s", datefmt="%m/%d/%Y %I:%M:%S %p")
logger = logging.getLogger(__name__)
router = APIRouter()

class jsonCertificate(BaseModel):
    context: Optional[List[str]] = Field(
        alias='@context',
        description='Relevant JSON-LD context links in order to validate Verifiable Credentials according to their spec.'
    )
    id: str
    type: List[str]
    issuer: str
    issuanceDate: str
    credentialSubject: dict
    displayHtml: Optional[str]
    crid: str
    cridType: Optional[str]
    metadataJson: Optional[str]
    proof: dict


    class Config:
        schema_extra = {
            "example":
                {
                    "@context": [
                        "https://www.w3.org/2018/credentials/v1",
                        "https://w3id.org/bloxberg/schema/research_object_certificate_v1"
                    ],
                    "type": [
                        "VerifiableCredential",
                        "BloxbergCredential"
                    ],
                    "issuer": "https://raw.githubusercontent.com/bloxberg-org/issuer_json/master/issuer.json",
                    "issuanceDate": "2021-04-08T14:16:42.721793+00:00",
                    "credentialSubject": {
                        "id": "https://blockexplorer.bloxberg.org/address/0x69575606E8b8F0cAaA5A3BD1fc5D032024Bb85AF",
                        "issuingOrg": {
                            "id": "https://bloxberg.org"
                        }
                    },
                    "id": "https://bloxberg.org",
                    "crid": "0x0e4ded5319861c8daac00d425c53a16bd180a7d01a340a0e00f7dede40d2c9f6",
                    "cridType": "sha2-256",
                    "metadataJson": "{\"authors\": \"Albert Einstein\"}",
                    "proof": {
                        "type": "MerkleProof2019",
                        "created": "2021-04-08T14:16:50.437593",
                        "proofValue": "z7veGu1qoKR3AS5Aj7L346qXbWzqETUy5T16AYKdDfL3f9g4wsns2Fh7zK4QgCzD4NtcbPLseL1BDnWb3jqdGVR9WUVjzpqgVx1Dc5bUGwrkLXH31fwNuqW6iSXM3rcNA8XQKcHjKddyzxiBDT7QUY7yLW1ERwaQZmnXsxdWTpbunqWb1VHYMo6La7n1ztTkBCuWrfq4w6keqRccHDWu3Ltfn7maAXGWTE4M2j3zrjD52SBdFcGyTDb6rPutEKjSHRJ26gZ8GnNChHf9S57j88AXi1n51iSfZbZAJM1RbbKvTkpRuFVM6t",
                        "proofPurpose": "assertionMethod",
                        "verificationMethod": "ecdsa-koblitz-pubkey:0xD748BF41264b906093460923169643f45BDbC32e",
                        "ens_name": "mpdl.berg"
                    }
                }
            }

class jsonCertificateBatch(BaseModel):
    __root__: Optional[List[jsonCertificate]]

class Batch(BaseModel):
    publicKey: str = Field(
        description='Public bloxberg address where the Research Object Certificate token will be minted')
    crid: List[str] = Field(
        description='Cryptographic Identifier of each file you wish to certify. One certificate will be generated per hash up to a maximum of 1001 in a single request',
        max_length=1001)
    cridType: Optional[str] = Field(
        description='If crid is not self-describing, provide the type of cryptographic function you used to generate the cryptographic identifier.'
                    ' Please use the name field from the multihash list to ensure compatibility: https://github.com/multiformats/multicodec/blob/master/table.csv')
    enableIPFS: bool = Field(
        description='EXPERIMENTAL: Set to true to enable posting certificate to IPFS. If set to false, will simply return certificates in the response.'
                    ' By default, this is disabled on the server due to performance and storage problems with IPFS')
    metadataJson: Optional[Json] = Field(
        description='Provide optional metadata to describe the research object batch in more detail '
                    'that will be included in the certificate.')

    class Config:
        schema_extra = {
            "example": {
                "publicKey": "0x69575606E8b8F0cAaA5A3BD1fc5D032024Bb85AF",
                "crid": ["0x0e4ded5319861c8daac00d425c53a16bd180a7d01a340a0e00f7dede40d2c9f6",
                         "0xfda3124d5319861c8daac00d425c53a16bd180a7d01a340a0e00f7dede40d2c9f6"],
                "cridType": "sha2-256",
                "enableIPFS": False,
                "metadataJson": "{\"authors\":\"Albert Einstein\"}"
            }
        }



async def issueRequest(url, headers, payload):
    #Asynchronous
    async with httpx.AsyncClient() as session:  # use httpx
        response = await session.request(method='POST', url=url, headers=headers, data=payload, timeout=None)
    encodedResponse = response.text.encode('utf8')
    jsonText = json.loads(encodedResponse)

    ## Sync
    # response = requests.request("POST", url, headers=headers, data=payload)
    # encodedResponse = response.text.encode('utf8')
    # jsonText = json.loads(encodedResponse)

    return jsonText


async def removeTempFiles(absolute_directory, uidArray):
    try:
        for x in uidArray:
            full_path_with_file = str(absolute_directory + '/' + 'unsigned_certificates/' + x + '.json')
            os.remove(full_path_with_file)
    except:
        print("Error while deleting file ", full_path_with_file)

    return




##Full Workflow
@router.post("/createBloxbergCertificate", dependencies=[Depends(api_key_security)], tags=['certificate'])
async def createBloxbergCertificate(batch: Batch):

    """
    Creates, transacts, and signs a research object certificate on the bloxberg blockchain. Hashes must be generated client side for each desired file and provided in an array. Each hash corresponds to one research object certificate returned in a JSON object array.

    API Key must be sent as a header or query, please contact bloxberg-services@mpdl.mpg.de in order to obtain an API key for production use.
    """

    # Currently don't support IPFS due to performance and space issues.
    if batch.enableIPFS is True:
        raise HTTPException(status_code=400,
                            detail="IPFS is not supported currently due to performance and storage requirements.")
    # limit number of CRIDs to 1000
    if len(batch.crid) >= 1001:
        raise HTTPException(status_code=400,
                            detail="You are trying to certify too many files at once, please limit to 1000 files per batch.")

    conf = create_v3_alpha_certificate_template.get_config()

    python_environment = os.getenv("app")
    # if python_environment == "production":
    #     full_path_with_file = str(conf.abs_data_dir + '/' + 'unsigned_certificates/')
    #     for file_name in os.listdir(full_path_with_file):
    #         if file_name.endswith('.json'):
    #             logger.info(full_path_with_file + file_name)
    #             os.remove(full_path_with_file + file_name)

    logger.info('Generating unsigned certs')
    create_v3_alpha_certificate_template.write_certificate_template(conf, batch.publicKey)
    conf_instantiate = instantiate_v3_alpha_certificate_batch.get_config()
    if batch.metadataJson is not None:
        uidArray = instantiate_v3_alpha_certificate_batch.instantiate_batch(conf_instantiate, batch.publicKey,
                                                                           batch.crid, batch.cridType, batch.metadataJson)
    else:
        uidArray = instantiate_v3_alpha_certificate_batch.instantiate_batch(conf_instantiate, batch.publicKey,
                                                                            batch.crid, batch.cridType)
    if python_environment == "production":
        cert_issuer_address = os.getenv("CERT_ISSUER_CONTAINER")
        url = "http://" + cert_issuer_address + "/issueBloxbergCertificate"
    else:
        url = "http://cert_issuer_api:80/issueBloxbergCertificate"

    payload = {"recipientPublickey": batch.publicKey, "unSignedCerts": uidArray, "enableIPFS": batch.enableIPFS
              }
    headers = {
        'Content-Type': 'application/json'
    }
    payload = json.dumps(payload)
    start2 = time.time()
    logger.info('starting cert-issuance')
    # TODO: Currently a simple post request, but need to research message queues for microservices
    try:
        jsonText = await issueRequest(url, headers, payload)
    # TODO: Move certificate removal to a background process or async function outside of try block

    except Exception as e:
        print('Bad post request')
        print(e)
        try:
            for x in uidArray:
                full_path_with_file = str(conf.abs_data_dir + '/' + 'unsigned_certificates/' + x + '.json')
                os.remove(full_path_with_file)
                full_path_with_pdf = str(conf.abs_data_dir + '/' + 'pdf_certificates/' + x + '.pdf')
                os.remove(full_path_with_pdf)
        except Exception as e:
            print(e)
        raise HTTPException(status_code=404, detail="Certifying batch to the blockchain failed.")
    await removeTempFiles(conf.abs_data_dir, uidArray)
    end2 = time.time()
    logger.info(end2 - start2)
    return jsonText


