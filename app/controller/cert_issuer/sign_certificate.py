from typing import List, Optional
from functools import lru_cache
from fastapi import Depends, FastAPI, Request, HTTPException, status, BackgroundTasks
from pydantic import BaseModel
import json
import os
import cProfile
import ipfshttpclient
import uuid
from fastapi.middleware.cors import CORSMiddleware
import fitz
import logging
from fastapi.logger import logger
import cert_issuer.config
from cert_issuer.blockchain_handlers import ethereum_sc
import cert_issuer.issue_certificates
from fastapi import APIRouter

router = APIRouter()
config = None

gunicorn_logger = logging.getLogger('gunicorn.error')
logger.handlers = gunicorn_logger.handlers
if __name__ != "main":
    logger.setLevel(gunicorn_logger.level)
else:
    logger.setLevel(logging.DEBUG)

logging.basicConfig(format="%(pathname)s %(lineno)d %(asctime)s %(message)s", datefmt="%m/%d/%Y %I:%M:%S %p")
# logger = logging.getLogger(__name__)


class createToken(BaseModel):
    recipientPublickey: str
    unSignedCerts: List[str]
    enableIPFS: bool

    # Used only for Testing API, not for entire workflow.
    class Config:
        schema_extra = {
            "example": {
                "recipientPublickey": "0x69575606E8b8F0cAaA5A3BD1fc5D032024Bb85AF",
                "unSignedCerts": ["45c5caba-378b-49eb-bf24-b0056d300f22", "150ed963-dfad-46ee-b242-dfa2eff98671"],
                "enableIPFS": True
            }
        }


def get_config():
    global config
    if config == None:
        config = cert_issuer.config.get_config()
    return config


async def issue_batch_to_blockchain(config, certificate_batch_handler, transaction_handler, recipientPublicKey,
                                    tokenURI, uidArray):
    (tx_id, token_id) = cert_issuer.issue_certificates.issue(config, certificate_batch_handler, transaction_handler,
                                                             recipientPublicKey, uidArray, tokenURI)
    return tx_id, token_id

def removeTempFiles(absolute_directory, uidArray):
    try:
        for x in uidArray:
            full_path_with_file = str(absolute_directory + '/' + x + '.json')
            os.remove(full_path_with_file)
    except:
        logger.info("Error while deleting file ", full_path_with_file)


# Full Workflow - Called from cert_tools_api
@router.post("/issueBloxbergCertificate")
async def issue(createToken: createToken, request: Request, background_tasks: BackgroundTasks):
    config = get_config()
    certificate_batch_handler, transaction_handler, connector = \
        ethereum_sc.instantiate_blockchain_handlers(config)

        # file that stores the ipfs hashes of the certificates in the batch
    if createToken.enableIPFS is True:
        try:
            ipfsHash = add_file_ipfs("./data/meta_certificates/.placeholder")
            generateKey = True
            ipnsHash, generatedKey = add_file_ipns(ipfsHash, generateKey)
            tokenURI = 'http://ipfs.io/ipns/' + ipnsHash['Name']
        except Exception as e:
            logger.info(e)
            raise HTTPException(status_code=400, detail=f"Couldn't add file to IPFS")
    else:
        tokenURI = 'https://bloxberg.org'
    try:
        #pr = cProfile.Profile()
        #pr.enable()
        tx_id, token_id = await issue_batch_to_blockchain(config, certificate_batch_handler, transaction_handler,
                                          createToken.recipientPublickey, tokenURI, createToken.unSignedCerts)
        #pr.disable()
        #pr.print_stats(sort="tottime")
        #pr.dump_stats('profileAPI.pstat')
    except Exception as e:
        logger.exception(e)
        raise HTTPException(status_code=400, detail=f"Failed to issue certificate batch to the blockchain")

    # Retrieve file path of certified transaction
    blockchain_file_path = config.blockchain_certificates_dir
    json_data = []

    for fileID in certificate_batch_handler.certificates_to_issue:
        full_path_with_file = str(blockchain_file_path + '/' + fileID + '.json')
        if createToken.enableIPFS is True:
            ipfsHash = add_file_ipfs(full_path_with_file)

        with open(full_path_with_file) as f:
            d = json.load(f)
        # Save JSON Certificate to IPFS
        if createToken.enableIPFS is True:
            temp = ipfs_object["file_certifications"]
            y = {"id": fileID, "ipfsHash": 'http://ipfs.io/ipfs/' + ipfsHash, "crid": d["crid"]}
            temp.append(y)

        json_data.append(d)

    # write ipfs object into the ipfs batch file
    try:
        if createToken.enableIPFS is True:
            with open(ipfs_batch_file, 'w') as file:
                json.dump(ipfs_object, file)
            ipfs_batch_hash = add_file_ipfs(ipfs_batch_file)
            generateKey = False
            ipnsHash = add_file_ipns(ipfs_batch_hash, generateKey, newKey=generatedKey)
            print("Updated IPNS Hash")
            print(ipnsHash)
            # update_ipfs_link(token_id, 'http://ipfs.io/ipfs/' + ipfs_batch_hash)
    except:
        return "Updating IPNS link failed,"


    python_environment = os.getenv("app")
    # if python_environment == "production":
    background_tasks.add_task(removeTempFiles, config.blockchain_certificates_dir, createToken.unSignedCerts)

    #     full_path_with_file = str(config.blockchain_certificates_dir + '/')
    #     for file_name in os.listdir(full_path_with_file):
    #         if file_name.endswith('.json'):
    #             print(full_path_with_file + file_name)
    #             os.remove(full_path_with_file + file_name)

    return json_data