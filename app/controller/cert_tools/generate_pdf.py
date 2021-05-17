from lds_merkle_proof_2019.merkle_proof_2019 import MerkleProof2019
from zipfile import ZipFile
import pyqrcode
from typing import List, Optional
import fitz
import json
import uuid
import io
import os
from fastapi_simple_security import api_key_security
from pydantic import BaseModel, Field, Json
from fastapi.responses import FileResponse
from fastapi import Depends, APIRouter, BackgroundTasks, HTTPException

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


# the files from given directory that matches the filter
def zipfilesindir(dirName, zipFileName, filter=None):
    # create a ZipFile object
    with ZipFile(zipFileName, 'w') as zipObj:
        # Iterate over all the files in directory
        for folderName, subfolders, filenames in os.walk(dirName):
            for filename in filenames:
                removedExtension = os.path.splitext(filename)[0]
                if removedExtension in filter or filter is None:
                    # create complete filepath of file in directory
                    filePath = os.path.join(folderName, filename)
                    # Add file to zip
                    zipObj.write(filePath, os.path.basename(filePath))
        return


@router.post("/generatePDF", tags=['pdf'], dependencies=[Depends(api_key_security)])
async def generatePDF(request: List[jsonCertificate], background_tasks: BackgroundTasks):
    """
    Accepts as input the response from the createBloxbergCertificate endpoint, for example a research object JSON array. Returns as response a zip archive with PDF files that correspond to the number of cryptographic identifiers provided. PDF files are embedded with the Research Object Certification which is used for verification.
    """
    try:
        # For JSON Certificate Batch Request
        # requestJson = request.json()
        # certificateObject = json.loads(request)
        uidArray = []
        for certificate in request:
            requestJson = certificate.json()
            certificateJson = json.loads(requestJson)
            certificateJson['@context'] = certificateJson.pop('context')
            generatedID = str(uuid.uuid1())
            uidArray.append(generatedID)
            stringCert = json.dumps(certificateJson)
            bytestring = io.StringIO(stringCert)
            content = io.BytesIO(bytestring.read().encode('utf8'))
            await buildPDF(content, certificateJson, generatedID)
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail="Failed building PDF")

    try:
        tempZip = str(uuid.uuid1())
        filePathZip = "./sample_data/zipFiles/" + tempZip + ".zip"
        zipfilesindir("./sample_data/pdf_certificates", filePathZip, uidArray)
    except Exception as e:
        raise HTTPException(status_code=400, detail="Failed zipping PDF")
    resp = FileResponse(filePathZip, media_type="application/x-zip-compressed")
    resp.headers['Content-Disposition'] = 'attachment; filename=bloxbergResearchCertificates'

    file_path = str('./sample_data/pdf_certificates/')
    # Clean up after response
    background_tasks.add_task(removeTempFiles, file_path, filePathZip, uidArray)
    return resp


def removeTempFiles(file_path, filePathZip, uidArray):
    os.remove(filePathZip)
    for x in uidArray:
        full_path_with_file = str(file_path + x + '.pdf')
        print(full_path_with_file)
        os.remove(full_path_with_file)


async def buildPDF(content, certificate, generatedID):
    doc = fitz.open('./bloxbergDataCertificate.pdf')
    decodedProof = decode_proof(certificate['proof']['proofValue'])
    blockchainLink = decodedProof['anchors'][0]

    page = doc[0]
    p1 = fitz.Point(65, 330)
    p2 = fitz.Point(65, 380)
    p3 = fitz.Point(65, 430)
    p4 = fitz.Point(65, 480)
    cryptographicIdentifier = certificate['crid']
    transactionIdentifier = blockchainLink.replace('blink:eth:bloxberg:', '')
    timestamp = certificate['proof']['created']
    merkleRoot = decodedProof['merkleRoot']

    page.insertText(p1,  # bottom-left of 1st char
                    cryptographicIdentifier,  # the text (honors '\n')
                    fontname="helv",  # the default font
                    stroke_opacity=0.50,
                    fontsize=11,  # the default font size
                    rotate=0,  # also available: 90, 180, 270
                    )
    page.insertText(p2,  # bottom-left of 1st char
                    transactionIdentifier,  # the text (honors '\n')
                    fontname="helv",  # the default font
                    stroke_opacity=0.50,
                    fontsize=11,  # the default font size
                    rotate=0,  # also available: 90, 180, 270
                    )
    page.insertText(p3,  # bottom-left of 1st char
                    timestamp,  # the text (honors '\n')
                    fontname="helv",  # the default font
                    stroke_opacity=0.50,
                    fontsize=11,  # the default font size
                    rotate=0,  # also available: 90, 180, 270
                    )
    page.insertText(p4,  # bottom-left of 1st char
                    merkleRoot,  # the text (honors '\n')
                    fontname="helv",  # the default font
                    stroke_opacity=0.50,
                    fontsize=11,  # the default font size
                    rotate=0,  # also available: 90, 180, 270
                    )

    # QRCode Generation
    url = pyqrcode.create('https://certify.bloxberg.org/verify', error='L', version=27)
    buffer = io.BytesIO()
    url.png(buffer)

    # QR code embedding
    rect = fitz.Rect(575, 298, 775, 498)  # where we want to put the image
    pix = fitz.Pixmap(buffer.getvalue())  # any supported image file
    page.insertImage(rect, pixmap=pix, overlay=True)  # insert image
    # TODO add .json file ending
    doc.embeddedFileAdd("bloxbergJSONCertificate", content)
    doc.save('./sample_data/pdf_certificates/' + generatedID + '.pdf', garbage=4, deflate=True)


def decode_proof(proofEncoded):
    try:
        mp2019 = MerkleProof2019()
        check_decoded = mp2019.decode(proofEncoded)
    except Exception as e:
        print(e)
        raise HTTPException(status_code=400, detail="Invalid Proof Value, could not decode")
    return check_decoded
