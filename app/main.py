from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel, HttpUrl

from git import Repo
import os, requests, time, json, shutil, uuid
from functools import wraps

# Constants
###########
# # https://github.com/0c34/govwa https://github.com/netlify/gocommerce
project_ip      = str(os.environ["IP_DT"])
apiKey          = str(os.environ["API_KEY"])

axidex_username = "axidex"
axidex_password = str(os.environ["PASSWORD_AUTH"])

# print(project_name, project_rep, project_branch, project_ip, apiKey, git_name)

# Path finding methods
######################
class FExist: 
    @staticmethod   
    def folderExist(path: str):
        return os.path.exists(path)
    
    @staticmethod
    def fileExist(path: str):
        return os.path.isfile(path)

# Sender to dependency track via cUrl
#####################################
# def dtSend(request: Request):
#     headers = {"X-Api-Key": apiKey, "accept": "application/json"}

#     files = {
#         'autoCreate':       (None, 'true'),
#         'projectName':      (None, project_name+'/'+project_rep),
#         'projectVersion':   (None, project_branch),
#         'bom':              ('sbom.xml', open('/code/sbom.xml', 'rb'), 'application/xml')
#     }

#     response = requests.post( project_ip + '/api/v1/bom', 
#                             headers=headers, 
#                             files=files )

# FastAPI
#########
app = FastAPI()

# CORS
######
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Разрешить доступ из любых источников (можете настроить список разрешенных источников)
    allow_credentials=True,
    allow_methods=["*"],  # Разрешить любые HTTP-методы (GET, POST, PUT, DELETE и другие)
    allow_headers=["*"],  # Разрешить любые заголовки
)

# Limiter
#########
# https://youtu.be/49oC1uHxJ-o?si=YbChXV5XsxJA75eQ
def rateLimited(maxCalls: int, timeFrame: int):
    def decorator(func):
        calls = []

        @wraps(func)
        async def wrapper(*args, **kwargs):
            now = time.time()
            callsInTimeFrame = [call for call in calls if call > now - timeFrame]
            if len(callsInTimeFrame) >= maxCalls:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
            calls.append(now)
            return await func(*args, **kwargs)
        return wrapper
    return decorator

# FastAPI Security 
##################
security = HTTPBasic()
users_db = {
    axidex_username: {
        "password": axidex_password,
    }
}
def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = users_db.get(credentials.username)
    if user is None or user["password"] != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user

# Pydantic
##########
class MyDataModel(BaseModel):
    website_url: HttpUrl 
    git_branch: str

# FastAPI Methods
#################
@app.get("/")
@rateLimited(maxCalls=10, timeFrame=60)
async def readRoot(user: dict = Depends(authenticate_user)):
    return {"Documentation in": "/docs"}

@app.post("/sca") # 0c34 govwa
@rateLimited(maxCalls=10, timeFrame=60)
async def sca(data: MyDataModel, user: dict = Depends(authenticate_user)):

    gitUrl = data.website_url
    gitBranch = data.git_branch
    if (len(gitUrl)*len(gitBranch) == 0):
        return { "result": "gitUrl and gitBranch error"}
    repPath = "/code/" + str(uuid.uuid4())

    gitName = gitUrl.split('/')[-2]
    gitRep  = gitUrl.split('/')[-1]
    Repo.clone_from(gitUrl, repPath, branch=gitBranch)
    headers = {"X-Api-Key": apiKey, "accept": "application/json"}
    if FExist.folderExist(repPath):
        os.system('./cyclonedx-gomod app -output ./sbom.xml ' + repPath)
    else:
        return { "result": "the folder with repository does not exist"}
    
    if FExist.fileExist('/code/sbom.xml'):
        files = {
            'autoCreate':       (None, 'true'),
            'projectName':      (None, gitName+'/'+gitRep),
            'projectVersion':   (None, gitBranch),
            'bom':              ('sbom.xml', open('/code/sbom.xml', 'rb'), 'application/xml')
        }

        response = requests.post( project_ip + '/api/v1/bom', 
                                headers=headers, 
                                files=files )
    else:
        return { "result": "file with sbom does not exist" }
    try:
        shutil.rmtree(repPath)
        print(f"Folder {repPath} successfully deleted.")
    except OSError as e:
        print(f"Warning with deleting {repPath}: {e}")
    uuid_resp = 'not_found'
    resp = requests.get(project_ip + '/api/v1/project', headers=headers)
    parsed = json.loads(resp.content)
    for el in parsed:
        if el['name'] == gitName+'/'+gitRep and el['version'] == gitBranch:
            uuid_resp  = el["uuid"]
    return { "result": uuid_resp }
