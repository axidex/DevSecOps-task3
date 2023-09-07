from fastapi import FastAPI, HTTPException, Request, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials

from git import Repo
import os, requests, time
from functools import wraps

# Constants
###########
project_name    = str(os.environ["NAME_DT"]).split('/')[-2] # https://github.com/0c34/govwa https://github.com/netlify/gocommerce
project_rep     = str(os.environ["NAME_DT"]).split('/')[-1]
project_branch  = str(os.environ["BRANCH_DT"])
project_ip      = str(os.environ["IP_DT"])
apiKey          = str(os.environ["API_KEY"])
git_name        = "https://github.com/" + project_name + "/" + project_rep
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
def rateLimited(maxCalls: int, timeFrame: int):
    def decorator(func):
        calls = []

        @wraps(func)
        async def wrapper(request: Request, *args, **kwargs):
            now = time.time()
            callsInTimeFrame = [call for call in calls if call > now - timeFrame]
            if len(callsInTimeFrame) >= maxCalls:
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Rate limit exceeded")
            calls.append(now)
            return await func(request, *args, **kwargs)
        return wrapper
    return decorator

# FastAPI Security
##################
security = HTTPBasic()
fake_users_db = {
    "axidex": {
        "username": "axidex",
        "password": "333",
    }
}

def authenticate_user(credentials: HTTPBasicCredentials = Depends(security)):
    user = fake_users_db.get(credentials.username)
    if user is None or user["password"] != credentials.password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return user

# FastAPI Methods
#################
@app.get("/")
@rateLimited(maxCalls=10, timeFrame=60)
async def readRoot(request: Request, user: dict = Depends(authenticate_user)):
    return {"Documentation in": "/docs"}

@app.post("/sca/git") # 0c34 govwa
@rateLimited(maxCalls=10, timeFrame=60)
async def cloneRep(request: Request):
    Repo.clone_from(git_name, "./rep", branch=project_branch)
    return { "result": "success" }

@app.get("/sca/sbom")
@rateLimited(maxCalls=10, timeFrame=60)
async def genSbom(request: Request):
    if FExist.folderExist('/code/rep'):
        os.system('./cyclonedx-gomod app -output ./sbom.xml ./rep')
    return { "result": "success" } if FExist.folderExist('/code/rep')   else { "result": "the folder with repository does not exist"}

@app.get("/sca/dt")
@rateLimited(maxCalls=10, timeFrame=60)
async def dtSend(request: Request):
    if FExist.fileExist('/code/sbom.xml'):
        headers = {"X-Api-Key": apiKey, "accept": "application/json"}

        files = {
            'autoCreate':       (None, 'true'),
            'projectName':      (None, project_name+'/'+project_rep),
            'projectVersion':   (None, project_branch),
            'bom':              ('sbom.xml', open('/code/sbom.xml', 'rb'), 'application/xml')
        }

        response = requests.post( project_ip + '/api/v1/bom', 
                                headers=headers, 
                                files=files )
    return { "result": "success" } if FExist.fileExist('/code/sbom.xml') else { "result": "file with sbom does not exist" }