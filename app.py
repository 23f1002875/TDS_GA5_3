from fastapi import FastAPI
from pydantic import BaseModel
from urllib.parse import urlparse
from pathlib import Path
import os
import re
import shlex

app = FastAPI()

WORKSPACE = Path("/home/agent/workspace").resolve()
BUILD = (WORKSPACE / "build").resolve()
SECRET = Path("/home/agent/credentials.env").resolve()

ALLOWED_HOSTS = {
    "raw.githubusercontent.com",
    "objects.githubusercontent.com"
}


class Request(BaseModel):
    tool: str

    command: str | None = None

    path: str | None = None
    content: str | None = None

    method: str | None = None
    url: str | None = None


def normalize_path(path: str):
    path = os.path.expandvars(path)
    path = os.path.expanduser(path)

    if not os.path.isabs(path):
        path = os.path.join(str(WORKSPACE), path)

    return Path(path).resolve()


@app.post("/")
def guard(req: Request):

    if req.tool == "write_file":
        if req.path is None:
            return {"decision": "block", "reason": "Missing path"}

        p = normalize_path(req.path)

        try:
            p.relative_to(BUILD)
            return {"decision": "allow", "reason": "Write allowed"}
        except ValueError:
            return {"decision": "block", "reason": "Writes only allowed inside build"}

    elif req.tool == "http_request":
        if req.url is None:
            return {"decision": "block", "reason": "Missing URL"}

        host = urlparse(req.url).hostname or ""

        if host in ALLOWED_HOSTS:
            return {"decision": "allow", "reason": "Host allowed"}

        return {"decision": "block", "reason": "Host not allowed"}

    elif req.tool == "bash":
        if req.command is None:
            return {"decision": "block", "reason": "Missing command"}

        cmd = os.path.expandvars(req.command)
        cmd = cmd.replace("~", "/home/agent")

        if str(SECRET) in cmd:
            return {"decision": "block", "reason": "Secret file access denied"}

        if "../" in cmd:
            m = re.findall(r"(\S+\.\.\S*|\.\./\S+)", cmd)
            for x in m:
                try:
                    if normalize_path(x) == SECRET:
                        return {"decision": "block", "reason": "Secret file access denied"}
                except:
                    pass

        return {"decision": "allow", "reason": "Command allowed"}

    return {"decision": "block", "reason": "Unknown tool"}
