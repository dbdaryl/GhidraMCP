from mcp.server.fastmcp import FastMCP
import requests
import json
import asyncio
import hmac
import hashlib
from typing import Dict, List, Union, Optional
from dataclasses import dataclass
from functools import wraps

# Configuration
GHIDRA_SERVER_URL = "http://127.0.0.1:8080"  # Explicitly using localhost
API_KEY = "your-secret-key-here"  # Should be set via environment variable in production
MAX_RETRIES = 3
TIMEOUT_SECONDS = 5

# Custom Exceptions
class ValidationError(Exception):
    pass

class AuthenticationError(Exception):
    pass

# Response Models
@dataclass
class ResponseModel:
    success: bool
    data: Optional[Union[List[str], str, Dict]]
    error: Optional[str] = None
    job_id: Optional[str] = None

    def to_dict(self) -> Dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}

# Job Queue
class JobQueue:
    def __init__(self):
        self.jobs: Dict[str, asyncio.Task] = {}
        self.results: Dict[str, ResponseModel] = {}

    async def add_job(self, job_id: str, coroutine) -> None:
        task = asyncio.create_task(coroutine)
        self.jobs[job_id] = task
        try:
            result = await task
            self.results[job_id] = ResponseModel(success=True, data=result)
        except Exception as e:
            self.results[job_id] = ResponseModel(success=False, error=str(e))
        finally:
            del self.jobs[job_id]

job_queue = JobQueue()

# Utility Functions
def validate_api_key(provided_key: str) -> bool:
    """Validate API key using constant-time comparison."""
    return hmac.compare_digest(provided_key, API_KEY)

def sanitize_error(error: Exception) -> str:
    """Sanitize error messages to avoid leaking sensitive information."""
    return f"Error: {error.__class__.__name__}"

def validate_input(**validators):
    """Decorator for input validation."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            for param_name, validator in validators.items():
                if param_name in kwargs:
                    value = kwargs[param_name]
                    if not validator(value):
                        raise ValidationError(f"Invalid {param_name}")
            return func(*args, **kwargs)
        return wrapper
    return decorator

# Request Handlers
def safe_get(endpoint: str, params: Optional[Dict] = None) -> ResponseModel:
    """
    Perform a GET request with improved error handling and response formatting.
    """
    if params is None:
        params = {}

    try:
        url = f"{GHIDRA_SERVER_URL}/{endpoint}"
        response = requests.get(
            url,
            params=params,
            timeout=TIMEOUT_SECONDS,
            headers={"X-API-Key": API_KEY}
        )
        response.raise_for_status()
        return ResponseModel(
            success=True,
            data=response.text.splitlines()
        )
    except requests.exceptions.RequestException as e:
        return ResponseModel(
            success=False,
            error=sanitize_error(e)
        )

def safe_post(endpoint: str, data: Union[Dict, str]) -> ResponseModel:
    """
    Perform a POST request with improved error handling and response formatting.
    """
    try:
        url = f"{GHIDRA_SERVER_URL}/{endpoint}"
        headers = {"X-API-Key": API_KEY}

        if isinstance(data, dict):
            response = requests.post(
                url,
                json=data,  # Use json parameter for automatic serialization
                timeout=TIMEOUT_SECONDS,
                headers=headers
            )
        else:
            response = requests.post(
                url,
                data=data.encode("utf-8"),
                timeout=TIMEOUT_SECONDS,
                headers=headers
            )

        response.raise_for_status()
        return ResponseModel(
            success=True,
            data=response.text.strip()
        )
    except requests.exceptions.RequestException as e:
        return ResponseModel(
            success=False,
            error=sanitize_error(e)
        )

# MCP Server Configuration
mcp = FastMCP(
    "ghidra-mcp",
    host="127.0.0.1"  # Explicitly bind to localhost
)

# Input Validators
def validate_pagination(value: int) -> bool:
    return isinstance(value, int) and 0 <= value <= 1000

def validate_name(value: str) -> bool:
    return isinstance(value, str) and 1 <= len(value) <= 256

def validate_address(value: str) -> bool:
    return isinstance(value, str) and value.startswith("0x")

# MCP Tools
@mcp.tool()
@validate_input(offset=validate_pagination, limit=validate_pagination)
def list_methods(offset: int = 0, limit: int = 100) -> Dict:
    """List all function names in the program with pagination."""
    response = safe_get("methods", {"offset": offset, "limit": limit})
    return response.to_dict()

@mcp.tool()
@validate_input(offset=validate_pagination, limit=validate_pagination)
def list_classes(offset: int = 0, limit: int = 100) -> Dict:
    """List all namespace/class names in the program with pagination."""
    response = safe_get("classes", {"offset": offset, "limit": limit})
    return response.to_dict()

@mcp.tool()
@validate_input(name=validate_name)
async def decompile_function(name: str) -> Dict:
    """Decompile a specific function by name and return the decompiled C code."""
    import uuid
    job_id = str(uuid.uuid4())

    async def decompile_job():
        response = safe_post("decompile", name)
        return response.to_dict()

    await job_queue.add_job(job_id, decompile_job())
    return ResponseModel(
        success=True,
        job_id=job_id,
        data="Decompilation job started"
    ).to_dict()

@mcp.tool()
@validate_input(old_name=validate_name, new_name=validate_name)
def rename_function(old_name: str, new_name: str) -> Dict:
    """Rename a function by its current name to a new user-defined name."""
    response = safe_post("renameFunction", {
        "oldName": old_name,
        "newName": new_name
    })
    return response.to_dict()

@mcp.tool()
@validate_input(address=validate_address, new_name=validate_name)
def rename_data(address: str, new_name: str) -> Dict:
    """Rename a data label at the specified address."""
    response = safe_post("renameData", {
        "address": address,
        "newName": new_name
    })
    return response.to_dict()

@mcp.tool()
@validate_input(offset=validate_pagination, limit=validate_pagination)
def list_segments(offset: int = 0, limit: int = 100) -> Dict:
    """List all memory segments in the program with pagination."""
    response = safe_get("segments", {"offset": offset, "limit": limit})
    return response.to_dict()

@mcp.tool()
@validate_input(offset=validate_pagination, limit=validate_pagination)
def list_imports(offset: int = 0, limit: int = 100) -> Dict:
    """List imported symbols in the program with pagination."""
    response = safe_get("imports", {"offset": offset, "limit": limit})
    return response.to_dict()

@mcp.tool()
@validate_input(offset=validate_pagination, limit=validate_pagination)
def list_exports(offset: int = 0, limit: int = 100) -> Dict:
    """List exported functions/symbols with pagination."""
    response = safe_get("exports", {"offset": offset, "limit": limit})
    return response.to_dict()

@mcp.tool()
@validate_input(offset=validate_pagination, limit=validate_pagination)
def list_namespaces(offset: int = 0, limit: int = 100) -> Dict:
    """List all non-global namespaces in the program with pagination."""
    response = safe_get("namespaces", {"offset": offset, "limit": limit})
    return response.to_dict()

@mcp.tool()
@validate_input(offset=validate_pagination, limit=validate_pagination)
def list_data_items(offset: int = 0, limit: int = 100) -> Dict:
    """List defined data labels and their values with pagination."""
    response = safe_get("data", {"offset": offset, "limit": limit})
    return response.to_dict()

@mcp.tool()
@validate_input(query=validate_name, offset=validate_pagination, limit=validate_pagination)
def search_functions_by_name(query: str, offset: int = 0, limit: int = 100) -> Dict:
    """Search for functions whose name contains the given substring."""
    if not query:
        return ResponseModel(
            success=False,
            error="Query string is required"
        ).to_dict()

    response = safe_get("searchFunctions", {
        "query": query,
        "offset": offset,
        "limit": limit
    })
    return response.to_dict()

@mcp.tool()
def get_job_status(job_id: str) -> Dict:
    """Get the status of an async job."""
    if job_id in job_queue.jobs:
        return ResponseModel(
            success=True,
            data="Job in progress"
        ).to_dict()
    elif job_id in job_queue.results:
        result = job_queue.results[job_id]
        del job_queue.results[job_id]  # Clean up after retrieving
        return result.to_dict()
    else:
        return ResponseModel(
            success=False,
            error="Job not found"
        ).to_dict()

if __name__ == "__main__":
    mcp.run()
