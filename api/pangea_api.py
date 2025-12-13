import os
import sys
import time
import json
from typing import Literal
import requests
import getpass
import urllib3
from requests.models import Response
from urllib.parse import urljoin
from utils.colors import DARK_RED, DARK_YELLOW, DARK_BLUE, DARK_GREEN, RED, RESET
from defaults import defaults
from dotenv import load_dotenv

# Disable urllib3 SSL warnings for corporate environments (Zscaler, etc.)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

load_dotenv(override=True)

ai_guard_token = os.getenv(defaults.ai_guard_token)
assert ai_guard_token, f"{defaults.ai_guard_token} environment variable not set"
base_url = os.getenv(defaults.pangea_base_url)
assert base_url, f"{defaults.pangea_base_url} environment variable not set"

connection_timeout = defaults.connection_timeout
read_timeout = defaults.read_timeout

# Default AIDR metadata
DEFAULT_AIDR_METADATA = {
    "event_type": "input",
    "app_id": "AIG-lab",
    # "actor_id": "test tool",
    "llm_provider": "test",
    "model": "GPT-6-super",
    "model_version": "6s",
    "source_ip": "74.244.51.54",
    "extra_info": {
        "actor_name": getpass.getuser(),  # Gets current username
        "app_name": os.path.splitext(os.path.basename(sys.argv[0]))[0] if sys.argv else "aiguard_lab.py"
    }
}


def create_error_response(status_code, message):
    """Create a mock error response."""
    response = Response()
    response.status_code = status_code
    error_content = {"status": status_code, "message": message}
    response._content = json.dumps(error_content).encode("utf-8")
    return response


def merge_aidr_metadata(data, aidr_config=None):
    """
    Merge AIDR metadata into the request data.

    Args:
        data: The base request data
        aidr_config: Optional dictionary to override default AIDR metadata

    Returns:
        Updated data dictionary with AIDR metadata
    """
    # Start with default metadata
    metadata = DEFAULT_AIDR_METADATA.copy()

    # Deep copy extra_info to avoid modifying the default
    metadata["extra_info"] = DEFAULT_AIDR_METADATA["extra_info"].copy()

    # Override with custom config if provided
    if aidr_config:
        for key, value in aidr_config.items():
            if key == "extra_info" and isinstance(value, dict):
                # Merge extra_info specifically
                metadata["extra_info"].update(value)
            else:
                metadata[key] = value

    # Merge metadata into data (don't override existing keys in data)
    for key, value in metadata.items():
        if key not in data:
            data[key] = value

    return data


def pangea_post_api(service: Literal["aiguard", "aidr"], endpoint: str, data, skip_cache=False, token=ai_guard_token, base_url=base_url,
                    aidr_config=None):
    """
    Post to Pangea API with optional AIDR metadata injection.

    Args:
        service: Service name ('aiguard' or 'aidr')
        endpoint: API endpoint
        data: Request payload
        skip_cache: Whether to skip cache
        token: API token
        base_url: Base URL for API
        aidr_config: Optional AIDR metadata overrides (only used if service=='aidr')
    """
    try:
        # Add AIDR metadata if using AIDR service
        if service == "aidr":
            data = merge_aidr_metadata(data, aidr_config)

        url = urljoin(base_url, endpoint)
        headers = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json"
        }
        if skip_cache:
            headers["x-pangea-skipcache"] = "true"

        response = requests.post(url, headers=headers, json=data, timeout=(connection_timeout, read_timeout))
        if response is None:
            return create_error_response(500, "Internal server error: failed to fetch data")
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_get_api(endpoint: str, token: str = ai_guard_token, base_url: str = base_url):
    """GET request to Pangea API (used for polling)."""
    try:
        url = urljoin(base_url, endpoint)
        headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
        response = requests.get(url, headers=headers, timeout=(connection_timeout, read_timeout))
        return response
    except requests.exceptions.Timeout:
        return create_error_response(408, "Request Timeout")
    except requests.exceptions.RequestException as e:
        return create_error_response(400, f"Bad Request: {e}")


def pangea_request(request_id, token=ai_guard_token, base_url=base_url, service="aidr"):
    """Poll a specific request by ID."""
    if service == "aidr":
        endpoint = f"{defaults.aidr_guard_poll_request_endpoint}/{request_id}"
    else:
        endpoint = f"/request/{request_id}"
    return pangea_get_api(endpoint, token=token, base_url=base_url)


def poll_request(request_id, max_attempts=12, verbose=False, token=ai_guard_token, base_url=base_url, service="aidr"):
    """
    Poll status until 'Success' or non-202 result, or max attempts reached.
    """
    status_code = "Accepted"
    response = None
    counter = 1
    if verbose:
        print(f"\nPolling for response using URL: {base_url}/request/{request_id}")
    while status_code == "Accepted":
        response = pangea_request(request_id, token=token, base_url=base_url, service=service)
        if response is None:
            if verbose:
                print(f"\n{DARK_YELLOW}poll_request failed with no response.{RESET}")
            break
        status_code = response.json()["status"]
        if verbose:
            print(f" {DARK_BLUE}{counter}{RESET} : Polling status code is {status_code} ...", end="\r")
        if status_code == "Success":
            if verbose:
                print(f"\n{DARK_GREEN}Success{RESET} for request {request_id}:")
            break
        elif status_code != "Accepted":
            if verbose:
                print(f"\n{DARK_RED}Error{RESET} getting status: {status_code}")
                print("Full Response:")
                print(json.dumps(response.json(), indent=4))
            break

        if counter == max_attempts:
            if verbose:
                print(f"\n{RED}Max attempts reached. Exiting polling loop.{RESET}")
            break
        time.sleep(5)
        counter += 1
    return status_code, response
