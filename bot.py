import asyncio
import json
import aiohttp
import logging
import os
import base64
import requests
from dataclasses import dataclass
from typing import List, Tuple, Optional, Dict, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# GitHub Config
@dataclass
class GitHubConfig:
    token: str
    owner: str
    repo: str
    file_path: str

def load_github_config() -> GitHubConfig:
    """Load GitHub configuration from environment variables."""
    token = os.getenv("GITHUB_TOKEN")
    if not token:
        logging.error("GITHUB_TOKEN is not set in environment variables")
        raise ValueError("GITHUB_TOKEN environment variable is not set")
    logging.info("GITHUB_TOKEN successfully loaded")
    return GitHubConfig(
        token=token,
        owner=os.getenv("GITHUB_OWNER", "Scromnyi4"),
        repo=os.getenv("GITHUB_REPO", "Likes-Application"),
        file_path=os.getenv("GITHUB_FILE_PATH", "token_bd.json")
    )

def update_github_file(config: GitHubConfig, tokens: List[Dict[str, Any]]) -> None:
    """Update token_bd.json file on GitHub."""
    headers = {
        "Authorization": f"token {config.token}",
        "Accept": "application/vnd.github.v3+json",
        "Content-Type": "application/json"
    }
    base_url = f"https://api.github.com/repos/{config.owner}/{config.repo}/contents/{config.file_path}"
    
    # Get current file SHA
    try:
        logging.info(f"Fetching current SHA for {config.file_path}")
        response = requests.get(base_url, headers=headers)
        response.raise_for_status()
        current_file = response.json()
        sha = current_file.get("sha")
        if not sha:
            logging.error("SHA not found in GitHub response")
            raise ValueError("SHA not found in GitHub response")
    except requests.RequestException as e:
        logging.error(f"Failed to fetch current file SHA: {e}")
        raise

    # Encode content to base64
    content_json = json.dumps(tokens, indent=2)
    encoded_content = base64.b64encode(content_json.encode()).decode()
    
    # Prepare payload
    payload = {
        "message": "Update token_bd.json with new tokens",
        "content": encoded_content,
        "sha": sha,
        "branch": "main"
    }
    
    # Update file
    try:
        logging.info(f"Uploading updated {config.file_path} to GitHub")
        response = requests.put(base_url, headers=headers, json=payload)
        response.raise_for_status()
        logging.info("Successfully updated token_bd.json on GitHub")
    except requests.RequestException as e:
        logging.error(f"Failed to update file on GitHub: {e}")
        raise

# Token Generation
API_BASE_URL = "http://203.18.158.202:6969/jwt"
BATCH_SIZE = 35
MAX_RETRIES = 3

async def fetch_token(session: aiohttp.ClientSession, uid: str, password: str, retry_count: int = 0) -> Optional[Dict[str, Any]]:
    """Fetch token for given UID and password. Return token dict or None."""
    try:
        logging.info(f"Fetching token for UID: {uid}")
        async with session.get(API_BASE_URL, params={"uid": uid, "password": password}, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 200:
                data = await response.json()
                logging.info(f"Successfully fetched token for UID: {uid}")
                # Check if response is a list and has valid token
                if isinstance(data, list) and len(data) > 0:
                    first_item = data[0]
                    if isinstance(first_item, dict) and "token" in first_item:
                        token_value = first_item["token"]
                        # Validate token format - starts with eyJ (JWT header)
                        if isinstance(token_value, str) and token_value.startswith("eyJ"):
                            return {"token": token_value}
                        else:
                            logging.warning(f"Invalid token format for UID: {uid}")
                            return None
                logging.warning(f"Invalid response format for UID: {uid}")
                return None
            elif response.status == 500:
                logging.error(f"Server error for UID: {uid}. Status: {response.status}")
                return None
            else:
                logging.warning(f"Failed to fetch token for UID: {uid}. Status: {response.status}")
                return None
    except asyncio.TimeoutError:
        logging.warning(f"Timeout for UID: {uid}")
    except aiohttp.ClientError as e:
        logging.warning(f"Network error for UID: {uid}: {e}")
    except Exception as e:
        logging.error(f"Unexpected error for UID: {uid}: {e}")
    
    # Retry logic
    if retry_count < MAX_RETRIES:
        wait_time = 2 ** retry_count  # Exponential backoff
        logging.info(f"Retrying for UID: {uid} in {wait_time} seconds (attempt {retry_count + 1}/{MAX_RETRIES})")
        await asyncio.sleep(wait_time)
        return await fetch_token(session, uid, password, retry_count + 1)
    
    logging.error(f"Failed to fetch token for UID: {uid} after {MAX_RETRIES} attempts")
    return None

async def process_credentials_in_batches(credentials: List[Tuple[str, str]]) -> List[Dict[str, Any]]:
    """Process credentials in batches and collect only valid tokens."""
    all_tokens = []
    failed_credentials = []
    total_batches = (len(credentials) + BATCH_SIZE - 1) // BATCH_SIZE
    
    logging.info(f"Starting to process {len(credentials)} credentials in {total_batches} batches")
    
    connector = aiohttp.TCPConnector(limit=50)  # Limit concurrent connections
    async with aiohttp.ClientSession(connector=connector) as session:
        for batch_index in range(total_batches):
            start_index = batch_index * BATCH_SIZE
            end_index = min(start_index + BATCH_SIZE, len(credentials))
            current_batch = credentials[start_index:end_index]
            
            logging.info(f"Processing batch {batch_index + 1}/{total_batches} with {len(current_batch)} credentials")
            
            tasks = []
            for uid, password in current_batch:
                task = fetch_token(session, uid, password)
                tasks.append(task)
            
            # Gather results
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            for idx, result in enumerate(results):
                uid, password = current_batch[idx]
                if isinstance(result, Exception):
                    logging.error(f"Exception for UID {uid}: {result}")
                    failed_credentials.append((uid, password))
                elif result is not None:
                    all_tokens.append(result)
                else:
                    failed_credentials.append((uid, password))
            
            # Small delay between batches to avoid overwhelming the server
            if batch_index < total_batches - 1:
                await asyncio.sleep(1)
        
        # Retry failed credentials
        if failed_credentials:
            logging.info(f"Retrying {len(failed_credentials)} failed credentials")
            retry_tasks = []
            for uid, password in failed_credentials:
                task = fetch_token(session, uid, password)
                retry_tasks.append(task)
            
            retry_results = await asyncio.gather(*retry_tasks, return_exceptions=True)
            
            for idx, result in enumerate(retry_results):
                uid, password = failed_credentials[idx]
                if isinstance(result, Exception):
                    logging.error(f"Retry exception for UID {uid}: {result}")
                elif result is not None:
                    all_tokens.append(result)
    
    # Filter out any tokens that might have "N/A" value
    valid_tokens = []
    for token_dict in all_tokens:
        if (isinstance(token_dict, dict) and 
            "token" in token_dict and 
            isinstance(token_dict["token"], str) and 
            token_dict["token"].startswith("eyJ") and
            token_dict["token"] != "N/A"):
            valid_tokens.append(token_dict)
        else:
            logging.warning(f"Filtered out invalid token: {token_dict}")
    
    logging.info(f"Completed. Total valid tokens generated: {len(valid_tokens)}")
    return valid_tokens

async def process_file(filename: str) -> Optional[List[Dict[str, Any]]]:
    """Process input file and generate tokens."""
    file_path = f"{filename}.json"
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return None

    logging.info(f"Processing file: {file_path}")
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
        
        credentials = []
        for line_num, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) == 2:
                uid, password = parts
                credentials.append((uid, password))
            else:
                logging.warning(f"Invalid format on line {line_num}: {line}")
        
        if not credentials:
            logging.error("No valid credentials found")
            return None
        
        logging.info(f"Found {len(credentials)} valid credentials")
        
        tokens = await process_credentials_in_batches(credentials)
        
        if tokens:
            # Debug: show first token format
            if tokens:
                logging.info(f"First token example: {tokens[0]}")
            
            # Save to local file
            with open("token_bd.json", "w") as f:
                json.dump(tokens, f, indent=2)
            logging.info(f"Successfully saved {len(tokens)} tokens to token_bd.json")
            
            # Update GitHub
            try:
                config = load_github_config()
                update_github_file(config, tokens)
                logging.info("Successfully updated GitHub repository")
            except Exception as e:
                logging.error(f"Failed to update GitHub: {e}")
                return None
            
            return tokens
        
        logging.error("No valid tokens generated from any credentials")
        return None
    
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except Exception as e:
        logging.error(f"Error processing file: {e}")
        return None

async def main(filename: str) -> None:
    """Main function to process tokens and update GitHub."""
    logging.info(f"Starting token generation process for {filename}.json")
    
    # Validate input file exists
    file_path = f"{filename}.json"
    if not os.path.exists(file_path):
        logging.error(f"Input file {file_path} does not exist")
        raise SystemExit(1)
    
    # Process file
    tokens = await process_file(filename)
    if not tokens:
        logging.error("Token generation failed")
        raise SystemExit(1)
    
    # Summary
    logging.info("=" * 50)
    logging.info("TOKEN GENERATION SUMMARY")
    logging.info(f"Total valid tokens generated: {len(tokens)}")
    logging.info(f"Output saved to: token_bd.json")
    logging.info(f"First few tokens: {tokens[:3] if len(tokens) > 3 else tokens}")
    logging.info("=" * 50)
    
    # Verify no "N/A" values
    for idx, token_dict in enumerate(tokens):
        if token_dict.get("token") == "N/A":
            logging.error(f"Found N/A token at index {idx}: {token_dict}")
            raise SystemExit(1)
    
    logging.info("✓ All tokens are valid (no N/A values)")

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        logging.error("Usage: python script.py <filename>")
        logging.error("Example: python script.py credentials")
        raise SystemExit(1)
    
    filename = sys.argv[1]
    
    try:
        asyncio.run(main(filename))
    except KeyboardInterrupt:
        logging.info("Process interrupted by user")
        raise SystemExit(0)
    except Exception as e:
        logging.error(f"Unexpected error: {e}")
        raise SystemExit(1)
