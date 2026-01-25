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

    # Format tokens as required
    formatted_tokens = []
    for token_data in tokens:
        if "token" in token_data:
            formatted_tokens.append({"token": token_data["token"]})
    
    # Encode content to base64
    content_json = json.dumps(formatted_tokens, indent=2)
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

async def fetch_token(session: aiohttp.ClientSession, uid: str, password: str, retry_count: int = 0) -> Optional[List[Dict[str, Any]]]:
    """Fetch token for given UID and password."""
    try:
        logging.info(f"Fetching token for UID: {uid}")
        async with session.get(API_BASE_URL, params={"uid": uid, "password": password}, timeout=aiohttp.ClientTimeout(total=30)) as response:
            if response.status == 200:
                data = await response.json()
                if isinstance(data, list):
                    logging.info(f"Successfully fetched token for UID: {uid}")
                    return data
                logging.warning(f"Unexpected response format for UID: {uid}")
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
    """Process credentials in batches and collect tokens."""
    tokens = []
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
                tasks.append((uid, password, task))
            
            # Gather results
            for uid, password, task in tasks:
                try:
                    result = await task
                    if result:
                        tokens.extend(result)
                    else:
                        failed_credentials.append((uid, password))
                except Exception as e:
                    logging.error(f"Task error for UID: {uid}: {e}")
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
                retry_tasks.append((uid, password, task))
            
            second_failed = []
            for uid, password, task in retry_tasks:
                try:
                    result = await task
                    if result:
                        tokens.extend(result)
                    else:
                        second_failed.append((uid, password))
                except Exception as e:
                    logging.error(f"Retry task error for UID: {uid}: {e}")
                    second_failed.append((uid, password))
            
            if second_failed:
                logging.warning(f"Still failed for {len(second_failed)} credentials after retry")
    
    logging.info(f"Completed. Total tokens generated: {len(tokens)}")
    return tokens

def validate_token_response(token_data: List[Dict[str, Any]]) -> bool:
    """Validate that token response has the expected structure."""
    if not isinstance(token_data, list):
        return False
    
    for item in token_data:
        if not isinstance(item, dict):
            return False
        if "token" not in item:
            return False
        if not isinstance(item["token"], str) or not item["token"].startswith("eyJ"):
            return False
    
    return True

def format_tokens_for_output(tokens: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Format tokens for output in required format."""
    formatted = []
    for token_data in tokens:
        if isinstance(token_data, dict) and "token" in token_data:
            formatted.append({"token": token_data["token"]})
    return formatted

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
            # Validate tokens
            if not validate_token_response(tokens):
                logging.error("Token validation failed")
                return None
            
            # Format tokens for output
            formatted_tokens = format_tokens_for_output(tokens)
            
            # Save to local file
            with open("token_bd.json", "w") as f:
                json.dump(formatted_tokens, f, indent=2)
            logging.info(f"Successfully saved {len(formatted_tokens)} tokens to token_bd.json")
            
            # Update GitHub
            try:
                config = load_github_config()
                update_github_file(config, formatted_tokens)
                logging.info("Successfully updated GitHub repository")
            except Exception as e:
                logging.error(f"Failed to update GitHub: {e}")
                return None
            
            return formatted_tokens
        
        logging.error("No tokens generated from any credentials")
        return None
    
    except FileNotFoundError:
        logging.error(f"File not found: {file_path}")
        return None
    except json.JSONDecodeError as e:
        logging.error(f"Invalid JSON in file {file_path}: {e}")
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
    logging.info(f"Total tokens generated: {len(tokens)}")
    logging.info(f"Output saved to: token_bd.json")
    logging.info("=" * 50)

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
