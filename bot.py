import asyncio
import json
import aiohttp
import logging
import os
import base64
import requests
from dataclasses import dataclass
from typing import List, Tuple, Optional

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

def update_github_file(config: GitHubConfig, tokens: List[dict]) -> None:
    """Update token_eu.json file on GitHub."""
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
        logging.info("Successfully updated token_eu.json on GitHub")
    except requests.RequestException as e:
        logging.error(f"Failed to update file on GitHub: {e}")
        raise

# Token Generation
API_URL = "https://jwtapi-nu.vercel.app/oauth/guest/token/grant?uid={}&password={}"
BATCH_SIZE = 1500

async def fetch_token(session: aiohttp.ClientSession, uid: str, password: str, retry_count: int = 0) -> Optional[List[str]]:
    """Fetch token for given UID and password."""
    try:
        logging.info(f"Fetching token for UID: {uid}")
        async with session.get(API_URL.format(uid, password)) as response:
            if response.status == 200:
                data = await response.json()
                if isinstance(data, list):
                    return [item.get("token") for item in data if "token" in item]
                logging.error(f"Unexpected response format for UID: {uid}")
                return None
            logging.error(f"Failed to fetch token for UID: {uid}. Status: {response.status}")
            return None
    except Exception as e:
        if retry_count < 2:
            logging.warning(f"Retrying for UID: {uid}. Attempt {retry_count + 1}")
            return await fetch_token(session, uid, password, retry_count + 1)
        logging.error(f"Error fetching token for UID: {uid}: {e}")
        return None

async def process_credentials_in_batches(credentials: List[Tuple[str, str]]) -> List[dict]:
    """Process credentials in batches and collect tokens."""
    tokens = []
    failed_credentials = []
    total_batches = (len(credentials) + BATCH_SIZE - 1) // BATCH_SIZE
    
    async with aiohttp.ClientSession() as session:
        for batch_index in range(total_batches):
            start_index = batch_index * BATCH_SIZE
            end_index = min(start_index + BATCH_SIZE, len(credentials))
            current_batch = credentials[start_index:end_index]
            
            logging.info(f"Processing batch {batch_index + 1}/{total_batches}")
            tasks = [fetch_token(session, uid, password) for uid, password in current_batch]
            results = await asyncio.gather(*tasks)
            
            for idx, result in enumerate(results):
                if result:
                    tokens.extend({"token": token} for token in result)
                else:
                    failed_credentials.append(current_batch[idx])
        
        # Retry failed credentials
        if failed_credentials:
            logging.info(f"Retrying {len(failed_credentials)} failed credentials")
            retry_tasks = [fetch_token(session, uid, password) for uid, password in failed_credentials]
            retry_results = await asyncio.gather(*retry_tasks)
            
            for idx, result in enumerate(retry_results):
                if result:
                    tokens.extend({"token": token} for token in result)
        
        logging.info(f"Completed. Total tokens generated: {len(tokens)}")
    return tokens

async def process_file(filename: str) -> Optional[List[dict]]:
    """Process input file and generate tokens."""
    file_path = f"{filename}.json"
    if not os.path.exists(file_path):
        logging.error(f"File not found: {file_path}")
        return None

    logging.info(f"Processing file: {file_path}")
    try:
        with open(file_path, "r") as file:
            lines = file.readlines()
        
        credentials = [line.strip().split() for line in lines if len(line.strip().split()) == 2]
        if not credentials:
            logging.error("No valid credentials found")
            return None
        
        tokens = await process_credentials_in_batches(credentials)
        
        if tokens:
            with open("token_bd.json", "w") as f:
                json.dump(tokens, f, indent=4)
            logging.info("Tokens saved to token_bd.json")
            
            # Update GitHub
            try:
                config = load_github_config()
                update_github_file(config, tokens)
            except Exception as e:
                logging.error(f"Failed to update GitHub: {e}")
                return None
            
            return tokens
        logging.error("No tokens generated")
        return None
    except Exception as e:
        logging.error(f"Error processing file: {e}")
        return None

async def main(filename: str) -> None:
    """Main function to process tokens and update GitHub."""
    tokens = await process_file(filename)
    if not tokens:
        logging.error("Token generation failed")
        raise SystemExit(1)

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        logging.error("Filename not provided")
        raise SystemExit(1)
    filename = sys.argv[1]
    asyncio.run(main(filename))
