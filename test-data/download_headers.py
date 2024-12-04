import asyncio
import os
import time
from contextlib import asynccontextmanager
import json
import random

import httpx
from dotenv import load_dotenv


class RateLimiter:
    def __init__(self, requests_per_second: float):
        self.rate = requests_per_second
        self.tokens = requests_per_second
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()
    
    async def acquire(self):
        async with self._lock:
            now = time.monotonic()
            time_passed = now - self.last_update
            self.tokens = min(self.rate, self.tokens + time_passed * self.rate)
            self.last_update = now
            
            if self.tokens < 1:
                sleep_time = (1 - self.tokens) / self.rate
                await asyncio.sleep(sleep_time)
                self.tokens = 0
            else:
                self.tokens -= 1

    @asynccontextmanager
    async def limit(self):
        await self.acquire()
        try:
            yield
        finally:
            pass


async def download_header(height: int, bitcoin_rpc: str, rate_limiter: RateLimiter, max_retries: int = 5):
    headers = {
        "content-type": "application/json",
    }

    async def attempt_download():
        async with rate_limiter.limit():
            async with httpx.AsyncClient() as client:
                # First get block hash for the height
                payload = {
                    "jsonrpc": "2.0",
                    "method": "getblockhash",
                    "params": [height],
                    "id": 1
                }
                response = await client.post(bitcoin_rpc, json=payload, headers=headers)
                response.raise_for_status()
                block_hash = response.json()["result"]
            
                # Get block header using the hash
                payload = {
                    "jsonrpc": "2.0",
                    "method": "getblockheader",
                    "params": [block_hash, False],
                    "id": 1
                }
                response = await client.post(bitcoin_rpc, json=payload, headers=headers)
                response.raise_for_status()
                return response.json()["result"]

    for retry in range(max_retries):
        try:
            return await attempt_download()
        except Exception as e:
            if retry == max_retries - 1:  # Last retry
                raise  # Re-raise the last exception
            
            # Calculate exponential backoff with jitter
            wait_time = (2 ** retry) + random.uniform(0, 1)
            print(f"\nError downloading height {height} (attempt {retry + 1}/{max_retries}): {e}")
            print(f"Retrying in {wait_time:.2f} seconds...")
            await asyncio.sleep(wait_time)


def save_headers_to_file(headers: list[tuple[int, str]], filename: str = 'data/blocks.json', start_height: int = None, end_height: int = None) -> None:
    # Filter headers based on height range if provided
    if start_height is not None and end_height is not None:
        headers = [(height, header) for height, header in headers if start_height <= height <= end_height]
    
    for height, header in headers:
        assert header is not None
        assert len(header) == 80*2, f"Header length is {len(header)} for height {height}\nHeader: {header}"
    
    headers_dict = {height: header for height, header in headers if header is not None}
    
    os.makedirs(os.path.dirname(filename), exist_ok=True)

    with open(filename, 'w') as f:
        json.dump(headers_dict, f, indent=2)
    
    print(f"\nSaved {len(headers_dict)} headers to {filename}")


def load_existing_headers(filename: str) -> dict[int, str]:
    try:
        with open(filename, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def find_missing_heights(existing_headers: dict[int, str], start_height: int, end_height: int) -> list[int]:
    all_heights = set(range(start_height, end_height + 1))
    existing_heights = set(map(int, existing_headers.keys()))
    return sorted(list(all_heights - existing_heights))

async def download_full_block(height: int, bitcoin_rpc: str, rate_limiter: RateLimiter, max_retries: int = 5):
    headers = {
        "content-type": "application/json",
    }

    async def attempt_download():
        async with rate_limiter.limit():
            async with httpx.AsyncClient() as client:
                # First get block hash for the height
                payload = {
                    "jsonrpc": "2.0",
                    "method": "getblockhash",
                    "params": [height],
                    "id": 1
                }
                response = await client.post(bitcoin_rpc, json=payload, headers=headers)
                response.raise_for_status()
                block_hash = response.json()["result"]
            
                # Get full block using the hash
                payload = {
                    "jsonrpc": "2.0",
                    "method": "getblock",
                    "params": [block_hash, 0],  # 0 means return hex-encoded data
                    "id": 1
                }
                response = await client.post(bitcoin_rpc, json=payload, headers=headers)
                response.raise_for_status()
                return response.json()["result"]

    for retry in range(max_retries):
        try:
            return await attempt_download()
        except Exception as e:
            if retry == max_retries - 1:
                raise
            wait_time = (2 ** retry) + random.uniform(0, 1)
            print(f"\nError downloading block {height} (attempt {retry + 1}/{max_retries}): {e}")
            print(f"Retrying in {wait_time:.2f} seconds...")
            await asyncio.sleep(wait_time)

async def save_full_block(height: int, block_data: str):
    os.makedirs('data/blocks', exist_ok=True)
    filename = f'data/blocks/block_{height}.hex'
    
    with open(filename, 'w') as f:
        f.write(block_data)
    
    print(f"\nSaved block {height} to {filename}")

def load_existing_blocks(blocks_dir: str = 'data/blocks') -> set[int]:
    """Load the set of block heights that have already been downloaded"""
    try:
        existing_files = os.listdir(blocks_dir)
        return {int(f.replace('block_', '').replace('.hex', '')) 
                for f in existing_files if f.endswith('.hex')}
    except FileNotFoundError:
        return set()

async def download_headers(bitcoin_rpc: str, end_height: int, headers_per_second: int):
    # Load existing headers from both files
    headers_0_9999 = load_existing_headers('data/headers_0_9999.json')
    headers_10000_plus = load_existing_headers('data/headers_10000_800000.json')
    
    # Find missing heights for each range
    missing_0_9999 = find_missing_heights(headers_0_9999, 0, 9999)
    missing_10000_plus = find_missing_heights(headers_10000_plus, 10000, end_height)
    
    total_missing = len(missing_0_9999) + len(missing_10000_plus)
    
    if total_missing == 0:
        print("No missing headers found. All data is complete!")
        return
        
    print(f"Found {len(missing_0_9999)} missing headers in range 0-9999")
    print(f"Found {len(missing_10000_plus)} missing headers in range 10000-800000")
    print(f"Total missing headers: {total_missing}")
    
    rate_limiter = RateLimiter(headers_per_second)
    completed_blocks = 0
    start_time = time.time()
    
    async def process_height(height: int):
        nonlocal completed_blocks
        try:
            header = await download_header(height, bitcoin_rpc, rate_limiter)
            completed_blocks += 1
            
            elapsed_time = time.time() - start_time
            headers_remaining = total_missing - completed_blocks
            avg_time_per_block = elapsed_time / completed_blocks if completed_blocks > 0 else 0
            estimated_remaining = headers_remaining * avg_time_per_block
            
            print(f"\rProgress: {completed_blocks}/{total_missing} headers | "
                  f"Estimated time remaining: {estimated_remaining:.1f}s", 
                  end="", flush=True)
                  
            return height, header
        except Exception as e:
            print(f"\nError downloading height {height}: {e}")
            return height, None

    # Process missing headers in batches
    batch_size = headers_per_second * 10
    
    for heights, filename, start, end in [
        (missing_0_9999, 'data/blocks_0_9999.json', 0, 9999),
        (missing_10000_plus, 'data/blocks_10000_800000.json', 10000, end_height)
    ]:
        if not heights:
            continue
            
        print(f"\nProcessing missing headers for range {start}-{end}")
        existing_headers = load_existing_headers(filename)
        
        for batch_start_idx in range(0, len(heights), batch_size):
            batch_heights = heights[batch_start_idx:batch_start_idx + batch_size]
            tasks = [process_height(height) for height in batch_heights]
            batch_results = await asyncio.gather(*tasks)
            
            for height, header in batch_results:
                if header is not None:
                    existing_headers[str(height)] = header
            
            save_headers_to_file([(int(h), v) for h, v in existing_headers.items()], 
                               filename, start, end)

async def download_blocks(bitcoin_rpc: str, start_height: int, end_height: int, blocks_per_second: int):
    print("\nChecking full blocks...")
    existing_blocks = load_existing_blocks()
    
    target_heights = list(set(range(start_height, end_height + 1)) - existing_blocks)
    
    blocks_needed = len(target_heights)
    print(f"Need to download {blocks_needed} more blocks")
    
    rate_limiter = RateLimiter(blocks_per_second)
    
    for height in target_heights:
        try:
            print(f"\nDownloading block {height}...")
            block_data = await download_full_block(height, bitcoin_rpc, rate_limiter)
            await save_full_block(height, block_data)
        except Exception as e:
            print(f"\nError downloading full block {height}: {e}")

async def main():
    bitcoin_rpc = os.getenv("BITCOIN_RPC")
    end_header_height = 800000
    headers_per_second = 50

    start_block_height = 799_990
    end_block_height = 800_000
    blocks_per_second = 2

    await download_headers(bitcoin_rpc, end_header_height, headers_per_second)
    await download_blocks(bitcoin_rpc, start_block_height, end_block_height, blocks_per_second)

if __name__ == "__main__":
    load_dotenv()
    asyncio.run(main())