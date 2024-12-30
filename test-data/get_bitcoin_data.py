import asyncio
import os
import time
from contextlib import asynccontextmanager
import json
import random

import httpx
from dotenv import load_dotenv

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

async def download_headers_for_range(bitcoin_rpc: str, headers_filename: str, missing_heights: list[int], 
                                   rate_limiter: RateLimiter, total_missing: int, start_height: int, 
                                   end_height: int, completed_blocks: int = 0, start_time: float = None):
    """Helper function to download headers for a specific range of blocks"""
    if not missing_heights:
        return
        
    start_time = start_time or time.time()
    existing_headers = load_existing_headers(headers_filename)
    batch_size = int(rate_limiter.rate) * 10
    
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

    for batch_start_idx in range(0, len(missing_heights), batch_size):
        batch_heights = missing_heights[batch_start_idx:batch_start_idx + batch_size]
        tasks = [process_height(height) for height in batch_heights]
        batch_results = await asyncio.gather(*tasks)
        
        for height, header in batch_results:
            if header is not None:
                existing_headers[str(height)] = header
        
        save_headers_to_file([(int(h), v) for h, v in existing_headers.items()], 
                           headers_filename, start_height, end_height)

async def download_bitcoin_canon_headers(bitcoin_rpc: str, end_height: int, headers_per_second: int):
    """Download Bitcoin canonical chain headers in two chunks (0-9999 and 10000-end_height)"""
    first_chunk_headers_filename = 'data/headers_0_9999.json'
    second_chunk_headers_filename = 'data/headers_10000_800000.json'
    
    # Load existing headers from both files
    headers_0_9999 = load_existing_headers(first_chunk_headers_filename)
    headers_10000_plus = load_existing_headers(second_chunk_headers_filename)
    
    # Find missing heights for each range
    missing_0_9999 = find_missing_heights(headers_0_9999, 0, 9999)
    missing_10000_plus = find_missing_heights(headers_10000_plus, 10000, end_height)
    
    total_missing = len(missing_0_9999) + len(missing_10000_plus)
    
    if total_missing == 0:
        print("No missing headers found. All data is complete!")
        return
        
    print(f"Found {len(missing_0_9999)} missing headers in range 0-9999")
    print(f"Found {len(missing_10000_plus)} missing headers in range 10000-{end_height}")
    print(f"Total missing headers: {total_missing}")
    
    rate_limiter = RateLimiter(headers_per_second)
    start_time = time.time()
    completed_blocks = 0
    
    # Process each range
    for heights, filename, start, end in [
        (missing_0_9999, first_chunk_headers_filename, 0, 9999),
        (missing_10000_plus, second_chunk_headers_filename, 10000, end_height)
    ]:
        await download_headers_for_range(
            bitcoin_rpc, filename, heights, rate_limiter, total_missing,
            start, end, completed_blocks, start_time
        )

async def download_bitcoin_cash_headers(bitcoin_rpc: str, block_count: int, headers_per_second: int):
    """Download Bitcoin Cash headers starting from the fork block"""
    fork_height = 478559  # First block after the Bitcoin Cash fork
    end_height = fork_height + block_count
    headers_filename = f'data/bch_headers_{fork_height}_{end_height}.json'

    print(f"Downloading Bitcoin Cash headers from {fork_height} to {end_height}")
    
    # Load existing headers and find missing ones
    existing_headers = load_existing_headers(headers_filename)
    missing_heights = find_missing_heights(existing_headers, fork_height, end_height)
    total_missing = len(missing_heights)
    
    if total_missing == 0:
        print("No missing Bitcoin Cash headers found. All data is complete!")
        return
        
    print(f"Found {total_missing} missing Bitcoin Cash headers in range {fork_height}-{end_height}")
    
    rate_limiter = RateLimiter(headers_per_second)
    await download_headers_for_range(
        bitcoin_rpc, headers_filename, missing_heights, rate_limiter,
        total_missing, fork_height, end_height
    )

async def main():
    bitcoin_rpc = os.getenv("BITCOIN_RPC")
    bitcoin_cash_rpc = os.getenv("BITCOIN_CASH_RPC")
    end_header_height = 800000
    headers_per_second = 50

    start_block_height = 799_990
    end_block_height = 800_000
    blocks_per_second = 2

    bitcoin_cash_post_fork_blocks = 100_000
    bitcoin_cash_headers_per_second = 50

    # Download Bitcoin canonical headers
    await download_bitcoin_canon_headers(bitcoin_rpc, end_header_height, headers_per_second)
    
    # Download full blocks
    await download_blocks(bitcoin_rpc, start_block_height, end_block_height, blocks_per_second)

    # Download Bitcoin Cash headers (100,000 blocks after fork)
    await download_bitcoin_cash_headers(bitcoin_cash_rpc, bitcoin_cash_post_fork_blocks, bitcoin_cash_headers_per_second)

if __name__ == "__main__":
    load_dotenv()
    asyncio.run(main())
