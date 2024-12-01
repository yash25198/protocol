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


async def main():
    start_height = 0
    end_height = 800000
    bitcoin_rpc = os.getenv("BITCOIN_RPC")

    # each header is 2 HTTP requests
    headers_per_second = 50
    
    rate_limiter = RateLimiter(headers_per_second)
    total_blocks = end_height - start_height + 1
    start_time = time.time()
    completed_blocks = 0
    time_to_first_download = None 
    start_time = time.time()
    
    print(f"Downloading bitcoin headers from {start_height} to {end_height}...")
    
    async def process_height(height: int):
        nonlocal completed_blocks
        nonlocal time_to_first_download
        try:

            header = await download_header(height, bitcoin_rpc, rate_limiter)

            if time_to_first_download is None:
                time_to_first_download = time.time() - start_time
                print(f"Time to first download: {time_to_first_download:.2f}s")
            
            completed_blocks += 1
            
            # Calculate progress and estimated time remaining
            elapsed_time = time.time() - start_time
            blocks_remaining = total_blocks - completed_blocks
            avg_time_per_block = elapsed_time / completed_blocks if completed_blocks > 0 else 0
            estimated_remaining = blocks_remaining * avg_time_per_block
            
            print(f"\rProgress: {completed_blocks}/{total_blocks} blocks | "
                  f"Estimated time remaining: {estimated_remaining:.1f}s", 
                  end="", flush=True)
                  
            return height, header
        except Exception as e:
            print(f"\nError downloading height {height}: {e}")
            return height, None

    # Batch size is 10x the headers per second rate
    batch_size = headers_per_second * 10
    all_results = []

    print(f"Downloading {total_blocks} headers in batches of {batch_size}...")
    
    for batch_start in range(start_height, end_height + 1, batch_size):
        batch_end = min(batch_start + batch_size, end_height + 1)
        tasks = [process_height(height) for height in range(batch_start, batch_end)]
        batch_results = await asyncio.gather(*tasks)
        all_results.extend(batch_results)
        
        # Save to appropriate files based on ranges
        save_headers_to_file(all_results, 'data/blocks_0_9999.json', 0, 9999)
        save_headers_to_file(all_results, 'data/blocks_10000_800000.json', 10000, 800000)

    # Remove the final save since we're already saving in batches
    # save_headers_to_file(all_results)

if __name__ == "__main__":
    load_dotenv()
    asyncio.run(main())

