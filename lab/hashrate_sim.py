import requests
import math
import os
import json
import time

CACHE_FILE = "bitcoin_cache.json"
CACHE_EXPIRY = 600  # 10 minutes in seconds

def fetch_data():
    """Fetch data from the blockchain API with caching."""
    if os.path.exists(CACHE_FILE):
        with open(CACHE_FILE, "r") as f:
            cache = json.load(f)
            if time.time() - cache["timestamp"] < CACHE_EXPIRY:
                return cache["data"]

    # Fetch the latest block header information
    block_hash = requests.get("https://blockchain.info/latestblock").json()['hash']
    bits = requests.get(f"https://blockchain.info/rawblock/{block_hash}").json()['bits']

    # Save to cache
    data = {"block_hash": block_hash, "bits": bits}
    with open(CACHE_FILE, "w") as f:
        json.dump({"timestamp": time.time(), "data": data}, f)

    return data

def get_bitcoin_network_stats(hours: float, percentage_hashrate: float):
    """
    Calculate Bitcoin network statistics.

    Args:
        hours (float): Number of hours to simulate mining.
        percentage_hashrate (float): Hashrate as a percentage of the total network hashrate (e.g., 10 for 10%).

    Returns:
        dict: Contains total blocks mined in the given hours and the time to mine 1 block with the given percentage.
    """
    # Fetch data from cache or API
    data = fetch_data()
    bits = data["bits"]

    # Calculate the target from bits
    exponent = (bits >> 24) - 3
    coefficient = bits & 0xFFFFFF
    target = coefficient * (2 ** (8 * exponent))

    # Constants
    BLOCK_TIME_SECONDS = 600  # Average block time in seconds (10 minutes)
    MAX_TARGET = 0xFFFF * (2 ** 208)  # Maximum target as defined in Bitcoin protocol

    # Calculate the total network hashrate
    total_network_hashrate = (2 ** 256) / (target * BLOCK_TIME_SECONDS)

    # Convert percentage of hashing power to a fraction
    fraction_hashrate = percentage_hashrate / 100

    # Calculate total blocks mined in the given hours
    total_seconds = hours * 3600
    network_blocks_mined = total_seconds / BLOCK_TIME_SECONDS
    miner_blocks_mined = network_blocks_mined * fraction_hashrate

    # Calculate the time it would take for the given percentage to mine 1 block
    avg_block_time = BLOCK_TIME_SECONDS / fraction_hashrate

    return {
        "total_network_hashrate": total_network_hashrate / 1e18,  # Hashes per second for the entire network in EH/s
        "blocks_mined": miner_blocks_mined,  # Total blocks mined by the given percentage in the given time frame
        "avg_block_time": avg_block_time,  # Time in seconds for the given percentage to mine 1 block
    }

if __name__ == "__main__":
    hours = 4  # Number of hours to simulate
    percentage_hashrate = 10  # Percentage of total hashrate

    stats = get_bitcoin_network_stats(hours, percentage_hashrate)
    print(f"Total network hashrate: {stats['total_network_hashrate']:.2f} EH/s")
    print(f"With {percentage_hashrate}% of network hashrate:")
    print(f"Blocks mined in {hours} hours: {stats['blocks_mined']:.2f}")
    print(f"Average time to mine 1 block: {stats['avg_block_time'] / 60:.2f} minutes")

