"""
This script calculates the probability of mining a certain number of blocks in a certain amount of time.
Those times are collected from the block_analysis.py script which analyzes 800k blocks and determines the 
maximum time to mine a certain number of sequential blocks.
"""

from scipy.stats import gamma
from block_analysis import get_associated_time_to_mines

# Parameters
scale = 10  # Scale (θ) = average time per block (minutes)
shape = 2 
max_times = 4*60

# CDF
probability = gamma.cdf(max_times, a=shape, scale=scale)
print(f"[CDF] Probability of {shape} block/s mining in {max_times:.2f} minutes: {probability*100:.10f}%")

# Parameters
scale = 10  # Scale (θ) = average time per block (minutes)
search_ranges = range(2, 20)
shape = list(search_ranges) # Shape (k) = num blocks 
max_times = [max_time / 60 for block_range, max_time in get_associated_time_to_mines(windows=search_ranges)[0].items()]

# CDF
probabilities = []
for i in range(len(shape)):
    probability = gamma.cdf(max_times[i], a=shape[i], scale=scale)
    probabilities.append(probability)
    print(f"[CDF] Probability of {shape[i]} block/s mining in {max_times[i]:.2f} minutes: {probability*100:.10f}%")

