from scipy.stats import gamma

epsilon = 1e-8

epsilon_percentage = (1-epsilon) * 100
print(f"[INFO] Confidence Level: {epsilon_percentage:.10f}%")

# Parameters
scale = 10  # Scale (θ) = average time per block (minutes)
shapes = [2, 3, 4, 5, 6, 7, 8, 9, 10]

# Calculate the upper bound using ppf (percent point function / quantile function)
for shape in shapes:
    upper_bound = gamma.ppf((1-epsilon), a=shape, scale=scale)
    print(f"[INFO] Tracked Upper Bound for {shape} block/s: {upper_bound:.2f} minutes")