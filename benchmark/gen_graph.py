import subprocess
import re
import matplotlib.pyplot as plt
import matplotlib.ticker as ticker
from tqdm import tqdm
import pickle
import os

# define the buffer sizes to test
bufsizes = list(range(16, 4096, 8))

# regex to extract cycles per byte for all ciphers
cpb_pattern = re.compile(r"(AES-\d{3}-\w+\d? \w+ \(generic\)|AES-\d{3}-\w+\d? \w+ \(simd\)|Polyval hashing \(generic\)|Polyval hashing \(clmul\))\s+([\d\.]+)")

# dictionary to store cycles per byte results for each cipher
cpb_results = {}

# Check if results exist
if os.path.exists('cpb_results.pkl'):
    # Load the results from disk
    with open('cpb_results.pkl', 'rb') as f:
        cpb_results = pickle.load(f)
else:
    # Run the benchmark and collect results
    for bufsize in tqdm(bufsizes):
        cmd = ["./build/host/cipherbench", "--bufsize={}".format(bufsize),
               "--ntries=20", "HCTR2", "XTS"]
        # execute the command and get the output
        result = subprocess.run(cmd, stdout=subprocess.PIPE)
        # decode the output and extract cycles per byte
        output = result.stdout.decode()
        cpb_matches = cpb_pattern.findall(output)

        for cipher, cpb in cpb_matches:
            if cipher not in cpb_results:
                cpb_results[cipher] = []
            cpb_results[cipher].append(float(cpb))

    # Save the results
    with open('cpb_results.pkl', 'wb') as f:
        pickle.dump(cpb_results, f)

included_ciphers = [
    "AES-256-XTS encryption (simd)",
    "AES-256-XTS decryption (simd)",
    "AES-256-HCTR2 encryption (simd)",
    "AES-256-HCTR2 decryption (simd)",
]

# plot the data
for cipher, results in cpb_results.items():
    if cipher in included_ciphers:
        plt.plot(bufsizes, results, label=cipher)

plt.title('Cipher Performance vs. Buffer Size')
plt.xlabel('Buffer Size')
plt.ylabel('Cycles Per Byte')
plt.yscale('log')  # make y-axis logarithmic
plt.grid(True)

# set more granular y-axis labeling
plt.gca().yaxis.set_minor_locator(ticker.LogLocator(subs='all'))
plt.gca().yaxis.set_minor_formatter(ticker.FormatStrFormatter("%d"))
plt.gca().yaxis.set_major_formatter(ticker.FormatStrFormatter("%d"))

# place legend inside plot
plt.legend(loc='best', fontsize='small')

plt.show()

