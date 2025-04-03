import csv
import sys
import matplotlib.pyplot as plt
import os

base_dir = sys.argv[1]

files = os.listdir(base_dir)
bw_files = map(lambda file_name: f'{base_dir}/{file_name}', [file for file in files if file.endswith('_bw.csv')])

for file_path in bw_files:
    try:
        with open(file_path, 'r') as file:
            lines: str = file.readlines()
        if lines[0][:2] == ',,':
        # fields = lines.split(',')
            with open(file_path, 'w') as file:
                file.writelines(lines[1:])
    except FileNotFoundError:
        print(f"File not found: {file_path}")
    except Exception as e:
        print(f"An error occurred: {e}")

    with open(file_path) as f:
        reader = csv.DictReader(f)
        bw_data = []
        for row in reader:
            if row['Read'] is None:
                continue
            if float(row['Read']) > 500:
                continue
            bw_data.append(float(row['Read']))
        plt.plot(bw_data, marker='o', label=f'{file_path}')
        
plt.title("Bandwidth")
plt.xlabel("Time (0.1s)")
plt.ylabel("Read Bandwidth (MB/s)")
plt.grid(True)
plt.legend()
plt.savefig("bandwidth.png", dpi=300)