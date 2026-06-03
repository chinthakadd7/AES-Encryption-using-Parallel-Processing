import argparse
import time
import os
from collections import defaultdict
from aes_mod import encrypt_cbc, encrypt_ctr_parallel, encrypt_ctr_seq
from Crypto.Random import get_random_bytes
import matplotlib.pyplot as plt


def human(n):
    return f"{n/1024/1024:.2f} MB"


def run_once(data: bytes, key: bytes, nonce: bytes, workers: int):
    # CBC baseline
    t0 = time.perf_counter()
    _ = encrypt_cbc(data, key)
    t1 = time.perf_counter()
    # CTR seq
    t2 = time.perf_counter()
    _ = encrypt_ctr_seq(data, key, nonce)
    t3 = time.perf_counter()
    # CTR parallel
    t4 = time.perf_counter()
    _ = encrypt_ctr_parallel(data, key, nonce, workers=workers)
    t5 = time.perf_counter()
    return (t1-t0, t3-t2, t5-t4)


def benchmark(sizes, workers_list, runs):
    key = get_random_bytes(16)
    nonce = get_random_bytes(8)
    results = defaultdict(lambda: defaultdict(dict))

    for size in sizes:
        data = os.urandom(size)
        # Measure CBC and CTR sequential once per size (they don't depend on worker count)
        t_cbc = 0.0
        t_ctr_seq = 0.0
        for _ in range(runs):
            a, b, _ = run_once(data, key, nonce, workers_list[0])
            t_cbc += a
            t_ctr_seq += b
        results[size]['CBC'][None] = t_cbc / runs
        results[size]['CTR_seq'][None] = t_ctr_seq / runs

        # Measure CTR parallel for each worker count separately
        for w in workers_list:
            t_ctr_par = 0.0
            for _ in range(runs):
                _, _, c = run_once(data, key, nonce, w)
                t_ctr_par += c
            results[size]['CTR_par'][w] = t_ctr_par / runs

    return results


def plot_results(results, workers_list, out_file='aes_benchmark.png'):
    # Prepare plot
    plt.style.use('ggplot')
    fig, ax = plt.subplots(figsize=(8, 5))

    sizes = sorted(results.keys())
    x = [s / 1024 / 1024 for s in sizes]

    # CBC line
    y_cbc = [results[s]['CBC'][None] for s in sizes]
    ax.plot(x, y_cbc, marker='o', linestyle='-', linewidth=2, label='CBC (baseline)')

    # CTR sequential
    if any('CTR_seq' in results[s] for s in sizes):
        y_ctr_seq = [results[s]['CTR_seq'][None] for s in sizes]
        ax.plot(x, y_ctr_seq, marker='s', linestyle='--', linewidth=2, label='CTR Sequential')

    # CTR parallel for each worker count
    for w in workers_list:
        y = []
        for s in sizes:
            val = results[s]['CTR_par'].get(w, None)
            y.append(val)
        # Only plot sizes where we have a value
        x_plot = [xp for xp, yp in zip(x, y) if yp is not None]
        y_plot = [yp for yp in y if yp is not None]
        if not x_plot:
            continue
        ax.plot(x_plot, y_plot, marker='^' if w >= 4 else 'v', linestyle='-.', linewidth=2, label=f'CTR Parallel ({w} workers)')

    ax.set_title('AES Encryption Time vs File Size', fontsize=14, weight='bold')
    ax.set_xlabel('File Size (MB)', fontsize=12)
    ax.set_ylabel('Execution Time (seconds)', fontsize=12)
    ax.set_xticks(x)
    ax.set_xlim(min(x) - 0.5, max(x) + 0.5)
    ax.grid(True, which='both', linestyle='--', linewidth=0.5, alpha=0.8)
    ax.legend(loc='upper left', fontsize=10)

    # Annotate points
    for s in sizes:
        xs = s / 1024 / 1024
        for label, style in [('CBC', 'o'), ('CTR_seq', 's')]:
            if label in results[s]:
                val = results[s][label][None]
                ax.annotate(f'{val:.4f}s', (xs, val), textcoords='offset points', xytext=(6, 4), fontsize=9)
        for w in workers_list:
            val = results[s]['CTR_par'].get(w, None)
            if val is not None:
                ax.annotate(f'{val:.4f}s', (xs, val), textcoords='offset points', xytext=(6, -12), fontsize=9)

    fig.tight_layout()
    fig.savefig(out_file, dpi=300)
    print(f'Saved plot to {out_file}')
    plt.show()


def main():
    parser = argparse.ArgumentParser(description="AES performance benchmark and plot")
    parser.add_argument('--sizes', nargs='+', type=int, default=[1024*1024, 5*1024*1024], help='sizes in bytes')
    parser.add_argument('--workers', nargs='+', type=int, default=[1,2,4], help='worker counts for parallel CTR')
    parser.add_argument('--runs', type=int, default=3)
    parser.add_argument('--csv', type=str, default=None, help='optional CSV file to write results to')
    args = parser.parse_args()

    print('Running benchmarks...')
    results = benchmark(args.sizes, args.workers, args.runs)

    # Print results table
    for s in sorted(results.keys()):
        print(f"\nSize: {s} bytes ({human(s)})")
        print(f"  CBC: {results[s]['CBC'][None]:.4f}s")
        print(f"  CTR_seq: {results[s]['CTR_seq'][None]:.4f}s")
        for w in args.workers:
            val = results[s]['CTR_par'].get(w, None)
            if val is not None:
                print(f"  CTR_par (workers={w}): {val:.4f}s")

    plot_results(results, args.workers)

    # Optionally write CSV in one-row-per-size format; merge with existing file if present
    if args.csv:
        import csv
        csv_path = args.csv
        worker_cols = [f'workers_{w}(time_s)' for w in args.workers]
        header = ['size_bytes', 'size_mb', 'cbc(time_s)', 'ctr_seq(time_s)'] + worker_cols

        # Load existing rows (keyed by size_bytes) if file exists
        existing = {}
        if os.path.exists(csv_path):
            try:
                with open(csv_path, 'r', newline='') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        key = row.get('size_bytes')
                        if key:
                            existing[key] = row
            except Exception:
                # If reading fails, continue with empty existing
                existing = {}

        # Update existing entries (or add new) using current results
        for s in sorted(results.keys()):
            size_mb = s / 1024 / 1024
            row = {col: '' for col in header}
            row['size_bytes'] = str(s)
            row['size_mb'] = f"{size_mb:.6f}"
            row['cbc(time_s)'] = f"{results[s]['CBC'][None]:.6f}"
            row['ctr_seq(time_s)'] = f"{results[s]['CTR_seq'][None]:.6f}"
            for w in args.workers:
                col = f'workers_{w}(time_s)'
                val = results[s]['CTR_par'].get(w, None)
                row[col] = f"{val:.6f}" if val is not None else ''
            existing[str(s)] = row

        # Write merged file (overwrite with merged content)
        with open(csv_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=header)
            writer.writeheader()
            for key in sorted(existing.keys(), key=lambda x: int(x)):
                # ensure the row has exactly the header keys
                out_row = {k: existing[key].get(k, '') for k in header}
                writer.writerow(out_row)

        print(f'Wrote CSV results to {csv_path}')


if __name__ == '__main__':
    main()
