"""
Optimized Performance Testing Harness for AES Optimization.
Streamlined to print terminal results instantly without generating plots.
"""

import argparse
import time
import os
from collections import defaultdict
from Crypto.Random import get_random_bytes

# Import mode implementations from local dependency wrapper
from aes_mod import encrypt_cbc, encrypt_ctr_parallel, encrypt_ctr_seq


def format_to_mb(byte_count: int) -> str:
    """Converts bytes into a clean string displaying values in MB."""
    return f"{byte_count / 1024 / 1024:.2f} MB"


def run_single_comparison(data: bytes, key: bytes, nonce: bytes, workers: int):
    """Runs a single encryption execution across all modes to isolate raw execution periods."""
    # Track CBC (Sequential Baseline)
    start_cbc = time.perf_counter()
    _ = encrypt_cbc(data, key)
    end_cbc = time.perf_counter()
    
    # Track CTR (Sequential Mode)
    start_ctr_seq = time.perf_counter()
    _ = encrypt_ctr_seq(data, key, nonce)
    end_ctr_seq = time.perf_counter()
    
    # Track CTR (Parallelized multi-worker execution environment)
    start_ctr_par = time.perf_counter()
    _ = encrypt_ctr_parallel(data, key, nonce, workers=workers)
    end_ctr_par = time.perf_counter()
    
    return (end_cbc - start_cbc, end_ctr_seq - start_ctr_seq, end_ctr_par - start_ctr_par)


def execute_benchmark(sizes_list, workers_list, iterations_count):
    """Iterates through sizes and prints terminal results instantly."""
    key = get_random_bytes(16)
    nonce = get_random_bytes(8)

    for sample_size in sizes_list:
        print("\n---------------------------------------------------------")
        print(f" Testing Data Size: {format_to_mb(sample_size)} ({sample_size} bytes) ")
        print("---------------------------------------------------------")
        random_payload = os.urandom(sample_size)
        
        accumulated_cbc_time = 0.0
        accumulated_ctr_seq_time = 0.0
        
        # 1. Run Baseline Sequential Modes
        for _ in range(iterations_count):
            cbc_t, ctr_seq_t, _ = run_single_comparison(random_payload, key, nonce, workers_list[0])
            accumulated_cbc_time += cbc_t
            accumulated_ctr_seq_time += ctr_seq_t
            
        print(f" [+] CBC Baseline Mode     : {accumulated_cbc_time / iterations_count:.4f}s")
        print(f" [+] CTR Sequential Mode   : {accumulated_ctr_seq_time / iterations_count:.4f}s")

        # 2. Run Parallel CTR Modes for each worker count and print instantly
        for thread_count in workers_list:
            accumulated_ctr_par_time = 0.0
            for _ in range(iterations_count):
                _, _, ctr_par_t = run_single_comparison(random_payload, key, nonce, thread_count)
                accumulated_ctr_par_time += ctr_par_t
            
            avg_par_time = accumulated_ctr_par_time / iterations_count
            print(f" [+] CTR Parallel ({thread_count} wrks): {avg_par_time:.4f}s")


def main():
    # Setup Argument Parser
    parser = argparse.ArgumentParser(description="Fast AES benchmark tool (Terminal Only)")
    # Defaulting to a smaller 1MB file for instant testing, can be adjusted in terminal
    parser.add_argument('--sizes', nargs='+', type=int, default=[1024*1024], help='Sizes to evaluate in bytes')
    parser.add_argument('--workers', nargs='+', type=int, default=[1, 2, 4], help='Concurrent worker allocations')
    # Default runs changed from 3 down to 1 to speed up execution drastically
    parser.add_argument('--runs', type=int, default=1, help='Iterations per test block')
    args = parser.parse_args()

    print("=========================================================")
    print(" Running Fast Terminal-Only Benchmarks... ")
    print("=========================================================")
    
    execute_benchmark(args.sizes, args.workers, args.runs)
    print("\n=========================================================")
    print(" Benchmark completed successfully.")
    print("=========================================================")


if __name__ == '__main__':
    main()