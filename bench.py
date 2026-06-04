"""
Optimized Performance Testing Harness for AES Optimization.
Displays Execution Time and calculated Throughput directly to the terminal.
"""

import argparse
import time
import os
from Crypto.Random import get_random_bytes

# Import mode implementations from local dependency wrapper
from aes_mod import encrypt_cbc, encrypt_ctr_parallel, encrypt_ctr_seq


def format_to_mb(byte_count: int) -> float:
    """Converts bytes into a float value representing Megabytes (MB)."""
    return byte_count / 1024 / 1024


def run_single_comparison(data: bytes, key: bytes, nonce: bytes, workers: int):
    """Runs a single encryption execution across all modes to isolate raw execution periods[cite: 11]."""
    # Track CBC (Sequential Baseline)
    start_cbc = time.perf_counter()
    _ = encrypt_cbc(data, key)
    end_cbc = time.perf_counter()
    
    # Track CTR (Sequential Mode)
    start_ctr_seq = time.perf_counter()
    _ = encrypt_ctr_seq(data, key, nonce)
    end_ctr_seq = time.perf_counter()
    
    # Track CTR (Parallelized multi-worker execution environment [cite: 10])
    start_ctr_par = time.perf_counter()
    _ = encrypt_ctr_parallel(data, key, nonce, workers=workers)
    end_ctr_par = time.perf_counter()
    
    return (end_cbc - start_cbc, end_ctr_seq - start_ctr_seq, end_ctr_par - start_ctr_par)


def execute_benchmark(sizes_list, workers_list, iterations_count):
    """Iterates through sizes and prints terminal results instantly[cite: 17]."""
    key = get_random_bytes(16)
    nonce = get_random_bytes(8)

    for sample_size in sizes_list:
        size_in_mb = format_to_mb(sample_size)
        print("\n-------------------------------------------------------------------------------")
        print(f" Testing Data Size: {size_in_mb:.2f} MB ({sample_size} bytes)")
        print("-------------------------------------------------------------------------------")
        print(f" {'ALGORITHM MODE':<28} | {'EXECUTION TIME':<16}  | {'THROUGHPUT':<15}")
        print("-------------------------------------------------------------------------------")
        
        random_payload = os.urandom(sample_size)
        
        accumulated_cbc_time = 0.0
        accumulated_ctr_seq_time = 0.0
        
        # 1. Run Baseline Sequential Modes [cite: 11]
        for _ in range(iterations_count):
            cbc_t, ctr_seq_t, _ = run_single_comparison(random_payload, key, nonce, workers_list[0])
            accumulated_cbc_time += cbc_t
            accumulated_ctr_seq_time += ctr_seq_t
            
        avg_cbc_time = accumulated_cbc_time / iterations_count
        cbc_throughput = size_in_mb / avg_cbc_time if avg_cbc_time > 0 else 0
        
        avg_ctr_seq_time = accumulated_ctr_seq_time / iterations_count
        ctr_seq_throughput = size_in_mb / avg_ctr_seq_time if avg_ctr_seq_time > 0 else 0
            
        print(f" [+] CBC Baseline Mode        | {avg_cbc_time:>13.4f}s    | {cbc_throughput:>10.2f} MB/s")
        print(f" [+] CTR Sequential Mode      | {avg_ctr_seq_time:>13.4f}s    | {ctr_seq_throughput:>10.2f} MB/s")
        print(" - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -")

        # 2. Run Parallel CTR Modes for each worker count and print instantly [cite: 10]
        for thread_count in workers_list:
            accumulated_ctr_par_time = 0.0
            for _ in range(iterations_count):
                _, _, ctr_par_t = run_single_comparison(random_payload, key, nonce, thread_count)
                accumulated_ctr_par_time += ctr_par_t
            
            avg_par_time = accumulated_ctr_par_time / iterations_count
            par_throughput = size_in_mb / avg_par_time if avg_par_time > 0 else 0
            
            print(f" [+] CTR Parallel ({thread_count} Workers) | {avg_par_time:>13.4f}s    | {par_throughput:>10.2f} MB/s")


def main():
    # Setup Argument Parser
    parser = argparse.ArgumentParser(description="Fast AES terminal-only benchmark tool tracking time and throughput.")
    # Defaulting to 1MB and 5MB test loads [cite: 17]
    parser.add_argument('--sizes', nargs='+', type=int, default=[1024*1024, 5*1024*1024], help='Sizes to evaluate in bytes')
    parser.add_argument('--workers', nargs='+', type=int, default=[1, 2, 4], help='Concurrent worker allocations')
    parser.add_argument('--runs', type=int, default=1, help='Iterations per test block')
    args = parser.parse_args()

    print("===============================================================================")
    print(" Running Performance Evaluation (Execution Time & Throughput)  ")
    print("===============================================================================")
    
    execute_benchmark(args.sizes, args.workers, args.runs)
    print("\n===============================================================================")
    print(" Benchmark completed successfully.")
    print("===============================================================================")


if __name__ == '__main__':
    main()