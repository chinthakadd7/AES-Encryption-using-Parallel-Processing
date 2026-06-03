# AES Parallelization Project

This repository demonstrates a simple experiment to compare AES encryption performance
between a sequential CBC implementation and a parallelized CTR implementation.

Setup

1. Create a virtual environment and install dependencies:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

Running benchmark

```powershell
python bench.py --sizes 1048576 5242880 --workers 1 2 4 --runs 3 --csv results.csv
```

Notes

- `aes_mod.py` contains `encrypt_cbc` (baseline), `encrypt_ctr_seq` and `encrypt_ctr_parallel`.
- The parallel CTR uses `ProcessPoolExecutor` to encrypt disjoint chunks in parallel.
- This is a performance exploration; security properties of AES are unchanged.
