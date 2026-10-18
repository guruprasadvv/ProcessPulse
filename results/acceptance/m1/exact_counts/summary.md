| configuration | runs | exact | expected | observed values | median s |
|---|---|---|---|---|---|
| test_exact_entry_counts[openat-1] | 10 | 10 | 1 | [1] | 8.498 |
| test_exact_entry_counts[open-1] | 10 | 10 | 1 | [1] | 0.031 |
| test_exact_entry_counts[execve-1] | 10 | 10 | 1 | [1] | 0.032 |
| test_exact_entry_counts[clone-1] | 10 | 10 | 1 | [1] | 0.033 |
| test_exact_entry_counts[openat-1000] | 10 | 10 | 1000 | [1000] | 0.036 |
| test_exact_entry_counts[open-1000] | 10 | 10 | 1000 | [1000] | 0.034 |
| test_exact_entry_counts[execve-1000] | 10 | 10 | 1000 | [1000] | 0.038 |
| test_exact_entry_counts[clone-1000] | 10 | 10 | 1000 | [1000] | 0.413 |
| test_exact_entry_counts_100000[openat] | 10 | 10 | 100000 | [100000] | 0.369 |
| test_exact_entry_counts_100000[execve] | 10 | 10 | 100000 | [100000] | 0.373 |
| test_exact_entry_counts_100000[clone] | 10 | 10 | 100000 | [100000] | 41.323 |

RESULT: PASS (10 repetitions required)
