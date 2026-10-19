| configuration | runs | passed | expected entries | observed entries | median s |
|---|---|---|---|---|---|
| test_exact_pairs[openat-1] | 10 | 10 | 2 | [2] | 10.824 |
| test_exact_pairs[openat-1000] | 10 | 10 | 1001 | [1001] | 0.038 |
| test_exact_pairs[open-1] | 10 | 10 | 2 | [2] | 0.035 |
| test_exact_pairs[open-1000] | 10 | 10 | 1001 | [1001] | 0.041 |
| test_exact_pairs[execve-1] | 10 | 10 | 2 | [2] | 0.04 |
| test_exact_pairs[execve-1000] | 10 | 10 | 1001 | [1001] | 0.049 |
| test_exact_pairs[clone-1] | 10 | 10 | 2 | [2] | 0.042 |
| test_exact_pairs[clone-1000] | 10 | 10 | 1001 | [1001] | 0.56 |
| test_exact_pairs_100000[openat] | 10 | 10 | 100001 | [100001] | 0.433 |
| test_exact_pairs_100000[execve] | 10 | 10 | 100001 | [100001] | 0.447 |
| test_exact_pairs_100000[clone] | 10 | 10 | 100001 | [100001] | 49.206 |
| test_exact_pairs_mixed_sequence | 10 | 10 | 12 | [12] | 0.042 |
| test_exact_pairs_across_an_exec | 10 | 10 | 5 | [5] | 0.094 |
| test_ground_truth_over_a_scope_with_exit_and_purge | 10 | 10 | 21 | [21] | 0.954 |

| equivalence run | fields | identical | different |
|---|---|---|---|
| 01 | 34 | 34 | [] |
| 02 | 34 | 34 | [] |
| 03 | 34 | 34 | [] |
| 04 | 34 | 34 | [] |
| 05 | 34 | 34 | [] |
| 06 | 34 | 34 | [] |
| 07 | 34 | 34 | [] |
| 08 | 34 | 34 | [] |
| 09 | 34 | 34 | [] |
| 10 | 34 | 34 | [] |

RESULT: PASS (10 repetitions required)
