| workload | interval | reps | agent+collector CPU % (median, IQR) | BPF CPU % (median, IQR) | BPF ns/event | agent RSS kB (HWM) | collector RSS kB (HWM) | sample dur ms | throughput change % vs baseline |
|---|---|---|---|---|---|---|---|---|---|
| idle | 250 ms | 5 | 2.967 (0.067) | 0.0336 (0.0016) | 504.3 | 218580 (220428) | 1996 (1996) | 2.891 | n/a |
| idle | 1000 ms | 5 | 0.8 (0.033) | 0.0115 (0.0019) | 527.9 | 218588 (220556) | 1996 (1996) | 2.891 | n/a |
| idle | 5000 ms | 5 | 0.233 (0.0) | 0.0073 (0.0006) | 680.5 | 218576 (220492) | 1996 (1996) | 2.94 | n/a |
| cpu | 250 ms | 5 | 2.964 (0.0) | 0.0327 (0.003) | 491.8 | 218592 (220460) | 1996 (1996) | 2.872 | -4.54 |
| cpu | 1000 ms | 5 | 0.766 (0.033) | 0.011 (0.0024) | 560.1 | 218588 (220508) | 1996 (1996) | 2.954 | -7.28 |
| cpu | 5000 ms | 5 | 0.233 (0.066) | 0.0054 (0.0021) | 679.2 | 218560 (220544) | 1996 (1996) | 2.889 | -6.41 |
| churn | 250 ms | 5 | 10.992 (0.098) | 1.4171 (0.0036) | 2255.6 | 219932 (220440) | 1996 (1996) | 2.656 | -9.87 |
| churn | 1000 ms | 5 | 10.326 (0.133) | 1.418 (0.0467) | 2469.7 | 222304 (222304) | 1996 (1996) | 2.505 | -10.07 |
| churn | 5000 ms | 5 | 8.861 (0.199) | 1.4315 (0.0237) | 2505.8 | 234564 (234564) | 1996 (1996) | 2.617 | -9.73 |

**Post-hoc note (2026-10-19):** the "throughput change % vs baseline" column is confounded by run order (baselines always ran first; instrumented runs followed a BCC compile) and is not attributable to the agent. See ../README.md, section C, "Limitation". The CPU, BPF, RSS and timing columns are direct measurements.
