# 可重复性报告（同机同参数）

总体结论：**PASS**；容差 15%；观测到的最大中位偏差 11.684%。

| 算法 | 操作 | 各次 median ops/s | 最大相对偏差 | 判定 |
|---|---|---|---:|:---:|
| `ML-KEM-768` | size:object_actual_bytes | 1088, 1088 B | 0.00% | ✅ |
| `ML-KEM-768` | `keypair` | 170,913, 192,120 | 11.68% | ✅ |
| `ML-KEM-768` | `encaps` | 177,152, 181,984 | 2.69% | ✅ |
| `ML-KEM-768` | `decaps` | 148,140, 151,127 | 2.00% | ✅ |
| `ML-KEM-1024` | size:object_actual_bytes | 1568, 1568 B | 0.00% | ✅ |
| `ML-KEM-1024` | `keypair` | 143,711, 148,166 | 3.05% | ✅ |
| `ML-KEM-1024` | `encaps` | 137,992, 135,759 | 1.63% | ✅ |
| `ML-KEM-1024` | `decaps` | 110,251, 111,556 | 1.18% | ✅ |
| `ML-DSA-65` | size:object_actual_bytes | 3309, 3309 B | 0.00% | ✅ |
| `ML-DSA-65` | `keypair` | 59,244, 59,019 | 0.38% | ✅ |
| `ML-DSA-65` | `sign` | 18,267, 18,331 | 0.35% | ✅ |
| `ML-DSA-65` | `verify` | 59,375, 59,224 | 0.25% | ✅ |
| `Falcon-512` | size:object_actual_bytes | 658, 656 B | 0.30% | ✅ |
| `Falcon-512` | `keypair` | 273.5, 269.6 | 1.45% | ✅ |
| `Falcon-512` | `sign` | 9,370.4, 9,480.2 | 1.17% | ✅ |
| `Falcon-512` | `verify` | 47,943, 47,497 | 0.93% | ✅ |
| `SLH_DSA_PURE_SHA2_128F` | size:object_actual_bytes | 17088, 17088 B | 0.00% | ✅ |
| `SLH_DSA_PURE_SHA2_128F` | `keypair` | 1,978.1, 2,022.6 | 2.22% | ✅ |
| `SLH_DSA_PURE_SHA2_128F` | `sign` | 86.22, 79.65 | 7.93% | ✅ |
| `SLH_DSA_PURE_SHA2_128F` | `verify` | 1,413.2, 1,373.8 | 2.83% | ✅ |

尺寸字段必须逐字节一致；若尺寸不一致直接判失败。相对偏差 = |m₁−m₂| / ((m₁+m₂)/2)。
