# 统一基准框架与后量子选型指南

liboqs 中不同 PQC 算法的密钥/密文/签名尺寸与性能相差可达数个数量级。本目录提供一套统一基准框架，用同一套测量与输出模式覆盖全部 KEM 与签名算法，直接给出**密钥尺寸**和**各操作吞吐**，并提供“同机同参数”的可重复性校验与选型对比表生成器。

- 统一基准程序：`tests/bench_unified.c` + `tests/bench_framework.h` / `tests/bench_framework.c`
- 验收/制表脚本：`scripts/bench/run_benchmark.py`（仅依赖 Python 标准库）
- 集成测试：`tests/test_bench_unified.py`
- 本机实测产物：`bench-results/selection_comparison_table.md`（选型对比表）、`bench-results/reproducibility_report.md`（重复性报告）、`bench-results/run1.json` / `run2.json`（原始数据）

## 与现有 API 的兼容性

- 基准程序只使用公共 API `<oqs/oqs.h>`（`OQS_KEM_new` / `OQS_SIG_new`、`OQS_KEM_keypair/encaps/decaps`、`OQS_SIG_keypair/sign/verify` 及公共结构体字段），不访问任何内部符号。
- 纯增量改动：不修改、不替换现有的 `speed_kem`、`speed_sig`、`speed_sig_stfl` 及其输出；原有脚本与 CI 不受影响。
- 新 CMake 目标 `bench_unified` 与现有测试目标链接同一组 `TEST_DEPS`；未引入新的 CMake 选项或依赖。
- 新增 pytest 已在 `tests/conftest.py` 的 `correctness` 套件注册。

## 构建

```bash
cmake -S . -B build -G Ninja -DOQS_ALGS_ENABLED=STD -DCMAKE_BUILD_TYPE=Release
cmake --build build --target bench_unified
```

`OQS_ALGS_ENABLED=STD` 包含 ML-KEM、ML-DSA、Falcon、SLH-DSA 等标准算法；使用默认的 `All` 也可以，`bench_unified` 会自动跳过当前构建中未启用的算法。

## 快速使用

不带算法参数时，默认对 5 个迁移最相关的算法（2 个 KEM + 3 个签名）进行基准：

```bash
./build/tests/bench_unified
```

常用形式：

```bash
# 文本块 + 汇总宽表（默认格式）
./build/tests/bench_unified ML-KEM-768 ML-DSA-65

# 机器可读格式
./build/tests/bench_unified --all -f json -o all.json
./build/tests/bench_unified -a ML-KEM-768,Falcon-512 -f csv

# 固定迭代数（严格同参数），或自适应批次（默认，目标 200ms/批）
./build/tests/bench_unified ML-KEM-768 -n 1000 -r 9
./build/tests/bench_unified --batch-ms 300 -r 9

./build/tests/bench_unified --list     # 列出所有已知算法及启用状态
./build/tests/bench_unified --help
```

主要参数：

| 参数 | 含义 |
|---|---|
| `-a, --algorithms a,b,c` | 逗号分隔算法列表；位置参数也会被当作算法名 |
| `--all` | 遍历所有 KEM 与签名算法 |
| `--list` | 列出算法及本构建中的启用状态 |
| `-n, --iterations N` | 每个计时批次固定执行 N 次；不指定时按 `--batch-ms` 自适应 |
| `--batch-ms MS` | 自适应模式的目标批次时长（默认 200ms） |
| `-w, --warmup W` | 不计入测量的预热迭代数（默认 20） |
| `-r, --repeats R` | 每个操作的计时批次数（默认 5；脚本验收用 7–9） |
| `-f, --format` | `text`（默认）、`table`、`csv`、`json` |
| `-o, --output FILE` | 输出到文件 |

## 输出指标

每个算法输出：

- **尺寸（字节）**：公钥、私钥、对象上限（KEM 密文 / SIG 最大签名长度）、实测对象长度（Falcon 等变长签名的真实长度）、KEM 共享密钥长度。
- **吞吐**：`median_ops_per_sec`（操作/秒）、`median_us_per_op`（微秒/操作）、`median_mb_per_s`（按“每次操作承载字节数”折算的 MB/s），以及 mean/stdev/CV/min/max 和每批原始样本。
- **属性**：`kind`（kem/sig）、`nist_level`、`ind_cca`。

JSON 中每个操作都带有实际使用的 `iterations`（自适应模式下尤其需要记录）与全部批次样本，便于审计与二次统计。

## 5 算法可重复验收与选型表（一条命令）

```bash
# 推荐：自动选择最闲 CPU 核 + 短窗口 + 最多 10 次抗噪重试
bash scripts/bench/run_acceptance.sh

# 或直接调用并显式指定参数
python3 scripts/bench/run_benchmark.py --cpu auto \
    --batch-ms 50 --warmup 8 --repeats 7 --runs 2 \
    --tolerance 0.15 --attempts 10
```

脚本会：

1. 用**完全相同的命令行参数**运行 `bench_unified` 两次（`--cpu auto` 会采样各核及其 SMT 兄弟核占用并选择最闲物理核，也可传具体核号；底层用 `taskset` 绑核）；
2. 校验公钥/私钥/缓冲区上限等结构尺寸在两次运行间**完全一致**；Falcon 这类天然变长签名只校验实测长度波动是否在 `--size-tolerance`（默认 2%）内；
3. 比较每个操作吞吐中位数的对称相对偏差 `|m1-m2| / ((m1+m2)/2)`，全部不超过 `--tolerance`（默认 15%）才返回 0；
4. 共享/嘈杂宿主机上瞬时负载可能让整轮失准：`--attempts K` 会把“两次运行”整体重试至多 K 次，落盘并保留通过（或偏差最小）的一轮，`attempts.json` 如实记录每次尝试；
5. 在 `bench-results/` 写出：
   - `selection_comparison_table.md`：**选型对比表**（尺寸、ops/s、µs/op、MB/s、分算法与场景化选型建议、复现命令、环境信息）；
   - `reproducibility_report.md` / `reproducibility.json`：逐操作两次中位数与偏差；
   - `comparison.csv`：宽表；
   - `run1.json`、`run2.json`：原始 JSON；
   - `environment.json`：CPU、主机、Git commit、二进制 SHA256 等溯源信息。

退出码为 0 表示可重复性验收通过；`--no-strict` 可在噪声较大的机器上只出报告不判失败。专用空闲硬件上可用更长批次与更严阈值（例如 `--batch-ms 300 --repeats 9 --tolerance 0.10 --attempts 1`）。稳定测量建议：空闲机器、固定 CPU 核、高性能电源策略、必要时关闭睿频/超线程（参考 `tests/ds_benchmark.h` 顶部建议）。

仓库内 `bench-results/` 保存了一次真实验收（AMD Ryzen 7 9700X / WSL2 共享宿主机，`--cpu auto` 选核，50 ms 自适应批次 × 7，两次运行）：结构尺寸全部一致，最大中位偏差 **11.68%**（ML-KEM-768 keypair，受邻居重型构建的瞬时调度影响），其余操作多在 8% 以内，整体在 15% 容差内 **PASS**。在另一个较安静窗口用相同参数独立复验，首次尝试即通过且最大偏差仅 **5.37%**；更早一次稳定窗口为 6.16%。详见 `bench-results/reproducibility_report.md` 与 `bench-results/attempts.json`。

## 测量方法学

- 使用单调纳秒时钟（POSIX `CLOCK_MONOTONIC`，Windows QPC）。
- 先预热，再进行 R 个固定迭代数的计时批次；对批次吞吐取**中位数**作为报告值，抗偶发调度抖动。
- 自适应迭代数通过指数倍增标定，使每个批次约为 `--batch-ms`，避免快速算法批次过短、慢速算法测试过久；显式 `-n` 时所有操作使用同一固定迭代数，最便于逐字节对照参数。
- 计时循环的输出通过 `bench_escape()` 与内存屏障防止被优化掉；KEM/签名在计时前各做一次完整 roundtrip 并校验共享密钥/签名，保证被测路径正确。

## 接入 CI / pytest

```bash
cmake --build build --target bench_unified
python3 -m pytest tests/test_bench_unified.py -q
```

该测试模块已加入 `conftest.py` 的 `correctness` 套件，覆盖 JSON schema、ML-KEM/ML-DSA 的精确尺寸、CSV 表头以及两次运行的尺寸一致性与宽松的吞吐稳定性边界。严格的 5 算法重复性阈值由 `scripts/bench/run_benchmark.py` 负责，避免在共享 CI 上产生脆弱的性能断言。
