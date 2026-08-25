# Latency and Time Measurements — 2026-06-03 (final)

## Filtering criteria
- is_error == False
- latency > 0
- Claude MCP only: latency <= 60s (excludes Claude Desktop license-stop events lasting up to 2 hours)
- DeepSeek / GPT-5.1 / local: full distribution (normal rate-limit retries on commercial APIs are kept; local has no rate limit)

## Question answering — Per-question latency

### Cloud

| Provider | n_valid | mean (s) | median (s) | std (s) |
|---|---:|---:|---:|---:|
| DeepSeek V3 | 1642 | 35.49 | 24.09 | 34.70 |
| OpenAI GPT-5.1 | 1567 | 5.65 | 4.65 | 3.87 |
| Claude Opus 4.1 (MCP) | 1132 | 23.65 | 23.40 | 16.32 |
| Claude Sonnet 4.5 (MCP) | 989 | 23.44 | 21.30 | 13.67 |

### Local

| Provider | n_valid | mean (s) | median (s) | std (s) |
|---|---:|---:|---:|---:|
| Llama 3.1 8B + RAG | 600 | 3.51 | — | 4.81 |
| Qwen 2.5 14B + RAG | 300 | 2.91 | — | 2.13 |
| Phi-4 14B + RAG | 712 | 3.75 | — | 5.11 |

## Attack-chain reconstruction — Chain reconstruction time

### Per case x provider

| Case | Model | n_runs_valid | Mean elapsed (s) | Std elapsed (s) |
|---|---|---:|---:|---:|
| Hunter_4orensics | deepseek | 3 | 14.3 | 0.3 |
| Hunter_4orensics | openai | 3 | 40.4 | 7.9 |
| Hunter_4orensics | opus | 3 | 57.8 | 14.6 |
| Hunter_4orensics | sonnet | 3 | 44.3 | 2.7 |
| KDFS_2023 | deepseek | 3 | 13.8 | 1.1 |
| KDFS_2023 | openai | 3 | 46.4 | 11.5 |
| KDFS_2023 | opus | 3 | 59.9 | 10.7 |
| KDFS_2023 | sonnet | 3 | 72.7 | 35.5 |
| Magnet_CTF_2022 | deepseek | 3 | 12.5 | 0.9 |
| Magnet_CTF_2022 | openai | 3 | 54.1 | 2.4 |
| Magnet_CTF_2022 | opus | 3 | 55.7 | 11.1 |
| Magnet_CTF_2022 | sonnet | 3 | 45.5 | 6.2 |

### Provider means (across 3 cases)

| Provider | Mean elapsed (s) |
|---|---:|
| deepseek | 13.5 |
| openai | 47.0 |
| opus | 57.8 |
| sonnet | 54.2 |

### Case means (across 4 providers)

| Case | Mean elapsed (s) |
|---|---:|
| Hunter_4orensics | 39.2 |
| KDFS_2023 | 48.2 |
| Magnet_CTF_2022 | 42.0 |

## Notes

Selective cutoff applied: Claude MCP providers (Opus 4.1, Sonnet 4.5) used cutoff 60s to filter Claude Desktop license-stop interruptions (~2h gaps that contaminate cloud-API latency comparison); 115 (Opus) and 87 (Sonnet) records excluded as license stops. DeepSeek V3 and GPT-5.1 retain full distribution without cutoff because rate-limit tail is normal API behavior, not license-related. Local providers (Llama 3.1 8B, Qwen 2.5 14B, Phi-4 14B) retain all records without cutoff. Error records (is_error or invalid latency) excluded uniformly. Source: aggregated from benchmark_results/*.json over all runs; full JSON at c:/tmp/latency_final.json.
