# Regression fixtures for the ClickHouse config validator.
#
# Each subdirectory is a known-bad config that should be rejected by
# ./test-clickhouse-config.sh. These were real bugs we shipped during
# the ircfiber-ovh log flood incident (June 2026) — the production
# loop took 30+ minutes to surface and required manual rollback. The
# test harness catches each of these in ~3 seconds.
#
# Usage:
#   ./test-clickhouse-config-regressions.sh   # runs the full suite
#
# History (June 2026):
#   - nested-logger-size: removed from fixtures. On 25.5.6 the nested
#     <log><size> form produces wrong log paths ("Logging trace to
#     100M\n5") but the daemon stays up and SELECT 1 returns. Cosmetic
#     only — the actual OVH exit 36 was the underflow issues below.
#   - underflow-pool: the first version of the OVH fix set
#     background_pool_size=1, ratio=1 (1*1 < 20 default mutation free
#     entries). ClickHouse exits 36 with "is greater than the value
#     of 'background_pool_size' * 'background_merges_mutations_concurrency_ratio' (1)".
#   - underflow-optimize-pool: the second version set pool=4 ratio=5
#     (4*5=20) but the partition-optimizer default is 25. Same error
#     wording but a different code path — easy to miss in the log.

# BAD: background_pool_size=1 with mutations default 20 — fails 36
# because pool * ratio (=1) is less than number_of_free_entries (20).
fixtures/underflow-pool/
  clickhouse-server-overrides.xml

# BAD: number_of_free_entries_in_pool_to_execute_optimize_entire_partition
# default is 25; pool_size * ratio must be >= 25. With pool=4,
# ratio=5 you get 20 which is < 25 → exit 36.
fixtures/underflow-optimize-pool/
  clickhouse-server-overrides.xml
