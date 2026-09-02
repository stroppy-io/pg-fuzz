-- storage_fuzzer seed 0
-- failure: after_load/t0: probe failed: SELECT count(*) FROM t0 WHERE v > 0
-- writers: 2
-- steps:   drop_column:t0 attach_partition:t1 upsert:t1 restart_clean:t0 restart_crash:t1 concurrent_write:t0 prepare_2pc:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 0 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint[], x1 text, payload text, PRIMARY KEY (i, j)) USING orioledb;
CREATE INDEX t0_brin_idx ON t0 USING brin (v);
INSERT INTO t0 (i, j, v, x0, x1, payload) SELECT g, g % 97, g * 2, ARRAY[g, g + 1], 'r' || g, repeat('x', 2000) FROM generate_series(1, 5000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint, x1 timestamptz) USING orioledb TABLESPACE ts_b;
INSERT INTO t1 (i, j, v, x0, x1) SELECT g, g % 97, g * 2, g, '2020-01-01'::timestamptz + (g || ' seconds')::interval FROM generate_series(1, 50000) g;
