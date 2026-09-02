-- storage_fuzzer seed 1074
-- failure: after_analyze:t2/t2: probe failed: SELECT count(*) FROM t2 WHERE v > 0
-- writers: 1
-- steps:   savepoint_partial:t1 analyze:t2 savepoint_partial:t2 alter_type:t1 vacuum:t0 checkpoint:t2 reindex:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1074 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = table_lock;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, payload text, PRIMARY KEY (i, j)) USING orioledb WITH (compress = -1) TABLESPACE ts_a;
CREATE INDEX t0_brin_idx ON t0 USING brin (v) TABLESPACE ts_b;
CREATE INDEX t0_partial_idx ON t0 (v) TABLESPACE ts_b WHERE v > 0;
INSERT INTO t0 (i, j, v, payload) SELECT g, g % 97, g * 2, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE UNLOGGED TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k text NOT NULL, x0 jsonb, PRIMARY KEY (i, k)) USING heap;
INSERT INTO t1 (i, j, v, k, x0) SELECT g, g % 97, g * 2, 'r' || g, jsonb_build_object('k', g) FROM generate_series(1, 50000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 jsonb, x1 bigint) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t2_p0 PARTITION OF t2 FOR VALUES FROM (MINVALUE) TO (25001) USING orioledb WITH (compress = 1) TABLESPACE ts_b;
CREATE TABLE t2_p1 PARTITION OF t2 FOR VALUES FROM (25001) TO (MAXVALUE) USING orioledb WITH (compress = 1) TABLESPACE ts_b;
CREATE INDEX t2_multicolumn_idx ON t2 (j, v) TABLESPACE ts_a;
INSERT INTO t2 (i, j, v, x0, x1) SELECT g, g % 97, g * 2, jsonb_build_object('k', g), g FROM generate_series(1, 50000) g;
