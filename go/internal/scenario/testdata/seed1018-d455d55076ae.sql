-- storage_fuzzer seed 1018
-- failure: after_load/t0: probe failed: SELECT count(*) FROM t0 WHERE v > 0
-- writers: 1
-- steps:   move_across_partition:t0 reindex:t1 reindex:t0 vacuum_full:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1018 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k smallint NOT NULL, x0 text, x1 bigint, x2 jsonb, PRIMARY KEY (i, k)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (25001) USING orioledb WITH (compress = 5) TABLESPACE ts_b;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (25001) TO (MAXVALUE) USING orioledb WITH (compress = 5) TABLESPACE ts_b;
CREATE INDEX t0_brin_idx ON t0 USING brin (v) TABLESPACE ts_a;
INSERT INTO t0 (i, j, v, k, x0, x1, x2) SELECT g, g % 97, g * 2, (g % 30000)::smallint, 'r' || g, g, jsonb_build_object('k', g) FROM generate_series(1, 50000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 jsonb, x1 uuid) USING heap;
CREATE INDEX t1_btree_idx ON t1 (v);
CREATE INDEX t1_multicolumn_idx ON t1 (j, v);
INSERT INTO t1 (i, j, v, x0, x1) SELECT g, g % 97, g * 2, jsonb_build_object('k', g), md5(g::text)::uuid FROM generate_series(1, 5000) g;
