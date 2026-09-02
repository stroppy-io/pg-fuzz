-- storage_fuzzer seed 9028
-- failure: after_load/t1: probe failed: SELECT count(*) FROM t1 WHERE v > 0
-- writers: 2
-- steps:   attach_partition:t0 move_across_partition:t1 savepoint_partial:t0 prepare_2pc:t1 detach_partition:t0 upsert:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 9028 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, PRIMARY KEY (i)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (25001) USING orioledb TABLESPACE ts_b;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (25001) TO (MAXVALUE) USING orioledb TABLESPACE ts_b;
CREATE INDEX t0_btree_idx ON t0 (v) TABLESPACE ts_b;
CREATE INDEX t0_expression_idx ON t0 ((v * 2)) TABLESPACE ts_b;
INSERT INTO t0 (i, j, v) SELECT g, g % 97, g * 2 FROM generate_series(1, 50000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, gen bigint GENERATED ALWAYS AS (i * 2) STORED, PRIMARY KEY (i, j)) USING orioledb WITH (compress = -1) TABLESPACE ts_a;
CREATE INDEX t1_brin_idx ON t1 USING brin (v) TABLESPACE ts_b;
CREATE INDEX t1_hash_idx ON t1 USING hash (v) TABLESPACE ts_b;
INSERT INTO t1 (i, j, v) SELECT g, g % 97, g * 2 FROM generate_series(1, 50000) g;
