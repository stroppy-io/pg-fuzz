-- storage_fuzzer seed 131
-- failure: vacuum: ERROR:  cannot update tuples during a parallel operation
-- writers: 1
-- steps:   rollback_ddl:t1 vacuum:t1 analyze:t0 prepare_2pc:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 131 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, PRIMARY KEY (i)) USING orioledb TABLESPACE ts_b;
CREATE INDEX t0_partial_idx ON t0 (v) TABLESPACE ts_b WHERE v > 0;
INSERT INTO t0 (i, j, v) SELECT g, g % 97, g * 2 FROM generate_series(1, 500) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 timestamptz, x1 bigint[], x2 text, PRIMARY KEY (i, j)) PARTITION BY RANGE (i) TABLESPACE ts_a;
CREATE TABLE t1_p0 PARTITION OF t1 FOR VALUES FROM (MINVALUE) TO (25001) USING orioledb TABLESPACE ts_a;
CREATE TABLE t1_p1 PARTITION OF t1 FOR VALUES FROM (25001) TO (MAXVALUE) USING orioledb TABLESPACE ts_a;
CREATE INDEX t1_hash_idx ON t1 USING hash (v) TABLESPACE ts_a;
CREATE INDEX t1_btree_idx ON t1 (v) TABLESPACE ts_a;
CREATE INDEX t1_multicolumn_idx ON t1 (j, v) TABLESPACE ts_a;
INSERT INTO t1 (i, j, v, x0, x1, x2) SELECT g, g % 97, g * 2, '2020-01-01'::timestamptz + (g || ' seconds')::interval, ARRAY[g, g + 1], 'r' || g FROM generate_series(1, 50000) g;
