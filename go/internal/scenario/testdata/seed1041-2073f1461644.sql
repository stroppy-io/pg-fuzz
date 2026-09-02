-- storage_fuzzer seed 1041
-- failure: setup: CREATE UNLOGGED TABLE t0 (i bigint NOT NULL, j bigint NOT NU -> ERROR:  partitioned tables cannot be unlogged
-- writers: 1
-- steps:   move_index:t1 rollback_delete:t0 churn_evict:t1 restart_crash:t1 vacuum_full:t1 concurrent_checkpoint:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1041 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE UNLOGGED TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 uuid, PRIMARY KEY (i)) PARTITION BY RANGE (i) TABLESPACE ts_a;
CREATE UNLOGGED TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (251) USING heap TABLESPACE ts_a;
CREATE UNLOGGED TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (251) TO (MAXVALUE) USING heap TABLESPACE ts_a;
INSERT INTO t0 (i, j, v, x0) SELECT g, g % 97, g * 2, md5(g::text)::uuid FROM generate_series(1, 500) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint[]) USING heap TABLESPACE ts_a;
INSERT INTO t1 (i, j, v, x0) SELECT g, g % 97, g * 2, ARRAY[g, g + 1] FROM generate_series(1, 50000) g;
