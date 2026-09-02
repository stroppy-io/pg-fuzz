-- storage_fuzzer seed 9012
-- failure: after_concurrent_ddl:t0/t0: orioledb_tbl_check: server closed the connection unexpectedly
	This probably means the server terminated abnormally
	before or while processing the request.
connection to server was lost
-- writers: 1
-- steps:   concurrent_ddl:t0 restart_clean:t0 serializable_write:t0 vacuum:t0 churn_evict:t1 analyze:t0 restart_clean:t0 move_across_partition:t0 analyze:t0 checkpoint:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 9012 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = 1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint, x1 uuid, payload text) USING orioledb;
CREATE INDEX t0_partial_idx ON t0 (v) TABLESPACE ts_b WHERE v > 0;
CREATE INDEX t0_hash_idx ON t0 USING hash (v) TABLESPACE ts_b;
INSERT INTO t0 (i, j, v, x0, x1, payload) SELECT g, g % 97, g * 2, g, md5(g::text)::uuid, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint[], x1 bigint, payload text, gen bigint GENERATED ALWAYS AS (i * 2) STORED, PRIMARY KEY (i)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t1_p0 PARTITION OF t1 FOR VALUES FROM (MINVALUE) TO (1001) USING orioledb TABLESPACE ts_b;
CREATE TABLE t1_p1 PARTITION OF t1 FOR VALUES FROM (1001) TO (MAXVALUE) USING orioledb TABLESPACE ts_b;
CREATE INDEX t1_gin_idx ON t1 USING gin (x0);
INSERT INTO t1 (i, j, v, x0, x1, payload) SELECT g, g % 97, g * 2, ARRAY[g, g + 1], g, repeat('x', 2000) FROM generate_series(1, 2000) g;
