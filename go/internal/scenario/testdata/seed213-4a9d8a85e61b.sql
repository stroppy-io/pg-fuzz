-- storage_fuzzer seed 213
-- failure: after_concurrent_ddl:t0/t0: probe failed: SELECT count(*) FROM t0 WHERE i BETWEEN 1 AND 4000
-- writers: 2
-- steps:   alter_type:t0 alter_type:t0 churn_evict:t0 concurrent_ddl:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 213 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = table_lock;
ALTER DATABASE postgres SET orioledb.default_compress = 1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k int NOT NULL, x0 bigint[], payload text, PRIMARY KEY (i, k)) PARTITION BY RANGE (i) TABLESPACE ts_a;
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (1001) USING orioledb TABLESPACE ts_a;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (1001) TO (MAXVALUE) USING orioledb TABLESPACE ts_a;
CREATE INDEX t0_gin_idx ON t0 USING gin (x0) TABLESPACE ts_b;
INSERT INTO t0 (i, j, v, k, x0, payload) SELECT g, g % 97, g * 2, (g % 1000000)::int, ARRAY[g, g + 1], repeat('x', 2000) FROM generate_series(1, 2000) g;
