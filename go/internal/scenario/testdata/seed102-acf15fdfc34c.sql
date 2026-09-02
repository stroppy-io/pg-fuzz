-- storage_fuzzer seed 102
-- failure: after_set_tablespace:t0/t0: count failed
-- writers: 1
-- steps:   truncate_refill:t0 insert_more:t0 concurrent_ddl:t0 concurrent_write:t0 set_tablespace:t0 serializable_write:t0 delete_half:t0 truncate_refill:t0 savepoint_partial:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 102 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = table_lock;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 timestamptz, payload text) USING orioledb WITH (compress = 5) TABLESPACE ts_b;
CREATE INDEX t0_partial_idx ON t0 (v) WHERE v > 0;
CREATE INDEX t0_expression_idx ON t0 ((v * 2));
INSERT INTO t0 (i, j, v, x0, payload) SELECT g, g % 97, g * 2, '2020-01-01'::timestamptz + (g || ' seconds')::interval, repeat('x', 2000) FROM generate_series(1, 2000) g;
