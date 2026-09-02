-- storage_fuzzer seed 116
-- failure: after_delete_half:t1/t1: orioledb_tbl_check: server closed the connection unexpectedly
	This probably means the server terminated abnormally
	before or while processing the request.
connection to server was lost
-- writers: 4
-- steps:   rollback_ddl:t2 serializable_write:t1 savepoint_partial:t0 concurrent_write:t2 delete_half:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 116 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = 1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 uuid, x1 bigint[], x2 bigint, payload text) USING orioledb TABLESPACE ts_b;
CREATE INDEX t0_hash_idx ON t0 USING hash (v) TABLESPACE ts_a;
CREATE INDEX t0_multicolumn_idx ON t0 (j, v) TABLESPACE ts_a;
CREATE UNIQUE INDEX t0_unique_idx ON t0 (i, j) TABLESPACE ts_a;
INSERT INTO t0 (i, j, v, x0, x1, x2, payload) SELECT g, g % 97, g * 2, md5(g::text)::uuid, ARRAY[g, g + 1], g, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 jsonb, payload text) USING orioledb WITH (compress = 5) TABLESPACE ts_b;
INSERT INTO t1 (i, j, v, x0, payload) SELECT g, g % 97, g * 2, jsonb_build_object('k', g), repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k date NOT NULL, x0 timestamptz, x1 uuid, x2 text, PRIMARY KEY (i, k)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t2_p0 PARTITION OF t2 FOR VALUES FROM (MINVALUE) TO (25001) USING heap TABLESPACE ts_b;
CREATE TABLE t2_p1 PARTITION OF t2 FOR VALUES FROM (25001) TO (MAXVALUE) USING heap TABLESPACE ts_b;
CREATE INDEX t2_hash_idx ON t2 USING hash (v) TABLESPACE ts_a;
CREATE INDEX t2_btree_idx ON t2 (v) TABLESPACE ts_a;
INSERT INTO t2 (i, j, v, k, x0, x1, x2) SELECT g, g % 97, g * 2, '2020-01-01'::date + (g % 3000), '2020-01-01'::timestamptz + (g || ' seconds')::interval, md5(g::text)::uuid, 'r' || g FROM generate_series(1, 50000) g;
