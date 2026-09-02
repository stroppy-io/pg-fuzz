-- storage_fuzzer seed 116
-- failure: after_delete_half:t1/t1: orioledb_tbl_check: server closed the connection unexpectedly
	This probably means the server terminated abnormally
	before or while processing the request.
connection to server was lost
-- writers: 4
-- steps:   delete_half:t1
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
INSERT INTO t0 (i, j, v, x0, x1, x2, payload) SELECT g, g % 97, g * 2, md5(g::text)::uuid, ARRAY[g, g + 1], g, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 jsonb, payload text) USING orioledb WITH (compress = 5) TABLESPACE ts_b;
INSERT INTO t1 (i, j, v, x0, payload) SELECT g, g % 97, g * 2, jsonb_build_object('k', g), repeat('x', 2000) FROM generate_series(1, 2000) g;
