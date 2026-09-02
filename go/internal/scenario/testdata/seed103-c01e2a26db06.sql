-- storage_fuzzer seed 103
-- failure: after_load/t0: probe failed: SELECT count(*) FROM t0 WHERE v > 0
-- writers: 2
-- steps:   serializable_write:t2 rollback_insert:t0 add_column:t1 concurrent_write:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 103 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = 1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 jsonb, x1 numeric, x2 bigint, PRIMARY KEY (i, j)) USING orioledb WITH (compress = 1) TABLESPACE ts_b;
CREATE INDEX t0_hash_idx ON t0 USING hash (v);
CREATE INDEX t0_brin_idx ON t0 USING brin (v);
INSERT INTO t0 (i, j, v, x0, x1, x2) SELECT g, g % 97, g * 2, jsonb_build_object('k', g), (g::numeric / 7), g FROM generate_series(1, 50000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k int NOT NULL, x0 text, x1 timestamptz, x2 bigint[], payload text, PRIMARY KEY (i, k)) USING heap TABLESPACE ts_a;
CREATE INDEX t1_hash_idx ON t1 USING hash (v);
INSERT INTO t1 (i, j, v, k, x0, x1, x2, payload) SELECT g, g % 97, g * 2, (g % 1000000)::int, 'r' || g, '2020-01-01'::timestamptz + (g || ' seconds')::interval, ARRAY[g, g + 1], repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k boolean NOT NULL, x0 bigint[], x1 text, x2 uuid, PRIMARY KEY (i, k)) USING heap;
CREATE INDEX t2_btree_idx ON t2 (v);
CREATE INDEX t2_gin_idx ON t2 USING gin (x0);
INSERT INTO t2 (i, j, v, k, x0, x1, x2) SELECT g, g % 97, g * 2, (g % 2 = 0), ARRAY[g, g + 1], 'r' || g, md5(g::text)::uuid FROM generate_series(1, 50000) g;
