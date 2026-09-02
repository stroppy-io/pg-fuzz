-- storage_fuzzer seed 1072
-- failure: update_all: ERROR:  duplicate key value violates unique constraint "index_bridge"
DETAIL:  Key (index_bridging_ctid)=((0,1)) already exists.
-- writers: 2
-- steps:   rollback_delete:t0 alter_type:t0 vacuum:t1 upsert:t1 rollback_delete:t1 concurrent_ddl:t1 restart_crash:t1 checkpoint:t0 restart_crash:t0 update_all:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1072 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = 5;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 timestamptz, x1 bigint[], x2 uuid, payload text, PRIMARY KEY (i)) PARTITION BY RANGE (i) TABLESPACE ts_a;
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (2501) USING orioledb TABLESPACE ts_a;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (2501) TO (MAXVALUE) USING orioledb TABLESPACE ts_a;
CREATE INDEX t0_gin_idx ON t0 USING gin (x1) TABLESPACE ts_a;
CREATE INDEX t0_brin_idx ON t0 USING brin (v) TABLESPACE ts_a;
INSERT INTO t0 (i, j, v, x0, x1, x2, payload) SELECT g, g % 97, g * 2, '2020-01-01'::timestamptz + (g || ' seconds')::interval, ARRAY[g, g + 1], md5(g::text)::uuid, repeat('x', 2000) FROM generate_series(1, 5000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 text) USING heap TABLESPACE ts_a;
CREATE INDEX t1_hash_idx ON t1 USING hash (v);
CREATE INDEX t1_spgist_idx ON t1 USING spgist (x0);
INSERT INTO t1 (i, j, v, x0) SELECT g, g % 97, g * 2, 'r' || g FROM generate_series(1, 5000) g;
