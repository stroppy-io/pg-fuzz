-- storage_fuzzer seed 1065
-- failure: rollback_insert: psql:<stdin>:2: ERROR:  duplicate key value violates unique constraint "index_bridge"
DETAIL:  Key (index_bridging_ctid)=((0,1)) already exists.
-- writers: 1
-- steps:   savepoint_partial:t1 detach_partition:t2 vacuum_full:t2 restart_crash:t1 vacuum:t0 rollback_insert:t1 rollback_delete:t1 rollback_ddl:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1065 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = repeatable_read;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 text, x1 uuid, x2 numeric, PRIMARY KEY (i)) USING heap;
CREATE INDEX t0_brin_idx ON t0 USING brin (v);
INSERT INTO t0 (i, j, v, x0, x1, x2) SELECT g, g % 97, g * 2, 'r' || g, md5(g::text)::uuid, (g::numeric / 7) FROM generate_series(1, 5000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 numeric, x1 uuid, x2 bigint[], payload text, PRIMARY KEY (i)) USING orioledb WITH (compress = 1) TABLESPACE ts_b;
CREATE INDEX t1_gin_idx ON t1 USING gin (x2);
INSERT INTO t1 (i, j, v, x0, x1, x2, payload) SELECT g, g % 97, g * 2, (g::numeric / 7), md5(g::text)::uuid, ARRAY[g, g + 1], repeat('x', 2000) FROM generate_series(1, 5000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k uuid NOT NULL, x0 numeric, x1 text, payload text, PRIMARY KEY (i, k)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t2_p0 PARTITION OF t2 FOR VALUES FROM (MINVALUE) TO (2501) USING heap TABLESPACE ts_b;
CREATE TABLE t2_p1 PARTITION OF t2 FOR VALUES FROM (2501) TO (MAXVALUE) USING heap TABLESPACE ts_b;
CREATE INDEX t2_btree_idx ON t2 (v) TABLESPACE ts_a;
CREATE INDEX t2_partial_idx ON t2 (v) TABLESPACE ts_a WHERE v > 0;
INSERT INTO t2 (i, j, v, k, x0, x1, payload) SELECT g, g % 97, g * 2, md5(g::text)::uuid, (g::numeric / 7), 'r' || g, repeat('x', 2000) FROM generate_series(1, 5000) g;
