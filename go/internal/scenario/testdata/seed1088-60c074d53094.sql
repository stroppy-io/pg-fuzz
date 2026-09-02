-- storage_fuzzer seed 1088
-- failure: prepare_2pc: psql:<stdin>:2: ERROR:  duplicate key value violates unique constraint "index_bridge"
DETAIL:  Key (index_bridging_ctid)=((0,1)) already exists.
-- writers: 1
-- steps:   restart_crash:t0 move_index:t0 prepare_2pc:t0 rollback_delete:t1 move_index:t0 reindex:t0 attach_partition:t2 insert_more:t1 repeatable_read_write:t2 rollback_delete:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1088 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = repeatable_read;
ALTER DATABASE postgres SET orioledb.default_compress = 1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k double precision NOT NULL, payload text, PRIMARY KEY (i, k)) USING orioledb WITH (compress = 1);
CREATE INDEX t0_partial_idx ON t0 (v) WHERE v > 0;
CREATE INDEX t0_brin_idx ON t0 USING brin (v);
INSERT INTO t0 (i, j, v, k, payload) SELECT g, g % 97, g * 2, (g::float8 / 3), repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, payload text, PRIMARY KEY (i, j)) USING orioledb WITH (compress = -1) TABLESPACE ts_a;
CREATE INDEX t1_expression_idx ON t1 ((v * 2));
INSERT INTO t1 (i, j, v, payload) SELECT g, g % 97, g * 2, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k text NOT NULL, x0 uuid, x1 numeric, x2 timestamptz, payload text, PRIMARY KEY (i, k)) USING orioledb WITH (compress = 1) TABLESPACE ts_a;
CREATE INDEX t2_brin_idx ON t2 USING brin (v) TABLESPACE ts_a;
INSERT INTO t2 (i, j, v, k, x0, x1, x2, payload) SELECT g, g % 97, g * 2, 'r' || g, md5(g::text)::uuid, (g::numeric / 7), '2020-01-01'::timestamptz + (g || ' seconds')::interval, repeat('x', 2000) FROM generate_series(1, 2000) g;
