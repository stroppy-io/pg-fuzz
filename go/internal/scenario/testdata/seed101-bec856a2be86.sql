-- storage_fuzzer seed 101
-- failure: after_savepoint_partial:t1/t2: orioledb_tbl_check: server closed the connection unexpectedly
	This probably means the server terminated abnormally
	before or while processing the request.
connection to server was lost
-- writers: 2
-- steps:   alter_type:t0 move_index:t2 serializable_write:t0 restart_clean:t1 reindex:t1 restart_crash:t0 delete_half:t2 savepoint_partial:t1 move_across_partition:t2
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 101 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = repeatable_read;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 jsonb, x1 timestamptz) USING heap TABLESPACE ts_a;
CREATE INDEX t0_multicolumn_idx ON t0 (j, v);
INSERT INTO t0 (i, j, v, x0, x1) SELECT g, g % 97, g * 2, jsonb_build_object('k', g), '2020-01-01'::timestamptz + (g || ' seconds')::interval FROM generate_series(1, 50000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k smallint NOT NULL, x0 timestamptz, payload text, PRIMARY KEY (i, k)) USING orioledb WITH (compress = -1) TABLESPACE ts_a;
CREATE UNIQUE INDEX t1_unique_idx ON t1 (i, j) TABLESPACE ts_a;
CREATE INDEX t1_partial_idx ON t1 (v) TABLESPACE ts_a WHERE v > 0;
CREATE INDEX t1_btree_idx ON t1 (v) TABLESPACE ts_a;
INSERT INTO t1 (i, j, v, k, x0, payload) SELECT g, g % 97, g * 2, (g % 30000)::smallint, '2020-01-01'::timestamptz + (g || ' seconds')::interval, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k date NOT NULL, payload text, gen bigint GENERATED ALWAYS AS (i * 2) STORED, PRIMARY KEY (i, k)) USING orioledb WITH (compress = -1) TABLESPACE ts_a;
CREATE UNIQUE INDEX t2_unique_idx ON t2 (i, j);
CREATE INDEX t2_btree_idx ON t2 (v);
INSERT INTO t2 (i, j, v, k, payload) SELECT g, g % 97, g * 2, '2020-01-01'::date + (g % 3000), repeat('x', 2000) FROM generate_series(1, 5000) g;
