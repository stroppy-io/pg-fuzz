-- storage_fuzzer seed 1057
-- failure: after_load/t2: probe failed: SELECT count(*) FROM t2 WHERE v > 0
-- writers: 1
-- steps:   prepare_2pc:t0 add_column:t1 rollback_ddl:t2 attach_partition:t2 repeatable_read_write:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1057 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = repeatable_read;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 timestamptz, x1 jsonb, x2 bigint[], gen bigint GENERATED ALWAYS AS (i * 2) STORED) PARTITION BY RANGE (i);
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (251) USING heap;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (251) TO (MAXVALUE) USING heap;
CREATE INDEX t0_btree_idx ON t0 (v);
CREATE INDEX t0_partial_idx ON t0 (v) WHERE v > 0;
INSERT INTO t0 (i, j, v, x0, x1, x2) SELECT g, g % 97, g * 2, '2020-01-01'::timestamptz + (g || ' seconds')::interval, jsonb_build_object('k', g), ARRAY[g, g + 1] FROM generate_series(1, 500) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 uuid, x1 text, x2 bigint[], payload text, PRIMARY KEY (i)) USING heap TABLESPACE ts_a;
INSERT INTO t1 (i, j, v, x0, x1, x2, payload) SELECT g, g % 97, g * 2, md5(g::text)::uuid, 'r' || g, ARRAY[g, g + 1], repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k timestamptz NOT NULL, PRIMARY KEY (i, k)) USING orioledb WITH (compress = 1);
CREATE INDEX t2_expression_idx ON t2 ((v * 2)) TABLESPACE ts_b;
CREATE INDEX t2_brin_idx ON t2 USING brin (v) TABLESPACE ts_b;
INSERT INTO t2 (i, j, v, k) SELECT g, g % 97, g * 2, '2020-01-01'::timestamptz + (g || ' seconds')::interval FROM generate_series(1, 50000) g;
