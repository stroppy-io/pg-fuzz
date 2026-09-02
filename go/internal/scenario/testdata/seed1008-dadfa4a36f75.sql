-- storage_fuzzer seed 1008
-- failure: after_set_tablespace:t2/t2: count failed
-- writers: 4
-- steps:   concurrent_write:t1 insert_more:t1 set_tablespace:t2 concurrent_ddl:t0 move_across_partition:t2 savepoint_partial:t0 vacuum:t2 rollback_delete:t1 move_index:t0 restart_crash:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1008 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, payload text, PRIMARY KEY (i, j)) PARTITION BY RANGE (i) TABLESPACE ts_a;
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (1001) USING orioledb WITH (compress = 1) TABLESPACE ts_a;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (1001) TO (MAXVALUE) USING orioledb WITH (compress = 1) TABLESPACE ts_a;
CREATE INDEX t0_expression_idx ON t0 ((v * 2));
CREATE INDEX t0_partial_idx ON t0 (v) WHERE v > 0;
INSERT INTO t0 (i, j, v, payload) SELECT g, g % 97, g * 2, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 numeric, payload text, gen bigint GENERATED ALWAYS AS (i * 2) STORED) USING heap;
CREATE INDEX t1_partial_idx ON t1 (v) TABLESPACE ts_a WHERE v > 0;
INSERT INTO t1 (i, j, v, x0, payload) SELECT g, g % 97, g * 2, (g::numeric / 7), repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint[], x1 numeric, payload text) USING orioledb WITH (compress = 5);
CREATE INDEX t2_multicolumn_idx ON t2 (j, v);
CREATE INDEX t2_btree_idx ON t2 (v);
CREATE INDEX t2_expression_idx ON t2 ((v * 2));
INSERT INTO t2 (i, j, v, x0, x1, payload) SELECT g, g % 97, g * 2, ARRAY[g, g + 1], (g::numeric / 7), repeat('x', 2000) FROM generate_series(1, 2000) g;
