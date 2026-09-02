-- storage_fuzzer seed 211
-- failure: after_concurrent_ddl:t2/t2: probe failed: SELECT count(*) FROM t2 WHERE v > 0
-- writers: 4
-- steps:   concurrent_ddl:t2 move_across_partition:t2 restart_crash:t1 set_tablespace:t2 concurrent_checkpoint:t2 concurrent_checkpoint:t2 attach_partition:t0 drop_column:t0 insert_more:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 211 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = 5;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k int NOT NULL, x0 numeric, PRIMARY KEY (i, k)) USING orioledb WITH (compress = -1) TABLESPACE ts_b;
INSERT INTO t0 (i, j, v, k, x0) SELECT g, g % 97, g * 2, (g % 1000000)::int, (g::numeric / 7) FROM generate_series(1, 500) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, PRIMARY KEY (i, j)) PARTITION BY RANGE (i);
CREATE TABLE t1_p0 PARTITION OF t1 FOR VALUES FROM (MINVALUE) TO (2501) USING orioledb WITH (compress = 5);
CREATE TABLE t1_p1 PARTITION OF t1 FOR VALUES FROM (2501) TO (MAXVALUE) USING orioledb WITH (compress = 5);
CREATE INDEX t1_multicolumn_idx ON t1 (j, v) TABLESPACE ts_a;
CREATE INDEX t1_partial_idx ON t1 (v) TABLESPACE ts_a WHERE v > 0;
CREATE INDEX t1_btree_idx ON t1 (v) TABLESPACE ts_a;
INSERT INTO t1 (i, j, v) SELECT g, g % 97, g * 2 FROM generate_series(1, 5000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 uuid, x1 text, PRIMARY KEY (i, j)) USING orioledb TABLESPACE ts_b;
CREATE INDEX t2_expression_idx ON t2 ((v * 2)) TABLESPACE ts_a;
CREATE INDEX t2_btree_idx ON t2 (v) TABLESPACE ts_a;
CREATE INDEX t2_brin_idx ON t2 USING brin (v) TABLESPACE ts_a;
INSERT INTO t2 (i, j, v, x0, x1) SELECT g, g % 97, g * 2, md5(g::text)::uuid, 'r' || g FROM generate_series(1, 50000) g;
