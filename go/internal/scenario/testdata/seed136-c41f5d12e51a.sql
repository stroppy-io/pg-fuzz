-- storage_fuzzer seed 136
-- failure: after_set_tablespace:t2/t2: access paths disagree -- seqscan='500' indexscan='0' for [SELECT count(*) FROM t2 WHERE v > 0]
-- writers: 1
-- steps:   insert_more:t1 concurrent_write:t0 vacuum_full:t1 set_tablespace:t2 concurrent_ddl:t1 analyze:t1 upsert:t1 rollback_insert:t0 update_all:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 136 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = table_lock;
ALTER DATABASE postgres SET orioledb.default_compress = 1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint, x1 text, x2 uuid, gen bigint GENERATED ALWAYS AS (i * 2) STORED, PRIMARY KEY (i, j)) USING orioledb WITH (compress = 5);
INSERT INTO t0 (i, j, v, x0, x1, x2) SELECT g, g % 97, g * 2, g, 'r' || g, md5(g::text)::uuid FROM generate_series(1, 5000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, PRIMARY KEY (i)) USING orioledb WITH (compress = 5);
INSERT INTO t1 (i, j, v) SELECT g, g % 97, g * 2 FROM generate_series(1, 5000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint[], x1 timestamptz) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t2_p0 PARTITION OF t2 FOR VALUES FROM (MINVALUE) TO (251) USING orioledb WITH (compress = 5) TABLESPACE ts_b;
CREATE TABLE t2_p1 PARTITION OF t2 FOR VALUES FROM (251) TO (MAXVALUE) USING orioledb WITH (compress = 5) TABLESPACE ts_b;
CREATE INDEX t2_hash_idx ON t2 USING hash (v);
CREATE INDEX t2_btree_idx ON t2 (v);
CREATE INDEX t2_expression_idx ON t2 ((v * 2));
INSERT INTO t2 (i, j, v, x0, x1) SELECT g, g % 97, g * 2, ARRAY[g, g + 1], '2020-01-01'::timestamptz + (g || ' seconds')::interval FROM generate_series(1, 500) g;
