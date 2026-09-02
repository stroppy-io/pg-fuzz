-- storage_fuzzer seed 9013
-- failure: after_update_all:t0/t0: access paths disagree -- seqscan='5000' indexscan='1' for [SELECT count(*) FROM t0 WHERE v > 0]
-- writers: 1
-- steps:   set_tablespace:t0 upsert:t0 rollback_delete:t1 churn_evict:t0 update_all:t0 rollback_delete:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 9013 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = table_lock;
ALTER DATABASE postgres SET orioledb.default_compress = 1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 numeric, PRIMARY KEY (i)) USING orioledb;
CREATE INDEX t0_btree_idx ON t0 (v);
CREATE INDEX t0_brin_idx ON t0 USING brin (v);
INSERT INTO t0 (i, j, v, x0) SELECT g, g % 97, g * 2, (g::numeric / 7) FROM generate_series(1, 5000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint, x1 timestamptz) USING heap TABLESPACE ts_b;
CREATE INDEX t1_brin_idx ON t1 USING brin (v) TABLESPACE ts_a;
CREATE INDEX t1_hash_idx ON t1 USING hash (v) TABLESPACE ts_a;
INSERT INTO t1 (i, j, v, x0, x1) SELECT g, g % 97, g * 2, g, '2020-01-01'::timestamptz + (g || ' seconds')::interval FROM generate_series(1, 5000) g;
