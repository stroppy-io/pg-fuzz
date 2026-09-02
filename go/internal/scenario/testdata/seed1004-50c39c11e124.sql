-- storage_fuzzer seed 1004
-- failure: setup: CREATE UNLOGGED TABLE t1 (i bigint NOT NULL, j bigint NOT NU -> ERROR:  partitioned tables cannot be unlogged
-- writers: 4
-- steps:   update_all:t1 rollback_ddl:t1 upsert:t0 set_tablespace:t1 vacuum_full:t0 insert_more:t0 savepoint_partial:t0 checkpoint:t1 vacuum_full:t1 attach_partition:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1004 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = repeatable_read;
ALTER DATABASE postgres SET orioledb.default_compress = 5;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 uuid, PRIMARY KEY (i, j)) USING heap TABLESPACE ts_b;
CREATE INDEX t0_hash_idx ON t0 USING hash (v);
CREATE INDEX t0_partial_idx ON t0 (v) WHERE v > 0;
INSERT INTO t0 (i, j, v, x0) SELECT g, g % 97, g * 2, md5(g::text)::uuid FROM generate_series(1, 50000) g;
CREATE UNLOGGED TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k date NOT NULL, x0 timestamptz, x1 bigint, x2 numeric, PRIMARY KEY (i, k)) PARTITION BY RANGE (i);
CREATE UNLOGGED TABLE t1_p0 PARTITION OF t1 FOR VALUES FROM (MINVALUE) TO (251) USING heap;
CREATE UNLOGGED TABLE t1_p1 PARTITION OF t1 FOR VALUES FROM (251) TO (MAXVALUE) USING heap;
INSERT INTO t1 (i, j, v, k, x0, x1, x2) SELECT g, g % 97, g * 2, '2020-01-01'::date + (g % 3000), '2020-01-01'::timestamptz + (g || ' seconds')::interval, g, (g::numeric / 7) FROM generate_series(1, 500) g;
