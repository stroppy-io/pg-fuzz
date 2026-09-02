-- storage_fuzzer seed 1078
-- failure: setup: CREATE UNLOGGED TABLE t0 (i bigint NOT NULL, j bigint NOT NU -> ERROR:  partitioned tables cannot be unlogged
-- writers: 1
-- steps:   vacuum:t0 add_column:t0 drop_column:t0 delete_half:t0 rollback_insert:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1078 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE UNLOGGED TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k text NOT NULL, x0 text, x1 uuid, PRIMARY KEY (i, k)) PARTITION BY RANGE (i) TABLESPACE ts_a;
CREATE UNLOGGED TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (25001) USING heap TABLESPACE ts_a;
CREATE UNLOGGED TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (25001) TO (MAXVALUE) USING heap TABLESPACE ts_a;
CREATE INDEX t0_expression_idx ON t0 ((v * 2)) TABLESPACE ts_a;
CREATE INDEX t0_brin_idx ON t0 USING brin (v) TABLESPACE ts_a;
CREATE INDEX t0_btree_idx ON t0 (v) TABLESPACE ts_a;
INSERT INTO t0 (i, j, v, k, x0, x1) SELECT g, g % 97, g * 2, 'r' || g, 'r' || g, md5(g::text)::uuid FROM generate_series(1, 50000) g;
