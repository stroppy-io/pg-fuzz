-- storage_fuzzer seed 107
-- failure: after_set_tablespace:t0/t0: expected 6000 rows, got 0
-- writers: 1
-- steps:   vacuum:t0 reindex:t0 insert_more:t0 vacuum_full:t0 move_index:t0 set_tablespace:t0
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 107 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = table_lock;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL) USING orioledb TABLESPACE ts_b;
CREATE INDEX t0_multicolumn_idx ON t0 (j, v) TABLESPACE ts_b;
CREATE INDEX t0_partial_idx ON t0 (v) TABLESPACE ts_b WHERE v > 0;
INSERT INTO t0 (i, j, v) SELECT g, g % 97, g * 2 FROM generate_series(1, 5000) g;
