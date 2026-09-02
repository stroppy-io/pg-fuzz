-- storage_fuzzer seed 9003
-- failure: after_load/t2: probe failed: SELECT count(*) FROM t2 WHERE v > 0
-- writers: 1
-- steps:   restart_crash:t0 rollback_insert:t2 upsert:t1 rollback_ddl:t1 prepare_2pc:t2
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 9003 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLE warmup (i int);
INSERT INTO warmup VALUES (1);
CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET orioledb.serializable = repeatable_read;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 jsonb, x1 bigint[], payload text, PRIMARY KEY (i, j)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (1001) USING heap TABLESPACE ts_b;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (1001) TO (MAXVALUE) USING heap TABLESPACE ts_b;
CREATE INDEX t0_brin_idx ON t0 USING brin (v);
CREATE UNIQUE INDEX t0_unique_idx ON t0 (i, j);
INSERT INTO t0 (i, j, v, x0, x1, payload) SELECT g, g % 97, g * 2, jsonb_build_object('k', g), ARRAY[g, g + 1], repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, payload text) USING orioledb WITH (compress = 1);
CREATE INDEX t1_hash_idx ON t1 USING hash (v);
INSERT INTO t1 (i, j, v, payload) SELECT g, g % 97, g * 2, repeat('x', 2000) FROM generate_series(1, 5000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint, payload text, PRIMARY KEY (i, j)) USING orioledb TABLESPACE ts_a;
CREATE INDEX t2_brin_idx ON t2 USING brin (v) TABLESPACE ts_b;
INSERT INTO t2 (i, j, v, x0, payload) SELECT g, g % 97, g * 2, g, repeat('x', 2000) FROM generate_series(1, 5000) g;
