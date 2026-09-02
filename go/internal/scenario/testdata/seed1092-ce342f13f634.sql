-- storage_fuzzer seed 1092
-- failure: after_load/t0: probe failed: SELECT count(*) FROM t0 WHERE v > 0
-- writers: 1
-- steps:   delete_half:t1 detach_partition:t2 insert_more:t2 reindex:t2 analyze:t0 insert_more:t1
--
-- reproduce:
--   storage_fuzzer.py --seeds 1 --start-seed 1092 --orioledb
--
-- setup only; the perturbations above are applied by the driver.

CREATE TABLESPACE ts_a LOCATION '';
CREATE TABLESPACE ts_b LOCATION '';
ALTER DATABASE postgres SET default_tablespace = ts_a;
ALTER DATABASE postgres SET orioledb.serializable = error;
ALTER DATABASE postgres SET orioledb.default_compress = -1;
CREATE TABLE t0 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k timestamptz NOT NULL, payload text, PRIMARY KEY (i, k)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t0_p0 PARTITION OF t0 FOR VALUES FROM (MINVALUE) TO (1001) USING orioledb WITH (compress = -1) TABLESPACE ts_b;
CREATE TABLE t0_p1 PARTITION OF t0 FOR VALUES FROM (1001) TO (MAXVALUE) USING orioledb WITH (compress = -1) TABLESPACE ts_b;
CREATE UNIQUE INDEX t0_unique_idx ON t0 (i, j);
CREATE INDEX t0_brin_idx ON t0 USING brin (v);
INSERT INTO t0 (i, j, v, k, payload) SELECT g, g % 97, g * 2, '2020-01-01'::timestamptz + (g || ' seconds')::interval, repeat('x', 2000) FROM generate_series(1, 2000) g;
CREATE TABLE t1 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, x0 bigint[], x1 timestamptz, payload text, PRIMARY KEY (i)) USING heap TABLESPACE ts_b;
CREATE UNIQUE INDEX t1_unique_idx ON t1 (i, j) TABLESPACE ts_a;
CREATE INDEX t1_expression_idx ON t1 ((v * 2)) TABLESPACE ts_a;
INSERT INTO t1 (i, j, v, x0, x1, payload) SELECT g, g % 97, g * 2, ARRAY[g, g + 1], '2020-01-01'::timestamptz + (g || ' seconds')::interval, repeat('x', 2000) FROM generate_series(1, 5000) g;
CREATE TABLE t2 (i bigint NOT NULL, j bigint NOT NULL, v bigint NOT NULL, k int NOT NULL, x0 uuid, x1 bigint[], x2 numeric, payload text, PRIMARY KEY (i, k)) PARTITION BY RANGE (i) TABLESPACE ts_b;
CREATE TABLE t2_p0 PARTITION OF t2 FOR VALUES FROM (MINVALUE) TO (1001) USING orioledb WITH (compress = -1) TABLESPACE ts_b;
CREATE TABLE t2_p1 PARTITION OF t2 FOR VALUES FROM (1001) TO (MAXVALUE) USING orioledb WITH (compress = -1) TABLESPACE ts_b;
CREATE INDEX t2_partial_idx ON t2 (v) TABLESPACE ts_a WHERE v > 0;
INSERT INTO t2 (i, j, v, k, x0, x1, x2, payload) SELECT g, g % 97, g * 2, (g % 1000000)::int, md5(g::text)::uuid, ARRAY[g, g + 1], (g::numeric / 7), repeat('x', 2000) FROM generate_series(1, 2000) g;
