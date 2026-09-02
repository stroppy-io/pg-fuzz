# Local variant of OSS-Fuzz's projects/postgresql: builds from a bind-mounted
# PostgreSQL source export instead of a fresh clone of upstream master, so any
# tag/branch/commit -- or OrioleDB's patched fork -- can be fuzzed.
#
# Driven by ../pgfuzz; this is not meant to be invoked by hand.  pgfuzz
# symlinks this directory into the cached OSS-Fuzz clone as
# projects/pgfuzz-<workspace> and calls infra/helper.py against it.

FROM gcr.io/oss-fuzz-base/base-builder:ubuntu-24-04

RUN apt-get update && apt-get install -y make libreadline-dev zlib1g-dev bison\
    flex pkg-config libicu-dev patch zip \
    libzstd-dev libcurl4-openssl-dev libssl-dev

# Build dependencies COMMON to plugins, and only those that coexist.
#
# The union of every plugin's dependencies cannot be installed at once: on this
# base image libgdal-dev (PostGIS) and libmariadb-dev (mysql_fdw) conflict --
# gdal pulls default-libmysqlclient-dev, which needs libmysqlclient-dev, which
# is not installable, while mariadb-dev provides a competing implementation.
# Baking the union in makes the image unbuildable the moment two plugins
# disagree, which is not a property of any workspace.
#
# So only the conflict-free common set lives here; the rest are installed at
# build time from the manifest, for the plugins a workspace actually asked for.
# A workspace requesting two genuinely incompatible plugins then fails with the
# apt error naming them, which is the truth, rather than the image failing for
# everyone.
#
# Deliberately absent everywhere: Oracle Instant Client, which oracle_fdw needs.
# It is proprietary and cannot be fetched unauthenticated.
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake liblz4-dev libjson-c-dev libxml2-dev \
    && rm -rf /var/lib/apt/lists/*

# The local checkout is bind-mounted over this directory by helper.py, so we do
# not clone anything here -- we only need the WORKDIR to exist.
RUN mkdir -p $SRC/postgres

WORKDIR postgres

COPY fuzzer $SRC/fuzzer
COPY build.sh add_fuzzers.diff main.diff guc_file_nul.diff $SRC/
