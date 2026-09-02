#-------------------------------------------------------------------------
#
# Makefile for the fuzzer module
#
# src/backend/fuzzer/Makefile
#
# Two link flavors:
#   * every fuzz target links the whole backend (libpostgres.a plus the
#     per-subdirectory objfiles.txt lists) against the fuzzing engine;
#   * protocol_fuzzer additionally wraps exit(), pq_getbyte() and
#     pq_startmsgread() (the last only to know whether a message read is in
#     progress, since PqCommReadingMsg is static in pqcomm.c), so it can
#     feed wire-protocol bytes to a backend that thinks it is reading a socket
#     and survive that backend calling exit().
#
# conninfo_fuzzer is NOT built here -- it is a frontend program linked against
# libpq rather than the backend, and is compiled directly by build.sh.
#
#-------------------------------------------------------------------------
subdir = src/backend/fuzzer
top_builddir = ../../..
include $(top_builddir)/src/Makefile.global

subsysfilename = objfiles.txt

SUBDIROBJS = $(SUBDIRS:%=%/$(subsysfilename))

# make function to expand objfiles.txt contents
expand_subsys = $(foreach file,$(1),$(if $(filter %/objfiles.txt,$(file)),$(patsubst ../../src/backend/%,%,$(addprefix $(top_builddir)/,$(shell cat $(file)))),$(file)))

objfiles.txt: Makefile $(SUBDIROBJS) $(OBJS_FUZZERS)
# Don't rebuild the list if only the OBJS have changed.
	 $(if $(filter-out $(OBJS_FUZZERS),$?),( $(if $(SUBDIROBJS),cat $(SUBDIROBJS); )echo $(addprefix $(subdir)/,$(OBJS_FUZZERS)) ) >$@,touch $@)

SUBDIRS = ../access ../bootstrap ../catalog ../parser ../commands ../executor ../foreign ../lib ../libpq \
	../main ../nodes ../optimizer ../partitioning ../port ../postmaster \
	../regex ../replication ../rewrite ../backup \
	../statistics ../storage ../tcop ../tsearch ../utils $(top_builddir)/src/timezone \
	../jit

OBJS = \
	$(LOCALOBJS) \
	$(SUBDIROBJS) \
	$(top_builddir)/src/common/libpgcommon_srv.a \
	$(top_builddir)/src/port/libpgport_srv.a \
        $(top_builddir)/src/backend/libpostgres.a \

OBJS_FUZZERS = $(filter-out ../main/objfiles.txt, $(OBJS))

# Targets that link the backend but never boot one: fast, no catalog.
STANDALONE_FUZZERS = \
	json_parser_fuzzer \
	raw_parser_fuzzer \
	scalar_types_fuzzer \
	numeric_fuzzer \
	datetime_fuzzer \
	formatting_fuzzer \
	geo_fuzzer \
	network_fuzzer \
	jsonb_fuzzer \
	jsonpath_fuzzer \
	tsearch_fuzzer \
	binary_recv_fuzzer \
	regex_fuzzer \
	encoding_fuzzer \
	config_file_fuzzer \
	hba_file_fuzzer \
	xlogreader_fuzzer

# Targets that call FuzzerInitialize() and run against a real data directory.
BACKEND_FUZZERS = \
	spi_query_fuzzer \
	backend_types_fuzzer \
	extension_funcs_fuzzer \
	simple_query_fuzzer

ALL_FUZZERS = $(STANDALONE_FUZZERS) $(BACKEND_FUZZERS)

FUZZER_OBJS = $(ALL_FUZZERS:%=%.o) protocol_fuzzer.o fuzzer_initialize.o fuzz_orphan.o

# --export-dynamic for the same reason the real postgres binary is linked with
# it: a loadable module (OrioleDB, any contrib .so) resolves backend symbols
# against the executable that dlopen()s it.  Here the backend is linked
# statically into the fuzz target, so without this its symbols stay local and
# shared_preload_libraries fails at load time.
# ICU is linked DYNAMICALLY, deliberately, and this is load-bearing.
#
# It used to be static (-l:libicuuc.a and friends), because base-runner carries
# no ICU at all and a statically linked target needs nothing at run time. That
# works right up until the target dlopens an extension that also uses ICU.
#
# --export-dynamic above is required so a dlopened module can resolve backend
# symbols against the executable. It exports the statically linked ICU too: 254
# ICU symbols became dynamic in the fuzz binary. mchar.so imports 17 of them,
# and every one interposed onto the executable's copy -- while mchar.so kept its
# own DT_NEEDED on libicuuc/libicui18n, so a second complete ICU was loaded as
# well. Two runtimes, separate converter caches, separate collator state,
# separate locks; objects made by one handed to code belonging to the other.
#
# That produced a reproducible palloc chunk-header corruption in mchar's regex
# path that looked exactly like a defect in the patch series, and was ours. See
# FINDINGS/mchar-regex-chunk-corruption.
#
# Linking dynamically means the executable and every dlopened extension resolve
# to the same libicuuc.so.74, because the loader reuses an object already loaded
# under the same SONAME. One ICU, as a real PostgreSQL has.
#
# The run-time cost is that base-runner must now find those libraries.
# build.sh copies them next to the installed tree unconditionally, and the rpath
# below points there -- $ORIGIN is the directory of the target itself, so this
# resolves wherever the build is mounted, with no environment set. $$ escapes
# it past make; the single quotes keep the shell from expanding it.
FUZZ_LIBS = -licui18n -licuuc -licudata $(LIB_FUZZING_ENGINE) \
	-lz -lpthread -ldl -lrt -Wl,--export-dynamic \
	-Wl,-rpath,'$$ORIGIN/tmp_install/usr/local/pgsql/lib'

createdb: dbfuzz

fuzzer: $(ALL_FUZZERS) protocol_fuzzer

# --wrap=AllocSetContextCreateInternal lets fuzz_orphan.c name a leaked context
# by context->name instead of leaving it to ASan, whose allocation stack is
# recycled through aset.c's context freelist and therefore names whichever site
# first allocated that chunk. Every caller that can create a ROOT context lives
# outside aset.c, so --wrap reaches them.
$(ALL_FUZZERS): %: %.o fuzzer_initialize.o fuzz_orphan.o $(OBJS_FUZZERS)
	$(CXX) $(CFLAGS) $(call expand_subsys,$^) -o $@ $(FUZZ_LIBS) -Wl,--wrap=AllocSetContextCreateInternal

$(FUZZER_OBJS): %.o: %.c
	$(CC) $(CFLAGS) $(CPPFLAGS) -c -o $@ $^

protocol_fuzzer: %: %.o fuzz_orphan.o $(OBJS_FUZZERS)
	$(CXX) $(CFLAGS) $(call expand_subsys,$^) -o $@ $(FUZZ_LIBS) -Wl,--wrap=AllocSetContextCreateInternal -Wl,--wrap=exit -Wl,--wrap=proc_exit -Wl,--wrap=pq_getbyte -Wl,--wrap=pq_getbytes -Wl,--wrap=pq_getmessage -Wl,--wrap=pq_startmsgread

# submake-libpgport and temp-install both build src/port and src/common.  As
# order-only prerequisites of dbfuzz they are otherwise free to run
# concurrently under "make -j", and the two "ar crs libpgcommon_shlib.a"
# invocations then race ("ar: unable to copy file ...: No such file or
# directory").  Force submake-libpgport to complete first.
temp-install: | submake-libpgport

dbfuzz: dbfuzz.o | submake-libpgport temp-install
	$(CC) $(CFLAGS) $^ $(LDFLAGS) $(LDFLAGS_EX) $(LIBS) -o $@ \
	&& PATH="$(abs_top_builddir)/tmp_install$(bindir):$$PATH" LD_LIBRARY_PATH="$(abs_top_builddir)/tmp_install/usr/local/pgsql/lib" ./dbfuzz

dbfuzz.o: dbfuzz.c $(top_builddir)/src/port/pg_config_paths.h
dbfuzz.o: override CPPFLAGS := $(CPPFLAGS) -I$(top_builddir)/src/port -I$(top_builddir)/../src/test/regress '-DSHELLPROG="$(SHELL)"'

$(top_builddir)/src/port/pg_config_paths.h: | submake-libpgport
	$(MAKE) -C $(top_builddir)/src/port pg_config_paths.h
