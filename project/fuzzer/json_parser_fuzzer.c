// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
///////////////////////////////////////////////////////////////////////////////

#include "postgres.h"

#include "common/jsonapi.h"
#include "mb/pg_wchar.h"
#include "utils/memutils.h"
#include "utils/memdebug.h"

#include "fuzz_util.h"
#include "fuzz_lineage.h"

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	//FuzzerInitialize("json_db", argv);
	return 0;
}

/*
** Main entry point.  The fuzzer invokes this function with each
** fuzzed input.
*/
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
	sigjmp_buf local_sigjmp_buf;
	char *buffer;
	JsonSemAction sem;
	JsonLexContext *lex;
	MemoryContext iter;
	MemoryContext old;

	buffer = (char *) calloc(size+1, sizeof(char));
	memcpy(buffer, data, size);

	/*
	 * Initialize once, not per input.  As written upstream this called
	 * MemoryContextInit() on every iteration and then destroyed
	 * TopMemoryContext at the end without clearing the pointer, so the second
	 * input tripped Assert(TopMemoryContext == NULL) inside
	 * MemoryContextInit().  That produced 106 identical "reproducers" in run 4
	 * -- all of them this harness bug rather than anything in the JSON parser.
	 */
	pgfuzz_init();

	/*
	 * Everything this iteration allocates goes in a context of its own, which
	 * is deleted at the end.  That frees the JsonLexContext and whatever
	 * pg_parse_json palloc'd, on every supported version -- freeJsonLexContext
	 * does not exist before PostgreSQL 17, and calling it unconditionally
	 * broke every 16 build in a campaign.  Deleting a child context also
	 * leaves TopMemoryContext and ErrorContext intact, which is what the
	 * original teardown got wrong.
	 */
	iter = AllocSetContextCreate(TopMemoryContext, "json_parser iteration",
								 ALLOCSET_SMALL_SIZES);
	old = MemoryContextSwitchTo(iter);

	sem = nullSemAction;
	/*
	 * PostgreSQL 17 added the leading JsonLexContext* parameter, letting the
	 * caller supply the struct.  Keep this harness buildable on 16 too, since
	 * OrioleDB pins a patched 16 branch.
	 */
#if PG_VERSION_NUM >= 170000
	lex = makeJsonLexContextCstringLen(NULL, buffer, size+1, PG_UTF8, true);
#else
	lex = makeJsonLexContextCstringLen(buffer, size+1, PG_UTF8, true);
#endif

	if(!sigsetjmp(local_sigjmp_buf,0)){
		error_context_stack = NULL;
		PG_exception_stack = &local_sigjmp_buf;
		pg_parse_json(lex, &sem);
	}
	else
	{
		FlushErrorState();
	}
	PG_exception_stack = NULL;
	error_context_stack = NULL;

	MemoryContextSwitchTo(old);
	MemoryContextDelete(iter);
	free(buffer);
	return 0;
}
