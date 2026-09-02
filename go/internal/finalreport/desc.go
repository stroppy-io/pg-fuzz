package finalreport

// What each target feeds in, and what it reaches.
//
// Written out rather than derived: the reader of this report is not expected
// to know what "spi_query" means, and a table of names with no explanation is
// a table nobody outside this project can use.
var Desc = map[string][2]string{
	"backend_types_fuzzer": {"A binary blob per built-in data type",
		"the input/output and send/receive functions of PostgreSQL's built-in types"},
	"binary_recv_fuzzer": {"Binary wire representations of values",
		"the binary receive path used by COPY BINARY and the extended protocol"},
	"config_file_fuzzer": {"postgresql.conf text",
		"the GUC configuration-file parser and value validators"},
	"conninfo_fuzzer": {"libpq connection strings and URIs",
		"connection-string and URI parsing in libpq"},
	"datetime_fuzzer": {"Date, time, interval and timezone text",
		"date/time parsing, formatting and timezone resolution"},
	"encoding_fuzzer": {"Byte strings in various server encodings",
		"encoding validation and conversion between character sets"},
	"extension_funcs_fuzzer": {"Argument tuples for extension SQL functions",
		"functions exposed by the loaded third-party extensions"},
	"formatting_fuzzer": {"Format strings and values for to_char/to_date",
		"the formatting family (to_char, to_date, to_number, to_timestamp)"},
	"geo_fuzzer": {"Geometric literals - points, boxes, paths, polygons",
		"the geometric types and their operators"},
	"hba_file_fuzzer": {"pg_hba.conf text",
		"the host-based authentication file parser"},
	"json_parser_fuzzer": {"Arbitrary JSON text",
		"the JSON lexer and parser"},
	"jsonb_fuzzer": {"JSON text and jsonb binary forms",
		"jsonb parsing, its binary representation, and jsonb operators"},
	"jsonpath_fuzzer": {"jsonpath expressions",
		"the SQL/JSON path parser and executor"},
	"network_fuzzer": {"inet, cidr and macaddr literals",
		"the network address types and their operators"},
	"numeric_fuzzer": {"Arbitrary-precision numeric literals and operations",
		"the NUMERIC type: parsing, arithmetic, rounding and formatting"},
	"protocol_fuzzer": {"Raw frontend/backend protocol message streams",
		"the wire protocol state machine inside a real running backend"},
	"raw_parser_fuzzer": {"Arbitrary SQL text",
		"the SQL grammar - lexer and bison parser - stopping before planning"},
	"regex_fuzzer": {"Regular expressions and subject strings",
		"the regex engine behind ~, SIMILAR TO and substring()"},
	"scalar_types_fuzzer": {"Text literals for the scalar types",
		"input/output functions for the simple scalar types"},
	"simple_query_fuzzer": {"SQL executed end to end",
		"parse, plan and execute inside a real backend - the deepest path"},
	"spi_query_fuzzer": {"SQL run through the server-programming interface",
		"SPI, the interface extensions and PL languages use to run queries"},
	"tsearch_fuzzer": {"Documents and text-search queries",
		"full-text search: parsing, dictionaries, ranking"},
	"xlogreader_fuzzer": {"Write-ahead-log record bytes",
		"the WAL reader used by recovery and replication"},
}

// ComponentLabel renames a component for the reader.
//
// "core (patched)" is every line of the files the patch series touches, not
// the patch itself, and the raw key invites the opposite reading.
var ComponentLabel = map[string]string{
	"core (patched)": "core files the patch touches",
}

// Builds names the two campaign builds and how the report labels them.
var Builds = [][2]string{
	{"pg17-ext-all-add", "ASan"},
	{"pg17-ext-all-und", "UBSan"},
}
