"""Minimal executable SQLite backend for pySigma semantic differential tests.

This is *not* a SIEM backend. It implements just enough of the TextQueryBackend
contract to convert the condition subset exercised by the semantic truth-table
tests (plain/wildcard strings, numbers, booleans, null, exists, NOT, value
lists and the ``all`` modifier) into SQL that can be executed against events
stored as JSON documents. Anything outside that subset raises
``SigmaFeatureNotSupportedByBackendError`` instead of producing a query with
silently different semantics.

Design constraints:
* Missing fields and explicit JSON ``null`` stay distinct in storage
  (``json_extract`` returns SQL NULL for both, but ``json_type`` distinguishes
  "missing path" from an actual null), so missing fields are never flattened to
  empty strings.
* Multi-valued (JSON array) event fields are matched element-wise through
  custom scalar functions, mirroring Sigma's "any element" / "all elements"
  semantics rather than relying on the array's string representation.
"""
