# F-004: denial without a reason code

Author: Gavin Blacklock

This fixture presents denial without a reason code. The expected verdict is invalid (DENIAL_REASON_MISSING). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
