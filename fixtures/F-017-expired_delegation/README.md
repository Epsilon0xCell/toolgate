# F-017: expired delegation: a manifest expiring at its own issue time

Author: Gavin Blacklock

This fixture presents expired delegation: a manifest expiring at its own issue time. The expected verdict is invalid (expires_at must be after issued_at). A wrong implementation would accept it; the conforming behaviour is stated field by field in expected.json and in the fixture file itself, which is the canonical runner input (see CORPUS-INDEX.md at the programme root for the format reconciliation).
