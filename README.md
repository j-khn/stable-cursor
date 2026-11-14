# Stable Cursor

> **Status:** Early-stage reference implementation; APIs may change.

Small, signed cursor tokens for APIs that need stable keyset pagination.

Offset pagination gets slower on deep pages and can skip or repeat rows when records are inserted. A cursor should carry the complete sort tuple, bind itself to active filters, and resist tampering. Stable Cursor handles token integrity and leaves SQL construction visible to the application.

## ✨ Example

~~~python
import os
from stable_cursor import CursorCodec

codec = CursorCodec(os.environ["CURSOR_SECRET"].encode())
token = codec.encode(
    scope="orders:status=open:sort=created_desc",
    after=["2026-03-01T10:00:00Z", 4812],
    snapshot=9000,
    now=1_773_000_000,
    ttl_seconds=900,
)
cursor = codec.decode(
    token,
    scope="orders:status=open:sort=created_desc",
    now=1_773_000_100,
)
print(cursor.after)  # timestamp plus a unique tie-breaker
print(cursor.snapshot)  # integer high-water mark for later pages
~~~

A matching query might use:

~~~sql
SELECT id, created_at, total
FROM orders
WHERE status = 'open'
  AND (created_at, id) < (?, ?)
  AND id <= ?
ORDER BY created_at DESC, id DESC
LIMIT 50
~~~

The unique ID breaks ties between equal timestamps. A string or integer snapshot can carry a high-water mark that keeps later inserts out of a multi-page scan.

## Security and scope

Tokens are authenticated, not encrypted. Do not put secrets or personal data in them. The scope should include the resource, filters, ordering, and tenant identity. Use a strong random key and rotate it deliberately; rotation invalidates cursors signed with the old key unless your application temporarily accepts both versions.

## Important limits

Keyset pagination is an established technique, and many frameworks offer cursor helpers. This package focuses on the token boundary: HMAC integrity, expiry, and query-scope binding. A signed token cannot create a database snapshot. Updates to sort keys and deletions can still change later pages. Choose stable sort columns, include a unique tie-breaker, and define snapshot semantics for your database.

## Install

~~~sh
python -m pip install .
~~~

## License

MIT.
