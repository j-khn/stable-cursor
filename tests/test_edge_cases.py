import unittest

from stable_cursor import CursorCodec, CursorError


class CursorCodecTests(unittest.TestCase):
    def setUp(self):
        self.codec = CursorCodec(b"k" * 32)

    def test_round_trip_preserves_order_tuple_and_scope(self):
        token = self.codec.encode(
            scope="orders:tenant=7:status=open:sort=created,id",
            after=["2026-03-01T10:00:00Z", 4812],
            snapshot="high-water-9000",
            now=1000,
            ttl_seconds=120,
        )
        cursor = self.codec.decode(
            token, scope="orders:tenant=7:status=open:sort=created,id", now=1050
        )
        self.assertEqual(cursor.after, ("2026-03-01T10:00:00Z", 4812))
        self.assertEqual(cursor.snapshot, "high-water-9000")

    def test_integer_snapshot_round_trip(self):
        token = self.codec.encode(
            scope="orders:tenant=7", after=[1000, 10], snapshot=9000, now=1000, ttl_seconds=120
        )
        cursor = self.codec.decode(token, scope="orders:tenant=7", now=1050)
        self.assertEqual(cursor.snapshot, 9000)
        self.assertIs(type(cursor.snapshot), int)

    def test_scope_tampering_and_expiry_are_rejected(self):
        token = self.codec.encode(scope="orders:tenant=7", after=[3, 9], now=100, ttl_seconds=10)
        with self.assertRaises(CursorError):
            self.codec.decode(token, scope="orders:tenant=8", now=101)
        changed = token[:-1] + ("A" if token[-1] != "A" else "B")
        with self.assertRaises(CursorError):
            self.codec.decode(changed, scope="orders:tenant=7", now=101)
        with self.assertRaises(CursorError):
            self.codec.decode(token, scope="orders:tenant=7", now=110)

    def test_invalid_secret_ttl_and_position_are_rejected(self):
        with self.assertRaises(ValueError):
            CursorCodec(b"short")
        with self.assertRaises(ValueError):
            self.codec.encode(scope="x", after=[float("nan")], now=1, ttl_seconds=5)
        with self.assertRaises(ValueError):
            self.codec.encode(scope="x", after=[1], now=1, ttl_seconds=0)
        with self.assertRaises(ValueError):
            self.codec.encode(scope="x", after=[1], snapshot=True, now=1, ttl_seconds=5)

    def test_encode_rejects_token_that_decode_would_reject_for_size(self):
        with self.assertRaisesRegex(ValueError, "cursor is too large"):
            self.codec.encode(
                scope="orders", after=["x" * 7000], now=1000, ttl_seconds=30
            )


if __name__ == "__main__":
    unittest.main()
