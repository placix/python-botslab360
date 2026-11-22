"""Deterministic synthetic LZ4 differential checks; no external codec/data."""

import base64
import random

from botslab360 import ApiError
from botslab360.occupancy import _decode_lz4_block, parse_occupancy_grid


def reference_decode(block: bytes) -> bytes:
    """Deliberately simple byte-wise oracle, independent of production helpers."""
    position = 0
    output = bytearray()

    def read() -> int:
        nonlocal position
        value = block[position]
        position += 1
        return value

    def length(initial: int) -> int:
        count = initial
        if initial == 15:
            while True:
                extra = read()
                count += extra
                if extra != 255:
                    break
        return count

    while position < len(block):
        token = read()
        for _ in range(length(token >> 4)):
            output.append(read())
        if position == len(block):
            break
        offset = read() + 256 * read()
        assert 0 < offset <= len(output)
        for _ in range(length(token & 15) + 4):
            output.append(output[-offset])
    return bytes(output)


def extension(length: int) -> bytes:
    return b"\xff" * (length // 255) + bytes([length % 255])


def valid_blocks():
    """2048 multi-sequence blocks: literal extensions, overlaps and tails."""
    rng = random.Random(360075)
    for number in range(2048):
        block = bytearray()
        size = 0
        for sequence in range(1 + number % 8):
            literal_count = rng.choice((0, 1, 14, 15, 16, 270, 300))
            if size == 0:
                literal_count = max(1, literal_count)
            literals = rng.randbytes(literal_count)
            size += literal_count
            offset = rng.randint(1, min(size, 65535))
            match_count = rng.choice((4, 5, 18, 19, 20, 274, 275, 1000))
            token = (min(15, literal_count) << 4) | min(15, match_count - 4)
            block.append(token)
            if literal_count >= 15:
                block.extend(extension(literal_count - 15))
            block.extend(literals)
            block.extend(offset.to_bytes(2, "little"))
            if match_count >= 19:
                block.extend(extension(match_count - 19))
            size += match_count
        if number % 3:
            count = 5 + number % 60
            block.append(min(count, 15) << 4)
            if count >= 15:
                block.extend(extension(count - 15))
            block.extend(rng.randbytes(count))
            size += count
        yield bytes(block), size


def test_valid_deterministic_corpus_matches_bytewise_reference():
    for block, size in valid_blocks():
        result = _decode_lz4_block(block, size)
        assert len(result) == size
        assert result == reference_decode(block)
        grid = parse_occupancy_grid(
            {
                "mapId": 17,
                "width": size,
                "height": 1,
                "resolution": 1,
                "x_min": 0,
                "y_min": 0,
                "map": base64.b64encode(block).decode(),
            }
        )
        assert grid.cells == result


def test_corrupt_and_mutated_corpus_never_leaks_unrelated_exceptions():
    rng = random.Random(360076)
    corpus = [
        (rng.randbytes(rng.randrange(97)), rng.randrange(1, 257)) for _ in range(10000)
    ]
    for number, (block, size) in enumerate(valid_blocks()):
        if number % 16:
            continue
        corpus.extend(
            (
                (block[: len(block) // 2], size),
                (block[:-1], size),
                (block + b"\xf0", size),
                (block, size - 1),
                (block, size + 1),
            )
        )
    for block, size in corpus:
        try:
            result = _decode_lz4_block(block, size)
        except ApiError as error:
            assert error.phase == "protocol"
        else:
            assert len(result) == size
            assert result == reference_decode(block)
