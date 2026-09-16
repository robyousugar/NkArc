"""Lenovo OKR 810/811 fixtures derived from the v10 format and writer.

No vendor images are embedded. The independent Python decoder verifies each
generated stream against the original volume before the product sees it.
"""
import hashlib
import io
import json
import struct
import tarfile
import zlib

UNIT = 32768
CHUNK = 4 * UNIT
MAGIC_COMP = 0x65617a63
MAGIC_RAW = 0x7370786e
DATA_GUID = bytes.fromhex("a2a0d0ebe5b9334487c068b6b72699c7")
FILES = {"hello.txt": b"Lenovo OKR format regression\n",
         "nested/payload.bin": bytes(range(256)) * 1500 + bytes(3 * UNIT) + b"tail"}


def align(n, size=4096):
    return (n + size - 1) // size * size


def lz4_encode(data):
    """Small greedy encoder, with the five literal bytes required at EOF."""
    out, seen = bytearray(), {}
    anchor = pos = 0

    def length(n):
        while n >= 255:
            out.append(255)
            n -= 255
        out.append(n)

    while pos + 12 <= len(data):
        key = data[pos:pos + 4]
        previous = seen.get(key, -65536)
        seen[key] = pos
        if pos - previous > 65535 or data[previous:previous + 4] != key:
            pos += 1
            continue
        end = pos + 4
        while end < len(data) - 5 and data[end] == data[previous + end - pos]:
            end += 1
        literals, match = pos - anchor, end - pos - 4
        out.append((min(literals, 15) << 4) | min(match, 15))
        if literals >= 15:
            length(literals - 15)
        out.extend(data[anchor:pos])
        out.extend(struct.pack("<H", pos - previous))
        if match >= 15:
            length(match - 15)
        pos = anchor = end
    literals = len(data) - anchor
    out.append(min(literals, 15) << 4)
    if literals >= 15:
        length(literals - 15)
    out.extend(data[anchor:])
    return bytes(out)


def lz4_decode(data):
    out, pos = bytearray(), 0
    while pos < len(data):
        token = data[pos]
        pos += 1
        literals = token >> 4
        if literals == 15:
            while True:
                value = data[pos]
                pos += 1
                literals += value
                if value != 255:
                    break
        out.extend(data[pos:pos + literals])
        pos += literals
        if pos == len(data):
            break
        distance = int.from_bytes(data[pos:pos + 2], "little")
        pos += 2
        match = (token & 15) + 4
        if token & 15 == 15:
            while True:
                value = data[pos]
                pos += 1
                match += value
                if value != 255:
                    break
        if not 0 < distance <= len(out):
            raise ValueError("invalid LZ4 fixture")
        for _ in range(match):
            out.append(out[-distance])
    return bytes(out)


def trailer(segments):
    """v10 hashes 2 MiB groups, then PBKDF2 of the outer SHA-256 digest."""
    outer = hashlib.sha256()
    for index, segment in enumerate(segments):
        last = index == len(segments) - 1
        if len(segment) > 340 * 1024 * 1024:
            window = (5 if len(segments) > 1 else 10) * 1024 * 1024
            positions = [i * (len(segment) // 17) for i in range(17)]
            positions.append(len(segment) - window - (32 if last else 0))
            data = b"".join(segment[p:p + window] for p in positions)
        else:
            data = segment[:-32] if last else segment
        for off in range(0, len(data), 2 * 1024 * 1024):
            outer.update(hashlib.sha256(data[off:off + 2 * 1024 * 1024]).digest())
        if len(segment) > 340 * 1024 * 1024 and len(data) % (2 * 1024 * 1024) == 0:
            outer.update(hashlib.sha256(b"").digest())
    first = segments[0]
    salt = first[len(first) // 2:len(first) // 2 + 32]
    iterations = 3000 + first[len(first) // 3]
    return hashlib.pbkdf2_hmac("sha256", outer.digest(), salt, iterations, 32)


def volume():
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        directory = tarfile.TarInfo("nested/")
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        for name, data in FILES.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    # A final partial 32 KiB unit tests clipping its padded physical payload.
    data = stream.getvalue().ljust(23 * UNIT + 512, b"\0")
    return data[:-512] + bytes(range(256)) * 2


def encode_part(raw, mode, chunk=CHUNK):
    bitmap = bytearray(align(((len(raw) + UNIT - 1) // UNIT + 7) // 8))
    packed = bytearray()
    for unit, off in enumerate(range(0, len(raw), UNIT)):
        block = raw[off:off + UNIT].ljust(UNIT, b"\0")
        if any(block):
            bitmap[unit // 8] |= 1 << (unit % 8)
            packed.extend(block)
    data, chunks = bytearray(bitmap), []
    for index, off in enumerate(range(0, len(packed), chunk)):
        plain = bytes(packed[off:off + chunk])
        compressed = mode in ("lz4", "alternate-lz4") or (mode == "mixed" and index % 2 == 0)
        payload = lz4_encode(plain) if compressed else plain
        magic = MAGIC_COMP if compressed else MAGIC_RAW
        if mode.startswith("alternate"):
            magic = 0x676a6763 if compressed else 0x676a6762
        chunks.append(len(data))
        length = align(16 + len(payload))
        data.extend(struct.pack("<IIII", magic, len(payload), length, 0))
        data.extend(payload)
        data.extend(bytes(length - 16 - len(payload)))
    # Decode by walking bitmap and record lengths, not the encoder's chunk list.
    unpacked, pos = bytearray(), len(bitmap)
    while pos < len(data):
        magic, stored, aligned = struct.unpack_from("<III", data, pos)
        payload = data[pos + 16:pos + 16 + stored]
        unpacked.extend(lz4_decode(payload) if magic in (MAGIC_COMP, 0x676a6763) else payload)
        pos += aligned
    result, cursor = bytearray(), 0
    for unit in range((len(raw) + UNIT - 1) // UNIT):
        if bitmap[unit // 8] & (1 << (unit % 8)):
            result.extend(unpacked[cursor:cursor + UNIT])
            cursor += UNIT
        else:
            result.extend(bytes(UNIT))
    if bytes(result[:len(raw)]) != raw or cursor != len(unpacked):
        raise RuntimeError("independent OKR stream reconstruction failed")
    return data, len(packed), chunks


def make_image(raws, version=0x09000811, mode="mixed", stride=176, checksum=False, split=False):
    table, fields = (0x200, 0x118) if version == 0x09000810 else (0x1e20, 0x538)
    # Include one unbacked descriptor, exercising omission and native stride.
    count = len(raws) + 1
    header_size = align(table + stride * count, 512)
    gpt = (34 if version == 0x09000810 else 128) * 512
    data_offset = align(header_size + gpt)
    data = bytearray(data_offset)
    struct.pack_into("<4sIII", data, 0, b"okr9", version, header_size, 1)
    data[fields + 9] = 1
    data[fields + 10] = 1
    struct.pack_into("<H", data, fields + 2, count)
    struct.pack_into("<I", data, fields + 4, gpt)
    struct.pack_into("<I", data, fields + 12, CHUNK)
    struct.pack_into("<I", data, fields + 24, data_offset)
    original, chunks, parts, start = 0, [], [], 2048
    for index, raw in enumerate(raws):
        stream, used, offsets = encode_part(raw, mode)
        row = table + stride * index
        struct.pack_into("<Q", data, row, start)
        struct.pack_into("<Q", data, row + 16, len(raw) // 512)
        data[row + 37] = 7
        data[row + 42] = 1
        struct.pack_into("<Q", data, row + 56, len(stream))
        data[row + 64:row + 80] = DATA_GUID
        data[row + 80:row + 96] = bytes([index + 1]) * 16
        label = f"OKR fixture {index + 1}".encode("utf-16le")
        data[row + 96:row + 96 + len(label)] = label
        parts.append((start, raw))
        chunks.extend(len(data) + off for off in offsets)
        data.extend(stream)
        original += used
        start += align(len(raw) // 512, 2048) + 2048
    # A valid but unbacked partition is excluded from the exposed GPT.
    row = table + stride * len(raws)
    struct.pack_into("<Q", data, row, start)
    struct.pack_into("<Q", data, row + 16, 128)
    sectors = start + 2048
    struct.pack_into("<Q", data, 0x110, sectors)
    struct.pack_into("<Q", data, 0x108, len(data))
    struct.pack_into("<Q", data, fields + 16, original)
    # Deliberately split inside a record payload; the logical stream reader
    # must also accept copied/resegmented images, not only writer boundaries.
    cuts = [chunks[0] + 19, chunks[-1] + 18] if split else []
    struct.pack_into("<I", data, fields + 28, len(cuts) + 1)
    segments = [bytes(data[a:b]) for a, b in zip([0] + cuts, cuts + [len(data)])]
    if checksum:
        segments[-1] += b"0" * 31 + b"\0"
        check = trailer(segments)
        segments[-1] = segments[-1][:-32] + check
    return segments, {"fields": fields, "table": table, "header_size": header_size,
                      "data_offset": data_offset, "chunks": chunks, "parts": parts, "sectors": sectors}


def expected_disk(meta):
    if len(meta["parts"]) == 1:
        return meta["parts"][0][1]
    sectors = meta["sectors"]
    disk = bytearray(sectors * 512)
    disk[446 + 4] = 0xee
    struct.pack_into("<II", disk, 446 + 8, 1, sectors - 1)
    disk[510:512] = b"\x55\xaa"
    entries = bytearray(128 * 128)
    for index, (start, data) in enumerate(meta["parts"]):
        row = index * 128
        entries[row:row + 16] = DATA_GUID
        entries[row + 16:row + 32] = bytes([index + 1]) * 16
        struct.pack_into("<QQ", entries, row + 32, start, start + len(data) // 512 - 1)
        name = f"OKR fixture {index + 1}".encode("utf-16le")
        entries[row + 56:row + 56 + len(name)] = name
        disk[start * 512:start * 512 + len(data)] = data
    def header(here, other, table):
        raw = bytearray(struct.pack("<8sIIIIQQQQ16sQIII", b"EFI PART", 0x10000, 92, 0, 0,
                                    here, other, 34, sectors - 34, b"ROVER-OKR-DISK\0\0\0",
                                    table, 128, 128, zlib.crc32(entries)))
        struct.pack_into("<I", raw, 16, zlib.crc32(raw))
        return raw
    disk[512:604] = header(1, sectors - 1, 2)
    disk[1024:1024 + len(entries)] = entries
    disk[-33 * 512:-512] = entries
    disk[-512:-420] = header(sectors - 1, 1, sectors - 33)
    return bytes(disk)


CASES = [
    ("810-stored", 0x09000810, "raw", 176, False, False, 1),
    ("810-lz4", 0x09000810, "lz4", 176, False, False, 1),
    ("811-mixed-check", 0x09000811, "mixed", 176, True, False, 1),
    ("811-split-check", 0x09000811, "mixed", 176, True, True, 1),
    ("810-multi-ia32", 0x09000810, "mixed", 172, False, True, 2),
    ("811-multi-x64", 0x09000811, "lz4", 176, True, False, 2),
    ("811-alt-lz4", 0x09000811, "alternate-lz4", 176, False, False, 1),
    ("811-alternate", 0x09000811, "alternate", 172, False, False, 1),
]


def generate_okr(root):
    raw = volume()
    for name, version, mode, stride, checksum, split, count in CASES:
        segments, meta = make_image([raw] * count, version, mode, stride, checksum, split)
        base = "okr-" + name + ".img"
        for i, segment in enumerate(segments):
            (root / (base + (f".{i}" if i else ""))).write_bytes(segment)
        (root / (base + ".expected")).write_bytes(expected_disk(meta))
    # Also exercise a real filesystem volume, not only TAR probing.
    fat = (root / "basic.img").read_bytes()
    segments, _ = make_image([fat], mode="lz4", checksum=True)
    (root / "okr-fat.img").write_bytes(segments[0])
    # Full small-file hash path crosses several 2 MiB digest boundaries.
    extra = raw + bytes(range(256)) * 20000
    segments, meta_extra = make_image([extra], mode="raw", checksum=True)
    (root / "okr-hash-groups.img").write_bytes(segments[0])
    (root / "okr-hash-groups.img.expected").write_bytes(extra)
    segments, _ = make_image([bytes(65 * 512)], checksum=True)
    (root / "okr-empty-bitmap.img").write_bytes(segments[0])
    (root / "okr-empty-bitmap.img.expected").write_bytes(bytes(65 * 512))
    from fixtures import make_tar
    members = {"backup.img" + (f".{i}" if i else ""): data for i, data in enumerate(
        make_image([raw], checksum=True, split=True)[0])}
    make_tar(root / "okr-nested.tar", members)
    good, meta = make_image([raw], mode="mixed")
    base = good[0]
    fields, table, chunk = meta["fields"], meta["table"], meta["chunks"][0]
    bad = {}
    def mutate(name, off, value):
        image = bytearray(base)
        image[off:off + len(value)] = value
        bad[name] = image
    def number(name, off, value, fmt="I"):
        mutate(name, off, struct.pack("<" + fmt, value))
    number("version", 4, 0x09000812)
    number("header-size", 8, 0xffffffff)
    number("partition-count", fields + 2, 65, "H")
    number("incomplete", fields + 9, 0, "B")
    number("block-size", fields + 12, 32769)
    number("block-limit", fields + 12, 0x80000000)
    number("data-offset", fields + 24, len(base) + 4096)
    number("gpt-size", fields + 4, 1)
    number("partition-outside", table, 1 << 62, "Q")
    number("partition-overflow", table + 16, (1 << 64) - 1, "Q")
    number("file-count", fields + 28, 4097)
    number("missing-segment", fields + 28, 2)
    number("original-size", fields + 16, 1, "Q")
    number("stream-size", table + 56, 4096, "Q")
    number("chunk-magic", chunk, 0)
    number("chunk-size", chunk + 4, 0xffffffff)
    number("chunk-alignment", chunk + 8, 17)
    number("raw-size", chunk, MAGIC_RAW)
    mutate("lz4", chunk + 16, b"\0\0\0\0")
    number("lz4-short", chunk + 4, 1)
    # Shrink to 23 units: the previously valid bit 23 is now outside.
    number("bitmap-tail", table + 16, 22 * 64 + 1, "Q")
    bad["truncated"] = base[:-1]
    bad["trailer-length"] = base + b"x"
    checked = bytearray((root / "okr-811-mixed-check.img").read_bytes())
    checked[-1] ^= 1
    bad["checksum"] = checked
    checked = bytearray((root / "okr-811-mixed-check.img").read_bytes())
    checked[meta["header_size"] + 500] ^= 1
    bad["checksum-body"] = checked
    multi, multi_meta = make_image([raw, raw])
    overlap = bytearray(multi[0])
    struct.pack_into("<Q", overlap, multi_meta["table"] + 176, 2048)
    bad["overlap"] = overlap
    for name, image in bad.items():
        (root / ("okr-bad-" + name + ".img")).write_bytes(image)
    # A -> malformed B -> A through the same open filter instance.
    broken = bytearray(base)
    struct.pack_into("<I", broken, meta["chunks"][1], MAGIC_COMP)
    broken[meta["chunks"][1] + 16:meta["chunks"][1] + 20] = bytes(4)
    (root / "okr-cache.img").write_bytes(broken)
    (root / "okr-cache.img.expected").write_bytes(raw)
    (root / "okr-manifest.json").write_text(json.dumps({"bad": sorted(bad), "cases": len(CASES)}), encoding="utf-8")


def check_okr(suite):
    from fixtures import FAT_FILES
    from run_product import require, digest

    for name, _, _, _, _, _, count in CASES:
        image = "okr-" + name + ".img"
        suite.command([suite.probe, "--image-read", suite.fixtures / image,
                       suite.fixtures / (image + ".expected")])
        for part in range(count):
            device = "img0" if count == 1 else f"img0,gpt{part + 1}"
            listing = suite.cli_run(image, f"--list=({device})/")
            require(sorted(listing.stdout.splitlines()) == ["hello.txt", "nested/"], image + " listing")
            output = suite.root / (image + f"-p{part}")
            suite.cli_run(image, "-e", f"({device})/nested/payload.bin", "-o", output, "--no-times")
            require(digest((output / "payload.bin").read_bytes()) == digest(FILES["nested/payload.bin"]),
                    image + " extraction hash")
        if count > 1:
            suite.cli_run(image, "--list=(img0,gpt3)/", expected=1)
    for name in ("okr-hash-groups.img", "okr-empty-bitmap.img"):
        suite.command([suite.probe, "--image-read", suite.fixtures / name,
                       suite.fixtures / (name + ".expected")])
    nested = suite.cli_run("okr-nested.tar", "-p", "(img0)/backup.img", "--list=(loop0)/")
    require(sorted(nested.stdout.splitlines()) == ["hello.txt", "nested/"], "nested split OKR listing")
    output = suite.root / "okr-nested-out"
    suite.cli_run("okr-nested.tar", "-p", "(img0)/backup.img", "-e", "(loop0)/nested/payload.bin", "-o", output)
    require((output / "payload.bin").read_bytes() == FILES["nested/payload.bin"], "nested split OKR extraction")
    suite.basic("okr-fat.img", FAT_FILES, {"dir"})
    manifest = json.loads((suite.fixtures / "okr-manifest.json").read_text(encoding="utf-8"))
    for name in manifest["bad"]:
        image = "okr-bad-" + name + ".img"
        suite.cli_run(image, "--list=(img0)/", expected=1)
        output = suite.root / (image + "-out")
        suite.cli_run(image, "-e", "(img0)/nested/payload.bin", "-o", output, expected=1)
        require(not any(p.is_file() for p in output.rglob("*")), image + " partial output")
    suite.command([suite.probe, "--image-read", suite.fixtures / "okr-cache.img",
                   suite.fixtures / "okr-cache.img.expected", CHUNK])
