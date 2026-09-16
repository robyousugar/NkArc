/*
 *  Rover -- Filesystem browser for Windows
 *  Copyright (C) 2026  A1ive
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/types.h>
#include <grub/misc.h>
#include <grub/file.h>
#include <grub/mm.h>
#include <grub/dl.h>
#include <grub/crypto.h>
#include <grub/hostfile.h>
#include <grub/gpt_partition.h>
#include <grub/msdos_partition.h>
#include <lz4.h>

GRUB_MOD_LICENSE ("GPLv3+");

#define OKR_UNIT 32768U
#define OKR_ALIGN 4096U
#define OKR_PARTS 64U
#define OKR_SEGMENTS 4096U
#define OKR_BLOCK_MAX (500U << 20)
#define OKR_METADATA_MAX (256U << 20)
#define OKR_COMPRESSED 0x65617a63U
#define OKR_STORED 0x7370786eU
#define OKR_GPT_BYTES (34U * 512)
#define OKR_HASH_GROUP (2U << 20)
#define OKR_OFFSET_MAX ((~(grub_uint64_t) 0) >> 1)

struct okr_segment
{
	grub_file_t file;
	grub_uint64_t start;
};

struct okr_chunk
{
	grub_uint64_t offset;
	grub_uint32_t stored;
	int compressed;
};

struct okr_part
{
	grub_uint64_t start, size, stream_size, used;
	grub_uint8_t type[16], guid[16], label[64];
	grub_uint8_t *bitmap;
	grub_uint64_t *rank;
	struct okr_chunk *chunks;
	grub_uint32_t count;
};

struct okr_image
{
	grub_file_t source;
	struct okr_segment *segments;
	grub_uint32_t nsegments, nparts, block_size;
	grub_uint64_t file_size, size, metadata;
	struct okr_part parts[OKR_PARTS];
	grub_uint8_t *primary, *backup, *plain, *stored;
	grub_uint32_t plain_capacity, stored_capacity;
	const struct okr_chunk *cached;
};

static struct grub_fs grub_okr_fs;

static grub_uint32_t
okr_u32 (const grub_uint8_t *p)
{
	return (grub_uint32_t) p[0] | ((grub_uint32_t) p[1] << 8)
		| ((grub_uint32_t) p[2] << 16) | ((grub_uint32_t) p[3] << 24);
}

static grub_uint64_t
okr_u64 (const grub_uint8_t *p)
{
	return okr_u32 (p) | ((grub_uint64_t) okr_u32 (p + 4) << 32);
}

static grub_err_t
okr_bad (const char *message)
{
	return grub_error (GRUB_ERR_BAD_FILE_TYPE, "OKR: %s", message);
}

static grub_err_t
okr_pread (grub_file_t file, grub_uint64_t off, void *buf, grub_size_t len)
{
	grub_ssize_t got;

	if (off > file->size || len > file->size - off)
		return okr_bad ("truncated image");
	if (grub_file_seek (file, off) == (grub_off_t) -1)
		return grub_errno;
	got = grub_file_read (file, buf, len);
	if (got < 0)
		return grub_errno;
	if ((grub_size_t) got != len)
		return okr_bad ("short image read");
	return GRUB_ERR_NONE;
}

/* Data offsets describe the concatenation of all physical segments. */
static grub_err_t
okr_read_at (struct okr_image *img, grub_uint64_t off, void *buffer, grub_size_t len)
{
	grub_uint8_t *buf = buffer;
	grub_uint32_t lo = 0, hi = img->nsegments;

	if (off > img->file_size || len > img->file_size - off)
		return okr_bad ("data outside image");
	while (lo + 1 < hi)
	{
		grub_uint32_t mid = lo + (hi - lo) / 2;
		if (img->segments[mid].start <= off)
			lo = mid;
		else
			hi = mid;
	}
	while (len)
	{
		struct okr_segment *seg = &img->segments[lo];
		grub_uint64_t relative = off - seg->start;
		grub_size_t n = len;

		if (n > seg->file->size - relative)
			n = (grub_size_t) (seg->file->size - relative);
		if (okr_pread (seg->file, relative, buf, n))
			return grub_errno;
		off += n;
		buf += n;
		len -= n;
		lo++;
	}
	return GRUB_ERR_NONE;
}

static void *
okr_alloc_metadata (struct okr_image *img, grub_uint64_t bytes)
{
	if (bytes > OKR_METADATA_MAX - img->metadata)
	{
		grub_error (GRUB_ERR_OUT_OF_RANGE, "OKR metadata exceeds 256 MiB");
		return NULL;
	}
	img->metadata += bytes;
	return grub_zalloc ((grub_size_t) bytes);
}

static unsigned
okr_popcount (grub_uint8_t v)
{
	v = (grub_uint8_t) (v - ((v >> 1) & 0x55));
	v = (grub_uint8_t) ((v & 0x33) + ((v >> 2) & 0x33));
	return (v + (v >> 4)) & 15;
}

static grub_uint64_t
okr_rank (const struct okr_part *part, grub_uint64_t unit)
{
	grub_uint64_t byte = (unit >> 12) * 512;
	grub_uint64_t end = unit >> 3;
	grub_uint64_t rank = part->rank[unit >> 12];

	while (byte < end)
		rank += okr_popcount (part->bitmap[byte++]);
	if (unit & 7)
		rank += okr_popcount ((grub_uint8_t) (part->bitmap[end] & ((1U << (unit & 7)) - 1)));
	return rank;
}

static grub_err_t
okr_index_part (struct okr_image *img, struct okr_part *part, grub_uint64_t off)
{
	grub_uint64_t units = (part->size + OKR_UNIT - 1) / OKR_UNIT;
	grub_uint64_t bytes = (units + 7) / 8;
	grub_uint64_t bitmap_disk_size = (bytes + OKR_ALIGN - 1) & ~(grub_uint64_t) (OKR_ALIGN - 1);
	grub_uint64_t end, i, count, used = 0;
	grub_uint8_t header[16];

	if (off > img->file_size || part->stream_size > img->file_size - off
		|| part->stream_size < bitmap_disk_size)
		return okr_bad ("invalid partition stream bounds");
	end = off + part->stream_size;
	part->bitmap = okr_alloc_metadata (img, bytes);
	part->rank = okr_alloc_metadata (img, ((bytes + 511) / 512) * sizeof (*part->rank));
	if (!part->bitmap || !part->rank)
		return grub_errno;
	if (okr_read_at (img, off, part->bitmap, (grub_size_t) bytes))
		return grub_errno;
	if ((units & 7) && (part->bitmap[bytes - 1] >> (units & 7)))
		return okr_bad ("bitmap has out-of-partition bits");
	for (i = 0; i < bytes; i++)
	{
		if (!(i & 511))
			part->rank[i / 512] = used;
		used += okr_popcount (part->bitmap[i]);
	}
	part->used = used * OKR_UNIT;
	count = (part->used + img->block_size - 1) / img->block_size;
	if (count > OKR_METADATA_MAX / sizeof (*part->chunks))
		return okr_bad ("too many data chunks");
	part->count = (grub_uint32_t) count;
	if (count)
	{
		part->chunks = okr_alloc_metadata (img, count * sizeof (*part->chunks));
		if (!part->chunks)
			return grub_errno;
	}
	off += bitmap_disk_size;
	for (i = 0; i < count; i++)
	{
		struct okr_chunk *chunk = &part->chunks[i];
		grub_uint32_t magic, aligned, expected;
		grub_uint64_t remaining = part->used - i * img->block_size;

		if (end - off < sizeof (header) || okr_read_at (img, off, header, sizeof (header)))
			return okr_bad ("truncated chunk header");
		magic = okr_u32 (header);
		chunk->stored = okr_u32 (header + 4);
		aligned = okr_u32 (header + 8);
		expected = remaining < img->block_size ? (grub_uint32_t) remaining : img->block_size;
		if (magic == OKR_COMPRESSED || magic == 0x676a6763U)
			chunk->compressed = 1;
		else if (magic != OKR_STORED && magic != 0x676a6762U)
			return okr_bad ("unknown chunk compression");
		if (!chunk->stored || chunk->stored > (grub_uint32_t) LZ4_COMPRESSBOUND (expected)
			|| (!chunk->compressed && chunk->stored != expected)
			|| aligned != ((chunk->stored + 16 + OKR_ALIGN - 1) & ~(OKR_ALIGN - 1))
			|| aligned > end - off)
			return okr_bad ("invalid chunk size or alignment");
		chunk->offset = off + 16;
		off += aligned;
	}
	if (off != end)
		return okr_bad ("bitmap and partition stream disagree");
	return GRUB_ERR_NONE;
}

/* Hash a sequence of regions, grouping the selected bytes in 2 MiB chunks.
   For large files the reference feeds 18 windows without resetting the inner
   hash at window boundaries and appends the final digest even when empty. */
static grub_err_t
okr_hash_segment (grub_file_t file, int last, int split, void *outer, void *inner,
	grub_uint8_t *buffer)
{
	const gcry_md_spec_t *md = GRUB_MD_SHA256;
	grub_uint64_t size = file->size;
	grub_uint64_t limit = split ? (5U << 20) : (10U << 20);
	grub_uint32_t group = 0, window, windows = size > (340U << 20) ? 18 : 1;

	md->init (inner, 0);
	for (window = 0; window < windows; window++)
	{
		grub_uint64_t off = 0, length = size - (last ? 32 : 0);

		if (windows != 1)
		{
			length = limit;
			off = window == 17 ? size - limit - (last ? 32 : 0) : window * (size / 17);
		}
		while (length)
		{
			grub_size_t n = length > 65536 ? 65536 : (grub_size_t) length;

			if (n > OKR_HASH_GROUP - group)
				n = OKR_HASH_GROUP - group;
			if (okr_pread (file, off, buffer, n))
				return grub_errno;
			md->write (inner, buffer, n);
			group += (grub_uint32_t) n;
			off += n;
			length -= n;
			if (group == OKR_HASH_GROUP)
			{
				md->final (inner);
				md->write (outer, md->read (inner), 32);
				md->init (inner, 0);
				group = 0;
			}
		}
	}
	if (group || windows != 1)
	{
		md->final (inner);
		md->write (outer, md->read (inner), 32);
	}
	return GRUB_ERR_NONE;
}

static grub_err_t
okr_verify (struct okr_image *img)
{
	const gcry_md_spec_t *md = GRUB_MD_SHA256;
	void *outer = NULL, *inner = NULL;
	grub_uint8_t *buffer = NULL;
	grub_uint8_t salt[32], iteration, expected[32], actual[32];
	grub_file_t first = img->source, last = img->segments[img->nsegments - 1].file;
	grub_uint32_t i;
	grub_err_t err = GRUB_ERR_NONE;

	outer = grub_malloc (md->contextsize);
	inner = grub_malloc (md->contextsize);
	buffer = grub_malloc (65536);
	if (!outer || !inner || !buffer)
		goto fail;
	md->init (outer, 0);
	for (i = 0; i < img->nsegments; i++)
	{
		if (okr_hash_segment (img->segments[i].file, i + 1 == img->nsegments,
			img->nsegments > 1, outer, inner, buffer))
			goto fail;
	}
	md->final (outer);
	if (okr_pread (first, first->size / 2, salt, sizeof (salt))
		|| okr_pread (first, first->size / 3, &iteration, 1)
		|| okr_pread (last, last->size - 32, expected, 32))
		goto fail;
	if (grub_crypto_pbkdf2 (md, md->read (outer), 32, salt, 32, 3000 + iteration, actual, 32))
	{
		okr_bad ("cannot compute image checksum");
		goto fail;
	}
	if (grub_memcmp (actual, expected, 32))
	{
		okr_bad ("image checksum mismatch");
		goto fail;
	}
	grub_free (outer);
	grub_free (inner);
	grub_free (buffer);
	return GRUB_ERR_NONE;
fail:
	err = grub_errno;
	grub_free (outer);
	grub_free (inner);
	grub_free (buffer);
	return err;
}

/* Validate a possible firmware pointer width before allocating stream data. */
static unsigned
okr_parts (const grub_uint8_t *table, unsigned count, unsigned stride,
	grub_uint64_t disk_sectors, struct okr_part *parts)
{
	unsigned i, j, backed = 0;
	int disk = -1;

	for (i = 0; i < count; i++)
	{
		const grub_uint8_t *p = table + i * stride;
		grub_uint64_t start = okr_u64 (p), sectors = okr_u64 (p + 16), stream = okr_u64 (p + 56);

		if (p[42] > 1)
			return 0;
		if (!p[42])
		{
			if (stream)
				return 0;
			continue;
		}
		/* The writer can disable an empty/failed partition and leave its size 0. */
		if (!stream)
			continue;
		if (!sectors || start >= disk_sectors || sectors > disk_sectors - start
			|| (stream & (OKR_ALIGN - 1)) || (disk >= 0 && disk != p[43]))
			return 0;
		disk = p[43];
		for (j = 0; j < backed; j++)
			if (start * 512 < parts[j].start + parts[j].size
				&& parts[j].start < (start + sectors) * 512)
				return 0;
		parts[backed].start = start * 512;
		parts[backed].size = sectors * 512;
		parts[backed].stream_size = stream;
		grub_memcpy (parts[backed].type, p + 64, 16);
		grub_memcpy (parts[backed].guid, p + 80, 16);
		grub_memcpy (parts[backed].label, p + 96, 64);
		backed++;
	}
	return backed;
}

static grub_uint32_t
okr_crc32 (const void *buffer, grub_size_t len)
{
	const grub_uint8_t *p = buffer;
	grub_uint32_t crc = 0xffffffffU;
	unsigned bit;

	while (len--)
	{
		crc ^= *p++;
		for (bit = 0; bit < 8; bit++)
			crc = (crc >> 1) ^ ((crc & 1) ? 0xedb88320U : 0);
	}
	return ~crc;
}

static grub_err_t
okr_gpt (struct okr_image *img, grub_uint64_t sectors)
{
	static const grub_uint8_t data_type[16] = {
		0xa2, 0xa0, 0xd0, 0xeb, 0xe5, 0xb9, 0x33, 0x44,
		0x87, 0xc0, 0x68, 0xb6, 0xb7, 0x26, 0x99, 0xc7
	};
	static const grub_uint8_t zero[16] = { 0 };
	struct grub_gpt_header *hdr, *backup;
	struct grub_gpt_partentry *entries;
	struct grub_msdos_partition_mbr *mbr;
	unsigned i;

	img->primary = grub_zalloc (OKR_GPT_BYTES);
	img->backup = grub_zalloc (33 * 512);
	if (!img->primary || !img->backup)
		return grub_errno;
	mbr = (struct grub_msdos_partition_mbr *) img->primary;
	mbr->signature = grub_cpu_to_le16_compile_time (0xaa55);
	mbr->entries[0].type = 0xee;
	mbr->entries[0].start = grub_cpu_to_le32_compile_time (1);
	mbr->entries[0].length = grub_cpu_to_le32 (sectors - 1 > 0xffffffffU ? 0xffffffffU : (grub_uint32_t) (sectors - 1));
	hdr = (struct grub_gpt_header *) (img->primary + 512);
	entries = (struct grub_gpt_partentry *) (img->primary + 1024);
	for (i = 0; i < img->nparts; i++)
	{
		struct okr_part *part = &img->parts[i];

		if (part->start < OKR_GPT_BYTES || sectors < 68
			|| (part->start + part->size) / 512 > sectors - 33)
			return okr_bad ("partitions leave no room for virtual GPT");
		grub_memcpy (&entries[i].type, grub_memcmp (part->type, zero, 16) ? part->type : data_type, 16);
		grub_memcpy (&entries[i].guid, part->guid, 16);
		if (!grub_memcmp (part->guid, zero, 16))
		{
			grub_memcpy (&entries[i].guid, "ROVER-OKR-PART", 14);
			((grub_uint8_t *) &entries[i].guid)[15] = (grub_uint8_t) (i + 1);
		}
		entries[i].start = grub_cpu_to_le64 (part->start / 512);
		entries[i].end = grub_cpu_to_le64 ((part->start + part->size) / 512 - 1);
		grub_memcpy (entries[i].name, part->label, 64);
	}
	grub_memcpy (hdr->magic, "EFI PART", 8);
	hdr->version = grub_cpu_to_le32_compile_time (0x10000);
	hdr->headersize = grub_cpu_to_le32 ((grub_uint32_t) sizeof (*hdr));
	hdr->primary = grub_cpu_to_le64_compile_time (1);
	hdr->backup = grub_cpu_to_le64 (sectors - 1);
	hdr->start = grub_cpu_to_le64_compile_time (34);
	hdr->end = grub_cpu_to_le64 (sectors - 34);
	grub_memcpy (&hdr->guid, "ROVER-OKR-DISK", 14);
	hdr->partitions = grub_cpu_to_le64_compile_time (2);
	hdr->maxpart = grub_cpu_to_le32_compile_time (128);
	hdr->partentry_size = grub_cpu_to_le32_compile_time (128);
	hdr->partentry_crc32 = grub_cpu_to_le32 (okr_crc32 (entries, 128 * 128));
	hdr->crc32 = grub_cpu_to_le32 (okr_crc32 (hdr, sizeof (*hdr)));
	grub_memcpy (img->backup, entries, 128 * 128);
	backup = (struct grub_gpt_header *) (img->backup + 32 * 512);
	grub_memcpy (backup, hdr, sizeof (*hdr));
	backup->primary = hdr->backup;
	backup->backup = hdr->primary;
	backup->partitions = grub_cpu_to_le64 (sectors - 33);
	backup->crc32 = 0;
	backup->crc32 = grub_cpu_to_le32 (okr_crc32 (backup, sizeof (*backup)));
	return GRUB_ERR_NONE;
}

static grub_err_t
okr_parse (struct okr_image *img)
{
	grub_uint8_t prefix[0x118], *header = NULL;
	struct okr_part *alternate = NULL;
	grub_uint32_t version, table, fields, size, count, data, gpt, i, other;
	grub_uint64_t sectors, physical = 0, off, original = 0;
	grub_err_t err;

	if (okr_pread (img->source, 0, prefix, sizeof (prefix)))
		goto fail;
	version = okr_u32 (prefix + 4);
	if (version != 0x09000810 && version != 0x09000811)
	{
		okr_bad ("unsupported header version");
		goto fail;
	}
	table = version == 0x09000810 ? 0x200 : 0x1e20;
	fields = version == 0x09000810 ? 0x118 : 0x538;
	size = okr_u32 (prefix + 8);
	sectors = okr_u64 (prefix + 0x110);
	img->file_size = okr_u64 (prefix + 0x108);
	if (size < table || size > ((table + OKR_PARTS * 176 + 511) & ~511U)
		|| (size & 511) || !sectors || sectors > (OKR_OFFSET_MAX - OKR_UNIT) / 512
		|| img->file_size > OKR_OFFSET_MAX - 32)
	{
		okr_bad ("invalid header bounds");
		goto fail;
	}
	header = grub_malloc (size);
	alternate = grub_zalloc (sizeof (img->parts));
	if (!header || !alternate)
		goto fail;
	if (okr_pread (img->source, 0, header, size))
		goto fail;
	count = header[fields + 2] | ((grub_uint32_t) header[fields + 3] << 8);
	gpt = okr_u32 (header + fields + 4);
	img->block_size = okr_u32 (header + fields + 12);
	data = okr_u32 (header + fields + 24);
	img->nsegments = okr_u32 (header + fields + 28);
	if (!count || count > OKR_PARTS || !img->nsegments || img->nsegments > OKR_SEGMENTS
		|| header[fields + 9] != 1 || header[0x100] > 1 || header[fields + 8] > 1
		|| img->block_size < OKR_UNIT || img->block_size > OKR_BLOCK_MAX
		|| (img->block_size % OKR_UNIT) || gpt < 512 || gpt > 128 * 512 || (gpt & 511)
		|| data < size + gpt || (data & 511) || data > img->file_size)
	{
		okr_bad ("invalid or incomplete image header");
		goto fail;
	}
	if (size == ((table + count * 176 + 511) & ~511U))
		img->nparts = okr_parts (header + table, count, 176, sectors, img->parts);
	other = 0;
	if (size == ((table + count * 172 + 511) & ~511U))
		other = okr_parts (header + table, count, 172, sectors, alternate);
	/* A candidate must account for every stream byte, not just plausible rows. */
	physical = 0;
	for (i = 0; i < img->nparts; i++)
	{
		if (img->parts[i].stream_size > img->file_size - data - physical)
			break;
		physical += img->parts[i].stream_size;
	}
	if (i != img->nparts || physical != img->file_size - data)
		img->nparts = 0;
	physical = 0;
	for (i = 0; i < other; i++)
	{
		if (alternate[i].stream_size > img->file_size - data - physical)
			break;
		physical += alternate[i].stream_size;
	}
	if (i != other || physical != img->file_size - data)
		other = 0;
	physical = 0;
	if (other && img->nparts && (other != img->nparts
		|| grub_memcmp (alternate, img->parts, other * sizeof (*alternate))))
	{
		okr_bad ("ambiguous partition record width");
		goto fail;
	}
	if (!img->nparts && other)
	{
		img->nparts = other;
		grub_memcpy (img->parts, alternate, sizeof (img->parts));
	}
	if (!img->nparts)
	{
		okr_bad ("invalid or missing backed partitions");
		goto fail;
	}
	img->segments = grub_zalloc (img->nsegments * sizeof (*img->segments));
	if (!img->segments)
		goto fail;
	for (i = 0; i < img->nsegments; i++)
	{
		grub_file_t file = img->source;

		if (i)
		{
			char *name;

			if (!img->source->name)
			{
				okr_bad ("split image has no source name");
				goto fail;
			}
			name = grub_xasprintf ("%s.%u", img->source->name, i);
			if (!name)
				goto fail;
			if (img->source->fs && (!grub_strcmp (img->source->fs->name, "winfile")
				|| !grub_strcmp (img->source->fs->name, "posixfile")))
				file = grub_hostfile_open (name, GRUB_FILE_TYPE_LOOPBACK | GRUB_FILE_TYPE_NO_DECOMPRESS);
			else
				file = grub_file_open (name, GRUB_FILE_TYPE_LOOPBACK | GRUB_FILE_TYPE_NO_DECOMPRESS);
			grub_free (name);
			if (!file)
				goto fail;
		}
		img->segments[i].file = file;
		img->segments[i].start = physical;
		if (!file->size || file->size > img->file_size + 32 - physical)
		{
			okr_bad ("invalid segment length");
			goto fail;
		}
		physical += file->size;
	}
	if (physical != img->file_size && physical != img->file_size + 32)
	{
		okr_bad ("segment lengths disagree with FileSize");
		goto fail;
	}
	if (physical != img->file_size)
	{
		if (img->segments[img->nsegments - 1].file->size < 32 || okr_verify (img))
		{
			if (!grub_errno)
				okr_bad ("truncated checksum");
			goto fail;
		}
	}
	off = data;
	for (i = 0; i < img->nparts; i++)
	{
		if (okr_index_part (img, &img->parts[i], off))
			goto fail;
		off += img->parts[i].stream_size;
		original += img->parts[i].used;
	}
	if (off != img->file_size || original != okr_u64 (header + fields + 16))
	{
		okr_bad ("image data totals disagree");
		goto fail;
	}
	img->size = img->nparts == 1 ? img->parts[0].size : sectors * 512;
	if (img->nparts == 1)
		img->parts[0].start = 0;
	else if (okr_gpt (img, sectors))
		goto fail;
	grub_free (header);
	grub_free (alternate);
	return GRUB_ERR_NONE;
fail:
	err = grub_errno;
	grub_free (header);
	grub_free (alternate);
	return err;
}

static grub_err_t
okr_load (struct okr_image *img, const struct okr_part *part, grub_uint32_t index)
{
	const struct okr_chunk *chunk = &part->chunks[index];
	grub_uint64_t remaining = part->used - (grub_uint64_t) index * img->block_size;
	grub_uint32_t expected = remaining < img->block_size ? (grub_uint32_t) remaining : img->block_size;
	void *buffer;

	if (img->cached == chunk)
		return GRUB_ERR_NONE;
	/* Failed reads/decodes must never leave the previous key on new bytes. */
	img->cached = NULL;
	if (img->plain_capacity < expected)
	{
		buffer = grub_realloc (img->plain, expected);
		if (!buffer)
			return grub_errno;
		img->plain = buffer;
		img->plain_capacity = expected;
	}
	if (chunk->compressed)
	{
		int decoded;

		if (img->stored_capacity < chunk->stored)
		{
			buffer = grub_realloc (img->stored, chunk->stored);
			if (!buffer)
				return grub_errno;
			img->stored = buffer;
			img->stored_capacity = chunk->stored;
		}
		if (okr_read_at (img, chunk->offset, img->stored, chunk->stored))
			return grub_errno;
		decoded = LZ4_decompress_safe ((const char *) img->stored, (char *) img->plain,
			(int) chunk->stored, (int) expected);
		if (decoded != (int) expected)
			return okr_bad ("invalid LZ4 data or decoded length");
	}
	else if (okr_read_at (img, chunk->offset, img->plain, expected))
		return grub_errno;
	img->cached = chunk;
	return GRUB_ERR_NONE;
}

static grub_ssize_t
grub_okr_read (grub_file_t file, char *buf, grub_size_t len)
{
	struct okr_image *img = file->data;
	grub_uint64_t off = file->offset;
	grub_size_t total = len;

	while (len)
	{
		struct okr_part *part = NULL;
		grub_uint64_t end = img->size;
		grub_size_t n = len;
		unsigned i;

		if (img->primary && off < OKR_GPT_BYTES)
		{
			if (n > OKR_GPT_BYTES - off)
				n = (grub_size_t) (OKR_GPT_BYTES - off);
			grub_memcpy (buf, img->primary + (grub_size_t) off, n);
		}
		else if (img->backup && off >= img->size - 33 * 512)
		{
			if (n > img->size - off)
				n = (grub_size_t) (img->size - off);
			grub_memcpy (buf, img->backup + (grub_size_t) (off - (img->size - 33 * 512)), n);
		}
		else
		{
			if (img->backup)
				end -= 33 * 512;
			for (i = 0; i < img->nparts; i++)
			{
				struct okr_part *p = &img->parts[i];

				if (off >= p->start && off - p->start < p->size)
					part = p;
				else if (p->start > off && p->start < end)
					end = p->start;
			}
			if (!part)
			{
				if (n > end - off)
					n = (grub_size_t) (end - off);
				grub_memset (buf, 0, n);
			}
			else
			{
				grub_uint64_t relative = off - part->start;
				grub_uint64_t unit = relative / OKR_UNIT;
				grub_uint32_t within = (grub_uint32_t) (relative % OKR_UNIT);

				if (n > OKR_UNIT - within)
					n = OKR_UNIT - within;
				if (n > part->size - relative)
					n = (grub_size_t) (part->size - relative);
				if (!(part->bitmap[unit >> 3] & (1U << (unit & 7))))
					grub_memset (buf, 0, n);
				else
				{
					grub_uint64_t packed = okr_rank (part, unit) * OKR_UNIT + within;
					grub_uint32_t chunk = (grub_uint32_t) (packed / img->block_size);
					grub_uint32_t position = (grub_uint32_t) (packed % img->block_size);

					if (okr_load (img, part, chunk))
						return -1;
					grub_memcpy (buf, img->plain + position, n);
				}
			}
		}
		if (!n)
		{
			okr_bad ("read made no progress");
			return -1;
		}
		off += n;
		buf += n;
		len -= n;
	}
	return (grub_ssize_t) total;
}

static void
okr_free (struct okr_image *img)
{
	unsigned i;

	if (img->segments)
		for (i = 1; i < img->nsegments; i++)
			if (img->segments[i].file)
				grub_file_close (img->segments[i].file);
	for (i = 0; i < OKR_PARTS; i++)
	{
		grub_free (img->parts[i].bitmap);
		grub_free (img->parts[i].rank);
		grub_free (img->parts[i].chunks);
	}
	grub_free (img->segments);
	grub_free (img->primary);
	grub_free (img->backup);
	grub_free (img->plain);
	grub_free (img->stored);
	grub_free (img);
}

static grub_err_t
grub_okr_close (grub_file_t file)
{
	struct okr_image *img = file->data;
	grub_file_t source = img->source;

	okr_free (img);
	grub_file_close (source);
	file->device = NULL;
	return grub_errno;
}

static grub_file_t
grub_okr_open (grub_file_t io, enum grub_file_type type)
{
	grub_uint8_t magic[4];
	struct okr_image *img = NULL;
	grub_file_t file = NULL;
	grub_err_t err;

	if (!(type & GRUB_FILE_TYPE_FILTER_VDISK) || io->size == GRUB_FILE_SIZE_UNKNOWN || io->size < 4)
		return io;
	if (okr_pread (io, 0, magic, 4) || grub_memcmp (magic, "okr9", 4))
	{
		grub_file_seek (io, 0);
		grub_errno = GRUB_ERR_NONE;
		return io;
	}
	img = grub_zalloc (sizeof (*img));
	if (!img)
		goto fail;
	img->source = io;
	if (okr_parse (img))
		goto fail;
	file = grub_zalloc (sizeof (*file));
	if (!file)
		goto fail;
	file->device = io->device;
	file->data = img;
	file->fs = &grub_okr_fs;
	file->size = img->size;
	file->not_easily_seekable = io->not_easily_seekable;
	return file;
fail:
	err = grub_errno;
	if (img)
		okr_free (img);
	grub_free (file);
	grub_errno = err;
	return NULL;
}

static struct grub_fs grub_okr_fs =
{
	.name = "okr",
	.fs_read = grub_okr_read,
	.fs_close = grub_okr_close
};

GRUB_MOD_INIT (okr)
{
	grub_file_filter_register (GRUB_FILE_FILTER_OKR, grub_okr_open);
}

GRUB_MOD_FINI (okr)
{
	grub_file_filter_unregister (GRUB_FILE_FILTER_OKR);
}
