/* Real GRUB printf regression probe. GPL-3.0-or-later. */
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <stdarg.h>
#ifdef _WIN32
#include <windows.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#endif
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/types.h>
#include "rover.h"

static unsigned failures, checks;

static void
check_bytes (const char *fmt, const char *expected, size_t len, va_list ap)
{
	char actual[512];
	va_list copy;
	size_t cap;
	int result;
	char *allocated;

	for (cap = 1; cap <= len + 2; cap++)
	{
		size_t kept = len < cap - 1 ? len : cap - 1;
		memset (actual, 0x5a, sizeof (actual));
		va_copy (copy, ap);
		result = grub_vsnprintf (actual, cap, fmt, copy);
		va_end (copy);
		checks++;
		if (result != (int) len || memcmp (actual, expected, kept)
			|| actual[kept] != 0 || actual[cap] != 0x5a)
		{
			fprintf (stderr, "FAIL format [%s], cap=%zu: got [%s] (%d), expected length %zu\n",
				fmt, cap, actual, result, len);
			failures++;
			break;
		}
	}
	va_copy (copy, ap);
	allocated = grub_xvasprintf (fmt, copy);
	va_end (copy);
	checks++;
	if (!allocated || memcmp (allocated, expected, len + 1))
	{
		fprintf (stderr, "FAIL allocated format [%s]\n", fmt);
		failures++;
	}
	grub_free (allocated);
}

static void
expect (const char *expected, const char *fmt, ...)
{
	va_list ap;
	va_start (ap, fmt);
	check_bytes (fmt, expected, strlen (expected), ap);
	va_end (ap);
}

static void
compare (const char *fmt, ...)
{
	char expected[256];
	va_list ap, copy;
	int len;
	va_start (ap, fmt);
	va_copy (copy, ap);
	len = vsnprintf (expected, sizeof (expected), fmt, copy);
	va_end (copy);
	if (len < 0 || len >= (int) sizeof (expected))
	{
		fprintf (stderr, "FAIL test oracle overflow\n");
		failures++;
	}
	else
		check_bytes (fmt, expected, (size_t) len, ap);
	va_end (ap);
}

static void
check_format (const char *fmt, const char *expected, int valid)
{
	int result = grub_printf_fmt_check (fmt, expected) == GRUB_ERR_NONE;
	checks++;
	if (result != valid)
	{
		fprintf (stderr, "FAIL format check [%s] against [%s]\n", fmt, expected);
		failures++;
	}
	grub_errno = GRUB_ERR_NONE;
}

/* Put NUL at the last readable byte: even a one-byte overread faults. */
static int
check_trailing (void)
{
	const char *suffixes[] = { "%", "%l", "%ll", "%z", "%.", "%5", "%-", "%+", "%#", "%*", "%.*", "%1$", "%1$*2$", "%1$.*2$" };
	size_t page, i;
	char *memory;
#ifdef _WIN32
	SYSTEM_INFO info;
	DWORD old;
	GetSystemInfo (&info);
	page = info.dwPageSize;
	memory = VirtualAlloc (NULL, page * 2, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!memory)
		goto fail;
	if (!VirtualProtect (memory + page, page, PAGE_NOACCESS, &old))
		goto fail;
#else
	page = (size_t) sysconf (_SC_PAGESIZE);
	memory = mmap (NULL, page * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (memory == MAP_FAILED)
		return 1;
	if (mprotect (memory + page, page, PROT_NONE))
		goto fail;
#endif
	for (i = 0; i < sizeof (suffixes) / sizeof (suffixes[0]); i++)
	{
		size_t len = strlen (suffixes[i]);
		char *fmt = memory + page - len - 3;
		memcpy (fmt, "ok", 2);
		memcpy (fmt + 2, suffixes[i], len + 1);
		expect ("ok", fmt);
		check_format (fmt, "", 0);
	}
#ifdef _WIN32
	VirtualFree (memory, 0, MEM_RELEASE);
#else
	munmap (memory, page * 2);
#endif
	return 0;
fail:
#ifdef _WIN32
	if (memory)
		VirtualFree (memory, 0, MEM_RELEASE);
#else
	munmap (memory, page * 2);
#endif
	return 1;
}

int
product_printf_probe (const char *mode)
{
	int status = 1;
	unsigned i, j;
	char long_text[301];
	const int values[] = { 0, 1, -1, 42, -42, INT_MIN, INT_MAX };
	const char *signed_formats[] = { "%d", "%05d", "%-05d", "%+06d", "% 06d", "%+ d", "%.0d", "%.d", "%8.4d", "%08.4d", "%-.4d", "%+8.0d" };
	const char *unsigned_formats[] = { "%u", "%#08x", "%#08X", "%#o", "%#.0o", "%#.0x", "%#8.4x", "%#08.4o", "%-#8x" };
	grub_packed_guid_t guid = { 0x12345678, 0x9abc, 0xdef0, { 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0 } };

	failures = checks = 0;
	rover_init (ROVER_INIT_NO_HOSTDISK);
	if (!strcmp (mode, "trailing"))
	{
		if (check_trailing ())
			goto fail;
	}
	else if (!strcmp (mode, "null"))
		expect ("(null)", "%pG", (void *) NULL);
	else if (!strcmp (mode, "minimum"))
		compare ("%lld", LLONG_MIN);
	else
	{
		for (i = 0; i < sizeof (values) / sizeof (values[0]); i++)
		{
			for (j = 0; j < sizeof (signed_formats) / sizeof (signed_formats[0]); j++)
				compare (signed_formats[j], values[i]);
			for (j = 0; j < sizeof (unsigned_formats) / sizeof (unsigned_formats[0]); j++)
				compare (unsigned_formats[j], (unsigned) values[i]);
		}
		compare ("[%5c][%-5c][%c]", 'A', 'A', 0);
		compare ("[%*c][%*s][%.*s]", -5, 'A', 8, "abc", -1, "abcdef");
		compare ("%*d:%d:%s", 6, 23, 77, "tail");
		compare ("%*.*d:%s", -8, 4, -23, "tail");
		compare ("%0*.*d", 8, -1, -23);
		compare ("%.*s|%8.3s|%-8s|%.s", 3, "abcdef", "abcdef", "xyz", "hidden");
		compare ("%ld:%lu:%lld:%llu:%llx", LONG_MIN, ULONG_MAX, LLONG_MIN, ULLONG_MAX, ULLONG_MAX);
		compare ("%zd:%zu:%zx", (grub_ssize_t) -1, (size_t) -1, (size_t) 0xdeadbeef);
		compare ("%d%%|%%|%d", 10, 20);
		expect ("3 2 1", "%3$d %2$lld %1$d", 1, 2LL, 3);
		expect ("    0023|end", "%3$*1$.*2$d|%4$s", 8, 4, 23, "end");
		expect ("yes/yes", "%1$s/%1$s", "yes");
		expect ("    A|A    |  \xe4\xb8\xad|\xe4\xb8\xad  ", "%5C|%-5C|%5C|%-5C", 'A', 'A', 0x4e2d, 0x4e2d);
		expect ("?", "%C", 0x110000);
		expect ("  \xc2\xa2| \xf0\x9f\x98\x80", "%4C|%5C", 0xa2, 0x1f600);
		memset (long_text, 'a', sizeof (long_text) - 1);
		long_text[sizeof (long_text) - 1] = 0;
		expect (long_text, "%s", long_text);
		expect ("111111111111111111111111111111111",
			"%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d%d",
			1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1);
		expect ("0x0|0x123", "%p|%p", (void *) NULL, (void *) (grub_addr_t) 0x123);
		expect ("12345678-9abc-def0-1234-56789abcdef0", "%pG", &guid);
		expect ("(null)", "%s", (char *) NULL);
		check_format ("%+08d %#x %*.*s", "%d %x %d %d %s", 1);
		check_format ("%*s", "%s", 0);
		check_format ("%.*s", "%u %s", 0);
		check_format ("%1$d", "%d", 0);
		check_format ("%*1$d", "%d %d", 0);
		check_format ("%.*1$d", "%d %d", 0);
		check_format ("%pG", "%s", 0);
		check_format ("%pG", "%pG", 1);
		check_format ("%% %s", "%s %d", 1);
		check_format ("%q", "", 0);
	}
	status = failures != 0;
	printf ("printf %s: %u checks, %u failures\n", mode, checks, failures);
fail:
	rover_fini ();
	return status;
}
