/* misc.c - definitions of misc functions */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 1999,2000,2001,2002,2003,2004,2005,2006,2007,2008,2009,2010  Free Software Foundation, Inc.
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/misc.h>
#include <grub/err.h>
#include <grub/mm.h>
#include <stdarg.h>
#include <grub/term.h>
#include <grub/env.h>
#include <grub/i18n.h>
#include <grub/types.h>
#include <grub/charset.h>
#include <stddef.h>

union printf_arg
{
  /* Yes, type is also part of union as the moment we fill the value
     we don't need to store its type anymore (when we'll need it, we'll
     have format spec again. So save some space.  */
  enum
    {
      INT, LONG, LONGLONG,
      UNSIGNED_INT = 3, UNSIGNED_LONG, UNSIGNED_LONGLONG,
      STRING,
      UUID,
      UNUSED
    } type;
  long long ll;
};

struct printf_args
{
  union printf_arg prealloc[32];
  union printf_arg *ptr;
  grub_size_t count;
};

static void
parse_printf_args (const char *fmt0, struct printf_args *args,
		   va_list args_in);
static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0,
		     struct printf_args *args);

static void
free_printf_args (struct printf_args *args)
{
  if (args->ptr != args->prealloc)
    grub_free (args->ptr);
}

static int
grub_iswordseparator (int c)
{
  return (grub_isspace (c) || c == ',' || c == ';' || c == '|' || c == '&');
}

/* grub_gettext_dummy is not translating anything.  */
static const char *
grub_gettext_dummy (const char *s)
{
  return s;
}

const char* (*grub_gettext) (const char *s) = grub_gettext_dummy;

#define ALIGN_MASK (sizeof (grub_addr_t) - 1)
/* Set the threshold to (2 * sizeof(grub_addr_t)) to guarantee at least one word copy. */
#define WORD_COPY_THRES (sizeof (grub_addr_t) * 2)

static void *
memmove_fwd (void *dest, const void *src, grub_size_t n)
{
  grub_uint8_t *d = (grub_uint8_t *) dest;
  const grub_uint8_t *s = (const grub_uint8_t *) src;
  grub_size_t offset = 0;
  grub_addr_t *dw;
  const grub_addr_t *sw;

  /*
   * Fallback to byte-by-byte copy if the buffers are too small or do not share the same
   * alignment offset.
   */
  if (n < WORD_COPY_THRES || (((grub_addr_t) d ^ (grub_addr_t) s) & ALIGN_MASK) != 0)
    goto byte_copy;

  /* Consume the first few bytes to make 'd' and 's' aligned */
  offset = (-((grub_addr_t) d)) & ALIGN_MASK;
  n -= offset;
  while (offset--)
    *d++ = *s++;

  /*
   * Copy data in chunks
   * Although 'd' and 's' are already aligned, casting to "grub_addr_t *" still
   * triggers "cast-align" errors. Cast them to "void *" to silence the error.
   */
  dw = (grub_addr_t *)(void *) d;
  sw = (const grub_addr_t *)(const void *) s;

  for (; n >= sizeof (grub_addr_t); n -= sizeof (grub_addr_t))
    *dw++ = *sw++;

  d = (grub_uint8_t *) dw;
  s = (const grub_uint8_t *) sw;

byte_copy:
  /* Finish the remaining bytes */
  while (n--)
    *d++ = *s++;

  return dest;
}

static void *
memmove_bwd (void *dest, const void *src, grub_size_t n)
{
  grub_uint8_t *d = (grub_uint8_t *) dest + n;
  const grub_uint8_t *s = (const grub_uint8_t *) src + n;
  grub_size_t offset = 0;
  grub_addr_t *dw;
  const grub_addr_t *sw;

  /*
   * Fallback to byte-by-byte copy if the buffers are too small or do not share the same
   * alignment offset.
   */
  if (n < WORD_COPY_THRES || (((grub_addr_t) d ^ (grub_addr_t) s) & ALIGN_MASK) != 0)
    goto byte_copy;

  /* Consume the last few bytes to make 'd' and 's' aligned */
  offset = (grub_addr_t) d & ALIGN_MASK;
  n -= offset;
  while (offset--)
    *--d = *--s;

  /*
   * Copy data in chunks
   * Although 'd' and 's' are already aligned, casting to "grub_addr_t *" still
   * triggers "cast-align" errors. Cast them to "void *" to silence the error.
   */
  dw = (grub_addr_t *)(void *) d;
  sw = (const grub_addr_t *)(const void *) s;

  for (; n >= sizeof (grub_addr_t); n -= sizeof (grub_addr_t))
    *--dw = *--sw;

  d = (grub_uint8_t *) dw;
  s = (const grub_uint8_t *) sw;

byte_copy:
  /* Finish the remaining bytes */
  while (n--)
    *--d = *--s;

  return dest;
}

void *
grub_memmove (void *dest, const void *src, grub_size_t n)
{
  char *d = (char *) dest;
  const char *s = (const char *) src;

  if (d < s || s + n <= d)
    return memmove_fwd (dest, src, n);

  /* Perform backward copy if dest >= src and buffers overlap to ensure memory safety. */
  return memmove_bwd (dest, src, n);
}

char *
grub_strcpy (char *dest, const char *src)
{
  char *p = dest;

  while ((*p++ = *src++) != '\0')
    ;

  return dest;
}

int
grub_printf (const char *fmt, ...)
{
  va_list ap;
  int ret;

#if defined(MM_DEBUG) && !defined(GRUB_UTIL) && !defined (GRUB_MACHINE_EMU)
  /*
   * To prevent infinite recursion when grub_mm_debug is on, disable it
   * when calling grub_vprintf(). One such call loop is:
   *   grub_vprintf() -> parse_printf_args() -> parse_printf_arg_fmt() ->
   *     grub_debug_calloc() -> grub_printf() -> grub_vprintf().
   */
  int grub_mm_debug_save = 0;

  if (grub_mm_debug)
    {
      grub_mm_debug_save = grub_mm_debug;
      grub_mm_debug = 0;
    }
#endif

  va_start (ap, fmt);
  ret = grub_vprintf (fmt, ap);
  va_end (ap);

#if defined(MM_DEBUG) && !defined(GRUB_UTIL) && !defined (GRUB_MACHINE_EMU)
  grub_mm_debug = grub_mm_debug_save;
#endif

  return ret;
}

int
grub_printf_ (const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vprintf (_(fmt), ap);
  va_end (ap);

  return ret;
}

int
grub_puts_ (const char *s)
{
  return grub_puts (_(s));
}

#if ( defined (__APPLE__) || defined (_MSC_VER) ) && ! defined (GRUB_UTIL)
int
grub_err_printf (const char *fmt, ...)
{
	va_list ap;
	int ret;

	va_start (ap, fmt);
	ret = grub_vprintf (fmt, ap);
	va_end (ap);

	return ret;
}
#endif

#if ! defined (__APPLE__) && ! defined (_MSC_VER) && ! defined (GRUB_UTIL)
int grub_err_printf (const char *fmt, ...)
__attribute__ ((alias("grub_printf")));
#endif

int
grub_debug_enabled (const char * condition)
{
  const char *debug, *found;
  grub_size_t clen;
  int ret = 0;

  debug = grub_env_get ("debug");
  if (!debug)
    return 0;

  if (grub_strword (debug, "all"))
    {
      if (debug[3] == '\0')
	return 1;
      ret = 1;
    }

  clen = grub_strlen (condition);
  found = debug-1;
  while(1)
    {
      found = grub_strstr (found+1, condition);

      if (found == NULL)
	break;

      /* Found condition is not a whole word, so ignore it. */
      if (*(found + clen) != '\0' && *(found + clen) != ','
	 && !grub_isspace (*(found + clen)))
	continue;

      /*
       * If found condition is at the start of debug or the start is on a word
       * boundary, then enable debug. Else if found condition is prefixed with
       * '-' and the start is on a word boundary, then disable debug. If none
       * of these cases, ignore.
       */
      if (found == debug || *(found - 1) == ',' || grub_isspace (*(found - 1)))
	ret = 1;
      else if (*(found - 1) == '-' && ((found == debug + 1) || (*(found - 2) == ','
			       || grub_isspace (*(found - 2)))))
	ret = 0;
    }

  return ret;
}

void
grub_real_dprintf (const char *file, const char *function, const int line, const char *condition,
		   const char *fmt, ...)
{
  va_list args;

  if (grub_debug_enabled (condition))
    {
      grub_printf ("%s:%s:%d:%s: ", file, function, line, condition);
      va_start (args, fmt);
      grub_vprintf (fmt, args);
      va_end (args);
      grub_refresh ();
    }
}

#define PREALLOC_SIZE 255

int
grub_vprintf (const char *fmt, va_list ap)
{
  grub_size_t s;
  static char buf[PREALLOC_SIZE + 1];
  char *curbuf = buf;
  struct printf_args args;

  parse_printf_args (fmt, &args, ap);

  s = grub_vsnprintf_real (buf, PREALLOC_SIZE, fmt, &args);
  if (s > PREALLOC_SIZE)
    {
      curbuf = grub_malloc (s + 1);
      if (!curbuf)
	{
	  grub_errno = GRUB_ERR_NONE;
	  buf[PREALLOC_SIZE - 3] = '.';
	  buf[PREALLOC_SIZE - 2] = '.';
	  buf[PREALLOC_SIZE - 1] = '.';
	  buf[PREALLOC_SIZE] = 0;
	  curbuf = buf;
	}
      else
	s = grub_vsnprintf_real (curbuf, s, fmt, &args);
    }

  free_printf_args (&args);

  grub_xputs (curbuf);

  if (curbuf != buf)
    grub_free (curbuf);

  return s;
}

int
grub_memcmp (const void *s1, const void *s2, grub_size_t n)
{
  const grub_uint8_t *t1 = s1;
  const grub_uint8_t *t2 = s2;

  while (n--)
    {
      if (*t1 != *t2)
	return (int) *t1 - (int) *t2;

      t1++;
      t2++;
    }

  return 0;
}

int
grub_strcmp (const char *s1, const char *s2)
{
  while (*s1 && *s2)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) (grub_uint8_t) *s1 - (int) (grub_uint8_t) *s2;
}

int
grub_strncmp (const char *s1, const char *s2, grub_size_t n)
{
  if (n == 0)
    return 0;

  while (*s1 && *s2 && --n)
    {
      if (*s1 != *s2)
	break;

      s1++;
      s2++;
    }

  return (int) (grub_uint8_t) *s1 - (int) (grub_uint8_t)  *s2;
}

char *
grub_strchr (const char *s, int c)
{
  do
    {
      if (*s == c)
	return (char *) s;
    }
  while (*s++);

  return 0;
}

char *
grub_strrchr (const char *s, int c)
{
  char *p = NULL;

  do
    {
      if (*s == c)
	p = (char *) s;
    }
  while (*s++);

  return p;
}

int
grub_strword (const char *haystack, const char *needle)
{
  const char *n_pos = needle;

  while (grub_iswordseparator (*haystack))
    haystack++;

  while (*haystack)
    {
      /* Crawl both the needle and the haystack word we're on.  */
      while(*haystack && !grub_iswordseparator (*haystack)
            && *haystack == *n_pos)
        {
          haystack++;
          n_pos++;
        }

      /* If we reached the end of both words at the same time, the word
      is found. If not, eat everything in the haystack that isn't the
      next word (or the end of string) and "reset" the needle.  */
      if ( (!*haystack || grub_iswordseparator (*haystack))
         && (!*n_pos || grub_iswordseparator (*n_pos)))
        return 1;
      else
        {
          n_pos = needle;
          while (*haystack && !grub_iswordseparator (*haystack))
            haystack++;
          while (grub_iswordseparator (*haystack))
            haystack++;
        }
    }

  return 0;
}

char *
grub_strtok_r (char *s, const char *delim, char **save_ptr)
{
  char *token;
  const char *c;
  bool is_delim;

  if (s == NULL)
    s = *save_ptr;

  /* Scan leading delimiters. */
  while (*s != '\0')
    {
      is_delim = false;
      for (c = delim; *c != '\0'; c++)
	{
	  if (*s == *c)
	    {
	      is_delim = true;
	      break;
	    }
	}
      if (is_delim == true)
	s++;
      else
	break;
    }

  if (*s == '\0')
    {
      *save_ptr = s;
      return NULL;
    }

  /* Find the end of the token. */
  token = s;
  while (*s != '\0')
    {
      for (c = delim; *c != '\0'; c++)
	{
	  if (*s == *c)
	    {
	      *s = '\0';
	      *save_ptr = s + 1;
	      return token;
	    }
	}
      s++;
    }

  *save_ptr = s;
  return token;
}

char *
grub_strtok (char *s, const char *delim)
{
  static char *last;

  return grub_strtok_r (s, delim, &last);
}

int
grub_isspace (int c)
{
  return (c == '\n' || c == '\r' || c == ' ' || c == '\t');
}

unsigned long
grub_strtoul (const char * restrict str, const char ** const restrict end,
	      int base)
{
  unsigned long long num;

  num = grub_strtoull (str, end, base);
#if GRUB_CPU_SIZEOF_LONG != 8
  if (num > ~0UL)
    {
      grub_error (GRUB_ERR_OUT_OF_RANGE, N_("overflow is detected"));
      return ~0UL;
    }
#endif

  return (unsigned long) num;
}

unsigned long long
grub_strtoull (const char * restrict str, const char ** const restrict end,
	       int base)
{
  unsigned long long num = 0;
  int found = 0;

  /* Skip white spaces.  */
  /* grub_isspace checks that *str != '\0'.  */
  while (grub_isspace (*str))
    str++;

  /* Guess the base, if not specified. The prefix `0x' means 16, and
     the prefix `0' means 8.  */
  if (str[0] == '0')
    {
      if (str[1] == 'x')
	{
	  if (base == 0 || base == 16)
	    {
	      base = 16;
	      str += 2;
	    }
	}
      else if (base == 0 && str[1] >= '0' && str[1] <= '7')
	base = 8;
    }

  if (base == 0)
    base = 10;

  while (*str)
    {
      unsigned long digit;

      digit = grub_tolower (*str) - '0';
      if (digit >= 'a' - '0')
	digit += '0' - 'a' + 10;
      else if (digit > 9)
	break;

      if (digit >= (unsigned long) base)
	break;

      found = 1;

      /* NUM * BASE + DIGIT > ~0ULL */
      if (num > grub_divmod64 (~0ULL - digit, base, 0))
	{
	  grub_error (GRUB_ERR_OUT_OF_RANGE,
		      N_("overflow is detected"));

          if (end)
            *end = (char *) str;

	  return ~0ULL;
	}

      num = num * base + digit;
      str++;
    }

  if (! found)
    {
      grub_error (GRUB_ERR_BAD_NUMBER,
		  N_("unrecognized number"));

      if (end)
        *end = (char *) str;

      return 0;
    }

  if (end)
    *end = (char *) str;

  return num;
}

char *
grub_strdup (const char *s)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s) + 1;
  p = (char *) grub_malloc (len);
  if (! p)
    return 0;

  return grub_memcpy (p, s, len);
}

char *
grub_strndup (const char *s, grub_size_t n)
{
  grub_size_t len;
  char *p;

  len = grub_strlen (s);
  if (len > n)
    len = n;
  p = (char *) grub_malloc (len + 1);
  if (! p)
    return 0;

  grub_memcpy (p, s, len);
  p[len] = '\0';
  return p;
}

/* clang detects that we're implementing here a memset so it decides to
   optimise and calls memset resulting in infinite recursion. With volatile
   we make it not optimise in this way.  */
#ifdef __clang__
#define VOLATILE_CLANG volatile
#else
#define VOLATILE_CLANG
#endif

void *
grub_memset (void *s, int c, grub_size_t len)
{
  void *p = s;
  grub_uint8_t pattern8 = c;

  if (len >= 3 * sizeof (unsigned long))
    {
      unsigned long patternl = 0;
      grub_size_t i;

      for (i = 0; i < sizeof (unsigned long); i++)
	patternl |= ((unsigned long) pattern8) << (8 * i);

      while (len > 0 && (((grub_addr_t) p) & (sizeof (unsigned long) - 1)))
	{
	  *(VOLATILE_CLANG grub_uint8_t *) p = pattern8;
	  p = (grub_uint8_t *) p + 1;
	  len--;
	}
      while (len >= sizeof (unsigned long))
	{
	  *(VOLATILE_CLANG unsigned long *) p = patternl;
	  p = (unsigned long *) p + 1;
	  len -= sizeof (unsigned long);
	}
    }

  while (len > 0)
    {
      *(VOLATILE_CLANG grub_uint8_t *) p = pattern8;
      p = (grub_uint8_t *) p + 1;
      len--;
    }

  return s;
}

grub_size_t
grub_strlen (const char *s)
{
  const char *p = s;

  while (*p)
    p++;

  return p - s;
}

static inline void
grub_reverse (char *str)
{
  char *p = str + grub_strlen (str) - 1;

  while (str < p)
    {
      char tmp;

      tmp = *str;
      *str = *p;
      *p = tmp;
      str++;
      p--;
    }
}

/* Divide N by D, return the quotient, and store the remainder in *R.  */
grub_uint64_t
grub_divmod64 (grub_uint64_t n, grub_uint64_t d, grub_uint64_t *r)
{
  /* This algorithm is typically implemented by hardware. The idea
     is to get the highest bit in N, 64 times, by keeping
     upper(N * 2^i) = (Q * D + M), where upper
     represents the high 64 bits in 128-bits space.  */
  unsigned bits = 64;
  grub_uint64_t q = 0;
  grub_uint64_t m = 0;

  /* ARM and IA64 don't have a fast 32-bit division.
     Using that code would just make us use software division routines, calling
     ourselves indirectly and hence getting infinite recursion.
  */
#if !GRUB_DIVISION_IN_SOFTWARE || defined(__mips__)
  /* Skip the slow computation if 32-bit arithmetic is possible.  */
  if (n < 0xffffffff && d < 0xffffffff)
    {
      if (r)
	*r = ((grub_uint32_t) n) % (grub_uint32_t) d;

      return ((grub_uint32_t) n) / (grub_uint32_t) d;
    }
#endif

  while (bits--)
    {
      m <<= 1;

      if (n & (1ULL << 63))
	m |= 1;

      q <<= 1;
      n <<= 1;

      if (m >= d)
	{
	  q |= 1;
	  m -= d;
	}
    }

  if (r)
    *r = m;

  return q;
}

/* Convert a long long value to a string. This function avoids 64-bit
   modular arithmetic or divisions.  */
static inline char *
grub_lltoa (char *str, int c, unsigned long long n)
{
  unsigned base = ((c == 'x') || (c == 'X')) ? 16 : ((c == 'o') ? 8 : 10);
  char *p;

  if ((long long) n < 0 && c == 'd')
    {
      n = 0ULL - n;
      *str++ = '-';
    }

  p = str;

  if (base == 16)
    do
      {
	unsigned d = (unsigned) (n & 0xf);
	*p++ = (d > 9) ? (d + ((c == 'x') ? 'a' : 'A') - 10) : d + '0';
      }
    while (n >>= 4);
  else if (base == 8)
    do
      {
	*p++ = ((unsigned) (n & 0x7)) + '0';
      }
    while (n >>= 3);
  else
    /* BASE == 10 */
    do
      {
	grub_uint64_t m;

	n = grub_divmod64 (n, 10, &m);
	*p++ = m + '0';
      }
    while (n);

  *p = 0;

  grub_reverse (str);
  return p;
}

/* A single scanner is shared by argument collection, validation and output.
   It never advances past NUL, including incomplete flags/width/lengths. */
struct printf_format
{
	grub_size_t width, precision;
	grub_size_t arg, width_arg, precision_arg;
	int type;
	char conversion, longfmt;
	char left, zero, sign, alternate, have_precision, positional;
	char dynamic_width, dynamic_precision;
};

static grub_size_t
printf_read_uint (const char **fmt)
{
	grub_size_t value = 0;

	while (grub_isdigit (**fmt))
	{
		unsigned digit = *(*fmt)++ - '0';

		/* Widths and precisions beyond the int return range cannot be
		   represented. Saturate without wrapping or changing grub_errno. */
		if (value > (GRUB_INT_MAX - digit) / 10)
			value = GRUB_INT_MAX;
		else
			value = value * 10 + digit;
	}
	return value;
}

/* Return a one-based position, or zero for a sequential argument. */
static grub_size_t
printf_read_position (const char **fmt, struct printf_format *spec)
{
	const char *start = *fmt;
	grub_size_t position;

	if (!grub_isdigit (**fmt))
		return 0;
	position = printf_read_uint (fmt);
	if (**fmt != '$')
	{
		*fmt = start;
		return 0;
	}
	(*fmt)++;
	spec->positional = 1;
	return position ? position : GRUB_SIZE_MAX;
}

static int
parse_printf_format (const char **fmt, struct printf_format *spec,
		     grub_size_t *nextarg)
{
	grub_size_t startarg = *nextarg;
	grub_size_t position;
	char c;

	grub_memset (spec, 0, sizeof (*spec));
	spec->type = UNUSED;
	position = printf_read_position (fmt, spec);
	for (;; (*fmt)++)
	{
		switch (**fmt)
		{
		case '-':
			spec->left = 1;
			break;
		case '0':
			spec->zero = 1;
			break;
		case '+':
			spec->sign = '+';
			break;
		case ' ':
			if (!spec->sign)
				spec->sign = ' ';
			break;
		case '#':
			spec->alternate = 1;
			break;
		default:
			goto width;
		}
	}
width:
	if (**fmt == '*')
	{
		grub_size_t index;

		(*fmt)++;
		spec->dynamic_width = 1;
		index = printf_read_position (fmt, spec);
		spec->width_arg = index ? index - 1 : *nextarg;
		(*nextarg)++;
	}
	else
		spec->width = printf_read_uint (fmt);
	if (**fmt == '.')
	{
		(*fmt)++;
		spec->have_precision = 1;
		if (**fmt == '*')
		{
			grub_size_t index;

			(*fmt)++;
			spec->dynamic_precision = 1;
			index = printf_read_position (fmt, spec);
			spec->precision_arg = index ? index - 1 : *nextarg;
			(*nextarg)++;
		}
		else
			spec->precision = printf_read_uint (fmt);
	}
	if (**fmt == 'z')
	{
		(*fmt)++;
		if (sizeof (size_t) == sizeof (unsigned long))
			spec->longfmt = 1;
		else if (sizeof (size_t) == sizeof (unsigned long long))
			spec->longfmt = 2;
	}
	else if (**fmt == 'l')
	{
		(*fmt)++;
		spec->longfmt = 1;
		if (**fmt == 'l')
		{
			(*fmt)++;
			spec->longfmt = 2;
		}
	}
	c = **fmt;
	if (!c)
	{
		*nextarg = startarg;
		return 0;
	}
	(*fmt)++;
	spec->conversion = c;
	switch (c)
	{
	case 'x':
	case 'X':
	case 'u':
	case 'o':
		spec->type = UNSIGNED_INT + spec->longfmt;
		break;
	case 'd':
		spec->type = INT + spec->longfmt;
		break;
	case 'p':
		spec->type = sizeof (void *) == sizeof (long long) ? UNSIGNED_LONGLONG : UNSIGNED_INT;
		if (**fmt == 'G')
		{
			(*fmt)++;
			spec->type = UUID;
		}
		break;
	case 's':
		spec->type = STRING;
		break;
	case 'c':
	case 'C':
		spec->type = INT;
		break;
	default:
		*nextarg = startarg;
		return 1;
	}
	spec->arg = position ? position - 1 : *nextarg;
	(*nextarg)++;
	return 1;
}

static int
printf_set_arg_type (struct printf_args *args, grub_size_t index, int type)
{
	if (index >= args->count)
		return 0;
	if (args->ptr[index].type != UNUSED && args->ptr[index].type != type)
		return 0;
	args->ptr[index].type = type;
	return 1;
}

/* Check mode also rejects positional arguments, including *m$, so untrusted
   formats cannot reinterpret a previously collected argument. */
static grub_err_t
parse_printf_arg_fmt (const char *fmt0, struct printf_args *args,
		      int fmt_check, grub_size_t max_args)
{
	const char *fmt;
	struct printf_format spec;
	grub_size_t n = 0;
	grub_size_t i;

	args->count = 0;
	COMPILE_TIME_ASSERT (sizeof (int) == sizeof (grub_uint32_t));
	COMPILE_TIME_ASSERT (sizeof (int) <= sizeof (long long));
	COMPILE_TIME_ASSERT (sizeof (long) <= sizeof (long long));
	COMPILE_TIME_ASSERT (sizeof (long long) == sizeof (void *)
			     || sizeof (int) == sizeof (void *));
	COMPILE_TIME_ASSERT (sizeof (size_t) == sizeof (unsigned)
			     || sizeof (size_t) == sizeof (unsigned long)
			     || sizeof (size_t) == sizeof (unsigned long long));

	fmt = fmt0;
	while (*fmt)
	{
		if (*fmt++ != '%')
			continue;
		if (!parse_printf_format (&fmt, &spec, &n))
		{
			if (fmt_check)
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "incomplete format");
			break;
		}
		if (fmt_check)
		{
			if (spec.positional)
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "positional arguments are not supported");
			if (spec.type == UNUSED && (spec.conversion != '%'
				|| spec.dynamic_width || spec.dynamic_precision))
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "unexpected format");
			if (n > max_args)
				return grub_error (GRUB_ERR_BAD_ARGUMENT, "too many arguments");
		}
	}
	args->count = n;
	if (args->count <= ARRAY_SIZE (args->prealloc))
		args->ptr = args->prealloc;
	else
	{
		args->ptr = grub_calloc (args->count, sizeof (args->ptr[0]));
		if (!args->ptr)
		{
			if (fmt_check)
				return grub_errno;
			grub_errno = GRUB_ERR_NONE;
			args->ptr = args->prealloc;
			args->count = ARRAY_SIZE (args->prealloc);
		}
	}
	for (i = 0; i < args->count; i++)
		args->ptr[i].type = UNUSED;

	fmt = fmt0;
	n = 0;
	while (*fmt)
	{
		if (*fmt++ != '%')
			continue;
		if (!parse_printf_format (&fmt, &spec, &n))
			break;
		if (spec.type == UNUSED || spec.arg >= args->count
			|| (spec.dynamic_width && spec.width_arg >= args->count)
			|| (spec.dynamic_precision && spec.precision_arg >= args->count))
			continue;
		if (!printf_set_arg_type (args, spec.arg, spec.type)
			|| (spec.dynamic_width && !printf_set_arg_type (args, spec.width_arg, INT))
			|| (spec.dynamic_precision && !printf_set_arg_type (args, spec.precision_arg, INT)))
			goto fail;
	}
	/* Repeated positions do not introduce extra va_args. Gaps cannot be read
	   safely because the missing argument's type is unknown. */
	while (args->count && args->ptr[args->count - 1].type == UNUSED)
		args->count--;
	for (i = 0; i < args->count; i++)
		if (args->ptr[i].type == UNUSED)
			goto fail;
	return GRUB_ERR_NONE;
fail:
	args->count = 0;
	return GRUB_ERR_NONE;
}

static void
parse_printf_args (const char *fmt0, struct printf_args *args, va_list args_in)
{
  grub_size_t n;

  parse_printf_arg_fmt (fmt0, args, 0, 0);

  for (n = 0; n < args->count; n++)
    switch (args->ptr[n].type)
      {
      case INT:
	args->ptr[n].ll = va_arg (args_in, int);
	break;
      case LONG:
	args->ptr[n].ll = va_arg (args_in, long);
	break;
      case UNSIGNED_INT:
	args->ptr[n].ll = va_arg (args_in, unsigned int);
	break;
      case UNSIGNED_LONG:
	args->ptr[n].ll = va_arg (args_in, unsigned long);
	break;
      case LONGLONG:
      case UNSIGNED_LONGLONG:
	args->ptr[n].ll = va_arg (args_in, long long);
	break;
      case STRING:
      case UUID:
	if (sizeof (void *) == sizeof (long long))
	  args->ptr[n].ll = va_arg (args_in, long long);
	else
	  args->ptr[n].ll = va_arg (args_in, unsigned int);
	break;
      case UNUSED:
	break;
      }
}

static inline void __attribute__ ((always_inline))
write_char (char *str, grub_size_t *count, grub_size_t max_len, unsigned char ch)
{
  if (*count < max_len)
    str[*count] = ch;

  (*count)++;
}

static void
write_fill (char *str, grub_size_t *count, grub_size_t max_len,
	    grub_size_t fill, char c)
{
	if (*count < max_len)
	{
		grub_size_t available = max_len - *count;

		grub_memset (str + *count, c, fill < available ? fill : available);
	}
	*count += fill;
}

static void
write_number (char *str, grub_size_t *count, grub_size_t max_len,
	      const struct printf_format *spec, unsigned long long value)
{
	char tmp[32];
	const char *p = tmp;
	char sign = 0;
	char c = spec->conversion;
	const char *prefix = "";
	grub_size_t len, zeros = 0, fill, total, prefix_len = 0;

	if (c == 'p')
		c = 'x';
	len = grub_lltoa (tmp, c, value) - tmp;
	if (*p == '-')
	{
		sign = *p++;
		len--;
	}
	else if (c == 'd')
		sign = spec->sign;
	if (spec->have_precision)
	{
		if (!spec->precision && !value)
			len = 0;
		if (spec->precision > len)
			zeros = spec->precision - len;
	}
	if (spec->alternate && c == 'o' && ((!len) || (*p != '0' && !zeros)))
		zeros = 1;
	if (spec->conversion == 'p' || (spec->alternate && value && (c == 'x' || c == 'X')))
	{
		prefix = c == 'X' ? "0X" : "0x";
		prefix_len = 2;
	}
	total = len + zeros + prefix_len + (sign != 0);
	fill = spec->width > total ? spec->width - total : 0;
	if (!spec->left && (!spec->zero || spec->have_precision))
		write_fill (str, count, max_len, fill, ' ');
	if (sign)
		write_char (str, count, max_len, sign);
	while (*prefix)
		write_char (str, count, max_len, *prefix++);
	if (!spec->left && spec->zero && !spec->have_precision)
		write_fill (str, count, max_len, fill, '0');
	write_fill (str, count, max_len, zeros, '0');
	while (len--)
		write_char (str, count, max_len, *p++);
	if (spec->left)
		write_fill (str, count, max_len, fill, ' ');
}

static void
write_text (char *str, grub_size_t *count, grub_size_t max_len,
	    const struct printf_format *spec, const char *text, grub_size_t len)
{
	grub_size_t fill = spec->width > len ? spec->width - len : 0;

	if (!spec->left)
		write_fill (str, count, max_len, fill, ' ');
	while (len--)
		write_char (str, count, max_len, *text++);
	if (spec->left)
		write_fill (str, count, max_len, fill, ' ');
}

static int
grub_vsnprintf_real (char *str, grub_size_t max_len, const char *fmt0,
		     struct printf_args *args)
{
	grub_size_t n = 0;
	grub_size_t count = 0;
	const char *fmt = fmt0;

	while (*fmt)
	{
		struct printf_format spec;
		unsigned long long curarg;
		char c = *fmt++;

		if (c != '%')
		{
			write_char (str, &count, max_len, c);
			continue;
		}
		if (!parse_printf_format (&fmt, &spec, &n))
			break;
		c = spec.conversion;
		if (c == '%')
		{
			write_char (str, &count, max_len, c);
			continue;
		}
		if (spec.type == UNUSED || spec.arg >= args->count)
			continue;
		if (spec.dynamic_width)
		{
			int width;

			if (spec.width_arg >= args->count)
				continue;
			width = (int) args->ptr[spec.width_arg].ll;
			if (width < 0)
			{
				spec.left = 1;
				spec.width = 0U - (unsigned) width;
			}
			else
				spec.width = (unsigned) width;
		}
		if (spec.dynamic_precision)
		{
			int precision;

			if (spec.precision_arg >= args->count)
				continue;
			precision = (int) args->ptr[spec.precision_arg].ll;
			spec.have_precision = precision >= 0;
			if (spec.have_precision)
				spec.precision = (unsigned) precision;
		}
		curarg = args->ptr[spec.arg].ll;
		switch (c)
		{
		case 'p':
			if (spec.type == UUID)
			{
				const grub_packed_guid_t *guid = (const grub_packed_guid_t *) (grub_addr_t) curarg;
				struct printf_format field;
				unsigned i;

				if (!guid)
				{
					write_text (str, &count, max_len, &spec, "(null)", 6);
					break;
				}
				grub_memset (&field, 0, sizeof (field));
				field.zero = 1;
				field.conversion = 'x';
				field.width = 8;
				write_number (str, &count, max_len, &field, guid->data1);
				write_char (str, &count, max_len, '-');
				field.width = 4;
				write_number (str, &count, max_len, &field, guid->data2);
				write_char (str, &count, max_len, '-');
				write_number (str, &count, max_len, &field, guid->data3);
				field.width = 2;
				for (i = 0; i < 8; i++)
				{
					if (i == 0 || i == 2)
						write_char (str, &count, max_len, '-');
					write_number (str, &count, max_len, &field, guid->data4[i]);
				}
				break;
			}
			/* Fall through. */
		case 'x':
		case 'X':
		case 'u':
		case 'd':
		case 'o':
			write_number (str, &count, max_len, &spec, curarg);
			break;
		case 'c':
		{
			char ch = curarg & 0xff;

			write_text (str, &count, max_len, &spec, &ch, 1);
			break;
		}
		case 'C':
		{
			grub_uint32_t code = curarg;
			int shift;
			unsigned mask;
			char encoded[4];
			grub_size_t len = 0;

			if (code <= 0x7f)
			{
				shift = 0;
				mask = 0;
			}
			else if (code <= 0x7ff)
			{
				shift = 6;
				mask = 0xc0;
			}
			else if (code <= 0xffff)
			{
				shift = 12;
				mask = 0xe0;
			}
			else if (code <= 0x10ffff)
			{
				shift = 18;
				mask = 0xf0;
			}
			else
			{
				code = '?';
				shift = 0;
				mask = 0;
			}
			encoded[len++] = mask | (code >> shift);
			for (shift -= 6; shift >= 0; shift -= 6)
				encoded[len++] = 0x80 | (0x3f & (code >> shift));
			write_text (str, &count, max_len, &spec, encoded, len);
			break;
		}
		case 's':
		{
			grub_size_t len = 0;
			const char *p = curarg ? (const char *) (grub_addr_t) curarg : "(null)";

			while ((!spec.have_precision || len < spec.precision) && p[len])
				len++;
			write_text (str, &count, max_len, &spec, p, len);
			break;
		}
		}
	}
	str[count < max_len ? count : max_len] = '\0';
	return count;
}

int
grub_vsnprintf (char *str, grub_size_t n, const char *fmt, va_list ap)
{
  grub_size_t ret;
  struct printf_args args;

  if (!n)
    return 0;

  n--;

  parse_printf_args (fmt, &args, ap);

  ret = grub_vsnprintf_real (str, n, fmt, &args);

  free_printf_args (&args);

  return ret;
}

int
grub_snprintf (char *str, grub_size_t n, const char *fmt, ...)
{
  va_list ap;
  int ret;

  va_start (ap, fmt);
  ret = grub_vsnprintf (str, n, fmt, ap);
  va_end (ap);

  return ret;
}

char *
grub_xvasprintf (const char *fmt, va_list ap)
{
  grub_size_t s, as = PREALLOC_SIZE;
  char *ret;
  struct printf_args args;

  parse_printf_args (fmt, &args, ap);

  while (1)
    {
      ret = grub_malloc (as + 1);
      if (!ret)
	{
	  free_printf_args (&args);
	  return NULL;
	}

      s = grub_vsnprintf_real (ret, as, fmt, &args);

      if (s <= as)
	{
	  free_printf_args (&args);
	  return ret;
	}

      grub_free (ret);
      as = s;
    }
}

char *
grub_xasprintf (const char *fmt, ...)
{
  va_list ap;
  char *ret;

  va_start (ap, fmt);
  ret = grub_xvasprintf (fmt, ap);
  va_end (ap);

  return ret;
}

grub_err_t
grub_printf_fmt_check (const char *fmt, const char *fmt_expected)
{
  struct printf_args args_expected, args_fmt;
  grub_err_t ret;
  grub_size_t n;

  if (fmt == NULL || fmt_expected == NULL)
    return grub_error (GRUB_ERR_BAD_ARGUMENT, "invalid format");

  ret = parse_printf_arg_fmt (fmt_expected, &args_expected, 1, GRUB_SIZE_MAX);
  if (ret != GRUB_ERR_NONE)
    return ret;

  /* Limit parsing to the number of expected arguments. */
  ret = parse_printf_arg_fmt (fmt, &args_fmt, 1, args_expected.count);
  if (ret != GRUB_ERR_NONE)
    {
      free_printf_args (&args_expected);
      return ret;
    }

  for (n = 0; n < args_fmt.count; n++)
    if (args_fmt.ptr[n].type != args_expected.ptr[n].type)
     {
	ret = grub_error (GRUB_ERR_BAD_ARGUMENT, "arguments types do not match");
	break;
     }

  free_printf_args (&args_expected);
  free_printf_args (&args_fmt);

  return ret;
}


/* Abort GRUB. This function does not return.  */
void __attribute__ ((noreturn))
grub_abort (void)
{
  grub_printf ("\nAborted.");

#ifndef GRUB_UTIL
  if (grub_term_inputs)
#endif
    {
      grub_printf (" Press any key to exit.");
      grub_getkey ();
    }

  grub_exit ();
}

void
grub_fatal (const char *fmt, ...)
{
  va_list ap;

  va_start (ap, fmt);
  grub_vprintf (_(fmt), ap);
  va_end (ap);

  grub_refresh ();

  grub_abort ();
}

grub_ssize_t
grub_utf8_to_utf16_alloc (const char *str8, grub_uint16_t **utf16_msg, grub_uint16_t **last_position)
{
  grub_size_t len;
  grub_size_t len16;

  len = grub_strlen (str8);

  /* Check for integer overflow */
  if (len > GRUB_SSIZE_MAX / GRUB_MAX_UTF16_PER_UTF8 - 1)
    {
      grub_error (GRUB_ERR_BAD_ARGUMENT, N_("string too long"));
      *utf16_msg = NULL;
      return -1;
    }

  len16 = len * GRUB_MAX_UTF16_PER_UTF8;

  *utf16_msg = grub_calloc (len16 + 1, sizeof (*utf16_msg[0]));
  if (*utf16_msg == NULL)
    return -1;

  len16 = grub_utf8_to_utf16 (*utf16_msg, len16, (grub_uint8_t *) str8, len, NULL);

  if (last_position != NULL)
    *last_position = *utf16_msg + len16;

  return len16;
}


#if BOOT_TIME_STATS

#include <grub/time.h>

struct grub_boot_time *grub_boot_time_head;
static struct grub_boot_time **boot_time_last = &grub_boot_time_head;

void
grub_real_boot_time (const char *file,
		     const int line,
		     const char *fmt, ...)
{
  struct grub_boot_time *n;
  va_list args;

  grub_error_push ();
  n = grub_malloc (sizeof (*n));
  if (!n)
    {
      grub_errno = 0;
      grub_error_pop ();
      return;
    }
  n->file = file;
  n->line = line;
  n->tp = grub_get_time_ms ();
  n->next = 0;

  va_start (args, fmt);
  n->msg = grub_xvasprintf (fmt, args);
  va_end (args);

  *boot_time_last = n;
  boot_time_last = &n->next;

  grub_errno = 0;
  grub_error_pop ();
}
#endif
