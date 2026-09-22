// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/*
 * Top-like full screen terminal UI layer.
 *
 * Like top(1), the frame has fixed regions (summary header, table,
 * footer) that always occupy the same rows, and each refresh only
 * rewrites the rows whose content actually changed, positioned with
 * absolute cursor addressing. No row ever receives a trailing newline,
 * so the terminal never scrolls: untouched rows are literally never
 * written again, which keeps the screen perfectly stable.
 * The bottom-right corner cell is never written either, because
 * touching it would force the terminal to scroll.
 * When stdout is not a tty the same calls fall back to plain text
 * output without any escape sequences.
 */
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include "tui.h"

#define TUI_MAX_ROWS 512
#define TUI_LINE_MAX 2048

static char tui_frame[TUI_MAX_ROWS][TUI_LINE_MAX];
static enum tui_row_style tui_frame_style[TUI_MAX_ROWS];
static int tui_frame_count;
static char tui_prev_frame[TUI_MAX_ROWS][TUI_LINE_MAX];
static enum tui_row_style tui_prev_style[TUI_MAX_ROWS];
static int tui_prev_count;
static int tui_term_rows = 24;
static int tui_term_cols = 80;
static bool tui_active;
static bool tui_termios_saved;
static struct termios tui_saved_termios;
static int tui_saved_stdin_flags = -1;
static char tui_status[256];

bool tui_is_active(void)
{
	return tui_active;
}

int tui_height(void)
{
	return tui_active ? tui_term_rows : INT_MAX;
}

void tui_statusf(const char *fmt, ...)
{
	va_list args;
	time_t now = time(NULL);
	struct tm tm_now;
	char stamp[32] = "";
	char msg[sizeof(tui_status) - sizeof(stamp)];

	va_start(args, fmt);
	vsnprintf(msg, sizeof(msg), fmt, args);
	va_end(args);
	if (localtime_r(&now, &tm_now))
		strftime(stamp, sizeof(stamp), "%H:%M:%S ", &tm_now);
	snprintf(tui_status, sizeof(tui_status), "%s%s", stamp, msg);
}

const char *tui_status_text(void)
{
	return tui_status;
}

/* append one frame row, truncated to the terminal width */
void tui_row(const char *text, enum tui_row_style style)
{
	char line[TUI_LINE_MAX];
	size_t len = strlen(text);

	if (tui_frame_count >= TUI_MAX_ROWS)
		return;
	if (len >= sizeof(line))
		len = sizeof(line) - 1;
	memcpy(line, text, len);
	line[len] = '\0';

	if (tui_active && (int)len > tui_term_cols)
		line[tui_term_cols] = '\0';

	strcpy(tui_frame[tui_frame_count], line);
	tui_frame_style[tui_frame_count] = tui_active ? style : TUI_STYLE_NORMAL;
	tui_frame_count++;
}

void tui_rowf(enum tui_row_style style, const char *fmt, ...)
{
	char line[TUI_LINE_MAX];
	va_list args;

	va_start(args, fmt);
	vsnprintf(line, sizeof(line), fmt, args);
	va_end(args);
	tui_row(line, style);
}

static void tui_update_winsize(void)
{
	struct winsize window = {};

	if (!tui_active)
		return;
	if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &window) == 0) {
		if (window.ws_row)
			tui_term_rows = window.ws_row < TUI_MAX_ROWS ?
				window.ws_row : TUI_MAX_ROWS;
		if (window.ws_col)
			tui_term_cols = window.ws_col;
	}
}

void tui_begin_frame(void)
{
	tui_frame_count = 0;
	tui_update_winsize();
}

/*
 * Emit the frame. Each changed row is written with absolute cursor
 * addressing and erased to end-of-line; unchanged rows are skipped.
 * The frame never ends with a newline, so the terminal cannot scroll.
 */
void tui_flush(void)
{
	char *out;
	size_t used = 0, cap = 1 << 16;
	int r;

	if (!tui_active) {
		for (r = 0; r < tui_frame_count; r++)
			printf("%s\n", tui_frame[r]);
		fflush(stdout);
		tui_prev_count = 0;
		return;
	}

	/* pad to full height; never touch the bottom-right corner cell */
	while (tui_frame_count < tui_term_rows)
		tui_row("", false);
	if (tui_term_cols >= 2) {
		char *last = tui_frame[tui_frame_count - 1];
		size_t n = strlen(last);

		if (n >= (size_t)tui_term_cols)
			last[tui_term_cols - 1] = '\0';
	}

	out = malloc(cap);
	if (!out)
		return;
	for (r = 0; r < tui_frame_count; r++) {
		const char *line = tui_frame[r];
		size_t n = strlen(line);

		if (r < tui_prev_count && tui_prev_style[r] == tui_frame_style[r]
				&& strcmp(tui_prev_frame[r], line) == 0)
			continue;
		while (used + n + 32 > cap) {
			char *p = realloc(out, cap * 2);

			if (!p) {
				free(out);
				return;
			}
			out = p;
			cap *= 2;
		}
		used += snprintf(out + used, cap - used, "\033[%d;1H", r + 1);
		if (tui_frame_style[r] == TUI_STYLE_HEADER)
			used += snprintf(out + used, cap - used, "\033[47;30m");
		else if (tui_frame_style[r] == TUI_STYLE_SELECTED)
			used += snprintf(out + used, cap - used, "\033[7m");
		memcpy(out + used, line, n);
		used += n;
		if (tui_frame_style[r] != TUI_STYLE_NORMAL)
			used += snprintf(out + used, cap - used, "\033[0m");
		used += snprintf(out + used, cap - used, "\033[K");
	}
	/*
	 * Erase only what lies below the frame's last row. The cursor must be
	 * moved there first: the write loop may have ended higher up, and a
	 * bare erase-below would wipe skipped (but valid) rows underneath.
	 */
	{
		const char *last = tui_frame[tui_frame_count - 1];

		while (used + 32 > cap) {
			char *p = realloc(out, cap * 2);

			if (!p) {
				free(out);
				return;
			}
			out = p;
			cap *= 2;
		}
		used += snprintf(out + used, cap - used, "\033[%d;%zuH\033[J",
				tui_frame_count, strlen(last) + 1);
	}
	fwrite(out, 1, used, stdout);
	fflush(stdout);
	free(out);

	memcpy(tui_prev_frame, tui_frame, sizeof(tui_prev_frame));
	memcpy(tui_prev_style, tui_frame_style, sizeof(tui_prev_style));
	tui_prev_count = tui_frame_count;
}

void tui_enter(void)
{
	struct termios tio;

	if (!isatty(STDOUT_FILENO))
		return;
	tui_active = true;
	tui_update_winsize();
	fputs("\033[?25l", stdout);
	fflush(stdout);

	if (tcgetattr(STDIN_FILENO, &tio) == 0) {
		tui_saved_termios = tio;
		tui_termios_saved = true;
		tio.c_lflag &= ~(ICANON | ECHO);
		tio.c_cc[VMIN] = 1;
		tio.c_cc[VTIME] = 0;
		tcsetattr(STDIN_FILENO, TCSANOW, &tio);
	}
	tui_saved_stdin_flags = fcntl(STDIN_FILENO, F_GETFL);
	if (tui_saved_stdin_flags >= 0)
		fcntl(STDIN_FILENO, F_SETFL, tui_saved_stdin_flags | O_NONBLOCK);
}

void tui_leave(void)
{
	if (tui_active) {
		fputs("\033[?25h", stdout);
		fflush(stdout);
		tui_active = false;
	}
	if (tui_termios_saved) {
		tcsetattr(STDIN_FILENO, TCSANOW, &tui_saved_termios);
		tui_termios_saved = false;
	}
	if (tui_saved_stdin_flags >= 0) {
		fcntl(STDIN_FILENO, F_SETFL, tui_saved_stdin_flags);
		tui_saved_stdin_flags = -1;
	}
}

enum tui_key tui_poll_key(void)
{
	static int seq_len;
	static struct timespec seq_since;
	enum tui_key key = TUI_KEY_NONE;
	char c;

	if (!tui_active)
		return TUI_KEY_NONE;

	while (read(STDIN_FILENO, &c, 1) == 1) {
		if (seq_len == 0) {
			if (c == 0x1b) {
				seq_len = 1;
				clock_gettime(CLOCK_MONOTONIC, &seq_since);
			} else if (c == 'q' || c == 'Q') {
				return TUI_KEY_QUIT;
			} else if (c == '\r' || c == '\n') {
				return TUI_KEY_ENTER;
			}
			continue;
		}
		if (seq_len == 1) {
			if (c == '[' || c == 'O') {
				seq_len = 2;
				continue;
			}
			seq_len = 0; /* not a recognized sequence, drop the ESC */
			continue;
		}
		/* seq_len == 2: final byte of a CSI/SS3 sequence */
		seq_len = 0;
		if (c == 'A')
			return TUI_KEY_UP;
		if (c == 'B')
			return TUI_KEY_DOWN;
		/* ignore the other finals (right/left/home/...) */
	}

	if (seq_len == 1) {
		/* A lone ESC: no '['/'O' byte arrived within 50 ms. Once the
		 * introducer is seen (seq_len == 2) the final byte is expected
		 * in the next poll cycle, so no timeout there. */
		struct timespec now;

		clock_gettime(CLOCK_MONOTONIC, &now);
		if ((now.tv_sec - seq_since.tv_sec) * 1000L +
				(now.tv_nsec - seq_since.tv_nsec) / 1000000L >= 50) {
			seq_len = 0;
			return TUI_KEY_ESC;
		}
	}
	return key;
}
