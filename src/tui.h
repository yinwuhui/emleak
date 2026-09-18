#ifndef __EMLEAK_TUI_H__
#define __EMLEAK_TUI_H__

/*
 * Top-like full screen terminal UI layer.
 *
 * The layer knows nothing about emleak data: the backend builds each
 * frame row by row (tui_begin_frame/tui_row/tui_rowf) and tui_flush()
 * emits only the rows that changed, positioned with absolute cursor
 * addressing, so the terminal never scrolls and untouched rows are
 * never rewritten. When stdout is not a tty the same calls fall back
 * to plain text output without any escape sequences.
 */
#include <stdbool.h>

/* enter/leave full screen mode; no-op unless top mode runs on a tty */
void tui_enter(void);
void tui_leave(void);
bool tui_is_active(void);

/* drain stdin; returns true when the user asked to quit ('q') */
bool tui_poll_quit(void);

/* record a status message, shown in the bottom row of the frame */
void tui_statusf(const char *fmt, ...);
/* the current status message, "" when none was recorded */
const char *tui_status_text(void);

/* start a new frame: clears the row buffer, refreshes terminal size */
void tui_begin_frame(void);
/* append one frame row, truncated to the terminal width */
void tui_row(const char *text, bool inverse);
void tui_rowf(bool inverse, const char *fmt, ...);
/* pad to full height and emit the changed rows in one write */
void tui_flush(void);

/* terminal height in rows, or INT_MAX when not in full screen mode */
int tui_height(void);

#endif
