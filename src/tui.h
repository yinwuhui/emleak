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

/* keys reported by tui_poll_key() */
enum tui_key {
	TUI_KEY_NONE = 0,
	TUI_KEY_QUIT,
	TUI_KEY_UP,
	TUI_KEY_DOWN,
	TUI_KEY_ENTER,
	TUI_KEY_ESC,
};

/* per-row style: the table header is black-on-white, the interactive
 * selection is reverse video
 */
enum tui_row_style {
	TUI_STYLE_NORMAL = 0,
	TUI_STYLE_HEADER,
	TUI_STYLE_SELECTED,
};

/* enter/leave full screen mode; no-op unless top mode runs on a tty */
void tui_enter(void);
void tui_leave(void);
bool tui_is_active(void);

/* drain stdin and report one key press; arrow keys and Enter are parsed
 * from their escape sequences (a lone ESC is reported once no
 * continuation byte arrives within 50 ms)
 */
enum tui_key tui_poll_key(void);

/* record a status message, shown in the bottom row of the frame */
void tui_statusf(const char *fmt, ...);
/* the current status message, "" when none was recorded */
const char *tui_status_text(void);

/* start a new frame: clears the row buffer, refreshes terminal size */
void tui_begin_frame(void);
/* append one frame row, truncated to the terminal width */
void tui_row(const char *text, enum tui_row_style style);
void tui_rowf(enum tui_row_style style, const char *fmt, ...);
/* pad to full height and emit the changed rows in one write */
void tui_flush(void);

/* terminal height in rows, or INT_MAX when not in full screen mode */
int tui_height(void);

#endif
