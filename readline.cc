// Copyright 2016 The Fuchsia Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// N.B. This is taken from mxsh/mxsh.c, and has a modest amount of changes.
// This can all be "fixed" to be "correct" c++ later.

#include "readline.h"

#include <algorithm>
#include <ctype.h>
#include <list>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

namespace debugserver {
namespace util {

static void cputc(uint8_t ch) {
  write(1, &ch, 1);
}

static void cputs(const char* s, size_t len) {
  write(1, s, len);
}

static int cgetc(void) {
  uint8_t ch;
  for (;;) {
    int r = read(0, &ch, 1);
    if (r < 0) {
      return r;
    }
    if (r == 1) {
      return ch;
    }
  }
}

static void beep(void) {
}

#define CTRL_C 3
#define BACKSPACE 8
#define TAB 9
#define NL 10
#define CTRL_L 12
#define CR 13
#define ESC 27
#define DELETE 127

#define EXT_UP 'A'
#define EXT_DOWN 'B'
#define EXT_RIGHT 'C'
#define EXT_LEFT 'D'

struct hitem {
  int len;
  char line[LINE_MAX];
};

static std::list<hitem*> history;

static const char nl[2] = {'\r', '\n'};
static const char erase_line[5] = {ESC, '[', '2', 'K', '\r'};
static const char cursor_left[3] = {ESC, '[', 'D'};
static const char cursor_right[3] = {ESC, '[', 'C'};

struct editstate {
  // The position of the cursor in |line|.
  int pos;
  // The length of the text in |line|.
  int len;
  // The length of the text in |save|.
  int save_len;
  // When scrolling through history, the current entry.
  // If not scrolling through history this is end().
  std::list<hitem*>::iterator item;
  // If scrolling back through history, saved copy of the original text.
  char save[LINE_MAX];
  // Buffer of what the user is typing in.
  char line[LINE_MAX + 1];
  // The prompt.
#define PROMPT_MAX 40
  char prompt[PROMPT_MAX + 1];
};

static void history_add(editstate* es) {
  if (es->len == 0)
    return;
  hitem* item = reinterpret_cast<hitem*>(malloc(sizeof(hitem)));
  if (item != nullptr) {
    item->len = es->len;
    memset(item->line, 0, sizeof(item->line));
    memcpy(item->line, es->line, es->len);
    history.push_front(item);
  }
}

static int history_up(editstate* es) {
  if (es->item != history.end()) {
    if (es->item != history.begin()) {
      --es->item;
      memcpy(es->line, (*es->item)->line, (*es->item)->len);
      es->pos = es->len = (*es->item)->len;
      cputs(erase_line, sizeof(erase_line));
      return 1;
    } else {
      beep();
      return 0;
    }
  } else {
    if (es->item != history.begin()) {
      --es->item;
      memset(es->save, 0, sizeof(es->save));
      memcpy(es->save, es->line, es->len);
      es->save_len = es->len;
      es->pos = es->len = (*es->item)->len;
      memcpy(es->line, (*es->item)->line, es->len);
      cputs(erase_line, sizeof(erase_line));
      return 1;
    } else {
      beep();
      return 0;
    }
  }
}

static int history_down(editstate* es) {
  if (es->item == history.end()) {
    beep();
    return 0;
  }
  ++es->item;
  if (es->item != history.end()) {
    es->pos = es->len = (*es->item)->len;
    memcpy(es->line, (*es->item)->line, es->len);
  } else {
    memcpy(es->line, es->save, es->save_len);
    es->pos = es->len = es->save_len;
  }
  cputs(erase_line, sizeof(erase_line));
  return 1;
}

void settitle(const ftl::StringView& title) {
  char ctitle[16];
  strlcpy(ctitle, title.data(), std::min(title.size() + 1, sizeof(ctitle)));
  char str[16];
  int n = snprintf(str, sizeof(str) - 1, "\033]2;%s", ctitle);
  if (n < 0) {
    return; // error
  } else if ((size_t)n >= sizeof(str) - 1) {
    n = sizeof(str) - 2; // truncated
  }
  str[n] = '\007';
  str[n+1] = '\0';
  cputs(str, n + 1);
}

static void tab_complete(editstate* es) {
  // TODO(dje)
  // What to complete on is context dependent. One can get really fancy here,
  // but for now it's time best spent on other things.
}

static editstate estate;

int readline(ftl::StringView* line) {
  int a, b, c;
  editstate* es = &estate;
  es->len = 0;
  es->pos = 0;
  es->save_len = 0;
  es->item = history.end();

 again:
  cputs(es->prompt, strlen(es->prompt));
  if (es->len) {
    cputs(es->line, es->len);
  }
  if (es->len != es->pos) {
    char tmp[16];
    sprintf(tmp, "%c[%dG", ESC, es->pos + 3);
    cputs(tmp, strlen(tmp));
  }
  for (;;) {
    if ((c = cgetc()) < 0) {
      es->item = history.end();
      return c;
    }
    if ((c >= ' ') && (c < 127)) {
      if (es->len < LINE_MAX) {
        if (es->pos != es->len) {
          memmove(es->line + es->pos + 1, es->line + es->pos, es->len - es->pos);
          // expensive full redraw of line
          es->len++;
          es->line[es->pos++] = c;
          es->item = history.end();
          cputs(erase_line, sizeof(erase_line));
          goto again;
        }
        es->len++;
        es->line[es->pos++] = c;
        cputc(c);
      }
      beep();
      continue;
    }
    switch (c) {
    case TAB:
      tab_complete(es);
      cputs(erase_line, sizeof(erase_line));
      goto again;
    case CTRL_C:
      es->len = 0;
      es->pos = 0;
      es->item = history.end();
      cputs(nl, sizeof(nl));
      goto again;
    case CTRL_L:
      cputs(erase_line, sizeof(erase_line));
      goto again;
    case BACKSPACE:
    case DELETE:
      if (es->pos > 0) {
        es->pos--;
        es->len--;
        memmove(es->line + es->pos, es->line + es->pos + 1, es->len - es->pos);
        // expensive full redraw of line
        es->item = history.end();
        cputs(erase_line, sizeof(erase_line));
        goto again;
      } else {
        beep();
      }
      es->item = history.end();
      continue;
    case NL:
    case CR:
      es->line[es->len] = 0;
      cputs(nl, sizeof(nl));
      history_add(es);
      *line = ftl::StringView(es->line, es->len);
      return 0;
    case ESC:
      if ((a = cgetc()) < 0) {
        return a;
      }
      if ((b = cgetc()) < 0) {
        return b;
      }
      if (a != '[') {
        break;
      }
      switch (b) {
      case EXT_UP:
        if (history_up(es)) {
          goto again;
        }
        break;
      case EXT_DOWN:
        if (history_down(es)) {
          goto again;
        }
        break;
      case EXT_RIGHT:
        if (es->pos < es->len) {
          es->pos++;
          cputs(cursor_right, sizeof(cursor_right));
        } else {
          beep();
        }
        break;
      case EXT_LEFT:
        if (es->pos > 0) {
          es->pos--;
          cputs(cursor_left, sizeof(cursor_left));
        } else {
          beep();
        }
        break;
      }
    }
    beep();
  }
}

void set_prompt(const ftl::StringView& prompt) {
  strlcpy(estate.prompt, prompt.data(),
          std::min(prompt.size() + 1, sizeof(estate.prompt)));
}

ftl::StringView get_history(int n) {
  if (n < 0 || static_cast<unsigned>(n) >= history.size())
    return "";
  std::list<hitem*>::iterator it = history.begin();
  while (n > 0) {
    ++it;
    --n;
  }
  return (*it)->line;
}

} // namespace util
} // namespace debugserver
