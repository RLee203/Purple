#include "usb_hid.h"
#include <USB.h>
#include <USBHIDKeyboard.h>
#include <SD.h>
#include <Arduino.h>

// Global — constructor runs before USB.begin(), registering the HID device.
static USBHIDKeyboard g_kb;

void usbHidInit() {
  g_kb.begin();
  USB.begin();  // no-op if CDC auto-start already called it
}

// ── Key code helpers ──────────────────────────────────────────────────────────

static uint8_t duckyModKey(const char* t) {
  if (!strcmp(t,"CTRL")    || !strcmp(t,"CONTROL"))  return KEY_LEFT_CTRL;
  if (!strcmp(t,"SHIFT"))                             return KEY_LEFT_SHIFT;
  if (!strcmp(t,"ALT"))                               return KEY_LEFT_ALT;
  if (!strcmp(t,"GUI")     || !strcmp(t,"WINDOWS")
                           || !strcmp(t,"COMMAND"))   return KEY_LEFT_GUI;
  return 0;
}

static uint8_t duckySpecialKey(const char* t) {
  if (!strcmp(t,"ENTER")       || !strcmp(t,"RETURN"))      return KEY_RETURN;
  if (!strcmp(t,"BACKSPACE")   || !strcmp(t,"BKSP"))        return KEY_BACKSPACE;
  if (!strcmp(t,"TAB"))                                      return KEY_TAB;
  if (!strcmp(t,"ESC")         || !strcmp(t,"ESCAPE"))      return KEY_ESC;
  if (!strcmp(t,"DELETE")      || !strcmp(t,"DEL"))         return KEY_DELETE;
  if (!strcmp(t,"SPACE"))                                    return ' ';
  if (!strcmp(t,"UP")          || !strcmp(t,"UPARROW"))     return KEY_UP_ARROW;
  if (!strcmp(t,"DOWN")        || !strcmp(t,"DOWNARROW"))   return KEY_DOWN_ARROW;
  if (!strcmp(t,"LEFT")        || !strcmp(t,"LEFTARROW"))   return KEY_LEFT_ARROW;
  if (!strcmp(t,"RIGHT")       || !strcmp(t,"RIGHTARROW"))  return KEY_RIGHT_ARROW;
  if (!strcmp(t,"HOME"))                                     return KEY_HOME;
  if (!strcmp(t,"END"))                                      return KEY_END;
  if (!strcmp(t,"PAGEUP")      || !strcmp(t,"PAGE_UP"))     return KEY_PAGE_UP;
  if (!strcmp(t,"PAGEDOWN")    || !strcmp(t,"PAGE_DOWN"))   return KEY_PAGE_DOWN;
  if (!strcmp(t,"INSERT"))                                   return KEY_INSERT;
  if (!strcmp(t,"CAPS_LOCK")   || !strcmp(t,"CAPSLOCK"))   return KEY_CAPS_LOCK;
  if (!strcmp(t,"PRINT_SCREEN")||!strcmp(t,"PRINTSCREEN")) return HID_KEY_PRINT_SCREEN;
  if (!strcmp(t,"SCROLL_LOCK"))                              return HID_KEY_SCROLL_LOCK;
  if (!strcmp(t,"PAUSE")       || !strcmp(t,"BREAK"))       return HID_KEY_PAUSE;
  if (!strcmp(t,"NUM_LOCK")    || !strcmp(t,"NUMLOCK"))     return HID_KEY_NUM_LOCK;
  if (!strcmp(t,"F1"))  return KEY_F1;   if (!strcmp(t,"F2"))  return KEY_F2;
  if (!strcmp(t,"F3"))  return KEY_F3;   if (!strcmp(t,"F4"))  return KEY_F4;
  if (!strcmp(t,"F5"))  return KEY_F5;   if (!strcmp(t,"F6"))  return KEY_F6;
  if (!strcmp(t,"F7"))  return KEY_F7;   if (!strcmp(t,"F8"))  return KEY_F8;
  if (!strcmp(t,"F9"))  return KEY_F9;   if (!strcmp(t,"F10")) return KEY_F10;
  if (!strcmp(t,"F11")) return KEY_F11;  if (!strcmp(t,"F12")) return KEY_F12;
  // Single character (e.g. "r" after "GUI")
  if (t[0] != '\0' && t[1] == '\0') return (uint8_t)t[0];
  return 0;
}

// ── Line executor ─────────────────────────────────────────────────────────────

static void runLine(const String& line, int defaultDelay) {
  if (line.length() == 0) return;

  // Comment
  if (line.startsWith("REM") || line.startsWith("//")) return;

  // STRING / STRINGLN
  if (line.startsWith("STRINGLN ")) {
    g_kb.println(line.substring(9).c_str());
    if (defaultDelay > 0) delay(defaultDelay);
    return;
  }
  if (line.startsWith("STRING ")) {
    g_kb.print(line.substring(7).c_str());
    if (defaultDelay > 0) delay(defaultDelay);
    return;
  }

  // DELAY
  if (line.startsWith("DELAY ") || line.startsWith("WAIT ")) {
    int sp = line.indexOf(' ');
    delay(line.substring(sp + 1).toInt());
    return;
  }

  // DEFAULTDELAY / DEFAULT_DELAY — handled by caller
  if (line.startsWith("DEFAULTDELAY ") || line.startsWith("DEFAULT_DELAY ")) return;

  // Key / modifier combo — tokenise
  char buf[128];
  strncpy(buf, line.c_str(), sizeof(buf) - 1);
  buf[sizeof(buf) - 1] = '\0';

  char* toks[8];
  int n = 0;
  char* p = strtok(buf, " ");
  while (p && n < 8) { toks[n++] = p; p = strtok(nullptr, " "); }
  if (n == 0) return;

  // Press modifiers (all tokens except last)
  for (int i = 0; i < n - 1; ++i) {
    uint8_t m = duckyModKey(toks[i]);
    if (m) g_kb.press(m);
  }

  // Last token: modifier-only press OR regular key
  uint8_t lastMod = duckyModKey(toks[n - 1]);
  if (lastMod) {
    g_kb.press(lastMod);
  } else {
    uint8_t k = duckySpecialKey(toks[n - 1]);
    if (k) g_kb.press(k);
  }

  delay(30);
  g_kb.releaseAll();
  if (defaultDelay > 0) delay(defaultDelay);
}

// ── Public: run a Ducky Script file ──────────────────────────────────────────

DuckyResult usbHidRunScript(const char* path) {
  DuckyResult res = {false, 0, {}};

  File f = SD.open(path);
  if (!f) {
    snprintf(res.error, sizeof(res.error), "Cannot open: %s", path);
    return res;
  }

  int  defaultDelay = 0;
  String lastLine   = "";

  while (f.available()) {
    String line = f.readStringUntil('\n');
    line.trim();                          // strips \r\n and surrounding whitespace
    if (line.length() == 0) continue;

    // Track default delay setting
    if (line.startsWith("DEFAULTDELAY ") || line.startsWith("DEFAULT_DELAY ")) {
      int sp = line.indexOf(' ');
      defaultDelay = line.substring(sp + 1).toInt();
      continue;
    }

    // REPEAT n  — repeat last executable line n times
    if (line.startsWith("REPEAT ")) {
      int rpt = line.substring(7).toInt();
      for (int i = 0; i < rpt; ++i) {
        if (lastLine.length() > 0) runLine(lastLine, defaultDelay);
        ++res.linesRun;
      }
      continue;
    }

    runLine(line, defaultDelay);
    lastLine = line;
    ++res.linesRun;
  }

  f.close();
  res.ok = true;
  return res;
}
