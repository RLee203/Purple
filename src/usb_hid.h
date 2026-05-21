#pragma once
#include <stdint.h>

struct DuckyResult {
  bool ok;
  int  linesRun;
  char error[48];
};

void        usbHidInit();
DuckyResult usbHidRunScript(const char* path);
