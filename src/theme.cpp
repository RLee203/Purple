#include "theme.h"

uint16_t themeModeAccent(TeamMode mode) {
  return mode == TeamMode::Red ? 0xE1A7 : 0x2D7F;
}

uint16_t themeModeSoft(TeamMode mode) {
  return mode == TeamMode::Red ? 0x79C7 : 0x4413;
}

uint16_t themeModeBg(TeamMode mode) {
  return mode == TeamMode::Red ? 0x0803 : 0x0148;
}

uint16_t themeModePanel(TeamMode mode) {
  return mode == TeamMode::Red ? 0x1804 : 0x11AA;
}
