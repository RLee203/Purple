#pragma once

#include <stdint.h>

#include "apps.h"

constexpr uint16_t kBg = 0x0821;
constexpr uint16_t kPanel = 0x10A2;
constexpr uint16_t kPanelAlt = 0x18E3;
constexpr uint16_t kText = 0xEF7D;
constexpr uint16_t kDimText = 0x7BEF;
constexpr uint16_t kGold = 0xD666;
constexpr uint16_t kPurpleTitle = 0xB81F;

uint16_t themeModeAccent(TeamMode mode);
uint16_t themeModeSoft(TeamMode mode);
uint16_t themeModeBg(TeamMode mode);
uint16_t themeModePanel(TeamMode mode);
