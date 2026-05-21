#pragma once

#include <M5Cardputer.h>
#include <M5Unified.h>
#include <utility/power/IP5306_Class.hpp>

inline m5::IP5306_Class g_twoFaceBatteryPmic{};
inline bool g_twoFaceBatteryPmicReady = false;

inline void initBatteryMonitoring() {
  g_twoFaceBatteryPmicReady = g_twoFaceBatteryPmic.begin();
}

inline int getBatteryPercent() {
  if (g_twoFaceBatteryPmicReady) {
    const int pct = g_twoFaceBatteryPmic.getBatteryLevel();
    if (pct >= 0) return pct;
  }
  return M5Cardputer.Power.getBatteryLevel();
}

inline void drawBatteryWidget(uint32_t bg, int bx = 184) {
  auto& d = M5Cardputer.Display;
  const int pct = getBatteryPercent();
  uint32_t col = pct > 50 ? static_cast<uint32_t>(0x00CC00)
               : pct > 20 ? static_cast<uint32_t>(0xCCAA00)
                          : static_cast<uint32_t>(0xFF3333);
  d.drawRect(bx, 7, 14, 8, col);
  d.fillRect(bx + 14, 9, 2, 4, col);
  const int fw = (pct >= 0) ? (pct * 12) / 100 : 0;
  if (fw > 0) d.fillRect(bx + 1, 8, fw, 6, col);
  char buf[5];
  snprintf(buf, sizeof(buf), pct >= 0 ? "%d" : "--", pct);
  d.setTextColor(col, bg);
  d.setCursor(bx + 18, 8);
  d.print(buf);
}
