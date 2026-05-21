#include "launcher.h"
#include "hardware.h"
#include "status.h"
#include "theme.h"

#include <M5Cardputer.h>

namespace {

enum class LauncherView {
  ModePicker,
  AppList,
};

TeamMode g_mode = TeamMode::Red;
int g_selectedIndex = 0;
LauncherView g_view = LauncherView::ModePicker;
constexpr int kScreenW = 240;
constexpr int kScreenH = 135;
constexpr int kVisibleApps = 5;

void clampSelection() {
  int count = 0;
  getAppsForMode(g_mode, count);
  if (count <= 0) {
    g_selectedIndex = 0;
  } else if (g_selectedIndex >= count) {
    g_selectedIndex = count - 1;
  } else if (g_selectedIndex < 0) {
    g_selectedIndex = 0;
  }
}

void drawRedGrid() {
  const uint16_t line = 0x3006;
  for (int x = 0; x < kScreenW; x += 20) {
    M5.Display.drawFastVLine(x, 0, kScreenH, line);
  }
  for (int y = 0; y < kScreenH; y += 16) {
    M5.Display.drawFastHLine(0, y, kScreenW, line);
  }
  M5.Display.fillTriangle(196, 0, kScreenW, 0, kScreenW, 28,
                          themeModeSoft(TeamMode::Red));
}

void drawBlueGrid() {
  const uint16_t line = 0x22B1;
  for (int x = 12; x < kScreenW; x += 24) {
    M5.Display.drawFastVLine(x, 0, kScreenH, line);
  }
  for (int y = 8; y < kScreenH; y += 16) {
    M5.Display.drawFastHLine(0, y, kScreenW, line);
  }
  M5.Display.drawRoundRect(172, 8, 56, 20, 6, themeModeSoft(TeamMode::Blue));
}

void drawModeCard(int x, int y, int w, int h, TeamMode mode, bool selected) {
  const uint16_t color = themeModeAccent(mode);
  const uint16_t fill = selected ? themeModeSoft(mode) : themeModePanel(mode);
  const int radius = mode == TeamMode::Red ? 3 : 10;
  M5.Display.fillRoundRect(x, y, w, h, radius, fill);
  M5.Display.drawRoundRect(x, y, w, h, radius, color);
  if (selected) {
    if (mode == TeamMode::Red) {
      M5.Display.drawFastHLine(x + 5, y + 4, w - 10, kGold);
      M5.Display.drawFastHLine(x + 5, y + h - 5, w - 10, kGold);
    } else {
      M5.Display.drawRoundRect(x + 2, y + 2, w - 4, h - 4, radius, kGold);
    }
  }
  M5.Display.setTextColor(selected ? kGold : color, fill);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(x + 10, y + 12);
  M5.Display.print(getModeName(mode));
  M5.Display.print(" ");
  M5.Display.println(getModeSubtitle(mode));
}

void drawChrome() {
  M5.Display.fillScreen(themeModeBg(g_mode));
  if (g_mode == TeamMode::Red) {
    drawRedGrid();
    M5.Display.fillRoundRect(8, 6, 224, 24, 4, themeModePanel(g_mode));
    M5.Display.drawRoundRect(8, 6, 224, 24, 4, themeModeAccent(g_mode));
    M5.Display.fillRoundRect(8, 36, 224, 42, 4, themeModePanel(g_mode));
    M5.Display.drawRoundRect(8, 36, 224, 42, 4, kGold);
    M5.Display.fillRoundRect(8, 84, 224, 44, 4, kPanelAlt);
    M5.Display.drawRoundRect(8, 84, 224, 44, 4, themeModeAccent(g_mode));
  } else {
    drawBlueGrid();
    M5.Display.fillRoundRect(8, 6, 224, 24, 12, themeModePanel(g_mode));
    M5.Display.drawRoundRect(8, 6, 224, 24, 12, kGold);
    M5.Display.fillRoundRect(8, 36, 224, 42, 12, themeModePanel(g_mode));
    M5.Display.drawRoundRect(8, 36, 224, 42, 12, themeModeAccent(g_mode));
    M5.Display.fillRoundRect(8, 84, 224, 44, 12, kPanelAlt);
    M5.Display.drawRoundRect(8, 84, 224, 44, 12, themeModeSoft(g_mode));
  }
}

void drawModePicker() {
  drawChrome();
  M5.Display.setTextColor(kPurpleTitle, kPanelAlt);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(18, 14);
  M5.Display.println("Purple");
  drawBatteryWidget(themeModePanel(g_mode), 132);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.fillRoundRect(168, 9, 58, 16, 6, themeModeBg(g_mode));
  M5.Display.drawRoundRect(168, 9, 58, 16, 6, themeModeSoft(g_mode));
  M5.Display.setCursor(183, 14);
  M5.Display.println(hardwareProfileShortName());

  M5.Display.setTextColor(kText, themeModeBg(g_mode));
  M5.Display.fillRect(20, 88, 200, 16, themeModeBg(g_mode));
  M5.Display.setCursor(44, 88);
  M5.Display.println(hardwareProfileName());
  M5.Display.setCursor(76, 100);
  M5.Display.println("Enter = open");
  M5.Display.setCursor(76, 110);
  M5.Display.println("Fn+, left  Fn+/ right");
  M5.Display.setCursor(76, 120);
  M5.Display.println("pick team  Tab+Bk modes");
}

void drawAppList() {
  int count = 0;
  const AppEntry* apps = getAppsForMode(g_mode, count);
  const uint16_t accent = themeModeAccent(g_mode);
  const uint16_t soft = themeModeSoft(g_mode);
  const int listStart = (g_selectedIndex / kVisibleApps) * kVisibleApps;
  const int listEnd = ((listStart + kVisibleApps) < count) ? (listStart + kVisibleApps) : count;

  M5.Display.fillRoundRect(8, 30, 224, 96, g_mode == TeamMode::Red ? 3 : 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 30, 224, 96, g_mode == TeamMode::Red ? 3 : 10, accent);

  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(18, 14);
  M5.Display.println(g_mode == TeamMode::Red ? "Red Team" : "Blue Team");
  drawBatteryWidget(kPanelAlt, 132);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.fillRoundRect(168, 9, 58, 16, 6, themeModeBg(g_mode));
  M5.Display.drawRoundRect(168, 9, 58, 16, 6, themeModeSoft(g_mode));
  M5.Display.setCursor(183, 14);
  M5.Display.println(hardwareProfileShortName());

  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(18, 38);
  M5.Display.println(g_mode == TeamMode::Red ? "ops" : "monitor");

  for (int i = listStart; i < listEnd; ++i) {
    const int row = i - listStart;
    const int x = 18;
    const int y = 50 + (row * 10);
    if (i == g_selectedIndex) {
      const int radius = g_mode == TeamMode::Red ? 2 : 6;
      M5.Display.fillRoundRect(14, y - 2, 212, 10, radius, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(x, y);
    M5.Display.printf("%d. %s", i + 1, apps[i].label);
  }

  M5.Display.setTextColor(soft, kPanelAlt);
  M5.Display.setCursor(176, 38);
  M5.Display.printf("%d/%d", g_selectedIndex + 1, count);
  if (count > kVisibleApps) {
    M5.Display.setCursor(176, 46);
    M5.Display.printf("p%d", (listStart / kVisibleApps) + 1);
  }
  M5.Display.setTextColor(soft, kPanelAlt);
  M5.Display.setCursor(18, 100);
  M5.Display.println(hardwareProfileHint());
}

}  // namespace

void launcherEnter() {
  g_mode = TeamMode::Red;
  g_selectedIndex = 0;
  g_view = LauncherView::ModePicker;
  launcherDraw();
}

void launcherDraw() {
  clampSelection();
  M5.Display.setTextWrap(false);
  if (g_view == LauncherView::ModePicker) {
    drawModePicker();
    drawModeCard(16, 42, 100, 30, TeamMode::Red, g_mode == TeamMode::Red);
    drawModeCard(124, 42, 100, 30, TeamMode::Blue, g_mode == TeamMode::Blue);
  } else {
    M5.Display.fillScreen(themeModeBg(g_mode));
    if (g_mode == TeamMode::Red) {
      drawRedGrid();
    } else {
      drawBlueGrid();
    }
    drawAppList();
    M5.Display.setTextColor(kDimText, themeModeBg(g_mode));
    M5.Display.fillRect(0, 124, kScreenW, 12, themeModeBg(g_mode));
    M5.Display.setCursor(8, 126);
    M5.Display.println("Ent open ; up . dn Tab+Bk");
  }
}

void launcherNextMode() {
  g_mode = (g_mode == TeamMode::Red) ? TeamMode::Blue : TeamMode::Red;
  if (g_view == LauncherView::AppList) {
    g_selectedIndex = 0;
  }
  launcherDraw();
}

void launcherNextHardwareProfile() {
  hardwareNextProfile();
  launcherDraw();
}

void launcherMoveSelection(int delta) {
  if (g_view != LauncherView::AppList) {
    return;
  }
  int count = 0;
  getAppsForMode(g_mode, count);
  if (count <= 0) {
    return;
  }
  g_selectedIndex += delta;
  if (g_selectedIndex < 0) {
    g_selectedIndex = count - 1;
  } else if (g_selectedIndex >= count) {
    g_selectedIndex = 0;
  }
  launcherDraw();
}

void launcherOpenTeamApps() {
  g_view = LauncherView::AppList;
  g_selectedIndex = 0;
  launcherDraw();
}

void launcherShowModePicker() {
  g_view = LauncherView::ModePicker;
  launcherDraw();
}

bool launcherShowingModePicker() {
  return g_view == LauncherView::ModePicker;
}

TeamMode launcherCurrentMode() {
  return g_mode;
}

AppId launcherCurrentApp() {
  int count = 0;
  const AppEntry* apps = getAppsForMode(g_mode, count);
  clampSelection();
  return apps[g_selectedIndex].id;
}
