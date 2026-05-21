#include <M5Cardputer.h>

#include "apps.h"
#include "hardware.h"
#include "launcher.h"
#include "status.h"

namespace {

enum class UiState {
  Launcher,
  App,
};

UiState g_state = UiState::Launcher;
TeamMode g_currentMode = TeamMode::Red;
AppId g_currentApp = AppId::WifiOps;
uint32_t g_lastNavMs = 0;
uint32_t g_lastModeMs = 0;
uint32_t g_lastSelectMs = 0;
uint32_t g_lastPickerRefreshMs = 0;
uint32_t g_lastAppRefreshMs = 0;

uint32_t appRefreshIntervalMs(TeamMode mode, AppId appId) {
  if (mode == TeamMode::Blue && appId == AppId::GpsMonitor) {
    return 550;
  }
  if (mode == TeamMode::Blue && appId == AppId::NfcScanner) {
    return 220;
  }
  if ((mode == TeamMode::Blue && (appId == AppId::Cc1101Scan || appId == AppId::NrfAnalyzer)) ||
      (mode == TeamMode::Red && (appId == AppId::Cc1101Ops || appId == AppId::Nrf24Ops))) {
    return 150;
  }
  if (mode == TeamMode::Blue && appId == AppId::NfcScanner) {
    return 200;
  }
  return 90;
}

template <typename T>
bool hasChar(const T& state, char target) {
  for (char c : state.word) {
    if (c == target) {
      return true;
    }
  }
  return false;
}

bool navReady(uint32_t now, uint32_t gap = 120) {
  if (now - g_lastNavMs < gap) return false;
  g_lastNavMs = now;
  return true;
}

bool modeReady(uint32_t now, uint32_t gap = 350) {
  if (hardwareCurrentProfile() == HardwareProfile::RfHat && gap < 900) {
    gap = 900;
  }
  if (now - g_lastModeMs < gap) return false;
  g_lastModeMs = now;
  return true;
}

bool selectReady(uint32_t now, uint32_t gap = 180) {
  if (now - g_lastSelectMs < gap) return false;
  g_lastSelectMs = now;
  return true;
}

template <typename T>
int teamSwitchDirection(const T& state) {
  // Use the physical arrow combo on the Cardputer:
  // Fn+, = left and Fn+/ = right.
  if (!state.fn || state.enter || state.del || state.tab) return 0;
  if (state.word.size() != 1) return 0;
  if (hasChar(state, ',')) return -1;
  if (hasChar(state, '/')) return 1;
  return 0;
}

template <typename T>
bool wantsModePicker(const T& state) {
  return state.tab && state.del;
}

void openCurrentApp() {
  g_currentMode = launcherCurrentMode();
  g_currentApp = launcherCurrentApp();
  g_state = UiState::App;
  drawAppScreen(g_currentMode, g_currentApp);
}

template <typename T>
void handleLauncherKeys(const T& state) {
  const uint32_t now = millis();
  const int teamDirection = teamSwitchDirection(state);
  if (!launcherShowingModePicker() && wantsModePicker(state)) {
    if (!modeReady(now, 250)) return;
    launcherShowModePicker();
    g_currentMode = launcherCurrentMode();
    return;
  }
  if (launcherShowingModePicker() && teamDirection != 0) {
    if (!modeReady(now)) return;
    TeamMode nextMode = launcherCurrentMode();
    if (teamDirection < 0) {
      nextMode = TeamMode::Red;
    } else if (teamDirection > 0) {
      nextMode = TeamMode::Blue;
    }
    if (nextMode != launcherCurrentMode()) {
      launcherNextMode();
    }
    g_currentMode = launcherCurrentMode();
    return;
  }
  if (launcherShowingModePicker()) {
    if (state.enter) {
      if (!selectReady(now)) return;
      g_currentMode = launcherCurrentMode();
      launcherOpenTeamApps();
    }
    return;
  }
  if (state.fn && hasChar(state, ';')) {
    if (!navReady(now)) return;
    launcherMoveSelection(-1);
    return;
  }
  if (state.fn && hasChar(state, '.')) {
    if (!navReady(now)) return;
    launcherMoveSelection(1);
    return;
  }
  if (state.enter) {
    if (!selectReady(now)) return;
    openCurrentApp();
  }
}

template <typename T>
void handleAppKeys(const T& state) {
  const uint32_t now = millis();
  const bool moveUp = state.fn && hasChar(state, ';');
  const bool moveDown = state.fn && hasChar(state, '.');
  const bool backPressed = state.fn && state.del;
  const bool cycleSort = state.fn && (hasChar(state, 's') || hasChar(state, 'S'));
  const bool rescanPressed = state.fn && (hasChar(state, 'r') || hasChar(state, 'R'));
  const bool deletePressed = state.fn && (hasChar(state, 'd') || hasChar(state, 'D'));
  const bool renamePressed = state.fn && (hasChar(state, 'n') || hasChar(state, 'N'));
  const bool modePickerPressed = wantsModePicker(state);

  // Set typed char for rename mode — only plain (non-modifier) key presses
  const bool isPlainChar = !state.fn && !state.enter && !state.del && !state.tab &&
                            state.word.size() == 1;
  g_appTypedChar    = isPlainChar ? (char)state.word[0] : 0;
  g_appTypedBackspace = state.del && !state.fn;

  if (modePickerPressed) {
    if (!modeReady(now, 250)) return;
    appOnExit(g_currentMode, g_currentApp);
    g_state = UiState::Launcher;
    launcherShowModePicker();
    return;
  }
  if ((moveUp || moveDown || backPressed || cycleSort || rescanPressed || deletePressed ||
       renamePressed || state.enter) &&
      !navReady(now, state.enter ? 160 : 110)) {
    return;
  }
  if (handleAppAction(g_currentMode, g_currentApp, moveUp, moveDown, state.enter,
                      backPressed, cycleSort, rescanPressed, deletePressed, renamePressed)) {
    return;
  }
  if (backPressed) {
    appOnExit(g_currentMode, g_currentApp);
    g_state = UiState::Launcher;
    launcherDraw();
  }
}

}  // namespace

void setup() {
  auto cfg = M5.config();
  M5Cardputer.begin(cfg, true);
  M5Cardputer.Speaker.stop();
  M5Cardputer.Speaker.setAllChannelVolume(0);
  M5Cardputer.Speaker.setVolume(0);
  M5Cardputer.Speaker.end();
  hardwareInit();
  settingsInit();
  initBatteryMonitoring();
  if (settingsDefaultTeam() == TeamMode::Blue) launcherNextMode();
  launcherEnter();
}

void loop() {
  M5Cardputer.update();
  g_appTypedChar = 0;
  g_appTypedBackspace = false;
  const uint32_t now = millis();
  const bool pickerActive = g_state == UiState::Launcher && launcherShowingModePicker();

  if (pickerActive && now - g_lastPickerRefreshMs >= 1200) {
    g_lastPickerRefreshMs = now;
    launcherDraw();
  }

    if (g_state == UiState::App && appNeedsPeriodicRefresh(g_currentMode, g_currentApp)) {
      const uint32_t refreshMs = appRefreshIntervalMs(g_currentMode, g_currentApp);
      if (now - g_lastAppRefreshMs >= refreshMs) {
        g_lastAppRefreshMs = now;
        handleAppAction(g_currentMode, g_currentApp, false, false, false, false, false, false, false);
      }
  }

  const bool shouldHandleKeys =
      M5Cardputer.Keyboard.isPressed() &&
      (M5Cardputer.Keyboard.isChange() || pickerActive);

  if (shouldHandleKeys) {
    auto state = M5Cardputer.Keyboard.keysState();
    if (g_state == UiState::Launcher) {
      handleLauncherKeys(state);
    } else {
      handleAppKeys(state);
    }
  }
  delay(20);
}
