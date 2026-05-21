#pragma once

enum class TeamMode {
  Red,
  Blue,
};

enum class AppId {
  WifiOps,
  BleOps,
  IrToolkit,
  Payloads,
  Cc1101Ops,
  Nrf24Ops,
  RfTools,
  FieldNotes,
  Files,
  Settings,
  WifiMonitor,
  BleMonitor,
  GpsMonitor,
  Cc1101Scan,
  NrfAnalyzer,
  Alerts,
  Logs,
  DeviceHealth,
  ResponseNotes,
  NfcScanner,
};

struct AppEntry {
  AppId id;
  const char* label;
};

const AppEntry* getAppsForMode(TeamMode mode, int& count);
const char* getModeName(TeamMode mode);
const char* getModeSubtitle(TeamMode mode);
AppId getPairedAppForTeam(AppId appId, TeamMode targetMode);
void drawAppScreen(TeamMode mode, AppId appId);
extern char g_appTypedChar;
extern bool g_appTypedBackspace;

bool handleAppAction(TeamMode mode, AppId appId, bool moveUp, bool moveDown,
                     bool selectPressed, bool backPressed, bool cycleSort,
                     bool rescanPressed, bool deletePressed, bool renamePressed = false);
bool appNeedsPeriodicRefresh(TeamMode mode, AppId appId);
void appOnExit(TeamMode mode, AppId appId);
void settingsInit();
TeamMode settingsDefaultTeam();
