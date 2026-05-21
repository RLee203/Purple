#include "nfc.h"
#include "hardware.h"
#include <Arduino.h>
#include <Wire.h>
#include <SD.h>
#include <SPI.h>

static constexpr uint8_t kPn532Addr = 0x24;

char g_nfcSdFiles[kNfcMaxSavedFiles][48] = {};
int  g_nfcSdFileCount = 0;
char g_nfcLastError[32] = {};

static bool g_nfcReady      = false;
static bool g_tgInitPending = false;  // TgInitAsTarget sent but reader not yet found
static TwoWire* g_wire      = nullptr;
static bool g_wireStarted   = false;

static bool nfcEnsureSd() {
  // Hold SX1262 in reset and deselect NSS — it shares the SPI bus with SD
  // and loads MISO while active even with NSS HIGH.
  const HardwarePins& pins = hardwarePins();
  digitalWrite(pins.loraSpiCs, HIGH);
  digitalWrite(pins.loraRst, LOW);
  if (SD.cardType() != CARD_NONE) return true;
  SPI.begin(pins.sdSck, pins.sdMiso, pins.sdMosi, pins.sdCs);
  pinMode(pins.sdCs, OUTPUT);
  digitalWrite(pins.sdCs, HIGH);
  delay(10);
  SD.begin(pins.sdCs, SPI);
  return SD.cardType() != CARD_NONE;
}

// ─── PN532 I2C helpers ────────────────────────────────────────────────────────

static bool pn532Write(const uint8_t* data, uint8_t len) {
  g_wire->beginTransmission(kPn532Addr);
  for (uint8_t i = 0; i < len; ++i) g_wire->write(data[i]);
  return g_wire->endTransmission() == 0;
}

// Poll until PN532 status byte == 0x01 (ready). Returns false on timeout.
static bool pn532WaitReady(int timeoutMs = 200) {
  const uint32_t deadline = millis() + (uint32_t)timeoutMs;
  while (millis() < deadline) {
    const int n = g_wire->requestFrom((uint8_t)kPn532Addr, (uint8_t)1);
    if (n >= 1 && g_wire->read() == 0x01) return true;
    delay(2);
  }
  return false;
}

// Send a PN532 command frame, wait for ACK + response. Returns response byte count or -1.
// resp[] receives TFI+command bytes (e.g. resp[0]=0xD5, resp[1]=cmd+1, ...).
static int pn532SendCmd(const uint8_t* cmd, uint8_t cmdLen,
                        uint8_t* resp, uint8_t respMax, int waitMs = 150) {
  uint8_t frame[72];
  if ((int)cmdLen + 8 > (int)sizeof(frame)) return -1;

  uint8_t dataSum = 0;
  for (uint8_t i = 0; i < cmdLen; ++i) dataSum += cmd[i];

  uint8_t pos = 0;
  frame[pos++] = 0x00; frame[pos++] = 0x00; frame[pos++] = 0xFF;
  frame[pos++] = cmdLen;
  frame[pos++] = (uint8_t)(0x100 - cmdLen);
  for (uint8_t i = 0; i < cmdLen; ++i) frame[pos++] = cmd[i];
  frame[pos++] = (uint8_t)(0x100 - dataSum);
  frame[pos++] = 0x00;

  if (!pn532Write(frame, pos)) return -1;

  // Wait for ACK, then read it
  if (!pn532WaitReady(waitMs + 100)) return -1;
  uint8_t ack[7];
  const int ackN = g_wire->requestFrom((uint8_t)kPn532Addr, (uint8_t)7);
  if (ackN < 7) return -1;
  for (int i = 0; i < 7; ++i) ack[i] = g_wire->read();
  if (ack[0] != 0x01 || ack[3] != 0xFF || ack[4] != 0x00) return -1;

  // Wait for response frame
  if (!pn532WaitReady(waitMs + 200)) return -1;
  uint8_t raw[80];
  const int rawN = g_wire->requestFrom((uint8_t)kPn532Addr, (uint8_t)sizeof(raw));
  if (rawN < 8) return -1;
  int got = 0;
  while (g_wire->available() && got < (int)sizeof(raw)) raw[got++] = g_wire->read();

  if (got < 7 || raw[0] != 0x01) return -1;

  // Scan for 00 00 FF preamble in response
  int startIdx = -1;
  for (int i = 1; i + 2 < got; ++i) {
    if (raw[i] == 0x00 && raw[i+1] == 0x00 && raw[i+2] == 0xFF) {
      startIdx = i + 3; break;
    }
  }
  if (startIdx < 0 || startIdx + 2 >= got) return -1;

  const uint8_t len = raw[startIdx];
  if (len == 0 || startIdx + 1 + len > got) return -1;
  const int copyLen = (len < respMax) ? len : respMax;
  memcpy(resp, raw + startIdx + 2, copyLen);
  return copyLen;
}

// ─── Public API ───────────────────────────────────────────────────────────────

static void nfcRestartWire() {
  if (g_wireStarted) { g_wire->end(); g_wireStarted = false; }
  delay(50);
  g_wire->begin(kNfcSdaPin, kNfcSclPin);
  g_wire->setClock(100000);
  g_wire->setTimeOut(80);
  g_wireStarted = true;
  delay(100);
}

bool nfcInit() {
  if (g_nfcReady) return true;
  g_wire = &Wire1;
  if (!g_wireStarted) {
    g_wire->begin(kNfcSdaPin, kNfcSclPin);
    g_wire->setClock(100000);
    g_wire->setTimeOut(80);
    g_wireStarted = true;
  }
  delay(50);

  uint8_t resp[16] = {};
  const uint8_t fwCmd[] = {0xD4, 0x02};
  int fw = pn532SendCmd(fwCmd, sizeof(fwCmd), resp, sizeof(resp), 150);

  // If PN532 is stuck (e.g. in TgInitAsTarget), restart Wire1 and retry
  if (!(fw >= 5 && resp[0] == 0xD5 && resp[1] == 0x03)) {
    nfcRestartWire();
    memset(resp, 0, sizeof(resp));
    fw = pn532SendCmd(fwCmd, sizeof(fwCmd), resp, sizeof(resp), 200);
  }

  g_nfcReady = (fw >= 5 && resp[0] == 0xD5 && resp[1] == 0x03);
  if (!g_nfcReady) return false;

  const uint8_t samCfg[] = {0xD4, 0x14, 0x01, 0x00, 0x00};
  uint8_t samResp[8] = {};
  const int n = pn532SendCmd(samCfg, sizeof(samCfg), samResp, sizeof(samResp), 100);
  if (n < 1 || samResp[0] != 0xD5) { g_nfcReady = false; return false; }
  return g_nfcReady;
}

void nfcDeinit() {
  // Reset PN532 state flags. Wire1 stays up — Wire1.end() can deadlock
  // the ESP32 I2C peripheral if no slave responded (CardputerOS finding).
  // GPIO8/9 don't conflict with SD SPI (GPIO40/39/14/12) so it's safe to leave it.
  g_tgInitPending = false;
  g_nfcReady = false;
}

bool nfcIsEmulating() {
  return g_tgInitPending;
}

bool nfcScanTag(NfcTag& out, int timeoutMs) {
  out.valid = false;
  if (!g_nfcReady && !nfcInit()) return false;

  const uint8_t cmd[] = {0xD4, 0x4A, 0x01, 0x00};
  uint8_t resp[32] = {};
  const int n = pn532SendCmd(cmd, sizeof(cmd), resp, sizeof(resp), timeoutMs);
  if (n < 9 || resp[0] != 0xD5 || resp[1] != 0x4B || resp[2] == 0) return false;

  out.atqa[0] = resp[4];
  out.atqa[1] = resp[5];
  out.sak     = resp[6];
  out.uidLen  = resp[7];
  if (out.uidLen > kNfcUidMaxLen) out.uidLen = kNfcUidMaxLen;
  for (int i = 0; i < out.uidLen; ++i) out.uid[i] = resp[8 + i];

  if      (out.sak == 0x08 || out.sak == 0x88) snprintf(out.typeStr, sizeof(out.typeStr), "MIFARE 1K");
  else if (out.sak == 0x18)                     snprintf(out.typeStr, sizeof(out.typeStr), "MIFARE 4K");
  else if (out.sak == 0x00)                     snprintf(out.typeStr, sizeof(out.typeStr), "NTAG/UL");
  else                                           snprintf(out.typeStr, sizeof(out.typeStr), "SAK:%02X", out.sak);

  memset(out.block0, 0, sizeof(out.block0));
  if (out.sak == 0x08 || out.sak == 0x18 || out.sak == 0x88) {
    uint8_t authFull[16] = {0xD4, 0x40, 0x01, 0x60, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    const int uidUse = out.uidLen < 4 ? out.uidLen : 4;
    for (int i = 0; i < uidUse; ++i) authFull[11 + i] = out.uid[i];
    uint8_t authResp[8] = {};
    pn532SendCmd(authFull, 11 + uidUse, authResp, sizeof(authResp), 80);

    const uint8_t readCmd[] = {0xD4, 0x40, 0x01, 0x30, 0x00};
    uint8_t readResp[24] = {};
    const int rn = pn532SendCmd(readCmd, sizeof(readCmd), readResp, sizeof(readResp), 80);
    if (rn >= 19 && readResp[0] == 0xD5 && readResp[2] == 0x00) {
      memcpy(out.block0, readResp + 3, 16);
    }
  }

  out.valid = true;
  return true;
}

bool nfcSaveToSd(const NfcTag& tag) {
  g_nfcLastError[0] = '\0';
  if (!tag.valid) {
    snprintf(g_nfcLastError, sizeof(g_nfcLastError), "no tag");
    return false;
  }
  if (!nfcEnsureSd()) {
    snprintf(g_nfcLastError, sizeof(g_nfcLastError), "no SD(t=%d)", (int)SD.cardType());
    return false;
  }
  const bool madeDir = SD.mkdir("/nfc");
  int idx = 0;
  char path[48];
  do {
    snprintf(path, sizeof(path), "/nfc/tag_%03d.bin", idx++);
  } while (SD.exists(path) && idx < 1000);
  File f = SD.open(path, FILE_WRITE);
  if (!f) {
    snprintf(g_nfcLastError, sizeof(g_nfcLastError), "open fail%s",
             madeDir ? "" : "(mkdir)");
    return false;
  }
  const uint8_t hdr[2] = {0x4E, 0x46};
  f.write(hdr, 2);
  f.write(tag.uidLen);
  f.write(tag.uid, kNfcUidMaxLen);
  f.write(tag.sak);
  f.write(tag.atqa, 2);
  f.write((const uint8_t*)tag.typeStr, 12);
  f.write(tag.block0, 16);
  f.close();
  return true;
}

bool nfcLoadFromSd(const char* path, NfcTag& out) {
  if (!nfcEnsureSd()) return false;
  File f = SD.open(path);
  if (!f) return false;
  uint8_t hdr[2];
  if (f.read(hdr, 2) < 2 || hdr[0] != 0x4E || hdr[1] != 0x46) { f.close(); return false; }
  out.uidLen = f.read();
  f.read(out.uid, kNfcUidMaxLen);
  out.sak = f.read();
  f.read(out.atqa, 2);
  f.read((uint8_t*)out.typeStr, 12);
  f.read(out.block0, 16);
  f.close();
  out.valid = (out.uidLen >= 4 && out.uidLen <= kNfcUidMaxLen);
  return out.valid;
}

void nfcScanSdFiles() {
  g_nfcSdFileCount = 0;
  if (!nfcEnsureSd()) return;
  File dir = SD.open("/nfc");
  if (!dir || !dir.isDirectory()) return;
  File f = dir.openNextFile();
  while (f && g_nfcSdFileCount < kNfcMaxSavedFiles) {
    if (!f.isDirectory()) {
      const char* name = f.name();
      const int nl = strlen(name);
      if (nl > 4 && strcmp(name + nl - 4, ".bin") == 0) {
        snprintf(g_nfcSdFiles[g_nfcSdFileCount], 48, "/nfc/%s", name);
        ++g_nfcSdFileCount;
      }
    }
    f.close();
    f = dir.openNextFile();
  }
  dir.close();
}

// Send TgInitAsTarget + read ACK only. g_tgInitPending must be false when called.
static bool sendTgInitAsTarget(const NfcTag& tag) {
  // SAMConfiguration resets any active ISO14443A session left from a previous scan
  {
    const uint8_t samCfg[] = {0xD4, 0x14, 0x01, 0x00, 0x00};
    uint8_t samResp[8] = {};
    pn532SendCmd(samCfg, sizeof(samCfg), samResp, sizeof(samResp), 100);
    delay(20);
  }

  // Full TgInitAsTarget parameter set (39 bytes total):
  //   Mode(1) + MifareParams: ATQA[2]+SAK+NFCIDt[3] (6) +
  //   FelicaParams(18) + NFCID3t(10) + GtLen(1) + TkLen(1)
  uint8_t cmd[48] = {};
  cmd[0] = 0xD4;
  cmd[1] = 0x8C;        // TgInitAsTarget
  cmd[2] = 0x00;        // mode: accept all passive initiations
  cmd[3] = tag.atqa[0];
  cmd[4] = tag.atqa[1];
  cmd[5] = tag.sak;
  cmd[6] = tag.uid[0];  // NFCIDt: exactly 3 bytes (PN532 derives 4th byte)
  cmd[7] = tag.uid[1];
  cmd[8] = tag.uid[2];
  // cmd[9..26]  = FelicaParams[18] zeros
  // cmd[27..36] = NFCID3t[10]      zeros
  // cmd[37]     = GtLen = 0
  // cmd[38]     = TkLen = 0
  const uint8_t cmdLen = 39;

  uint8_t frame[56] = {};
  uint8_t dataSum = 0;
  for (uint8_t i = 0; i < cmdLen; ++i) dataSum += cmd[i];
  uint8_t fpos = 0;
  frame[fpos++] = 0x00; frame[fpos++] = 0x00; frame[fpos++] = 0xFF;
  frame[fpos++] = cmdLen;
  frame[fpos++] = (uint8_t)(0x100 - cmdLen);
  for (uint8_t i = 0; i < cmdLen; ++i) frame[fpos++] = cmd[i];
  frame[fpos++] = (uint8_t)(0x100 - dataSum);
  frame[fpos++] = 0x00;

  if (!pn532Write(frame, fpos)) return false;

  // ACK comes within ~200ms
  if (!pn532WaitReady(500)) return false;
  uint8_t ack[7];
  const int ackN = g_wire->requestFrom((uint8_t)kPn532Addr, (uint8_t)7);
  if (ackN < 7) return false;
  for (int i = 0; i < 7; ++i) ack[i] = g_wire->read();
  return (ack[0] == 0x01);  // status byte must be ready
}

bool nfcEmulateTag(const NfcTag& tag, int durationMs) {
  if (!tag.valid || tag.uidLen < 4) return false;
  if (!g_nfcReady && !nfcInit()) return false;

  // Only send TgInitAsTarget once. While g_tgInitPending, just poll the response.
  // Resending while the PN532 is busy executing it corrupts state.
  if (!g_tgInitPending) {
    if (!sendTgInitAsTarget(tag)) return false;
    g_tgInitPending = true;
  }

  // Poll — returns false while no reader; true when a reader selected this tag
  if (!pn532WaitReady(durationMs)) return false;

  // Reader found — consume the response, then allow next call to restart emulation
  uint8_t resp[32] = {};
  const int rn = g_wire->requestFrom((uint8_t)kPn532Addr, (uint8_t)sizeof(resp));
  int got = 0;
  while (g_wire->available() && got < (int)sizeof(resp)) resp[got++] = g_wire->read();
  (void)rn;
  g_tgInitPending = false;
  return (got > 0 && resp[0] == 0x01);
}
