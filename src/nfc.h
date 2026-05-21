#pragma once
#include <stdint.h>

// PN532 on Grove I2C: G8=SDA, G9=SCL (Wire1)
constexpr int kNfcSdaPin = 8;
constexpr int kNfcSclPin = 9;

static constexpr int kNfcMaxSavedFiles = 8;
static constexpr int kNfcUidMaxLen = 7;

struct NfcTag {
  bool valid;
  uint8_t uid[kNfcUidMaxLen];
  uint8_t uidLen;
  uint8_t atqa[2];
  uint8_t sak;
  char typeStr[12];   // "MIFARE 1K", "MIFARE 4K", "NTAG", etc.
  uint8_t block0[16]; // sector 0 block 0 data (manufacturer block)
};

bool nfcInit();
void nfcDeinit();
bool nfcIsEmulating();
bool nfcScanTag(NfcTag& out, int timeoutMs = 2000);
bool nfcSaveToSd(const NfcTag& tag);
bool nfcLoadFromSd(const char* path, NfcTag& out);
void nfcScanSdFiles();
bool nfcEmulateTag(const NfcTag& tag, int durationMs = 10000);

extern char g_nfcSdFiles[kNfcMaxSavedFiles][48];
extern int  g_nfcSdFileCount;
extern char g_nfcLastError[32];  // set on failure by nfcSaveToSd / nfcLoadFromSd
