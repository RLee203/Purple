#pragma once
#include <stdint.h>

constexpr int kIrTxPin = 44;  // M5Cardputer ADV built-in IR emitter
constexpr int kIrRxPin = 2;   // External IR receiver module on GPIO2

struct IrCode {
  const char* label;
  uint16_t addr;
  uint8_t cmd;
};

struct IrReceived {
  bool valid;
  uint16_t addr;
  uint8_t cmd;
  uint32_t rawCode;
};

static constexpr int kIrRawMaxPulses = 128;
struct IrRawCapture {
  bool valid;
  uint16_t pulses[kIrRawMaxPulses];  // microseconds, alternating mark/space
  uint8_t count;
};

extern const IrCode kIrTvPowerCodes[];
extern const int kIrTvPowerCount;
extern const IrCode kIrAcPowerCodes[];
extern const int kIrAcPowerCount;

void irInit();
void irDeinit();
void irSendNec(uint16_t addr, uint8_t cmd);
void irSendRepeatFrame();
IrReceived irReceiveNec(int timeoutMs);
IrRawCapture irCaptureRaw(int timeoutMs);
void irReplayRaw(const IrRawCapture& cap);
