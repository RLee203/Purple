#include "ir.h"
#include <Arduino.h>

static bool g_irActive = false;

const IrCode kIrTvPowerCodes[] = {
  {"Samsung",   0xE0E0, 0x40},
  {"LG",        0x0004, 0x08},
  {"Vizio",     0x1A1A, 0x25},
  {"TCL/Roku",  0x0009, 0x00},  // TCL Roku TV power (NEC)
  {"Sharp",     0x5540, 0x01},
  {"Panasonic", 0x4004, 0x0C},
  {"Toshiba",   0x02FD, 0x01},
  {"Philips",   0x0502, 0x0C},
  {"Hisense",   0x1FE0, 0x20},
  {"Insignia",  0x1A2C, 0x25},
  {"RCA",       0x1C00, 0x12},
  {"Sanyo",     0x4040, 0x1A},
  {"Emerson",   0x1F00, 0x00},
  {"Haier",     0xA25D, 0x40},
};
const int kIrTvPowerCount = 14;

const IrCode kIrAcPowerCodes[] = {
  {"Midea",     0xFF00, 0x08},
  {"Carrier",   0xFF00, 0x12},
  {"LG AC",     0x0808, 0x08},
  {"Samsung AC",0xF20D, 0x0D},
  {"Daikin",    0x1680, 0x28},
  {"Mitsubishi",0x4DB2, 0x40},
};
const int kIrAcPowerCount = 6;

static constexpr uint8_t kIrLedcChannel = 5;
static constexpr uint8_t kIrRawSendRepeats = 4;
static constexpr uint16_t kIrReplayGapMs = 60;
static constexpr uint8_t kIrNecSendRepeats = 4;
static constexpr uint8_t kIrMinUsefulRawEdges = 6;

void irInit() {
  if (!g_irActive) {
    ledcSetup(kIrLedcChannel, 38000, 8);
    ledcAttachPin(kIrTxPin, kIrLedcChannel);
    ledcWrite(kIrLedcChannel, 0);
    pinMode(kIrRxPin, INPUT);
    g_irActive = true;
  }
}

void irDeinit() {
  if (g_irActive) {
    ledcWrite(kIrLedcChannel, 0);
    ledcDetachPin(kIrTxPin);
    g_irActive = false;
  }
}

static inline void irMark(uint32_t us) {
  ledcWrite(kIrLedcChannel, 128);
  delayMicroseconds(us);
}

static inline void irSpace(uint32_t us) {
  ledcWrite(kIrLedcChannel, 0);
  delayMicroseconds(us);
}

void irSendNec(uint16_t addr, uint8_t cmd) {
  if (!g_irActive) irInit();
  const uint8_t bytes[4] = {
    (uint8_t)(addr & 0xFF),
    (uint8_t)((addr >> 8) & 0xFF),
    cmd,
    (uint8_t)(~cmd),
  };
  irMark(9000);
  irSpace(4500);
  for (int b = 0; b < 4; ++b) {
    for (int bit = 0; bit < 8; ++bit) {
      irMark(560);
      irSpace((bytes[b] >> bit) & 1 ? 1690 : 560);
    }
  }
  irMark(560);
  irSpace(40000);

  for (uint8_t repeat = 0; repeat < kIrNecSendRepeats; ++repeat) {
    delay(kIrReplayGapMs);
    irMark(9000);
    irSpace(2250);
    irMark(560);
    irSpace(40000);
  }
}

void irSendRepeatFrame() {
  if (!g_irActive) irInit();
  irMark(9000);
  irSpace(2250);
  irMark(560);
  irSpace(40000);
}

IrReceived irReceiveNec(int timeoutMs) {
  // Capture raw then decode — avoids the pulseIn-skip-first-burst bug.
  IrRawCapture cap = irCaptureRaw(timeoutMs);
  IrReceived result = {false, 0, 0, 0};
  if (!cap.valid || cap.count < 66) return result;

  const auto inRange = [](uint16_t v, uint16_t lo, uint16_t hi) {
    return v >= lo && v <= hi;
  };
  if (!inRange(cap.pulses[0], 7500, 10500)) return result;  // header mark
  if (!inRange(cap.pulses[1], 3500, 5500))  return result;  // header space

  uint32_t data = 0;
  for (int bit = 0; bit < 32; ++bit) {
    const int idx = 2 + bit * 2;
    if (idx + 1 >= cap.count) return result;
    if (!inRange(cap.pulses[idx], 300, 900)) return result;
    if      (inRange(cap.pulses[idx+1], 350,  900)) { /* 0 */ }
    else if (inRange(cap.pulses[idx+1], 1300, 2000)) { data |= (1UL << bit); }
    else return result;
  }
  const uint8_t cmd  = (data >> 16) & 0xFF;
  const uint8_t cmdN = (data >> 24) & 0xFF;
  if ((uint8_t)(cmd + cmdN) != 0xFF) return result;
  result.valid   = true;
  result.addr    = (uint16_t)(data & 0xFFFF);
  result.cmd     = cmd;
  result.rawCode = data;
  return result;
}

IrRawCapture irCaptureRaw(int timeoutMs) {
  IrRawCapture result = {false, {}, 0};
  if (!g_irActive) irInit();

  const uint32_t deadline = millis() + (uint32_t)timeoutMs;
  while (millis() < deadline) {
    // Wait for signal start (pin goes LOW = IR burst begins)
    while (digitalRead(kIrRxPin) == HIGH) {
      if (millis() >= deadline) return result;
    }

    // Measure each pulse directly via spin-loop so we capture the burst we're
    // already inside — pulseIn() skips the current pulse which would lose the
    // 9ms NEC header mark and break NEC decoding.
    result.count = 0;
    uint8_t polarity = LOW;
    while (result.count < kIrRawMaxPulses) {
      const uint32_t t0 = micros();
      const uint32_t limit = (polarity == LOW) ? 12000u : 20000u;
      while ((uint8_t)digitalRead(kIrRxPin) == polarity) {
        if (micros() - t0 > limit) goto capture_done;
      }
      const uint32_t dur = micros() - t0;
      result.pulses[result.count++] = (uint16_t)(dur < 65535u ? dur : 65535u);
      polarity ^= 1;
    }
    capture_done:
    if (result.count >= kIrMinUsefulRawEdges) {
      result.valid = true;
      return result;
    }
    delay(10);
  }
  return result;
}

void irReplayRaw(const IrRawCapture& cap) {
  if (!g_irActive) irInit();
  for (uint8_t repeat = 0; repeat <= kIrRawSendRepeats; ++repeat) {
    bool polarity = LOW;  // first pulse is always a mark (IR on)
    for (int i = 0; i < cap.count; ++i) {
      ledcWrite(kIrLedcChannel, polarity == LOW ? 128 : 0);
      delayMicroseconds(cap.pulses[i]);
      polarity = !polarity;
    }
    ledcWrite(kIrLedcChannel, 0);
    if (repeat < kIrRawSendRepeats) delay(kIrReplayGapMs);
  }
  ledcWrite(kIrLedcChannel, 0);
}
