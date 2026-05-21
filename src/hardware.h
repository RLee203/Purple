#pragma once

#include "apps.h"
#include <stdint.h>

enum class HardwareProfile {
  Auto,
  LoraGpsCap,
  RfHat,
};

struct HardwarePins {
  int sdSck;
  int sdMiso;
  int sdMosi;
  int sdCs;
  int gpsTx;
  int gpsRx;
  int loraRst;
  int loraBusy;
  int loraDio1;
  int loraSpiCs;  // SX1262 NSS — must stay HIGH to isolate it from SD SPI bus
  int cc1101Cs;
  int cc1101Gdo0;
  int nrf24Csn;
  int nrf24Ce;
};

struct Cc1101ProbeResult {
  bool present;
  uint8_t partnum;
  uint8_t version;
  int gdo0;
  uint8_t marcState;
  uint8_t lqi;
  uint8_t pktStatus;
  uint8_t rxBytes;
  int rssiDbm;
};

struct Nrf24ProbeResult {
  bool present;
  uint8_t status;
  uint8_t setupAw;
  uint8_t rfCh;
  uint8_t rfSetup;
  uint8_t observeTx;
  uint8_t fifoStatus;
  uint8_t rpdHits;
  uint8_t sampleCount;
  int ce;
};

struct GpsFix {
  bool serialReady;
  bool valid;
  bool hasDateTime;
  int satellites;
  double latitude;
  double longitude;
  double altitudeMeters;
  double speedKmph;
  double courseDeg;
  uint32_t ageMs;
  char timeText[16];
  char dateText[16];
};

void hardwareInit();
HardwareProfile hardwareCurrentProfile();
void hardwareNextProfile();
const char* hardwareProfileName();
const char* hardwareProfileShortName();
const char* hardwareProfileHint();
const HardwarePins& hardwarePins();
bool hardwareProfileSupportsApp(AppId appId);
const char* hardwareAppRequirement(AppId appId);
bool hardwareGpsUpdate();
GpsFix hardwareGpsGetFix();
Cc1101ProbeResult hardwareProbeCc1101();
Nrf24ProbeResult hardwareProbeNrf24();
Cc1101ProbeResult hardwarePollCc1101(int bandMHz, int sensitivity);
Nrf24ProbeResult hardwarePollNrf24(int channel, int density);
int hardwareCc1101ReadRssiAtFreq(float mhz, int sensitivity);

struct Cc1101RxCapture {
  bool valid;
  uint8_t data[64];
  uint8_t len;
  int rssiDbm;
  uint8_t lqi;
};

static constexpr int kCc1101RawMaxPulses = 512;
struct Cc1101RawCapture {
  bool valid;
  uint16_t pulses[kCc1101RawMaxPulses];
  uint16_t count;
  int rssiDbm;
  int freqMHz;
};
bool hardwareCc1101CaptureRaw(int bandMHz, Cc1101RawCapture& out, int timeoutMs = 2000);
void hardwareCc1101ReplayRaw(const Cc1101RawCapture& cap);

void hardwareCc1101StartCwJam(int bandMHz);
void hardwareCc1101SendJamBurst(int bandMHz);
void hardwareCc1101StopJam();
bool hardwareCc1101TryCapturePacket(int bandMHz, Cc1101RxCapture& out);
void hardwareCc1101Replay(const Cc1101RxCapture& pkt, int bandMHz);

void hardwareNrf24StartJam(int channel);
void hardwareNrf24SendJamBurst(int channel);
void hardwareNrf24StopJam();
void hardwareNrf24FullSweepScan(uint8_t results[126]);

struct EsbScanResult {
  bool found;
  uint8_t addr[5];
  int channel;
  uint8_t dataLen;
  uint8_t data[32];
};

EsbScanResult hardwareNrf24ScanEsb(int startCh, int endCh, int dwellMs);
bool hardwareNrf24MouseJackInject(const EsbScanResult& target,
                                   uint8_t modifier,
                                   const uint8_t* keyCodes,
                                   uint8_t keyCount);

void hardwareCc1101StartOok(int bandMHz, int rateIdx = 1);  // rateIdx: 0=1.2k 1=2.4k 2=4.8k
void hardwareCc1101SendOokBurst(uint8_t pattern);
void hardwareCc1101StopOok();
void hardwareCc1101SendLfsrBurst(int codeBits, uint32_t& lfsrState);
