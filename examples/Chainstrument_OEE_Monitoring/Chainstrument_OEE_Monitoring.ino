#include "mbedtls/md.h"
#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <ArduinoJson.h>

// ===================== CONFIG =====================
#define WIFI_SSID ""
#define WIFI_PASSWORD ""

#define SERVER_URL "https://app.chainstrument.com/api/monitoring/ingest"
#define DEVICE_UID ""
#define DEVICE_SECRET ""
// ==================================================

#define NTP_URL "pool.ntp.org"

HTTPClient http;

String hmacSHA256(const String &key, const String &data);
void sendTelemetry(const float* values, uint8_t channelCount);
void ensureHttpConnection(const String& url);

bool httpInitialized = false;

void setup() {
  Serial.begin(115200);

  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
  Serial.print("Connecting WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nWiFi connected");

  // IMPORTANT: required for correct epoch time
  configTime(0, 0, NTP_URL);

  Serial.print("Waiting for time");
  while (time(nullptr) < 100000) {
    delay(500);
    Serial.print(".");
  }
  Serial.println("\nTime synced");
}

void loop() {
  static uint32_t telemetryTick = millis();
  if (millis() - telemetryTick >= 15000) {
    telemetryTick = millis();
    float temp = temperatureRead();
    Serial.printf("Temperature: %.2f C\n", temp);
    sendTelemetry(&temp, 1);
  }
}

String hmacSHA256(const String &key, const String &data) {
  unsigned char hmacResult[32];
  mbedtls_md_context_t ctx;
  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);

  mbedtls_md_init(&ctx);
  mbedtls_md_setup(&ctx, md, 1);
  mbedtls_md_hmac_starts(&ctx, (const unsigned char *)key.c_str(), key.length());
  mbedtls_md_hmac_update(&ctx, (const unsigned char *)data.c_str(), data.length());
  mbedtls_md_hmac_finish(&ctx, hmacResult);
  mbedtls_md_free(&ctx);

  // convert to hex string
  char hex[65];
  for (int i = 0; i < 32; i++) {
    sprintf(hex + i * 2, "%02x", hmacResult[i]);
  }
  hex[64] = 0;

  return String(hex);
}

void sendTelemetry(const float* values, uint8_t channelCount) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return;
  }

  if (channelCount == 0 || channelCount > 4) {
    Serial.println("Invalid channel count");
    return;
  }

  long now = time(nullptr);
  String timestampStr = String(now);

  // ---------- JSON BUILD ----------
  JsonDocument doc;
  JsonArray data = doc.createNestedArray("data");

  for (uint8_t i = 0; i < channelCount; i++) {
    JsonObject ch = data.createNestedObject();
    ch["channel_number"] = i + 1;   // auto numbering
    ch["value"] = values[i];
    ch["timestamp"] = now;
  }

  String body;
  serializeJson(doc, body);  // NO pretty print

  // ---------- SIGNATURE ----------
  String message = timestampStr + body;
  String signature = hmacSHA256(DEVICE_SECRET, message);

  ensureHttpConnection(SERVER_URL);
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Uid", DEVICE_UID);
  http.addHeader("X-Timestamp", timestampStr);
  http.addHeader("X-Signature", signature);

  Serial.print("[");
  Serial.print(timestampStr);
  Serial.print("] Sending ");
  Serial.print(channelCount);
  Serial.print(" channels... ");

  uint32_t start = millis();
  int httpCode = http.POST(body);

  uint32_t elapsed = millis() - start;
  Serial.printf("POST latency: %lu ms\n", elapsed);

  // ---------- RESPONSE ----------
  if (httpCode > 0) {
    Serial.printf("HTTP %d\n", httpCode);
    Serial.println(http.getString());
  } else {
    Serial.printf("HTTP request failed (%i), resetting connection\n", httpCode);
    http.end();
    httpInitialized = false;
  }
}

void ensureHttpConnection(const String& url) {
  if (!httpInitialized) {
    Serial.println("Initializing persistent HTTP connection...");
    http.begin(url);
    http.setReuse(true);
    httpInitialized = true;
  }
}