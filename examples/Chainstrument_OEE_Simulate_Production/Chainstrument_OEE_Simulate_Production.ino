#include "mbedtls/md.h"
#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <ArduinoJson.h>

// ===================== CONFIG =====================
#define WIFI_SSID ""
#define WIFI_PASSWORD ""

#define SERVER_URL "https://app.chainstrument.com/api/devices/counts"
#define DEVICE_UID ""
#define DEVICE_SECRET ""
// ==================================================

#define NTP_URL "pool.ntp.org"

HTTPClient http;

String hmacSHA256(const String &key, const String &data);
int send_data(int count, const String& status);
void ensureHttpConnection(const String& url);

bool httpInitialized = false;
static const uint32_t HTTP_TIMEOUT_MS = 5000;

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

  randomSeed(esp_random());
}

void loop() {
  static unsigned long lastSend = 0;
  static unsigned long nextInterval = 0;

  unsigned long now = millis();

  // Initialize first interval
  if (nextInterval == 0) {
    nextInterval = random(7000, 13001); // 7–13 seconds
  }

  if (now - lastSend >= nextInterval) {
    lastSend = now;

    // Random status
    String status = (random(0, 100) < 90) ? "OK" : "NG";

    send_data(1, status);

    // Schedule next send
    nextInterval = random(7000, 13001); // 7–13 seconds
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

int send_data(int count, const String& status) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected");
    return -1;
  }

  // ---------- TIMESTAMP ----------
  long timestamp = time(nullptr);
  String timestampStr = String(timestamp);

  // ---------- BODY ----------
  JsonDocument doc;
  doc["count"] = count;
  doc["status"] = status;
  String body;
  serializeJson(doc, body);

  // ---------- SIGNATURE ----------
  String message = timestampStr + body;
  String signature = hmacSHA256(DEVICE_SECRET, message);

  // ---------- CONNECT (ONCE) ----------
  ensureHttpConnection(SERVER_URL);

  // ---------- HEADERS ----------
  http.addHeader("Content-Type", "application/json");
  http.addHeader("X-Device-Uid", DEVICE_UID);
  http.addHeader("X-Timestamp", timestampStr);
  http.addHeader("X-Signature", signature);
  http.addHeader("Connection", "keep-alive");

  // ---------- POST ----------
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

  return httpCode;
}

void ensureHttpConnection(const String& url) {
  if (!httpInitialized) {
    Serial.println("Initializing persistent HTTP connection...");
    http.begin(url);
    http.setReuse(true);
    httpInitialized = true;
  }
}