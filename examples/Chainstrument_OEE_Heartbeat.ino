#include "mbedtls/md.h"
#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFi.h>

// ===================== CONFIG =====================
#define WIFI_SSID "ZaCK's PC"
#define WIFI_PASSWORD "2444666668888888000000"

#define SERVER_URL "https://app.chainstrument.com"
#define DEVICE_UID "OCHA-0001"
#define DEVICE_SECRET "Bfnr705gk0m1wlQGM77QKYfseeg0CMNH32jQ99h7n_k"
// ==================================================

#define NTP_URL "pool.ntp.org"

String hmacSHA256(const String &key, const String &data);
void send_heart_beat(void);

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
  /* send heartbeat data each 10 seconds to keep status */
  static uint32_t tick = millis();
  if (millis() - tick >= 10000) {
    tick = millis();
    send_heart_beat();
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

void send_heart_beat(void) {
  if (WiFi.status() != WL_CONNECTED) {
    Serial.println("WiFi not connected (heartbeat skipped)");
    return;
  }

  HTTPClient http;

  // 1. Timestamp (epoch seconds)
  long timestamp = time(nullptr);
  String timestampStr = String(timestamp);

  // 2. Body is EMPTY
  String body = "";

  // 3. Message = timestamp + empty body
  String message = timestampStr;  // IMPORTANT: nothing else appended

  // 4. HMAC
  String signature = hmacSHA256(DEVICE_SECRET, message);

  // 5. POST
  String url = String(SERVER_URL) + "/api/devices/heartbeat";

  http.begin(url);
  http.addHeader("X-Device-Uid", DEVICE_UID);
  http.addHeader("X-Timestamp", timestampStr);
  http.addHeader("X-Signature", signature);
  // Content-Type intentionally omitted (matches Python)

  int httpCode = http.POST(body);  // empty body

  Serial.println("---- HEARTBEAT ----");
  Serial.println("URL: " + url);
  Serial.println("Timestamp: " + timestampStr);
  Serial.println("Signature: " + signature);
  Serial.println("HTTP Code: " + String(httpCode));

  if (httpCode > 0) {
    Serial.println("Response:");
    Serial.println(http.getString());
  } else {
    Serial.println("Heartbeat failed");
  }

  http.end();
}