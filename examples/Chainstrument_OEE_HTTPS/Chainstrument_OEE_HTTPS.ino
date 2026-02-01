#include "mbedtls/md.h"
#include <Arduino.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <ArduinoJson.h>
#include <WiFiClientSecure.h>

// ===================== CONFIG =====================
#define WIFI_SSID ""
#define WIFI_PASSWORD ""

#define SERVER_URL "https://app.chainstrument.com/api/devices/counts"
#define DEVICE_UID ""
#define DEVICE_SECRET ""
// ==================================================

#define NTP_URL "pool.ntp.org"

static const char* CA_CERT_NEW PROGMEM = R"EOF(
-----BEGIN CERTIFICATE-----
MIIDejCCAmKgAwIBAgIQf+UwvzMTQ77dghYQST2KGzANBgkqhkiG9w0BAQsFADBX
MQswCQYDVQQGEwJCRTEZMBcGA1UEChMQR2xvYmFsU2lnbiBudi1zYTEQMA4GA1UE
CxMHUm9vdCBDQTEbMBkGA1UEAxMSR2xvYmFsU2lnbiBSb290IENBMB4XDTIzMTEx
NTAzNDMyMVoXDTI4MDEyODAwMDA0MlowRzELMAkGA1UEBhMCVVMxIjAgBgNVBAoT
GUdvb2dsZSBUcnVzdCBTZXJ2aWNlcyBMTEMxFDASBgNVBAMTC0dUUyBSb290IFI0
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE83Rzp2iLYK5DuDXFgTB7S0md+8Fhzube
Rr1r1WEYNa5A3XP3iZEwWus87oV8okB2O6nGuEfYKueSkWpz6bFyOZ8pn6KY019e
WIZlD6GEZQbR3IvJx3PIjGov5cSr0R2Ko4H/MIH8MA4GA1UdDwEB/wQEAwIBhjAd
BgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwDwYDVR0TAQH/BAUwAwEB/zAd
BgNVHQ4EFgQUgEzW63T/STaj1dj8tT7FavCUHYwwHwYDVR0jBBgwFoAUYHtmGkUN
l8qJUC99BM00qP/8/UswNgYIKwYBBQUHAQEEKjAoMCYGCCsGAQUFBzAChhpodHRw
Oi8vaS5wa2kuZ29vZy9nc3IxLmNydDAtBgNVHR8EJjAkMCKgIKAehhxodHRwOi8v
Yy5wa2kuZ29vZy9yL2dzcjEuY3JsMBMGA1UdIAQMMAowCAYGZ4EMAQIBMA0GCSqG
SIb3DQEBCwUAA4IBAQAYQrsPBtYDh5bjP2OBDwmkoWhIDDkic574y04tfzHpn+cJ
odI2D4SseesQ6bDrarZ7C30ddLibZatoKiws3UL9xnELz4ct92vID24FfVbiI1hY
+SW6FoVHkNeWIP0GCbaM4C6uVdF5dTUsMVs/ZbzNnIdCp5Gxmx5ejvEau8otR/Cs
kGN+hr/W5GvT1tMBjgWKZ1i4//emhA1JG1BbPzoLJQvyEotc03lXjTaCzv8mEbep
8RqZ7a2CPsgRbuvTPBwcOMBBmuFeU88+FSBX6+7iP0il8b4Z0QFqIwwMHfs/L6K1
vepuoxtGzi4CZ68zJpiq1UvSqTbFJjtbD4seiMHl
-----END CERTIFICATE-----
)EOF";

WiFiClientSecure secureClient;
HTTPClient http;

String hmacSHA256(const String &key, const String &data);
void ensureHttpConnection(const String& url);
int send_data(int count, const String& status);

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

  // ---- TLS / HTTP persistent setup ----
  secureClient.setCACert(CA_CERT_NEW);
  secureClient.setTimeout(HTTP_TIMEOUT_MS);
  secureClient.setHandshakeTimeout(5); // seconds
}

void loop() {
  static unsigned long lastSend = 0;
  static unsigned long nextInterval = 0;

  unsigned long now = millis();

  // Initialize first interval
  if (nextInterval == 0) {
    nextInterval = random(7000, 13001); // 8–13 seconds
  }

  if (now - lastSend >= nextInterval) {
    lastSend = now;

    // Random status
    String status = (random(0, 100) < 90) ? "OK" : "NG";

    // Always count = 1
    while (send_data(1, status) != HTTP_CODE_OK) {
      Serial.println("Retrying send_data...");
      delay(2000);
    }

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

void ensureHttpConnection(const String& url) {
  if (!httpInitialized) {
    Serial.println("Initializing persistent HTTPS connection...");
    http.begin(secureClient, url);
    http.setReuse(true);
    httpInitialized = true;
  }
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
  String body = "{\"count\":" + String(count) +
                ",\"status\":\"" + status + "\"}";

  // ---------- SIGNATURE ----------
  String message = timestampStr + body;
  String signature = hmacSHA256(DEVICE_SECRET, message);

  // ---------- URL ----------
  // String url = String(SERVER_URL) + "/api/devices/counts";

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
