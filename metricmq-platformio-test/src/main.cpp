#include <Arduino.h>
#include <WiFi.h>
#include <MetricMQ/MetricMQ.h>

const char* WIFI_SSID  = "YOUR_WIFI_SSID";
const char* WIFI_PASS  = "YOUR_WIFI_PASSWORD";
const char* BROKER_IP  = "192.168.1.100";   // ← your PC's IP
const char* CLIENT_ID  = "esp32-demo1";

MetricMQClient client;
uint32_t msgCount = 0;
uint32_t lastPub  = 0;

void connectWiFi() {
    Serial.printf("[WiFi] Connecting to %s", WIFI_SSID);
    WiFi.begin(WIFI_SSID, WIFI_PASS);
    while (WiFi.status() != WL_CONNECTED) { delay(500); Serial.print("."); }
    Serial.printf("\n[WiFi] Connected: %s\n", WiFi.localIP().toString().c_str());
}

void connectBroker() {
    Serial.printf("[Broker] Connecting to %s:6379...\n", BROKER_IP);
    client.begin(BROKER_IP, 6379);       // ← Step 1: store address
    client.connect(CLIENT_ID);           // ← Step 2: connect with client ID
    Serial.println(client.isConnected() ? "[Broker] Connected OK"
                                        : "[Broker] FAILED — check IP/firewall");
}

void setup() {
    Serial.begin(115200);
    delay(500);
    Serial.println("\n=== MetricMQ Demo 1: Basic Pub/Sub ===");
    connectWiFi();
    connectBroker();
}

void loop() {
    if (!client.isConnected()) {
        delay(2000);
        connectBroker();
        return;
    }

    client.loop();

    if (millis() - lastPub > 3000) {
        lastPub = millis();
        msgCount++;

        float temp = 20.0f + (float)random(-30, 80) / 10.0f;
        char payload[64];
        snprintf(payload, sizeof(payload),
                 "{\"msg\":%u,\"temp\":%.1f}", msgCount, temp);

        client.publish("sensors/temperature", payload);
        Serial.printf("[PUB #%u] %s\n", msgCount, payload);
    }
}