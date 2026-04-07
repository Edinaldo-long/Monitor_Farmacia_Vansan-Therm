/*
  ============================================================
  VANSAN THERM - MONITOR FARMÁCIA - ANVISA RDC 301
  Versão 6.1 - PROTOCOLO GREE/ELGIN CORRIGIDO (BIND FIX)
  ============================================================

  CORREÇÕES v6.1 (em relação ao v6.0):
    - BIND: verificação de MAC vazio antes de tentar bind
    - BIND: tenta ambas as chaves genéricas Gree conhecidas
    - SCAN: extração de MAC melhorada (tenta "cid", "mac" externo e pack)
    - SCAN: log detalhado do pacote bruto recebido
    - BIND: log completo do pacote de resposta (raw + B64 + decrypted)
    - Rota /ac/bindlog para diagnóstico via browser (sem Serial Monitor)
    - Rota /ac/status com JSON completo do estado do AC
    - acSendReceive: aumentado timeout padrão para 6000ms
    - acBroadcast: aumentado timeout padrão para 6000ms
    - greeInit: delay antes do bind aumentado para 3000ms
    - Variável global lastBindLog para diagnóstico remoto

  FLUXO GREE:
    1. SCAN  → broadcast UDP {"t":"scan"} → AC responde com MAC no "cid"
    2. BIND  → envia pack AES({"mac":MAC,"t":"bind","uid":0}) com chave genérica
               → AC responde com pack AES contendo {"key":"CHAVE_ESPECIFICA"}
    3. CMD   → envia pack AES(comando) com chave específica obtida no bind

  ACESSO:
    - No celular: conecte em VANSAN-CONFIG (senha: vansan123)
    - Na rede da farmácia: http://vansan.local
    - IP direto: aparece no LCD
    - Forçar rebind AC: http://vansan.local/ac/rebind
    - Log de diagnóstico: http://vansan.local/ac/bindlog
    - Status JSON do AC:  http://vansan.local/ac/status
  ============================================================
*/

#include <Preferences.h>
#include <Arduino.h>
#include <Wire.h>
#include <LiquidCrystal_I2C.h>
#include <DHT.h>
#include <WiFi.h>
#include <WiFiUDP.h>
#include <WebServer.h>
#include <DNSServer.h>
#include <HTTPClient.h>
#include <ESPmDNS.h>
#include <time.h>
#include <esp_task_wdt.h>
#include <mbedtls/aes.h>

// ========================================
// CONFIGURAÇÕES PRINCIPAIS
// ========================================
const char* apiKey             = "FFRJJ4CSC2FFBRKH";
const char* ntpServer          = "pool.ntp.org";
const long  gmtOffset_sec      = -10800;   // Brasília GMT-3
const int   daylightOffset_sec = 0;

#define DHT_PIN    13
#define LED_GREEN  25
#define LED_BLUE   26
#define LED_RED    27
#define TEMP_MIN   15.0
#define TEMP_MAX   25.0
#define HUM_MIN    40.0
#define HUM_MAX    70.0
#define BOOT_BTN   0

// ========================================
// AP FIXO
// ========================================
#define AP_SSID   "VANSAN-CONFIG"
#define AP_PASS   "vansan123"
#define AP_IP_STR "192.168.4.1"

// ========================================
// MULTI-NETWORK NVS
// ========================================
#define WIFI_NAMESPACE "wifi-nets"
#define MAX_NETWORKS   5

// ========================================
// TELEGRAM
// ========================================
const char* telegramToken  = "8671466467:AAF6zF5qC8PIFUUkBHbAB06BPHpIbzsyNi8";
const char* telegramChatId = "900525242";

// ========================================
// AC GREE/ELGIN — CONFIGURAÇÃO
// ========================================
const char* AC_IP   = "192.168.100.96";
const int   AC_PORT = 7000;

// Chaves AES genéricas do protocolo Gree — dois firmwares conhecidos
// O bind tentará a KEY1 primeiro; se falhar, tentará a KEY2
const char* GREE_GENERIC_KEY1 = "a3K8Bx%2r8Y7#xDh";  // Firmware padrão Gree (16 bytes)
const char* GREE_GENERIC_KEY2 = "{yxs#^A7D9AtG'd!";   // Firmware alternativo Gree (16 bytes)

// ========================================
// DIAGNÓSTICO — log do último bind
// ========================================
String lastBindLog = "Nenhum bind tentado ainda.";

// ========================================
// ESTADO DO AC
// ========================================
String         greeDeviceKey    = "";
String         greeDeviceMAC    = "";
bool           greeBound        = false;
String         greeActiveKey    = "";   // qual chave genérica funcionou
WiFiUDP        acUdp;

// Forward declarations
bool greeRebind();
bool greeScanAC();
bool greeBindAC();
bool greeCommand(bool power, int mode, int setTemp, int fanSpeed);

// ========================================
// CONTROLE DO AC
// ========================================
#define AC_INTERVALO_MIN    180000UL
#define AC_RETRY_INTERVALO  300000UL

bool             acEnabled            = false;
volatile bool    acLigado             = false;
unsigned long    ultimoAcionamentoAC  = 0;
unsigned long    ultimaTentativaFalha = 0;

typedef struct { bool ligar; } AcCmd;
QueueHandle_t acQueue;

// ========================================
// CONTROLE DE ALERTAS
// ========================================
bool alertaEnviado = false;

// ========================================
// SERVIDORES
// ========================================
WebServer server(80);
DNSServer dnsServer;

// ========================================
// PERIFÉRICOS
// ========================================
Preferences       prefs;
LiquidCrystal_I2C lcd(0x27, 16, 2);
DHT               dht(DHT_PIN, DHT22);

float         temp = 0, hum = 0;
bool          alert    = false;
bool          timeSync = false;
unsigned long lastRead     = 0;
unsigned long lastSend     = 0;
unsigned long lastLcd      = 0;
unsigned long lastNTPSync  = 0;
unsigned long lastRecon    = 0;
uint8_t       screen = 0;
struct tm     timeinfo;

// ============================================================
// BASE64
// ============================================================
static const char* B64CHARS =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

String base64Encode(const uint8_t* data, int len) {
  String out = "";
  int i = 0;
  uint8_t b3[3], b4[4];
  while (len--) {
    b3[i++] = *data++;
    if (i == 3) {
      b4[0] = (b3[0] & 0xfc) >> 2;
      b4[1] = ((b3[0] & 0x03) << 4) + ((b3[1] & 0xf0) >> 4);
      b4[2] = ((b3[1] & 0x0f) << 2) + ((b3[2] & 0xc0) >> 6);
      b4[3] =  b3[2] & 0x3f;
      for (int j = 0; j < 4; j++) out += B64CHARS[b4[j]];
      i = 0;
    }
  }
  if (i) {
    for (int j = i; j < 3; j++) b3[j] = 0;
    b4[0] = (b3[0] & 0xfc) >> 2;
    b4[1] = ((b3[0] & 0x03) << 4) + ((b3[1] & 0xf0) >> 4);
    b4[2] = ((b3[1] & 0x0f) << 2) + ((b3[2] & 0xc0) >> 6);
    b4[3] =  b3[2] & 0x3f;
    for (int j = 0; j < i + 1; j++) out += B64CHARS[b4[j]];
    while (i++ < 3) out += '=';
  }
  return out;
}

static int b64Val(char c) {
  if (c >= 'A' && c <= 'Z') return c - 'A';
  if (c >= 'a' && c <= 'z') return c - 'a' + 26;
  if (c >= '0' && c <= '9') return c - '0' + 52;
  if (c == '+') return 62;
  if (c == '/') return 63;
  return -1;
}

uint8_t* base64Decode(const String& encoded, int* outLen) {
  int len     = encoded.length();
  int outSize = (len * 3) / 4 + 4;
  uint8_t* out = (uint8_t*)malloc(outSize);
  if (!out) return nullptr;
  int i = 0, j = 0;
  uint8_t b4[4];
  *outLen = 0;
  for (int k = 0; k < len; k++) {
    int v = b64Val(encoded[k]);
    if (v < 0) continue;
    b4[i++] = v;
    if (i == 4) {
      out[j++] = (b4[0] << 2) + ((b4[1] & 0x30) >> 4);
      out[j++] = ((b4[1] & 0x0f) << 4) + ((b4[2] & 0x3c) >> 2);
      out[j++] = ((b4[2] & 0x03) << 6) +  b4[3];
      i = 0;
    }
  }
  if (i) {
    for (int x = i; x < 4; x++) b4[x] = 0;
    out[j++] = (b4[0] << 2) + ((b4[1] & 0x30) >> 4);
    if (i > 2) out[j++] = ((b4[1] & 0x0f) << 4) + ((b4[2] & 0x3c) >> 2);
  }
  *outLen = j;
  return out;
}

// ============================================================
// AES-128 ECB com PKCS7
// ============================================================
int pkcs7Pad(uint8_t* buf, int dataLen, int bufSize) {
  int padLen = 16 - (dataLen % 16);
  if (dataLen + padLen > bufSize) return -1;
  for (int i = 0; i < padLen; i++) buf[dataLen + i] = (uint8_t)padLen;
  return dataLen + padLen;
}

int pkcs7Unpad(const uint8_t* buf, int len) {
  if (len == 0) return 0;
  uint8_t padLen = buf[len - 1];
  if (padLen == 0 || padLen > 16) return len;
  return len - padLen;
}

String aesEncrypt(const String& plaintext, const String& key) {
  int dataLen = plaintext.length();
  int bufSize = dataLen + 32;
  uint8_t* buf = (uint8_t*)malloc(bufSize);
  if (!buf) return "";
  memcpy(buf, plaintext.c_str(), dataLen);
  int paddedLen = pkcs7Pad(buf, dataLen, bufSize);
  if (paddedLen < 0) { free(buf); return ""; }

  // Sempre usa exatamente 16 bytes da chave (completa com zeros se menor)
  uint8_t keyBuf[16] = {0};
  int keyLen = key.length();
  if (keyLen > 16) keyLen = 16;
  memcpy(keyBuf, key.c_str(), keyLen);

  uint8_t* out = (uint8_t*)malloc(paddedLen);
  if (!out) { free(buf); return ""; }

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_enc(&ctx, keyBuf, 128);
  for (int i = 0; i < paddedLen; i += 16)
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, buf + i, out + i);
  mbedtls_aes_free(&ctx);
  free(buf);

  String result = base64Encode(out, paddedLen);
  free(out);
  return result;
}

String aesDecrypt(const String& cipherB64, const String& key) {
  int decodedLen = 0;
  uint8_t* decoded = base64Decode(cipherB64, &decodedLen);
  if (!decoded || decodedLen == 0) { free(decoded); return ""; }

  uint8_t keyBuf[16] = {0};
  int keyLen = key.length();
  if (keyLen > 16) keyLen = 16;
  memcpy(keyBuf, key.c_str(), keyLen);

  uint8_t* out = (uint8_t*)malloc(decodedLen + 1);
  if (!out) { free(decoded); return ""; }

  mbedtls_aes_context ctx;
  mbedtls_aes_init(&ctx);
  mbedtls_aes_setkey_dec(&ctx, keyBuf, 128);
  for (int i = 0; i < decodedLen; i += 16)
    mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_DECRYPT, decoded + i, out + i);
  mbedtls_aes_free(&ctx);
  free(decoded);

  int realLen = pkcs7Unpad(out, decodedLen);
  out[realLen] = '\0';
  String result = String((char*)out);
  free(out);
  return result;
}

// ============================================================
// PARSER JSON MÍNIMO
// ============================================================
String jsonGetString(const String& json, const String& key) {
  String search = "\"" + key + "\":\"";
  int start = json.indexOf(search);
  if (start < 0) return "";
  start += search.length();
  int end = json.indexOf("\"", start);
  if (end < 0) return "";
  return json.substring(start, end);
}

String jsonEscape(const String& s) {
  String out = "";
  for (int i = 0; i < (int)s.length(); i++) {
    char c = s.charAt(i);
    if      (c == '"')  out += "\\\"";
    else if (c == '\\') out += "\\\\";
    else if (c == '\n') out += "\\n";
    else if (c == '\r') out += "\\r";
    else out += c;
  }
  return out;
}

// ============================================================
// COMUNICAÇÃO UDP COM O AC
// ============================================================
String acSendReceive(const String& payload, int timeoutMs = 6000) {
  if (WiFi.status() != WL_CONNECTED) { Serial.println("[AC] Sem WiFi"); return ""; }
  Serial.printf("[AC] TX → %s\n", payload.c_str());
  acUdp.beginPacket(AC_IP, AC_PORT);
  acUdp.print(payload);
  acUdp.endPacket();
  unsigned long start = millis();
  while (millis() - start < (unsigned long)timeoutMs) {
    int sz = acUdp.parsePacket();
    if (sz > 0) {
      char buf[1024];
      int len = acUdp.read(buf, sizeof(buf) - 1);
      buf[len] = '\0';
      Serial.printf("[AC] RX ← %s\n", buf);
      return String(buf);
    }
    delay(50);
    esp_task_wdt_reset();
  }
  Serial.println("[AC] Timeout!");
  return "";
}

String acBroadcast(const String& payload, int timeoutMs = 6000) {
  if (WiFi.status() != WL_CONNECTED) return "";
  Serial.printf("[AC] BROADCAST → %s\n", payload.c_str());

  // Broadcast na subnet atual
  IPAddress bcast = WiFi.localIP();
  bcast[3] = 255;
  acUdp.beginPacket(bcast, AC_PORT);
  acUdp.print(payload);
  acUdp.endPacket();

  // Também envia direto ao IP conhecido do AC
  acUdp.beginPacket(AC_IP, AC_PORT);
  acUdp.print(payload);
  acUdp.endPacket();

  unsigned long start = millis();
  while (millis() - start < (unsigned long)timeoutMs) {
    int sz = acUdp.parsePacket();
    if (sz > 0) {
      char buf[1024];
      int len = acUdp.read(buf, sizeof(buf) - 1);
      buf[len] = '\0';
      Serial.printf("[AC] RX ← %s\n", buf);
      return String(buf);
    }
    delay(50);
    esp_task_wdt_reset();
  }
  Serial.println("[AC] BROADCAST: sem resposta");
  return "";
}

// ============================================================
// ETAPA 1 — SCAN: descobre MAC do AC
// ============================================================
bool greeScanAC() {
  Serial.println("[AC] === SCAN ===");
  lastBindLog = "[SCAN] Enviando broadcast...\n";

  String resp = acBroadcast("{\"t\":\"scan\"}", 6000);

  if (resp.isEmpty()) {
    lastBindLog += "[SCAN] ERRO: sem resposta do AC.\n";
    Serial.println("[AC] SCAN: sem resposta");
    return false;
  }

  lastBindLog += "[SCAN] Resposta raw: " + resp + "\n";

  // Tenta extrair MAC de diferentes campos possíveis
  String mac = "";

  // 1. Campo "cid" externo (mais comum)
  mac = jsonGetString(resp, "cid");
  if (!mac.isEmpty()) {
    lastBindLog += "[SCAN] MAC via cid: " + mac + "\n";
  }

  // 2. Campo "mac" externo
  if (mac.isEmpty()) {
    mac = jsonGetString(resp, "mac");
    if (!mac.isEmpty()) lastBindLog += "[SCAN] MAC via mac externo: " + mac + "\n";
  }

  // 3. Tenta descriptografar o pack com ambas as chaves
  if (mac.isEmpty()) {
    String packB64 = jsonGetString(resp, "pack");
    if (!packB64.isEmpty()) {
      // Tenta KEY1
      String packJson = aesDecrypt(packB64, GREE_GENERIC_KEY1);
      lastBindLog += "[SCAN] pack decrypted KEY1: " + packJson + "\n";
      mac = jsonGetString(packJson, "mac");
      if (mac.isEmpty()) {
        // Tenta KEY2
        packJson = aesDecrypt(packB64, GREE_GENERIC_KEY2);
        lastBindLog += "[SCAN] pack decrypted KEY2: " + packJson + "\n";
        mac = jsonGetString(packJson, "mac");
      }
    }
  }

  if (!mac.isEmpty()) {
    greeDeviceMAC = mac;
    lastBindLog += "[SCAN] ✅ MAC encontrado: " + mac + "\n";
    Serial.printf("[AC] ✅ SCAN OK! MAC: %s\n", mac.c_str());
  } else {
    // Último recurso: usa string vazia e tenta bind mesmo assim
    greeDeviceMAC = "";
    lastBindLog += "[SCAN] ⚠️ MAC não encontrado na resposta.\n";
    Serial.println("[AC] SCAN: AC respondeu mas MAC não encontrado");
  }

  return true;
}

// ============================================================
// ETAPA 2 — BIND com uma chave específica
// ============================================================
bool greeBindWithKey(const String& genericKey, const String& keyName) {
  lastBindLog += "[BIND] Tentando com chave " + keyName + "\n";
  Serial.printf("[AC] BIND tentando chave: %s\n", keyName.c_str());

  // Garante MAC não vazio — usa string vazia se necessário mas avisa
  String mac = greeDeviceMAC;
  if (mac.isEmpty()) {
    lastBindLog += "[BIND] ⚠️ MAC vazio — bind pode falhar\n";
    Serial.println("[AC] BIND: MAC vazio!");
  }

  String bindInner = "{\"mac\":\"" + mac + "\",\"t\":\"bind\",\"uid\":0}";
  lastBindLog += "[BIND] pack interno: " + bindInner + "\n";

  String packEncrypted = aesEncrypt(bindInner, genericKey);
  if (packEncrypted.isEmpty()) {
    lastBindLog += "[BIND] ERRO: falha na criptografia\n";
    return false;
  }

  String bindMsg = "{\"cid\":\"app\",\"i\":1,\"pack\":\"" + packEncrypted
                 + "\",\"t\":\"pack\",\"tcid\":\"" + mac + "\",\"uid\":0}";

  String resp = acSendReceive(bindMsg, 6000);

  if (resp.isEmpty()) {
    lastBindLog += "[BIND] ERRO: sem resposta do AC com chave " + keyName + "\n";
    Serial.printf("[AC] BIND: sem resposta com chave %s\n", keyName.c_str());
    return false;
  }

  lastBindLog += "[BIND] Resposta raw: " + resp + "\n";

  String respPackB64 = jsonGetString(resp, "pack");
  if (respPackB64.isEmpty()) {
    lastBindLog += "[BIND] ERRO: sem campo 'pack' na resposta\n";
    Serial.println("[AC] BIND: sem pack na resposta");
    return false;
  }

  lastBindLog += "[BIND] pack B64: " + respPackB64 + "\n";

  String respPackJson = aesDecrypt(respPackB64, genericKey);
  lastBindLog += "[BIND] pack decrypted: " + respPackJson + "\n";
  Serial.printf("[AC] BIND resposta decrypted: %s\n", respPackJson.c_str());

  String deviceKey = jsonGetString(respPackJson, "key");
  if (deviceKey.isEmpty()) {
    lastBindLog += "[BIND] ERRO: campo 'key' não encontrado com chave " + keyName + "\n";
    Serial.printf("[AC] BIND: 'key' não encontrado com %s\n", keyName.c_str());
    return false;
  }

  greeDeviceKey = deviceKey;
  greeActiveKey = keyName;
  greeBound     = true;

  // Persiste chave na NVS
  Preferences p;
  p.begin("vansan", false);
  p.putString("acKey", greeDeviceKey);
  p.putString("acMAC", greeDeviceMAC);
  p.end();

  lastBindLog += "[BIND] ✅ BIND OK! Chave dispositivo: " + deviceKey + "\n";
  Serial.printf("[AC] ✅ BIND OK! Chave: %s\n", deviceKey.c_str());
  return true;
}

// ============================================================
// ETAPA 2 — BIND: tenta KEY1 depois KEY2
// ============================================================
bool greeBindAC() {
  Serial.println("[AC] === BIND ===");

  // Garante MAC antes de tentar bind
  if (greeDeviceMAC.isEmpty()) {
    lastBindLog += "[BIND] MAC vazio — executando scan primeiro\n";
    Serial.println("[AC] BIND: MAC vazio, executando scan...");
    if (!greeScanAC()) {
      lastBindLog += "[BIND] Scan falhou — bind abortado\n";
      return false;
    }
    delay(300);
    esp_task_wdt_reset();
  }

  // Tenta com chave 1
  if (greeBindWithKey(GREE_GENERIC_KEY1, "KEY1")) return true;

  delay(500);
  esp_task_wdt_reset();

  // Tenta com chave 2
  if (greeBindWithKey(GREE_GENERIC_KEY2, "KEY2")) return true;

  lastBindLog += "[BIND] ❌ Ambas as chaves falharam\n";
  Serial.println("[AC] BIND: ambas as chaves falharam");
  return false;
}

// ============================================================
// ETAPA 3 — COMANDO: envia ligar/desligar
// ============================================================
bool greeCommand(bool power, int mode = 1, int setTemp = 16, int fanSpeed = 0) {
  if (!greeBound || greeDeviceKey.isEmpty()) {
    Serial.println("[AC] Sem bind — executando rebind...");
    if (!greeRebind()) return false;
  }

  Serial.printf("[AC] === CMD Pow=%d Temp=%d ===\n", power ? 1 : 0, setTemp);

  String cmdInner = "{\"opt\":[\"Pow\",\"Mod\",\"SetTem\",\"WdSpd\","
                    "\"Air\",\"Blo\",\"Health\",\"SwhSlp\",\"Lig\","
                    "\"SwingLfRig\",\"SwUpDn\",\"Quiet\",\"Tur\",\"StHt\",\"SvSt\"],"
                    "\"p\":["
                    + String(power ? 1 : 0) + ","
                    + String(mode)          + ","
                    + String(setTemp)       + ","
                    + String(fanSpeed)      + ","
                    "0,0,1,0,1,0,1,0,0,0,0"
                    "],\"t\":\"cmd\"}";

  String packEncrypted = aesEncrypt(cmdInner, greeDeviceKey);
  if (packEncrypted.isEmpty()) { Serial.println("[AC] CMD: erro criptografia"); return false; }

  String cmdMsg = "{\"cid\":\"app\",\"i\":0,\"pack\":\"" + packEncrypted
                + "\",\"t\":\"pack\",\"tcid\":\"" + greeDeviceMAC + "\",\"uid\":0}";

  String resp = acSendReceive(cmdMsg, 6000);
  if (resp.isEmpty()) {
    Serial.println("[AC] CMD: sem resposta — chave pode ter expirado");
    greeBound = false;
    return false;
  }

  String respPackB64 = jsonGetString(resp, "pack");
  if (!respPackB64.isEmpty()) {
    String respJson = aesDecrypt(respPackB64, greeDeviceKey);
    Serial.printf("[AC] CMD resposta: %s\n", respJson.c_str());
    if (respJson.indexOf("\"r\":200") >= 0) {
      Serial.printf("[AC] ✅ AC %s confirmado!\n", power ? "LIGADO" : "DESLIGADO");
      return true;
    }
  }

  Serial.println("[AC] Resposta recebida — assumindo sucesso");
  return true;
}

// ============================================================
// REBIND COMPLETO
// ============================================================
bool greeRebind() {
  greeBound     = false;
  greeDeviceKey = "";
  lastBindLog   = "[REBIND] Iniciando...\n";
  Serial.println("[AC] === REBIND ===");

  if (!greeScanAC()) {
    lastBindLog += "[REBIND] Scan falhou\n";
    return false;
  }
  delay(500);
  esp_task_wdt_reset();

  if (!greeBindAC()) {
    lastBindLog += "[REBIND] Bind falhou\n";
    return false;
  }

  lastBindLog += "[REBIND] ✅ Concluído com sucesso!\n";
  Serial.println("[AC] ✅ REBIND concluído!");
  return true;
}

// ============================================================
// INICIALIZAÇÃO DO AC
// ============================================================
void greeInit() {
  Serial.println("[AC] Inicializando Gree/Elgin...");
  acUdp.begin(AC_PORT);

  Preferences p;
  p.begin("vansan", true);
  String savedKey = p.getString("acKey", "");
  String savedMAC = p.getString("acMAC", "");
  p.end();

  if (!savedKey.isEmpty()) {
    greeDeviceKey = savedKey;
    greeDeviceMAC = savedMAC;
    greeBound     = true;
    lastBindLog   = "[INIT] Chave restaurada da NVS: " + savedKey + "\n";
    Serial.printf("[AC] Chave restaurada da NVS: %s\n", savedKey.c_str());
  } else {
    Serial.println("[AC] Sem chave salva — executando bind inicial...");
    lastBindLog = "[INIT] Sem chave salva — executando bind...\n";
    delay(3000);
    esp_task_wdt_reset();
    greeRebind();
  }
}

// ============================================================
// FUNÇÃO PRINCIPAL — controlAC(bool)
// ============================================================
bool controlAC(bool ligar) {
  Serial.printf("\n[AC] ===== %s =====\n", ligar ? "LIGANDO" : "DESLIGANDO");
  bool ok = greeCommand(ligar, 1, 16, 0);
  if (!ok) {
    Serial.println("[AC] Tentativa 1 falhou — rebind + retry...");
    if (greeRebind()) ok = greeCommand(ligar, 1, 16, 0);
  }
  Serial.printf("[AC] Resultado: %s\n", ok ? "SUCESSO" : "FALHA");
  return ok;
}

// ========================================
// MULTI-NETWORK NVS
// ========================================
void saveNetwork(const String& ssid, const String& pass) {
  Preferences p;
  p.begin(WIFI_NAMESPACE, false);
  int count = p.getInt("count", 0);
  for (int i = 0; i < count; i++) {
    if (p.getString(("s" + String(i)).c_str(), "") == ssid) {
      p.putString(("p" + String(i)).c_str(), pass);
      p.end();
      return;
    }
  }
  if (count < MAX_NETWORKS) {
    p.putString(("s" + String(count)).c_str(), ssid);
    p.putString(("p" + String(count)).c_str(), pass);
    p.putInt("count", count + 1);
  }
  p.end();
}

void deleteNetwork(int idx) {
  Preferences p;
  p.begin(WIFI_NAMESPACE, false);
  int count = p.getInt("count", 0);
  if (idx < 0 || idx >= count) { p.end(); return; }
  for (int i = idx; i < count - 1; i++) {
    p.putString(("s" + String(i)).c_str(), p.getString(("s" + String(i+1)).c_str(), ""));
    p.putString(("p" + String(i)).c_str(), p.getString(("p" + String(i+1)).c_str(), ""));
  }
  p.remove(("s" + String(count-1)).c_str());
  p.remove(("p" + String(count-1)).c_str());
  p.putInt("count", count - 1);
  p.end();
}

bool connectToNetwork(const String& ssid, const String& pass, uint32_t timeout_ms = 20000) {
  Serial.printf("[WiFi] Conectando: %s\n", ssid.c_str());
  WiFi.disconnect(true, true);
  delay(200);
  WiFi.mode(WIFI_STA);
  delay(100);
  WiFi.begin(ssid.c_str(), pass.c_str());
  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && (millis() - start) < timeout_ms) {
    esp_task_wdt_reset();
    delay(500);
    Serial.print(".");
  }
  Serial.println();
  bool ok = (WiFi.status() == WL_CONNECTED);
  if (ok) Serial.printf("[WiFi] Conectado! IP: %s\n", WiFi.localIP().toString().c_str());
  else    { Serial.println("[WiFi] Falhou."); WiFi.disconnect(); }
  return ok;
}

bool tryKnownNetworks() {
  Preferences p;
  p.begin(WIFI_NAMESPACE, true);
  int count = p.getInt("count", 0);
  p.end();
  if (count == 0) return false;
  int n = WiFi.scanNetworks();
  for (int i = 0; i < count; i++) {
    Preferences p2;
    p2.begin(WIFI_NAMESPACE, true);
    String ssid = p2.getString(("s" + String(i)).c_str(), "");
    String pass = p2.getString(("p" + String(i)).c_str(), "");
    p2.end();
    if (ssid.isEmpty()) continue;
    bool found = false;
    for (int j = 0; j < n; j++) { if (WiFi.SSID(j) == ssid) { found = true; break; } }
    if (!found) continue;
    if (connectToNetwork(ssid, pass, 20000)) { WiFi.scanDelete(); return true; }
    WiFi.disconnect(true);
    delay(1000);
  }
  WiFi.scanDelete();
  return false;
}

void startAP() {
  IPAddress apIP(192, 168, 4, 1);
  IPAddress apMask(255, 255, 255, 0);
  WiFi.softAPConfig(apIP, apIP, apMask);
  WiFi.softAP(AP_SSID, AP_PASS);
  dnsServer.start(53, "*", apIP);
  Serial.printf("[AP] SSID: %s  IP: %s\n", AP_SSID, AP_IP_STR);
}

// ========================================
// NTP
// ========================================
bool syncNTP() {
  if (WiFi.status() != WL_CONNECTED) return false;
  Serial.println("[NTP] Sincronizando...");
  configTime(gmtOffset_sec, daylightOffset_sec, ntpServer);
  int tries = 0;
  while (!getLocalTime(&timeinfo) && tries++ < 20) {
    esp_task_wdt_reset();
    delay(500);
  }
  timeSync    = (tries < 21);
  lastNTPSync = millis();
  if (timeSync) Serial.println("[NTP] OK!");
  else          Serial.println("[NTP] Falhou.");
  return timeSync;
}

// ========================================
// AUXILIARES
// ========================================
String getDataHora() {
  if (timeSync && getLocalTime(&timeinfo)) {
    char buf[25];
    sprintf(buf, "%02d/%02d/%04d %02d:%02d:%02d",
            timeinfo.tm_mday, timeinfo.tm_mon+1, timeinfo.tm_year+1900,
            timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
    return String(buf);
  }
  return "sincronizando...";
}

// ========================================
// TELEGRAM
// ========================================
void enviarTelegram(String mensagem) {
  if (WiFi.status() != WL_CONNECTED) return;
  HTTPClient http;
  String url = "https://api.telegram.org/bot";
  url += telegramToken;
  url += "/sendMessage";
  http.begin(url);
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");
  String postData = "chat_id=" + String(telegramChatId)
                  + "&text=" + mensagem + "&parse_mode=HTML";
  http.POST(postData);
  http.end();
}

void handleTestarTelegram() {
  String msg = "Teste - Vansan Therm v6.1\n";
  msg += "Temp: " + String(temp, 1) + "°C\n";
  msg += "Umid: " + String(hum,  1) + "%\n";
  msg += "AC: "   + String(acLigado  ? "Ligado"  : "Desligado") + "\n";
  msg += "Auto: " + String(acEnabled ? "Ativo"   : "Inativo")   + "\n";
  msg += "Bind: " + String(greeBound ? "OK" : "Falhou") + "\n";
  if (greeBound) msg += "Chave: " + greeDeviceKey + "\n";
  msg += getDataHora();
  enviarTelegram(msg);
}

// ========================================
// CONTROLE DO AC — lógica de negócio
// ========================================
void setAcState(bool ligar) {
  if (acLigado == ligar) { Serial.println("[AC] Já está neste estado"); return; }
  Serial.printf("[AC] %s\n", ligar ? "LIGANDO" : "DESLIGANDO");
  lcd.clear();
  lcd.print(ligar ? "LIGANDO AC..." : "DESLIGANDO AC");
  lcd.setCursor(0, 1);
  lcd.print("Aguarde...");

  bool ok = controlAC(ligar);

  if (ok) {
    acLigado             = ligar;
    ultimoAcionamentoAC  = millis();
    ultimaTentativaFalha = 0;
    String msg = ligar ? "<b>✅ AC LIGADO!</b>\n" : "<b>✅ AC DESLIGADO!</b>\n";
    msg += "T: " + String(temp, 1) + "°C  U: " + String(hum, 0) + "%\n";
    msg += getDataHora();
    enviarTelegram(msg);
    lcd.clear();
    lcd.print(ligar ? "AC LIGADO!" : "AC DESLIGADO!");
    lcd.setCursor(0, 1);
    lcd.printf("%.1fC %.0f%%", temp, hum);
    delay(2000);
  } else {
    ultimaTentativaFalha = millis();
    String msg = "<b>⚠️ ERRO: AC não respondeu!</b>\n";
    msg += "IP: " + String(AC_IP) + "\n";
    msg += "Bind: " + String(greeBound ? "OK" : "Falhou") + "\n";
    msg += getDataHora();
    enviarTelegram(msg);
    lcd.clear();
    lcd.print("ERRO AC!");
    lcd.setCursor(0, 1);
    lcd.print("Nao responde");
    delay(3000);
  }
}

void acControlTask(void* pvParameters) {
  AcCmd cmd;
  for (;;) {
    if (xQueueReceive(acQueue, &cmd, portMAX_DELAY) == pdTRUE) {
      esp_task_wdt_reset();
      setAcState(cmd.ligar);
      esp_task_wdt_reset();
    }
  }
}

void solicitarAC(bool ligar) {
  AcCmd cmd = { ligar };
  xQueueSend(acQueue, &cmd, 0);
}

void verificarAC() {
  if (!acEnabled) return;
  unsigned long agora = millis();
  if (agora - ultimoAcionamentoAC  < AC_INTERVALO_MIN)  return;
  if (ultimaTentativaFalha > 0 &&
      agora - ultimaTentativaFalha < AC_RETRY_INTERVALO) return;
  bool deveLigar = (temp > TEMP_MAX || hum > HUM_MAX);
  if (deveLigar  && !acLigado) solicitarAC(true);
  if (!deveLigar &&  acLigado) solicitarAC(false);
}

// ========================================
// THINGSPEAK
// ========================================
String getUTCTimestamp() {
  time_t now; time(&now);
  struct tm* u = gmtime(&now);
  char ts[25];
  sprintf(ts, "%04d-%02d-%02d%%20%02d:%02d:%02d",
          u->tm_year+1900, u->tm_mon+1, u->tm_mday,
          u->tm_hour, u->tm_min, u->tm_sec);
  return String(ts);
}

void sendToThingSpeak() {
  if (isnan(temp) || isnan(hum)) return;
  digitalWrite(LED_BLUE, HIGH);
  HTTPClient http;
  http.setTimeout(10000);
  String postData = "api_key=" + String(apiKey);
  postData += "&field1=" + String(temp, 2);
  postData += "&field2=" + String(hum,  2);
  postData += "&field3=" + String(alert ? 1 : 0);
  if (timeSync) postData += "&created_at=" + getUTCTimestamp();
  http.begin("https://api.thingspeak.com/update");
  http.addHeader("Content-Type", "application/x-www-form-urlencoded");
  http.POST(postData);
  http.end();
  delay(100);
  digitalWrite(LED_BLUE, LOW);
}

// ========================================
// CSS COMPARTILHADO
// ========================================
const char* LIGHT_CSS = R"css(
*{box-sizing:border-box;margin:0;padding:0}
body{background:#f0f4f8;color:#1a2a3a;font-family:'Segoe UI',Arial,sans-serif;min-height:100vh;padding:16px}
h1{font-size:1.4rem;font-weight:900;letter-spacing:.08em;text-transform:uppercase;color:#1a2a3a;text-align:center;margin-bottom:2px}
.sub{text-align:center;font-size:.65rem;color:#7a9ab0;letter-spacing:.2em;margin-bottom:20px}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:12px}
.card{background:#fff;border:1px solid #dde6ef;border-radius:14px;padding:16px;text-align:center;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.card-label{font-size:.6rem;letter-spacing:.2em;text-transform:uppercase;color:#7a9ab0;margin-bottom:6px}
.card-value{font-size:2.2rem;font-weight:900;line-height:1;font-family:monospace}
.card-unit{font-size:.72rem;color:#7a9ab0;margin-top:3px}
.status-bar{border-radius:10px;padding:12px;text-align:center;font-weight:700;letter-spacing:.06em;font-size:.85rem;margin-bottom:12px;border:1px solid transparent}
.status-ok{background:#eafaf1;border-color:#a9dfbf;color:#1e8449}
.status-alert{background:#fdf2f2;border-color:#f5b7b1;color:#c0392b}
.sec{font-size:.58rem;letter-spacing:.2em;text-transform:uppercase;color:#7a9ab0;margin-bottom:8px;padding-left:2px;margin-top:4px}
.info-row{display:flex;justify-content:space-between;align-items:center;padding:8px 12px;background:#f7fafc;border-radius:8px;margin-bottom:6px;font-size:.78rem;border:1px solid #dde6ef}
.info-key{color:#7a9ab0;font-family:monospace}
.badge{display:inline-block;padding:3px 10px;border-radius:5px;font-size:.65rem;font-weight:700}
.badge-green{background:#eafaf1;color:#1e8449;border:1px solid #a9dfbf}
.badge-gray{background:#f0f4f8;color:#7a9ab0;border:1px solid #dde6ef}
.badge-blue{background:#ebf5fb;color:#1a5276;border:1px solid #aed6f1}
.badge-red{background:#fdf2f2;color:#c0392b;border:1px solid #f5b7b1}
.btn-row{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px}
.btn{display:block;width:100%;padding:13px 8px;border:none;border-radius:10px;font-family:inherit;font-weight:700;font-size:.82rem;cursor:pointer;text-transform:uppercase;letter-spacing:.05em;box-shadow:0 2px 6px rgba(0,0,0,.10)}
.btn:active{opacity:.8;transform:scale(.98)}
.btn-green{background:#27ae60;color:#fff}
.btn-red{background:#e74c3c;color:#fff}
.btn-blue{background:#2471a3;color:#fff}
.btn-gray{background:#aab8c2;color:#fff}
.btn-orange{background:#e67e22;color:#fff}
.btn-maint{background:#8e44ad;color:#fff}
.btn-yellow{background:#f39c12;color:#fff}
.divider{height:1px;background:#dde6ef;margin:14px 0}
.temp-color{color:#e67e22}
.hum-color{color:#2471a3}
.net-bar{background:#eafaf1;border:1px solid #a9dfbf;border-radius:8px;padding:8px 12px;margin-bottom:6px;font-size:.75rem;color:#1e8449}
.net-bar-warn{background:#fdf2f2;border:1px solid #f5b7b1;border-radius:8px;padding:8px 12px;margin-bottom:6px;font-size:.75rem;color:#c0392b}
.footer{text-align:center;font-size:.58rem;color:#aab8c2;margin-top:18px;font-family:monospace}
.log-box{background:#1a2a3a;color:#a8d8a8;font-family:monospace;font-size:.7rem;padding:14px;border-radius:10px;white-space:pre-wrap;word-break:break-all;margin-bottom:10px;max-height:400px;overflow-y:auto}
)css";

// ========================================
// PÁGINA PRINCIPAL
// ========================================
String buildPage() {
  bool staOk = WiFi.status() == WL_CONNECTED;
  String acAutoText = acEnabled ? "ATIVO"    : "INATIVO";
  String acLigText  = acLigado  ? "LIGADO"   : "DESLIGADO";
  String bindText   = greeBound ? "VINCULADO": "SEM BIND";

  String html = "<!DOCTYPE html><html lang='pt-BR'><head>";
  html += "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<meta http-equiv='refresh' content='15'>";
  html += "<title>VANSAN THERM</title>";
  html += "<style>" + String(LIGHT_CSS) + "</style></head><body>";

  html += "<h1>VANSAN THERM</h1>";
  html += "<div class='sub'>ANVISA RDC 301 &middot; v6.1</div>";

  html += "<div class='grid'>";
  html += "<div class='card'><div class='card-label'>Temperatura</div>";
  html += "<div class='card-value temp-color'>" + String(temp, 1) + "</div>";
  html += "<div class='card-unit'>°C &nbsp;|&nbsp; limite 15–25</div></div>";
  html += "<div class='card'><div class='card-label'>Umidade</div>";
  html += "<div class='card-value hum-color'>" + String(hum, 1) + "</div>";
  html += "<div class='card-unit'>% &nbsp;|&nbsp; limite 40–70</div></div>";
  html += "</div>";

  if (alert)
    html += "<div class='status-bar status-alert'>⚠️ FORA DO LIMITE ANVISA</div>";
  else
    html += "<div class='status-bar status-ok'>✓ AMBIENTE NORMAL</div>";

  // Wi-Fi
  html += "<div class='divider'></div><div class='sec'>Wi-Fi</div>";
  if (staOk) {
    html += "<div class='net-bar'>● Rede: <b>" + WiFi.SSID() + "</b> &nbsp;|&nbsp; IP: <b>"
          + WiFi.localIP().toString() + "</b> &nbsp;|&nbsp; vansan.local</div>";
  } else {
    html += "<div class='net-bar-warn'>⚠️ Sem rede local — usando AP (192.168.4.1)</div>";
  }
  html += "<div class='btn-row'>";
  html += "<a href='/redes'><button class='btn btn-gray'>Gerenciar WiFi</button></a>";
  html += "<a href='/ac/scan'><button class='btn btn-gray'>Scan AC</button></a>";
  html += "</div>";

  // Ar-condicionado
  html += "<div class='divider'></div><div class='sec'>Ar-Condicionado (Elgin Eco Inverter II)</div>";
  html += "<div class='info-row'><span class='info-key'>Controle Auto</span>";
  html += "<span class='badge " + String(acEnabled ? "badge-green" : "badge-gray") + "'>" + acAutoText + "</span></div>";
  html += "<div class='info-row'><span class='info-key'>Estado AC</span>";
  html += "<span class='badge " + String(acLigado ? "badge-blue" : "badge-gray") + "'>" + acLigText + "</span></div>";
  html += "<div class='info-row'><span class='info-key'>Protocolo Gree</span>";
  html += "<span class='badge " + String(greeBound ? "badge-green" : "badge-red") + "'>" + bindText + "</span></div>";
  if (greeBound) {
    html += "<div class='info-row'><span class='info-key'>Chave AES</span>";
    html += "<span style='font-family:monospace;font-size:.68rem'>" + greeDeviceKey.substring(0,8) + "...</span></div>";
    html += "<div class='info-row'><span class='info-key'>MAC do AC</span>";
    html += "<span style='font-family:monospace;font-size:.68rem'>" + greeDeviceMAC + "</span></div>";
  }

  html += "<br><div class='btn-row'>";
  html += "<a href='/ac/auto/on'><button class='btn btn-green'>Auto ON</button></a>";
  html += "<a href='/ac/auto/off'><button class='btn btn-gray'>Auto OFF</button></a>";
  html += "</div>";
  html += "<div class='btn-row'>";
  html += "<a href='/ac/ligar'><button class='btn btn-blue'>Ligar AC</button></a>";
  html += "<a href='/ac/desligar'><button class='btn btn-red'>Desligar AC</button></a>";
  html += "</div>";
  html += "<div class='btn-row'>";
  html += "<a href='/ac/rebind'><button class='btn btn-yellow' style='grid-column:1/-1'>🔗 Forçar Rebind AC</button></a>";
  html += "</div>";
  html += "<div class='btn-row'>";
  html += "<a href='/ac/bindlog'><button class='btn btn-blue' style='grid-column:1/-1'>📋 Ver Log do Bind</button></a>";
  html += "</div>";
  html += "<div class='btn-row'>";
  html += "<a href='/manutencao'><button class='btn btn-maint' style='grid-column:1/-1'>Modo Manutenção</button></a>";
  html += "</div>";

  // Sistema
  html += "<div class='divider'></div><div class='sec'>Sistema</div>";
  html += "<div class='info-row'><span class='info-key'>Horário</span><span>" + getDataHora() + "</span></div>";
  html += "<div class='info-row'><span class='info-key'>AP fixo</span><span>" + String(AP_SSID) + " / 192.168.4.1</span></div>";
  html += "<div class='info-row'><span class='info-key'>AC IP</span><span style='font-family:monospace'>" + String(AC_IP) + ":" + String(AC_PORT) + "</span></div>";

  html += "<br><div class='btn-row'>";
  html += "<a href='/telegram/teste'><button class='btn btn-orange'>Testar Telegram</button></a>";
  html += "<a href='/redes'><button class='btn btn-gray'>Redes WiFi</button></a>";
  html += "</div>";

  html += "<div class='footer'>v6.1 &middot; vansan.local &middot; Atualiza a cada 15s</div>";
  html += "</body></html>";
  return html;
}

// ========================================
// CSS EXTRA — PÁGINA DE REDES
// ========================================
const char* REDES_EXTRA_CSS = R"css(
.rcard{background:#fff;border:1px solid #dde6ef;border-radius:14px;padding:16px;margin-bottom:14px;box-shadow:0 2px 8px rgba(0,0,0,.06)}
.rsec{font-size:.6rem;letter-spacing:.2em;text-transform:uppercase;color:#7a9ab0;margin-bottom:10px}
.net-row{display:flex;align-items:center;gap:10px;padding:10px 12px;background:#f7fafc;border-radius:8px;margin-bottom:8px;border:1px solid #dde6ef;cursor:pointer}
.net-row:hover{background:#ebf5fb;border-color:#aed6f1}
.net-name{flex:1;font-size:.88rem;font-weight:700;color:#1a2a3a}
.net-saved-badge{background:#eafaf1;color:#1e8449;font-size:.6rem;font-weight:700;padding:2px 8px;border-radius:4px;border:1px solid #a9dfbf}
.net-signal{font-size:.7rem;color:#7a9ab0}
.del-btn{padding:7px 12px;border-radius:8px;border:1px solid #f5b7b1;background:#fdf2f2;color:#e74c3c;font-size:.75rem;font-weight:700;cursor:pointer}
.field{margin-bottom:12px}
.lbl{font-size:.62rem;letter-spacing:.18em;text-transform:uppercase;color:#7a9ab0;display:block;margin-bottom:6px}
input[type=text],input[type=password]{width:100%;background:#f7fafc;border:1px solid #dde6ef;border-radius:8px;color:#1a2a3a;padding:11px 14px;font-size:.95rem;font-family:inherit;outline:none}
input:focus{border-color:#2471a3;background:#fff}
.pass-wrap{position:relative}
.pass-wrap input{padding-right:90px}
.show-btn{position:absolute;right:8px;top:50%;transform:translateY(-50%);background:#dde6ef;border:none;color:#1a2a3a;font-size:.72rem;padding:5px 10px;border-radius:6px;cursor:pointer;font-weight:700}
.rbtn{display:block;width:100%;padding:13px;border-radius:10px;border:none;font-family:inherit;font-weight:700;font-size:.88rem;cursor:pointer;text-transform:uppercase;letter-spacing:.05em;margin-bottom:8px}
.rbtn-blue{background:#2471a3;color:#fff}
.rbtn-scan{background:#f0f4f8;color:#1a2a3a;border:1px solid #dde6ef}
.info-box{border-radius:8px;padding:10px 14px;font-size:.78rem;line-height:1.6;margin-bottom:8px}
.info-green{background:#eafaf1;border:1px solid #a9dfbf;color:#1e8449}
.info-orange{background:#fdf2f2;border:1px solid #f5b7b1;color:#c0392b}
.ap-box{background:#ebf5fb;border:1px solid #aed6f1;border-radius:8px;padding:12px 14px;margin-bottom:10px;font-size:.8rem;line-height:1.9;color:#1a5276}
.back-btn{display:block;text-align:center;padding:13px;border-radius:10px;background:#fff;color:#1a2a3a;font-size:.82rem;font-weight:700;text-decoration:none;border:1px solid #dde6ef;margin-top:4px}
.scan-list{max-height:260px;overflow-y:auto}
.scanning{text-align:center;color:#7a9ab0;font-size:.82rem;padding:14px}
#result{display:none;margin-top:10px}
)css";

// ========================================
// PÁGINA DE REDES
// ========================================
void handleRedesPage() {
  server.setContentLength(CONTENT_LENGTH_UNKNOWN);
  server.send(200, "text/html", "");

  server.sendContent("<!DOCTYPE html><html><head>"
    "<meta charset='UTF-8'><meta name='viewport' content='width=device-width,initial-scale=1'>"
    "<title>Redes Wi-Fi</title>");
  server.sendContent("<style>" + String(LIGHT_CSS) + String(REDES_EXTRA_CSS) + "</style></head><body>");
  server.sendContent("<h1>VANSAN THERM</h1><div class='sub'>GERENCIAR WI-FI &middot; v6.1</div>");

  server.sendContent("<div class='rcard'><div class='rsec'>AP Fixo (sempre ativo)</div>"
    "<div class='ap-box'>Rede: <strong>VANSAN-CONFIG</strong><br>"
    "Senha: <strong>vansan123</strong><br>IP: <strong>192.168.4.1</strong></div></div>");

  server.sendContent("<div class='rcard'><div class='rsec'>Rede Local</div>");
  if (WiFi.status() == WL_CONNECTED) {
    server.sendContent("<div class='info-box info-green'>Conectado: <strong>" + WiFi.SSID()
      + "</strong><br>IP: <strong>" + WiFi.localIP().toString() + "</strong><br>"
      "mDNS: <strong>http://vansan.local</strong></div>");
  } else {
    server.sendContent("<div class='info-box info-orange'>Sem rede local.</div>");
  }
  server.sendContent("</div>");

  server.sendContent("<div class='rcard'><div class='rsec'>Redes Salvas</div>"
    "<div id='saved-list'><div class='scanning'>Carregando...</div></div></div>");

  server.sendContent("<div class='rcard'><div class='rsec'>Adicionar Nova Rede</div>"
    "<button class='rbtn rbtn-scan' id='btn-scan' onclick='scanNets()'>Buscar Redes Wi-Fi</button>"
    "<div class='scan-list' id='scan-list'></div>"
    "<div class='field' style='margin-top:10px'><label class='lbl'>SSID</label>"
    "<input type='text' id='inp-ssid' placeholder='Selecione ou digite' autocomplete='off'></div>"
    "<div class='field'><label class='lbl'>Senha</label><div class='pass-wrap'>"
    "<input type='password' id='inp-pass'>"
    "<button class='show-btn' onclick=\"var i=document.getElementById('inp-pass');"
    "i.type=i.type==='password'?'text':'password';\">Mostrar</button>"
    "</div></div>"
    "<button class='rbtn rbtn-blue' id='btn-add' onclick='addNet()'>Salvar e Conectar</button>"
    "<div id='result'></div></div>");

  server.sendContent("<a href='/' class='back-btn'>← Voltar ao Painel</a>");

  server.sendContent(R"html(<script>
function loadSaved(){
  fetch('/api/wifi/list').then(r=>r.json()).then(list=>{
    var el=document.getElementById('saved-list');
    if(!list||!list.length){el.innerHTML='<div class="scanning">Nenhuma rede salva.</div>';return;}
    var h='';
    list.forEach(n=>{
      h+='<div class="net-row"><span class="net-name">'+n.ssid
        +(n.current?' <span class="net-saved-badge">Conectado</span>':'')+'</span>'
        +'<button class="del-btn" onclick="delNet(event,'+n.idx+',\''+n.ssid+'\')">Remover</button></div>';
    });
    el.innerHTML=h;
  }).catch(()=>document.getElementById('saved-list').innerHTML='<div class="scanning">Erro</div>');
}
function delNet(e,idx,ssid){
  e.stopPropagation();
  if(!confirm('Remover "'+ssid+'"?'))return;
  fetch('/api/wifi/delete?idx='+idx,{method:'DELETE'}).then(()=>loadSaved());
}
function scanNets(){
  var btn=document.getElementById('btn-scan');
  var sl=document.getElementById('scan-list');
  btn.disabled=true;btn.textContent='Buscando...';
  sl.innerHTML='<div class="scanning">Escaneando...</div>';
  fetch('/api/wifi/scan').then(r=>r.json()).then(nets=>{
    btn.disabled=false;btn.textContent='Buscar Redes Wi-Fi';
    if(!nets||!nets.length){sl.innerHTML='<div class="scanning">Nenhuma rede</div>';return;}
    var h='';
    nets.forEach(n=>{
      h+='<div class="net-row" onclick="selectNet(\''+n.ssid+'\')">'
        +'<span class="net-name">'+n.ssid+'</span>'
        +'<span class="net-signal">'+n.rssi+'dBm</span></div>';
    });
    sl.innerHTML=h;
  }).catch(()=>{btn.disabled=false;btn.textContent='Buscar Redes Wi-Fi';sl.innerHTML='<div class="scanning">Erro</div>';});
}
function selectNet(ssid){document.getElementById('inp-ssid').value=ssid;document.getElementById('inp-pass').focus();}
function addNet(){
  var ssid=document.getElementById('inp-ssid').value.trim();
  var pass=document.getElementById('inp-pass').value;
  if(!ssid){alert('Digite o nome da rede');return;}
  var btn=document.getElementById('btn-add');
  var res=document.getElementById('result');
  btn.disabled=true;btn.textContent='Conectando...';
  res.style.display='block';res.innerHTML='<div class="scanning">Conectando...</div>';
  fetch('/api/wifi/add',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'ssid='+encodeURIComponent(ssid)+'&pass='+encodeURIComponent(pass)})
  .then(r=>r.json()).then(d=>{
    btn.disabled=false;btn.textContent='Salvar e Conectar';
    if(d.connected){
      res.innerHTML='<div class="info-box info-green">✅ Conectado! IP: <strong>'+d.ip+'</strong></div>';
      loadSaved();
    } else {
      res.innerHTML='<div class="info-box info-orange">❌ '+d.msg+'</div>';
    }
  }).catch(()=>{btn.disabled=false;btn.textContent='Salvar e Conectar';res.innerHTML='<div class="info-box info-orange">Erro</div>';});
}
loadSaved();
scanNets();
</script>)html");

  server.sendContent("</body></html>");
  server.sendContent("");
}

// ========================================
// APIs WIFI
// ========================================
void apiWiFiList() {
  Preferences p;
  p.begin(WIFI_NAMESPACE, true);
  int count = p.getInt("count", 0);
  String cur = WiFi.SSID();
  String json = "[";
  bool first = true;
  for (int i = 0; i < count; i++) {
    String ssid = p.getString(("s" + String(i)).c_str(), "");
    if (ssid.isEmpty()) continue;
    if (!first) json += ",";
    first = false;
    json += "{\"idx\":" + String(i) + ",\"ssid\":\"" + jsonEscape(ssid)
          + "\",\"current\":" + (ssid == cur ? "true" : "false") + "}";
  }
  p.end();
  json += "]";
  server.send(200, "application/json", json);
}

void apiWiFiDelete() {
  deleteNetwork(server.arg("idx").toInt());
  server.send(200, "application/json", "{\"ok\":true}");
}

void apiWiFiAdd() {
  String ssid = server.arg("ssid");
  String pass = server.arg("pass");
  if (ssid.isEmpty()) {
    server.send(400, "application/json", "{\"ok\":false,\"msg\":\"SSID obrigatorio\"}");
    return;
  }
  saveNetwork(ssid, pass);
  esp_task_wdt_delete(NULL);
  bool ok = connectToNetwork(ssid, pass, 20000);
  esp_task_wdt_add(NULL);
  esp_task_wdt_reset();
  if (ok) {
    syncNTP();
    MDNS.end();
    MDNS.begin("vansan");
    MDNS.addService("http", "tcp", 80);
    acUdp.stop();
    acUdp.begin(AC_PORT);
    greeBound = false;
    greeInit();
    lcd.clear(); lcd.print("WiFi OK!"); lcd.setCursor(0,1); lcd.print(WiFi.localIP());
    server.send(200, "application/json",
      "{\"ok\":true,\"connected\":true,\"ip\":\"" + WiFi.localIP().toString() + "\"}");
  } else {
    WiFi.mode(WIFI_AP_STA);
    startAP();
    server.send(200, "application/json",
      "{\"ok\":true,\"connected\":false,\"msg\":\"Nao foi possivel conectar. Verifique senha e sinal.\"}");
  }
}

void apiWiFiScan() {
  int n = WiFi.scanNetworks(false, true);
  String json = "[";
  for (int i = 0; i < n; i++) {
    if (i > 0) json += ",";
    json += "{\"ssid\":\"" + jsonEscape(WiFi.SSID(i)) + "\",\"rssi\":" + String(WiFi.RSSI(i))
          + ",\"open\":" + (WiFi.encryptionType(i) == WIFI_AUTH_OPEN ? "true" : "false") + "}";
  }
  json += "]";
  WiFi.scanDelete();
  server.send(200, "application/json", json);
}

// ========================================
// SETUP WEB SERVER
// ========================================
void setupWebServer() {
  server.on("/", []() { server.send(200, "text/html", buildPage()); });

  // Portal captivo
  server.on("/generate_204",        []() { server.send(204); });
  server.on("/fwlink",              []() { server.send(204); });
  server.on("/hotspot-detect.html", []() { server.send(204); });
  server.on("/connecttest.txt",     []() { server.send(200, "text/plain", "Microsoft Connect Test"); });
  server.on("/ncsi.txt",            []() { server.send(200, "text/plain", "Microsoft NCSI"); });
  server.on("/favicon.ico",         []() { server.send(204); });
  server.on("/robots.txt",          []() { server.send(200, "text/plain", "User-agent: *\nDisallow: /\n"); });

  // Controle AC
  server.on("/ac/auto/on", []() {
    acEnabled = true;
    prefs.begin("vansan", false); prefs.putBool("acEnabled", acEnabled); prefs.end();
    enviarTelegram("<b>Controle automático ATIVADO</b>\n" + getDataHora());
    server.sendHeader("Location", "/"); server.send(303);
  });
  server.on("/ac/auto/off", []() {
    acEnabled = false;
    prefs.begin("vansan", false); prefs.putBool("acEnabled", acEnabled); prefs.end();
    if (acLigado) solicitarAC(false);
    enviarTelegram("<b>Controle automático DESATIVADO</b>\n" + getDataHora());
    server.sendHeader("Location", "/"); server.send(303);
  });
  server.on("/ac/ligar",    []() { solicitarAC(true);  server.sendHeader("Location", "/"); server.send(303); });
  server.on("/ac/desligar", []() { solicitarAC(false); server.sendHeader("Location", "/"); server.send(303); });

  server.on("/manutencao", []() {
    acEnabled = false;
    prefs.begin("vansan", false); prefs.putBool("acEnabled", acEnabled); prefs.end();
    if (acLigado) solicitarAC(false);
    enviarTelegram("<b>Modo Manutenção ATIVADO</b>\nAuto OFF + AC Desligado.\n" + getDataHora());
    server.sendHeader("Location", "/"); server.send(303);
  });

  // Rebind forçado
  server.on("/ac/rebind", []() {
    bool ok = greeRebind();
    String body = "<html><head><meta charset='UTF-8'></head><body style='font-family:monospace;padding:30px;background:#f7fafc'>";
    if (ok) {
      body += "<b style='color:#1e8449'>✅ Bind OK!</b><br>";
      body += "MAC: <code>" + greeDeviceMAC + "</code><br>";
      body += "Chave: <code>" + greeDeviceKey + "</code><br>";
    } else {
      body += "<b style='color:#c0392b'>❌ Bind falhou!</b><br>";
      body += "Verifique se o AC está ligado e IP " + String(AC_IP) + " acessível.<br>";
    }
    body += "<br><a href='/ac/bindlog'>Ver log detalhado</a>";
    body += "<br><br><a href='/'>← Voltar</a></body></html>";
    server.send(200, "text/html", body);
  });

  // Log do bind — diagnóstico via browser (substitui Serial Monitor)
  server.on("/ac/bindlog", []() {
    String body = "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
                  "<meta name='viewport' content='width=device-width,initial-scale=1'>"
                  "<title>Bind Log</title>";
    body += "<style>" + String(LIGHT_CSS) + "</style></head><body>";
    body += "<h1>VANSAN THERM</h1><div class='sub'>LOG DO BIND GREE &middot; v6.1</div>";
    body += "<div class='sec'>Estado Atual</div>";
    body += "<div class='info-row'><span class='info-key'>Bind</span>";
    body += "<span class='badge " + String(greeBound ? "badge-green" : "badge-red") + "'>";
    body += String(greeBound ? "OK" : "FALHOU") + "</span></div>";
    body += "<div class='info-row'><span class='info-key'>MAC</span>";
    body += "<span style='font-family:monospace'>" + (greeDeviceMAC.isEmpty() ? "não encontrado" : greeDeviceMAC) + "</span></div>";
    body += "<div class='info-row'><span class='info-key'>Chave</span>";
    body += "<span style='font-family:monospace'>" + (greeDeviceKey.isEmpty() ? "não obtida" : greeDeviceKey) + "</span></div>";
    body += "<div class='info-row'><span class='info-key'>AC IP</span>";
    body += "<span style='font-family:monospace'>" + String(AC_IP) + ":" + String(AC_PORT) + "</span></div>";
    body += "<br><div class='sec'>Log Detalhado</div>";
    body += "<div class='log-box'>" + lastBindLog + "</div>";
    body += "<div class='btn-row'>";
    body += "<a href='/ac/rebind'><button class='btn btn-yellow'>🔗 Tentar Rebind</button></a>";
    body += "<a href='/'><button class='btn btn-gray'>← Voltar</button></a>";
    body += "</div></body></html>";
    server.send(200, "text/html", body);
  });

  // Status JSON
  server.on("/ac/status", []() {
    String json = "{";
    json += "\"bound\":" + String(greeBound ? "true" : "false") + ",";
    json += "\"mac\":\"" + greeDeviceMAC + "\",";
    json += "\"key\":\"" + greeDeviceKey + "\",";
    json += "\"acOn\":" + String((bool)acLigado ? "true" : "false") + ",";
    json += "\"acEnabled\":" + String(acEnabled ? "true" : "false") + ",";
    json += "\"temp\":" + String(temp, 1) + ",";
    json += "\"hum\":" + String(hum, 1) + ",";
    json += "\"alert\":" + String(alert ? "true" : "false") + ",";
    json += "\"ip\":\"" + WiFi.localIP().toString() + "\"";
    json += "}";
    server.send(200, "application/json", json);
  });

  // Scan AC
  server.on("/ac/scan", []() {
    bool found = greeScanAC();
    server.send(200, "text/html",
      "<html><head><meta charset='UTF-8'></head><body style='font-family:monospace;padding:30px;background:#f7fafc'>"
      + String(found ? "✅ AC encontrado! MAC: " + greeDeviceMAC : "❌ AC não respondeu.")
      + "<br><br><a href='/ac/bindlog'>Ver log</a> &nbsp; <a href='/'>← Voltar</a></body></html>");
  });

  // Telegram
  server.on("/telegram/teste", []() {
    handleTestarTelegram();
    server.sendHeader("Location", "/"); server.send(303);
  });

  // Redes WiFi
  server.on("/redes",           HTTP_GET,    handleRedesPage);
  server.on("/api/wifi/list",   HTTP_GET,    apiWiFiList);
  server.on("/api/wifi/scan",   HTTP_GET,    apiWiFiScan);
  server.on("/api/wifi/delete", HTTP_DELETE, apiWiFiDelete);
  server.on("/api/wifi/add",    HTTP_POST,   apiWiFiAdd);

  server.onNotFound([]() { server.sendHeader("Location", "/"); server.send(302); });
  server.begin();
  Serial.println("[WebServer] Iniciado na porta 80");
}

// ========================================
// SETUP
// ========================================
void setup() {
  Serial.begin(115200);
  Serial.println("\n============================================");
  Serial.println("VANSAN THERM v6.1 - Protocolo Gree AES-128");
  Serial.println("============================================\n");

  esp_task_wdt_init(60, true);
  esp_task_wdt_add(NULL);

  pinMode(LED_GREEN, OUTPUT);
  pinMode(LED_BLUE,  OUTPUT);
  pinMode(LED_RED,   OUTPUT);
  pinMode(BOOT_BTN,  INPUT_PULLUP);

  lcd.init();
  lcd.backlight();
  lcd.print("VANSAN THERM");
  lcd.setCursor(0, 1);
  lcd.print("v6.1 AES Gree");
  delay(2000);
  esp_task_wdt_reset();

  dht.begin();

  prefs.begin("vansan", true);
  acEnabled = prefs.getBool("acEnabled", false);
  prefs.end();

  acQueue = xQueueCreate(5, sizeof(AcCmd));
  xTaskCreatePinnedToCore(acControlTask, "AC_Task", 8192, NULL, 1, NULL, 0);

  WiFi.mode(WIFI_AP_STA);
  startAP();
  esp_task_wdt_reset();

  lcd.clear(); lcd.print("AP: VANSAN"); lcd.setCursor(0, 1); lcd.print("Conectando WiFi");

  esp_task_wdt_delete(NULL);
  bool staOk = tryKnownNetworks();
  esp_task_wdt_add(NULL);
  esp_task_wdt_reset();

  if (staOk) {
    digitalWrite(LED_GREEN, HIGH);
    lcd.clear(); lcd.print("WiFi OK!"); lcd.setCursor(0, 1); lcd.print(WiFi.localIP());
    delay(1000);
    esp_task_wdt_reset();

    syncNTP();
    esp_task_wdt_reset();

    lcd.clear(); lcd.print("Init AC Gree"); lcd.setCursor(0, 1); lcd.print("Bind...");
    greeInit();
    esp_task_wdt_reset();

    MDNS.begin("vansan");
    MDNS.addService("http", "tcp", 80);
    Serial.println("[mDNS] http://vansan.local");

    String msg = "<b>Vansan Therm v6.1 Online!</b>\n";
    msg += "IP: " + WiFi.localIP().toString() + "\n";
    msg += "AC Bind: " + String(greeBound ? "✅ OK" : "⚠️ Falhou") + "\n";
    if (greeBound) msg += "MAC: " + greeDeviceMAC + "\n";
    msg += "Auto: " + String(acEnabled ? "Ativo" : "Inativo") + "\n";
    msg += getDataHora();
    enviarTelegram(msg);
    esp_task_wdt_reset();

  } else {
    lcd.clear(); lcd.print("AP: VANSAN-CFG"); lcd.setCursor(0, 1); lcd.print("192.168.4.1");
  }

  setupWebServer();
  esp_task_wdt_reset();

  lcd.clear();
  lcd.print("VANSAN THERM");
  lcd.setCursor(0, 1);
  if (staOk) lcd.print(WiFi.localIP());
  else       lcd.print("192.168.4.1");

  Serial.println("[Setup] Concluído!");
}

// ========================================
// LOOP
// ========================================
void loop() {
  esp_task_wdt_reset();
  dnsServer.processNextRequest();
  server.handleClient();

  // Comandos Serial
  if (Serial.available()) {
    String cmd = Serial.readStringUntil('\n');
    cmd.trim(); cmd.toUpperCase();
    if      (cmd == "LIGAR")    solicitarAC(true);
    else if (cmd == "DESLIGAR") solicitarAC(false);
    else if (cmd == "SCAN")     greeScanAC();
    else if (cmd == "BIND")     greeRebind();
    else if (cmd == "LOG")      Serial.println(lastBindLog);
    else if (cmd == "STATUS")
      Serial.printf("[Status] T:%.1f°C H:%.1f%% AC:%s Auto:%s Bind:%s MAC:%s IP:%s\n",
        temp, hum, acLigado?"ON":"OFF", acEnabled?"ON":"OFF",
        greeBound?"OK":"FAIL", greeDeviceMAC.c_str(), WiFi.localIP().toString().c_str());
    else if (cmd == "SYNC")  syncNTP();
    else if (cmd == "CLEAR") {
      Preferences p; p.begin(WIFI_NAMESPACE, false); p.clear(); p.end();
      Serial.println("[Serial] Redes apagadas! Reiniciando...");
      delay(2000); ESP.restart();
    }
    else if (cmd == "HELP")
      Serial.println("Comandos: LIGAR, DESLIGAR, SCAN, BIND, LOG, STATUS, SYNC, CLEAR");
  }

  digitalWrite(LED_GREEN, WiFi.status() == WL_CONNECTED ? HIGH : LOW);

  // Reconexão automática WiFi
  if (WiFi.status() != WL_CONNECTED && millis() - lastRecon > 30000) {
    lastRecon = millis();
    Serial.println("[WiFi] Reconectando...");
    esp_task_wdt_delete(NULL);
    bool ok = tryKnownNetworks();
    esp_task_wdt_add(NULL);
    esp_task_wdt_reset();
    if (ok) {
      syncNTP();
      acUdp.stop();
      acUdp.begin(AC_PORT);
      greeBound = false;
      greeInit();
    }
  }

  // Resync NTP a cada 6 horas
  if (WiFi.status() == WL_CONNECTED && millis() - lastNTPSync > 21600000UL) {
    syncNTP();
  }

  // Leitura DHT22 a cada 10s
  if (millis() - lastRead > 10000) {
    lastRead = millis();
    float nt = dht.readTemperature();
    float nh = dht.readHumidity();
    if (!isnan(nt) && !isnan(nh) && nt > -10 && nt < 80 && nh >= 0 && nh <= 100) {
      temp = nt; hum = nh;
      bool novoAlert = (temp < TEMP_MIN || temp > TEMP_MAX || hum < HUM_MIN || hum > HUM_MAX);
      if (novoAlert && !alertaEnviado) {
        alertaEnviado = true;
        String msg = "<b>⚠️ ALERTA ANVISA RDC 301</b>\n";
        msg += "T: <b>" + String(temp,1) + "°C</b>  U: <b>" + String(hum,1) + "%</b>\n";
        if (temp < TEMP_MIN) msg += "Temp ABAIXO do mínimo (15°C)\n";
        if (temp > TEMP_MAX) msg += "Temp ACIMA do máximo (25°C)\n";
        if (hum  < HUM_MIN)  msg += "Umidade ABAIXO do mínimo (40%)\n";
        if (hum  > HUM_MAX)  msg += "Umidade ACIMA do máximo (70%)\n";
        msg += getDataHora();
        enviarTelegram(msg);
      } else if (!novoAlert && alertaEnviado) {
        alertaEnviado = false;
        enviarTelegram("<b>✅ Ambiente Normalizado</b>\nT: " + String(temp,1) + "°C | U: " + String(hum,1) + "%\n" + getDataHora());
      }
      alert = novoAlert;
      digitalWrite(LED_RED, alert ? HIGH : LOW);
      verificarAC();
    } else {
      Serial.println("[DHT] Leitura inválida — descartada");
    }
  }

  // ThingSpeak a cada 5 min
  if (millis() - lastSend > 300000 && WiFi.status() == WL_CONNECTED) {
    lastSend = millis();
    sendToThingSpeak();
  }

  // LCD rotativo a cada 4s
  if (millis() - lastLcd > 4000) {
    lastLcd = millis();
    screen = (screen + 1) % 5;
    lcd.clear();
    switch (screen) {
      case 0:
        lcd.printf("T:%.1f%cC U:%.0f%%", temp, 223, hum);
        lcd.setCursor(0,1); lcd.print(alert ? "ALERTA!" : "Normal");
        break;
      case 1:
        lcd.print("ANVISA RDC 301");
        lcd.setCursor(0,1); lcd.print("T:15-25 U:40-70");
        break;
      case 2:
        lcd.print("AC Auto:");
        lcd.setCursor(0,1);
        lcd.print(acEnabled ? (acLigado ? "ATIVO-Ligado" : "ATIVO-Deslig.") : "INATIVO");
        break;
      case 3:
        if (WiFi.status() == WL_CONNECTED) {
          lcd.print("vansan.local");
          lcd.setCursor(0,1); lcd.print(WiFi.localIP());
        } else {
          lcd.print("AP: VANSAN-CFG");
          lcd.setCursor(0,1); lcd.print("192.168.4.1");
        }
        break;
      case 4:
        if (timeSync && getLocalTime(&timeinfo)) {
          lcd.printf("%02d/%02d/%04d", timeinfo.tm_mday, timeinfo.tm_mon+1, timeinfo.tm_year+1900);
          lcd.setCursor(0,1);
          lcd.printf("%02d:%02d:%02d", timeinfo.tm_hour, timeinfo.tm_min, timeinfo.tm_sec);
        } else {
          lcd.print("NTP sincroniz...");
        }
        break;
    }
  }

  delay(10);
}