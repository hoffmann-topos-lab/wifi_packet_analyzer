#include <M5StickCPlus.h>
#include <WiFi.h>
#include <vector>
extern "C" {
  #include "esp_wifi.h"
  #include "esp_wifi_types.h"
}

//#################################### Variáveis e definições globais ##################################

//Estrutura para salvar informações dos dispositivos deauth atacantes
struct DetectedDevice {
    std::string macAddress;
    int rssi;
    int deauthCount;
    unsigned long lastDeauthTime;

    DetectedDevice(const std::string& mac, int signalStrength, int count, unsigned long time)
        : macAddress(mac), rssi(signalStrength), deauthCount(count), lastDeauthTime(time) {}
};


//Estrutura para salvar informações dos probe requests
struct ProbeRequestInfo {
    String senderMac;
    String receiverMac;
    String ssid;
    int rssi;
};


//Estrutura para salvar informações dos beacon frames
struct BeaconInfo {
    String macAddress;
    int rssi;
    String ssid;
    String dataRates;
    String channel;
    String security;
    std::vector<uint8_t> rawBeaconData;
};

std::vector<DetectedDevice> detectedDeauthDevices; // Lista de dispositivos Deauth detectados
std::vector<ProbeRequestInfo> detectedProbeDevices; // Lista de Probe Requests detectados
std::vector<BeaconInfo> detectedBeaconDevices; // Lista de Beacons detectados

// Variáveis para controle do menu
int menuIndex = 0; // Índice da opção do menu selecionada
const int menuSize = 2; // Número de opções no menu
bool detecting = false; // Flag para controlar o estado da detecção

// Variáveis globais para controle do submenu
bool inSubmenu = false;
int submenuIndex = 0; // Índice da seleção no submenu

int deauthCount = 0; // Contador para pacotes de desautenticação

bool beaconDetectionEnabled = false;
bool probeDetectionEnabled = false; 
bool deauthDetectionEnabled = false;

bool inDeauthSubmenu = false;
bool inProbeSubmenu = false;
bool inBeaconSubmenu = false;
int secondLevelMenuIndex = 0;  // Índice para navegação dentro dos submenus de segundo nível
bool interruptDetection = false;


int deauthDeviceListIndex = 0;
int probeDeviceListIndex = 0;
int beaconDeviceListIndex = 0;

bool inDeviceDetails = false;  // Indica se estamos visualizando os detalhes de um dispositivo
int secondMenuIndex = 0; // Índice para navegar no submenu "Detected Devices"


static unsigned long lastDeauthAttackTime = 0; // Mantém o registro do último momento em que um ataque de deauth foi detectado
static int probeDisplayPositionY = 15; // Define a posição Y inicial para a mensagem de probe
static int beaconDisplayPositionY = 30; // Define a posição Y para a mensagem de beacon
static size_t lastProbeRequestCount = 0;
static size_t lastBeaconCount = 0;
static size_t lastDeauthCount = 0;
unsigned long lastResetTime = 0;

//################################################ Funções #############################################


//################## Display de Menus ###############

//Display do menu principal
void displayMenu() {
  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 0);

  // Opção para iniciar a detecção de desautenticação
  M5.Lcd.setTextColor(menuIndex == 0 ? GREEN : WHITE);
  M5.Lcd.println("1. Deauth Attack Detection");

  // Opção para iniciar a detecção de beacons
  M5.Lcd.setTextColor(menuIndex == 1 ? GREEN : WHITE);
  M5.Lcd.println("2. Beacon Sniffing");

  // Opção para iniciar a detecção de probe requests
  M5.Lcd.setTextColor(menuIndex == 2 ? GREEN : WHITE);
  M5.Lcd.println("3. Probe Sniffing");

  // Opção para visualizar dispositivos detectados
  M5.Lcd.setTextColor(menuIndex == 3 ? GREEN : WHITE);
  M5.Lcd.println("4. Detected Devices");
}

//Display do submenu
void displaySecondLevelMenu(int index) {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);

    // Opção "Deauth Devices"
    M5.Lcd.setTextColor(index == 0 ? GREEN : WHITE);
    M5.Lcd.println("1. Deauth Devices");

    // Opção "Probe Devices"
    M5.Lcd.setTextColor(index == 1 ? GREEN : WHITE);
    M5.Lcd.println("2. Probe Devices");

    // Opção "Beacon Devices"
    M5.Lcd.setTextColor(index == 2 ? GREEN : WHITE);
    M5.Lcd.println("3. Beacon Devices");

    // Opção "Back"
    M5.Lcd.setTextColor(index == 3 ? GREEN : WHITE);
    M5.Lcd.println("4. Back");
}


//Função para escrever mensagens no display
void displayMessage(const char* message, int line) {
  if (line == 0) {
    M5.Lcd.fillScreen(BLACK);
  }
  M5.Lcd.setCursor(0, line * 15); // Posiciona a mensagem na linha especificada
  M5.Lcd.println(message);
}
//############################################################################################################

//####### Funções de navegação do menu ############
//Função que define os botões para navegação no menu principal e lógica dos submenus
void navigateMenu() {
    M5.update(); // Atualiza o estado dos botões

    // Se estiver em modo de detecção, permite sair pressionando o botão B
    if (detecting) {
        if (M5.BtnB.wasPressed()) {
            detecting = false; // Desativa o modo de detecção
            probeDetectionEnabled = false; // Desativa a detecção de probe requests
            beaconDetectionEnabled = false; // Desativa a detecção de beacons
            deauthDetectionEnabled = false; // Desativa a detecção de deauth
            esp_wifi_set_promiscuous(false); // Desativa o modo promíscuo
            displayMenu(); // Retorna ao menu principal
            return; // Sai da função para evitar mais processamento
        }
    }

    // Navegação no menu principal
    if (!inSubmenu) {
        if (M5.BtnA.wasPressed()) {
            menuIndex = (menuIndex + 1) % 4; // Navegação circular no menu principal
            displayMenu(); // Atualiza o display com a opção selecionada
        }

        if (M5.BtnB.wasPressed()) {
            switch (menuIndex) {
                case 0: 
                    startDeauthDetection();
                    detecting = true; // Ativa o modo de detecção para Deauth
                    break;
                case 1: 
                    beaconSniffing();
                    detecting = true; // Ativa o modo de detecção para Beacon
                    break;
                case 2: 
                    probeSniffing();
                    detecting = true; // Ativa o modo de detecção para Probe
                    break;
                case 3: 
                    showDetectedDevicesMenu(); // Entra no submenu "Detected Devices"
                    break;
            }
        }
    }
}

void navigateDetectedDevicesMenu() {
    M5.update();

    if (M5.BtnA.wasPressed()) {
        secondMenuIndex = (secondMenuIndex + 1) % 4; // Existem 4 opções
        displaySecondLevelMenu(secondMenuIndex);
    }

    if (M5.BtnB.wasPressed()) {
        switch (secondMenuIndex) {
            case 0:
                inDeauthSubmenu = true;
                inProbeSubmenu = false;
                inBeaconSubmenu = false;
                displayDeauthDeviceList();
                break;
            case 1:
                inProbeSubmenu = true;
                inDeauthSubmenu = false;
                inBeaconSubmenu = false;
                displayProbeDeviceList();
                break;
            case 2:
                inBeaconSubmenu = true;
                inDeauthSubmenu = false;
                inProbeSubmenu = false;
                displayBeaconDeviceList();
                break;
            case 3:
                inSubmenu = false;
                displayMenu();
                break;
        }
    }
}

void displayDeauthDeviceList() {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("Deauth Devices:");

    int start = deauthDeviceListIndex / 4 * 4;
    int end = min(start + 4, static_cast<int>(detectedDeauthDevices.size()));
    for (int i = start; i < end; i++) {
        M5.Lcd.setTextColor(i == deauthDeviceListIndex ? GREEN : WHITE);
        M5.Lcd.printf("%d. MAC: %s\n", i + 1, detectedDeauthDevices[i].macAddress.c_str());
    }

    // Adicionando a opção "Back" ao final da lista
    M5.Lcd.setTextColor(deauthDeviceListIndex == end ? GREEN : WHITE);
    M5.Lcd.println("Back");
}

void navigateDeauthDevicesMenu() {
    M5.update();

    int totalOptions = detectedDeauthDevices.size() + 1; // Inclui a opção "Back"
    
    if (M5.BtnA.wasPressed()) {
        deauthDeviceListIndex = (deauthDeviceListIndex + 1) % totalOptions;
        displayDeauthDeviceList();
    }

    if (M5.BtnB.wasPressed()) {
        if (deauthDeviceListIndex < detectedDeauthDevices.size()) {
            displayDeauthDeviceDetails(deauthDeviceListIndex);
        } else {
            // Lógica para "Back"
            resetSubmenuStates();
            displayMenu();
        }
    }
}


void displayProbeDeviceList() {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("Probe Devices:");

    int start = probeDeviceListIndex / 4 * 4;
    int end = min(start + 4, static_cast<int>(detectedProbeDevices.size()));
    for (int i = start; i < end; i++) {
        M5.Lcd.setTextColor(i == probeDeviceListIndex ? GREEN : WHITE);
        M5.Lcd.printf("%d. Sender MAC: %s\n", i + 1, detectedProbeDevices[i].senderMac.c_str());
    }

    // Adicionando a opção "Back" ao final da lista
    M5.Lcd.setTextColor(probeDeviceListIndex == end ? GREEN : WHITE);
    M5.Lcd.println("Back");
}


void navigateProbeDevicesMenu() {
    M5.update();

    int totalOptions = detectedProbeDevices.size() + 1; // Inclui a opção "Back"
    
    if (M5.BtnA.wasPressed()) {
        probeDeviceListIndex = (probeDeviceListIndex + 1) % totalOptions;
        displayProbeDeviceList();
    }

    if (M5.BtnB.wasPressed()) {
        if (probeDeviceListIndex < detectedProbeDevices.size()) {
            displayProbeDeviceDetails(probeDeviceListIndex);
        } else {
            // Lógica para "Back"
            resetSubmenuStates();
            displayMenu();
        }
    }
}


void displayBeaconDeviceList() {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.println("Beacon Devices:");

    int start = beaconDeviceListIndex / 4 * 4;
    int end = min(start + 4, static_cast<int>(detectedBeaconDevices.size()));
    for (int i = start; i < end; i++) {
        M5.Lcd.setTextColor(i == beaconDeviceListIndex ? GREEN : WHITE);
        M5.Lcd.printf("%d. SSID: %s\n", i + 1, detectedBeaconDevices[i].ssid.c_str());
    }

    // Adicionando a opção "Back" ao final da lista
    M5.Lcd.setTextColor(beaconDeviceListIndex == end ? GREEN : WHITE);
    M5.Lcd.println("Back");
}


void navigateBeaconDevicesMenu() {
    M5.update();

    int totalOptions = detectedBeaconDevices.size() + 1; // Inclui a opção "Back"
    
    if (M5.BtnA.wasPressed()) {
        beaconDeviceListIndex = (beaconDeviceListIndex + 1) % totalOptions;
        displayBeaconDeviceList();
    }

    if (M5.BtnB.wasPressed()) {
        if (beaconDeviceListIndex < detectedBeaconDevices.size()) {
            displayBeaconDeviceDetails(beaconDeviceListIndex);
        } else {
            // Lógica para "Back"
            resetSubmenuStates();
            displayMenu();
        }
    }
}


void showDetectedDevicesMenu() {
    inSubmenu = true; // Entrando no submenu "Detected Devices"
    secondMenuIndex = 0; // Reseta o índice para a primeira opção do submenu
    displaySecondLevelMenu(secondMenuIndex); // Exibe o submenu "Detected Devices"
}

void resetSubmenuStates() {
    inDeauthSubmenu = inProbeSubmenu = inBeaconSubmenu = false;
    inSubmenu = true;
    displaySecondLevelMenu(secondMenuIndex); // Volta a exibir o submenu de dispositivos detectados.
}

//Função para mostrar as informações dos dispositivos atacantes
void showDetectedDevices() {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);

    if (detectedDeauthDevices.empty()) {
        M5.Lcd.println("No devices detected");
        delay(2000); // Dá tempo para ler a mensagem
        displayMenu(); // Volta ao menu principal
    } else {
        M5.Lcd.println("Detected Devices:");
        for (size_t i = 0; i < detectedDeauthDevices.size() && i < 5; ++i) { // Limita a exibição aos primeiros 5 dispositivos
            M5.Lcd.printf("%d. MAC: %s\n", i + 1, detectedDeauthDevices[i].macAddress.c_str());
        }
        inSubmenu = true; // Garante que o estado do submenu esteja ativo
    }
}

void displayDeauthDeviceDetails(int deviceIndex) {
    if (deviceIndex < detectedDeauthDevices.size()) {
        const DetectedDevice& device = detectedDeauthDevices[deviceIndex];
        M5.Lcd.fillScreen(BLACK);
        M5.Lcd.setCursor(0, 0);
        M5.Lcd.printf("MAC: %s\n", device.macAddress.c_str());
        M5.Lcd.printf("RSSI: %d\n", device.rssi);
        M5.Lcd.printf("Deauth Count: %d\n", device.deauthCount);
        // Aguarda interação para voltar
        while (!M5.BtnB.wasPressed()) {
            M5.update();
            delay(100);
        }
    }
}


void displayProbeDeviceDetails(int deviceIndex) {
    if (deviceIndex < detectedProbeDevices.size()) {
        const ProbeRequestInfo& device = detectedProbeDevices[deviceIndex];
        M5.Lcd.fillScreen(BLACK);
        M5.Lcd.setCursor(0, 0);
        M5.Lcd.printf("Sender MAC: %s\n", device.senderMac.c_str()); // Mostra o MAC do remetente
        M5.Lcd.printf("Receiver MAC: %s\n", device.receiverMac.c_str()); // Mostra o MAC do receptor
        M5.Lcd.printf("SSID: %s\n", device.ssid.c_str());
        M5.Lcd.printf("RSSI: %d\n", device.rssi);

        // Aguarda interação para voltar
        while (!M5.BtnB.wasPressed()) {
            M5.update();
            delay(100);
        }
    }
}


void displayBeaconDeviceDetails(int deviceIndex) {
    if (deviceIndex < detectedBeaconDevices.size()) {
        const BeaconInfo& device = detectedBeaconDevices[deviceIndex];
        int page = 0;

        auto displayPage = [&]() {
            M5.Lcd.fillScreen(BLACK);
            M5.Lcd.setCursor(0, 0);

            switch (page) {
                case 0:
                    M5.Lcd.printf("MAC: %s\n", device.macAddress.c_str());
                    M5.Lcd.printf("RSSI: %d\n", device.rssi);
                    M5.Lcd.printf("SSID: %s\n", device.ssid.c_str());
                    M5.Lcd.setTextColor(GREEN);
                    M5.Lcd.printf("Press M5 for more info");
                    M5.Lcd.setTextColor(WHITE);
                    break;
                case 1:
                    M5.Lcd.printf("Data Rates: %s\n", device.dataRates.c_str());
                    M5.Lcd.printf("Channel: %s\n", device.channel.c_str());
                    M5.Lcd.setTextColor(GREEN);
                    M5.Lcd.printf("Press M5 for more info");
                    M5.Lcd.setTextColor(WHITE);
                    break;
                case 2:
                    M5.Lcd.printf("Security: %s\n", device.security.c_str());
                    M5.Lcd.setTextColor(GREEN);
                    M5.Lcd.printf("Press both buttons to quit");
                    M5.Lcd.setTextColor(WHITE);
                    break;
            }
        };

        displayPage(); // Exibe a primeira página

        while (true) {
            M5.update();
            if (M5.BtnA.wasPressed()) {
                page = (page + 1) % 3; // Assumindo 3 páginas no total
                displayPage();
            }
            if (M5.BtnB.wasPressed()) {
                // Simplesmente sai do loop, permitindo retornar à lista
                break;
            }
        }
    }
}



//########################### Funções Para Detecção ##############################################

//########### Deauth attacks ##################

void startDeauthDetection() {

  M5.Lcd.fillScreen(BLACK);
  M5.Lcd.setCursor(0, 0);
  displayMessage("Starting Deauth Detector...", 0);
  delay(2000);

  WiFi.mode(WIFI_STA);
  WiFi.disconnect();

  displayMessage("Starting Promiscuous Mode", 0);
  delay(2000);

  if (esp_wifi_set_promiscuous(true) != ESP_OK) {
    handleError("Error: Promiscuous Mode falled");
  }

  if (esp_wifi_set_promiscuous_rx_cb(snifferCallback) != ESP_OK) {
    handleError("Error: Callback falled");
  }

  displayMessage("Monitoring Deauth Attacks..", 0);
  deauthDetectionEnabled = true;
}

void snifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) {
        return;
    }

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t*)buf;
    const uint8_t *frame = pkt->payload;
    const uint16_t frameControl = *((uint16_t*)frame);
    uint8_t frameType = (frameControl & 0x0C) >> 2;
    uint8_t frameSubType = (frameControl & 0xF0) >> 4;

    // Filtra apenas pacotes de desautenticação
    if (frameType == 0x00 && frameSubType == 0x0C) {
        char addr[18];
        snprintf(addr, sizeof(addr), "%02x:%02x:%02x:%02x:%02x:%02x",
                 frame[10], frame[11], frame[12], frame[13], frame[14], frame[15]);
        std::string macStr(addr);
        int rssi = pkt->rx_ctrl.rssi;
        unsigned long currentTime = millis();

        auto it = std::find_if(detectedDeauthDevices.begin(), detectedDeauthDevices.end(),
                               [&macStr](const DetectedDevice& d) { return d.macAddress == macStr; });

        if (it != detectedDeauthDevices.end()) {
            // Atualiza o dispositivo existente se necessário
            if ((currentTime - it->lastDeauthTime) < 10000) {
                it->deauthCount++;
                it->lastDeauthTime = currentTime;
                if (it->deauthCount == 5) {
                    displayDeauthAttackDetected(*it);
                }
            } else {
                it->deauthCount = 1;
                it->lastDeauthTime = currentTime;
            }
        } else {
            // Adiciona um novo dispositivo se não encontrado
            detectedDeauthDevices.push_back(DetectedDevice(macStr, rssi, 1, currentTime));
        }
    } 
}


void displayDeauthAttackDetected(const DetectedDevice& device) {
    M5.Lcd.fillScreen(BLACK);
    M5.Lcd.setCursor(0, 0);
    M5.Lcd.printf("Attack Detected from %s\n", device.macAddress.c_str());
    beep(1500); // Sinal sonoro indicando detecção
}


//############ Probe requests #################
void probeSniffing() {
    displayMessage("Starting Probe Sniffing...", 0);
  delay(2000);
    startPromiscuousMode(probeSnifferCallback);
    displayMessage("Sniffing Probes...", 0);
    probeDetectionEnabled = true;
}

void probeSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* frame = pkt->payload;
    size_t frameLength = pkt->rx_ctrl.sig_len;

    const uint16_t frameControl = *((uint16_t*)frame);
    uint8_t frameType = (frameControl & 0x0C) >> 2;
    uint8_t frameSubType = (frameControl & 0xF0) >> 4;

    if (frameType == 0x00 && frameSubType == 0x04) { // Probe Request
        const uint8_t* senderMac = frame + 10; // Endereço MAC do remetente
        const uint8_t* receiverMac = frame; // Endereço MAC do destinatário está no início do frame

        analyzeProbeRequest(senderMac, receiverMac, frame + 24, frameLength - 24, pkt->rx_ctrl.rssi);
    }
}



void analyzeProbeRequest(const uint8_t* senderMac, const uint8_t* receiverMac, const uint8_t* payload, uint16_t payloadLength, int rssi) {
    String senderMacAddress = getMacAddressAsString(senderMac);
    String receiverMacAddress = getMacAddressAsString(receiverMac); // Supondo que já tenhamos o receiverMac como argumento
    String ssid = extractSSIDFromProbe(payload, payloadLength); // Ajuste conforme necessário

    // Verifica se já existe uma entrada com o mesmo sender MAC Address e SSID
    auto it = std::find_if(detectedProbeDevices.begin(), detectedProbeDevices.end(),
                           [&senderMacAddress, &ssid](const ProbeRequestInfo& info) {
                               return info.senderMac == senderMacAddress && info.ssid == ssid;
                           });

    // Se não encontrar uma entrada duplicada, adiciona a nova informação
    if (it == detectedProbeDevices.end()) {
        ProbeRequestInfo newInfo = {
            senderMacAddress,
            receiverMacAddress,
            ssid,
            rssi
        };
        detectedProbeDevices.push_back(newInfo);

        // Limita o vetor a armazenar apenas os últimos registros para economizar memória
        while (detectedProbeDevices.size() > 15) {
            detectedProbeDevices.erase(detectedProbeDevices.begin());
        }
    } else {
        // Opcional: Atualize os dados existentes se quiser manter as informações mais recentes
        it->rssi = rssi;
    }
}


 //##################

 //################## beacon frames ######################

 void beaconSniffing() {

    displayMessage("Starting Beacon Sniffing...", 0);
    delay(2000);
    startPromiscuousMode(beaconSnifferCallback); 
    displayMessage("Sniffing Beacons...", 0);
    beaconDetectionEnabled = true; 

}

void beaconSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t* pkt = (wifi_promiscuous_pkt_t*)buf;
    const uint8_t* frame = pkt->payload;
    size_t frameLength = pkt->rx_ctrl.sig_len;

    const uint16_t frameControl = *((uint16_t*)frame);
    uint8_t frameType = (frameControl & 0x0C) >> 2;
    uint8_t frameSubType = (frameControl & 0xF0) >> 4;

    if (frameType == 0x00 && frameSubType == 0x08) { // Beacon Frame
        const uint8_t* macStart = frame + 10; // Supondo formato sem endereçamento de 4 endereços
        analyzeBeaconFrame(macStart, frame, frameLength, pkt->rx_ctrl.rssi);
    }
}

void processBeaconInfo(BeaconInfo& beacon) {
    beacon.ssid = extractSSID(beacon.rawBeaconData.data(), beacon.rawBeaconData.size());
    beacon.dataRates = getDataRates(beacon.rawBeaconData.data(), beacon.rawBeaconData.size());
    beacon.channel = getChannel(beacon.rawBeaconData.data(), beacon.rawBeaconData.size());
    beacon.security = getSecurity(beacon.rawBeaconData.data(), beacon.rawBeaconData.size());
}


void analyzeBeaconFrame(const uint8_t* macStart, const uint8_t* payload, uint16_t payloadLength, int rssi) {
    String macAddress = getMacAddressAsString(macStart);
    BeaconInfo newInfo;
    newInfo.macAddress = macAddress;
    newInfo.rssi = rssi;
    newInfo.ssid = extractSSID(payload, payloadLength);
    newInfo.dataRates = getDataRates(payload, payloadLength);
    newInfo.channel = getChannel(payload, payloadLength);
    newInfo.security = getSecurity(payload, payloadLength);
    
    // Adicione newInfo ao vetor detectedBeaconDevices somente se não existir
    auto it = std::find_if(detectedBeaconDevices.begin(), detectedBeaconDevices.end(),
                           [&macAddress](const BeaconInfo& device) {
                               return device.macAddress == macAddress;
                           });
    if (it == detectedBeaconDevices.end()) {
        detectedBeaconDevices.push_back(newInfo);
    }
}

//#####################################################################################


//################################# Funções Auxiliares ################################

//Função para emitir um sinal sonoro
void beep(int duration) {
  ledcWriteTone(0, 2000); // Liga o tom
  delay(duration);
  ledcWriteTone(0, 0); // Desliga o tom
}

//Função para lidar com erros
void handleError(const char* errorMsg) {
  displayMessage(errorMsg, 0);
  delay(5000); // Dá tempo para o usuário ler a mensagem
  ESP.restart(); // Reinicia o dispositivo
}

void resetCountersIfNeeded(DetectedDevice& device) {
    unsigned long currentTime = millis();
    unsigned long resetInterval = 60000; // 60 segundos, por exemplo

    // Para desautenticação
    if (currentTime - device.lastDeauthTime> resetInterval) {
        device.deauthCount = 0;
        device.lastDeauthTime = currentTime;
    }
}

//Função para iniciar o modo promiscuo
void startPromiscuousMode(wifi_promiscuous_cb_t cb) {

    displayMessage("Starting Promiscuous Mode", 0);
    delay(2000);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    if (esp_wifi_set_promiscuous(true) != ESP_OK) {
        handleError("Error: Promiscuous Mode failed");
    }

    if (esp_wifi_set_promiscuous_rx_cb(cb) != ESP_OK) {
        handleError("Error: Callback failed");
    }
}
// Função para extrair o endereço MAC do dispositivo como string
String getMacAddressAsString(const uint8_t* mac) {
    char macStr[18];
    snprintf(macStr, sizeof(macStr), "%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return String(macStr);
}

// Função para extrair o SSID de um pacote beacon
String extractSSID(const uint8_t* payload, size_t length) {
    const int SSID_ELEMENT_ID = 0;
    const size_t offset = 36; // Ajuste conforme necessário baseado na estrutura específica do seu pacote
    String ssid = "SSID Não Encontrado";
    size_t i = offset;

    while (i + 1 < length) {
        uint8_t elementID = payload[i];
        uint8_t len = payload[i + 1];

        if (i + 2 + len > length) {
            break;
        }

        if (elementID == SSID_ELEMENT_ID) {
            ssid = len > 0 ? String(reinterpret_cast<const char*>(payload + i + 2), len) : "SSID Oculto";
            break;
        }

        i += 2 + len;
    }

    return ssid;
}

// Função para extrair a taxa de dados de um pacote beacon
String getDataRates(const uint8_t* payload, size_t length) {
    String dataRates = "";
    const int SUPPORTED_RATES_ID = 1;
    const int EXT_SUPPORTED_RATES_ID = 50;


    // O índice 'i' começa de 0, então vamos percorrer o payload.
    size_t i = 36;  // Pulando cabeçalho do beacon, endereços MAC, e campos fixos para começar direto no SSID.
    while (i + 1 < length) {
        uint8_t elementID = payload[i];
        uint8_t len = payload[i + 1];

        // Avançar para além do SSID e seus campos para chegar às taxas de dados.
        if (elementID == SUPPORTED_RATES_ID) {
            for (int j = 0; j < len && (i + 2 + j) < length; ++j) {
                float rate = (payload[i + 2 + j] & 0x7F) * 0.5;

                if (!dataRates.isEmpty()) {
                    dataRates += ", ";
                }
                dataRates += String(rate, 1) + " Mbps";
            }
            i += 2 + len;  // Ajusta 'i' após processar as taxas de dados.
            break;  // Após encontrar e processar as taxas, podemos sair do loop.
        } else {
            // Avança para o próximo elemento se não for o de taxas de dados suportadas.
            i += 2 + len;
        }
    }

    return dataRates.isEmpty() ? "Nenhuma taxa de dados disponível" : dataRates;
}


// Função para determinar o canal de um pacote beacon
String getChannel(const uint8_t* payload, size_t length) {
    const int DS_PARAM_SET_ID = 3;

    // Definindo um ponto de início após o cabeçalho fixo do beacon (24 bytes) e alguns elementos iniciais esperados.
    size_t startIdx = 36;  // Um índice que pula o cabeçalho e o SSID, por exemplo.
    bool dsParamFound = false;
    uint8_t channel = 0;

    // Buscando por DS Parameter Set ID dentro de um intervalo razoável após o início esperado dos elementos.
    for (size_t i = startIdx; i + 1 < length && i < startIdx + 100; i++) {  // Limita a busca para evitar excessos.
        uint8_t elementID = payload[i];
        uint8_t len = payload[i + 1];

        // Validando a existência do DS Parameter Set.
        if (elementID == DS_PARAM_SET_ID && len == 1) {
            channel = payload[i + 2];
            dsParamFound = true;
            break;
        }
    }

    if (dsParamFound) {

        return String(int(channel));
    } else {

        return "Unknown";
    }
}



// Função para determinar o tipo de criptografia de um pacote beacon
String getSecurity(const uint8_t* payload, size_t length) {


    // Supondo que o índice inicial seja após o cabeçalho fixo do beacon
    size_t index = 36; // Ajuste este valor conforme necessário para pular os cabeçalhos

    const int RSN_ID = 48;
    const int VENDOR_SPECIFIC_ID = 221;
    bool isWPA2 = false, isWPA = false, isWEP = true;  // Assume WEP by default

    while (index < length) {
        uint8_t elementID = payload[index];
        uint8_t len = payload[index + 1];

        if (elementID == RSN_ID) {
            isWPA2 = true;
            isWEP = false;
            break; // Encontrou WPA2, não precisa procurar mais
        } else if (elementID == VENDOR_SPECIFIC_ID && len >= 4) {
            // Verifica se os primeiros bytes correspondem ao OUI da WPA
            if (payload[index + 2] == 0x00 && payload[index + 3] == 0x50 && payload[index + 4] == 0xF2) {
                isWPA = true;
                isWEP = false;
                break; // Encontrou WPA, não precisa procurar mais
            }
        }

        index += len + 2; // Avança para o próximo elemento
    }

    if (isWPA2) return "WPA2";
    if (isWPA) return "WPA";
    return  "Open/WEP"; // Se não encontrar nada, assume aberto ou WEP
}

String extractSSIDFromProbe(const uint8_t* payload, size_t length) {
    const uint8_t SSID_ELEMENT_ID = 0; // Element ID para SSID
    Serial.println("Iniciando extração do SSID...");

    for (size_t i = 0; i < length;) {
        uint8_t elementID = payload[i];
        uint8_t len = payload[i + 1];



        if (elementID == SSID_ELEMENT_ID) {
            if (len == 0) {
                return "SSID Oculto";
            }

            String ssid = String(reinterpret_cast<const char*>(payload + i + 2), len);

            return ssid;
        }

        i += 2 + len; // Avança para o próximo elemento
    }


    return "SSID Não Encontrado";
}

String getReceiverMacAddress(const uint8_t* frame) {
    return getMacAddressAsString(frame); // Supondo que `getMacAddressAsString` esteja implementada corretamente
}

void updateDetectionDisplays() {

        // Verifica se o modo de sniffing de probe requests está ativo antes de verificar novos pacotes
    if (detecting && probeDetectionEnabled) {
        size_t currentProbeRequestCount = detectedProbeDevices.size(); // Obtém o número atual de probe requests únicos

        // Verifica se um novo probe request único foi detectado
        if (currentProbeRequestCount != lastProbeRequestCount) {
            M5.Lcd.fillRect(0, probeDisplayPositionY, 320, 15, BLACK); // Limpa a área da mensagem anterior
            M5.Lcd.setCursor(0, probeDisplayPositionY);
            M5.Lcd.printf("Unique Probes: %d\n", currentProbeRequestCount);

            lastProbeRequestCount = currentProbeRequestCount; // Atualiza o contador para a próxima verificação
        }
    }

    // Verifica se o modo de sniffing de beacons está ativo antes de verificar novos beacons
    if (detecting && beaconDetectionEnabled) {
        size_t currentBeaconCount = detectedBeaconDevices.size(); // Obtém o número atual de beacons únicos

        // Verifica se um novo beacon único foi detectado
        if (currentBeaconCount != lastBeaconCount) {
            M5.Lcd.fillRect(0, beaconDisplayPositionY, 320, 15, BLACK); // Limpa a área da mensagem anterior
            M5.Lcd.setCursor(0, beaconDisplayPositionY);
            M5.Lcd.printf("Unique Beacons: %d\n", currentBeaconCount);

            lastBeaconCount = currentBeaconCount; // Atualiza o contador para a próxima verificação
        }
    }
}


//#####################################################################################


//############################## Setup e Loop #########################################

void setup() {
  M5.begin();
  M5.Lcd.setRotation(3);
  M5.Lcd.setTextSize(2);
  Serial.begin(115200);


  ledcAttachPin(0, 0); // Associa o canal PWM ao pino GPIO 0 (altere conforme a sua conexão)
  ledcSetup(0, 2000, 8); // Configura o canal PWM 0 para uma frequência de 2000 Hz e 8 bits de resolução
  displayMenu(); // Exibe o menu inicial em vez de iniciar diretamente a detecção
}

void loop() {
    
    if (!inSubmenu) {
        navigateMenu(); // Navegação no menu principal.
    } else {
        // Essas verificações agora são mutuamente exclusivas.
        if (inDeauthSubmenu) {
            navigateDeauthDevicesMenu();
        } else if (inProbeSubmenu) {
            navigateProbeDevicesMenu();
        } else if (inBeaconSubmenu) {
            navigateBeaconDevicesMenu();
        } else {
            navigateDetectedDevicesMenu();
        }
    }
    // Chama updateDetectionDisplays apenas se beaconDetectionEnabled ou probeDetectionEnabled estiverem ativos
    if (beaconDetectionEnabled || probeDetectionEnabled) {
        updateDetectionDisplays();
    }
    
    delay(100); // Delay para debouncing dos botões.
}

