#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "esp_netif.h"
#include "esp_http_server.h"
#include "esp_mac.h"

// ==========================================
// 核心：乙太網與網路層 API (ESP-IDF v6)
// ==========================================
#include "esp_eth.h"
#include "esp_eth_mac_esp.h"
#include "esp_eth_phy_lan87xx.h"

// ==========================================
// 核心：BTstack BNEP/PAN 協議棧
// ==========================================
#include "btstack.h"
#include "classic/bnep.h"
#include "classic/pan.h"

extern void btstack_init(void);
extern void btstack_run_loop_execute(void);

static const char *TAG = "BRIDGE_GATEWAY";

// 硬體引腳定義: WT32-ETH01 (LAN8720)
#define ETH_PHY_ADDR        1
#define ETH_PHY_RST_GPIO    16
#define ETH_MDC_GPIO        23
#define ETH_MDIO_GPIO       18

// ==========================================
// 全局全域變數與動態配置結構
// ==========================================
esp_eth_handle_t eth_handle = NULL;
esp_netif_t *eth_netif = NULL;
uint8_t esp32_eth_mac[6] = {0}; // 本機乙太網 MAC

// 藍牙運行時參數（由 NVS 載入）
char g_bt_name[33] = "Ethernet Bridge"; // 預設藍牙廣播名稱
uint32_t g_bt_cod = 0x7A020C;
uint8_t g_bt_mac[6] = {0x04, 0xB2, 0x47, 0x97, 0x4A, 0x32};

// 防火牆名單控制
uint8_t g_filter_mode = 0;       // 0: 白名單模式, 1: 黑名單模式
uint8_t g_filter_macs[20][6];    // 最多支援 20 個控制 MAC
int g_filter_mac_count = 0;

// 藍牙連接狀態
static uint8_t active_phone_mac[6] = {0}; 
static bool is_phone_connected = false;   
static uint16_t current_bnep_cid = 0;  
static uint8_t pan_nap_sdp_record[200];
static uint16_t network_packet_types[] = { 0x0800, 0x0806, 0x86DD, 0 }; 

// 跨執行緒安全隊列
typedef struct {
    uint8_t *buffer;
    uint32_t length;
} eth_tx_packet_t;

static QueueHandle_t eth_tx_queue;
static btstack_context_callback_registration_t tx_callback_registration;

// ==========================================
// NVS 配置讀寫模組
// ==========================================
// URL 解码函数 (原地解码，将 %3A 还原为冒号等)
static void url_decode(char *str) {
    char *pstr = str, *buf = str;
    while (*pstr) {
        if (*pstr == '%') {
            if (pstr[1] && pstr[2]) {
                int c;
                sscanf(pstr + 1, "%02x", &c);
                *buf++ = (char)c;
                pstr += 3;
            } else {
                *buf++ = *pstr++;
            }
        } else if (*pstr == '+') {
            *buf++ = ' ';
            pstr++;
        } else {
            *buf++ = *pstr++;
        }
    }
    *buf = '\0';
}

void load_settings_from_nvs(void) {
    nvs_handle_t my_handle;
    if (nvs_open("storage", NVS_READONLY, &my_handle) == ESP_OK) {
        size_t required_size = sizeof(g_bt_name);
        nvs_get_str(my_handle, "bt_name", g_bt_name, &required_size);
        nvs_get_u32(my_handle, "bt_cod", &g_bt_cod);
        
        required_size = 6;
        nvs_get_blob(my_handle, "bt_mac", g_bt_mac, &required_size);
        nvs_get_u8(my_handle, "filter_mode", &g_filter_mode);
        
        // 載入解析防火牆清單
        char mac_list_str[256] = {0};
        required_size = sizeof(mac_list_str);
        if (nvs_get_str(my_handle, "mac_list", mac_list_str, &required_size) == ESP_OK) {
            g_filter_mac_count = 0;
            char *token = strtok(mac_list_str, "\n, ");
            while (token != NULL && g_filter_mac_count < 20) {
                int m[6];
                if (sscanf(token, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                    for(int i=0; i<6; i++) g_filter_macs[g_filter_mac_count][i] = (uint8_t)m[i];
                    g_filter_mac_count++;
                }
                token = strtok(NULL, "\n, ");
            }
        }
        nvs_close(my_handle);
        ESP_LOGI(TAG, "⚙️ 成功從 NVS 載入自定義配置！");
    } else {
        ESP_LOGW(TAG, "⚠️ 未發現自定義配置，使用系統預設參數。");
    }
}

// ==========================================
// 安全過濾防火牆驗證
// ==========================================
bool validate_device_access(uint8_t *mac) {
    bool found = false;
    for (int i = 0; i < g_filter_mac_count; i++) {
        if (memcmp(g_filter_macs[i], mac, 6) == 0) {
            found = true;
            break;
        }
    }
    if (g_filter_mode == 0) { // 白名單模式
        return found; // 在清單內才允許連接
    } else { // 黑名單模式
        return !found; // 在清單內就拒絕連接
    }
}

// ==========================================
// 藍牙流控與發送核心
// ==========================================
static void process_tx_queue(void *arg) {
    eth_tx_packet_t pkt;
    while (xQueuePeek(eth_tx_queue, &pkt, 0) == pdTRUE) {
        if (!is_phone_connected) {
            xQueueReceive(eth_tx_queue, &pkt, 0);
            free(pkt.buffer);
            continue;
        }
        if (bnep_can_send_packet_now(current_bnep_cid)) {
            xQueueReceive(eth_tx_queue, &pkt, 0);
            bnep_send(current_bnep_cid, pkt.buffer, pkt.length);
            free(pkt.buffer);
        } else {
            bnep_request_can_send_now_event(current_bnep_cid);
            break; 
        }
    }
}

// ==========================================
// 關鍵：二層分流轉發器 (乙太網 -> LwIP / 藍牙)
// ==========================================
static esp_err_t eth_to_bt_forwarder(esp_eth_handle_t hdl, uint8_t *buffer, uint32_t length, void *priv) {
    uint8_t *dest_mac = buffer;
    
    // 1. 檢查是否是發給 ESP32 本機 Web 伺服器的流量
    bool is_for_esp32 = (memcmp(dest_mac, esp32_eth_mac, 6) == 0);
    bool is_broadcast = (dest_mac[0] == 0xFF && dest_mac[1] == 0xFF && dest_mac[2] == 0xFF && 
                         dest_mac[3] == 0xFF && dest_mac[4] == 0xFF && dest_mac[5] == 0xFF);
    
    uint16_t ethertype = (buffer[12] << 8) | buffer[13];
    bool is_arp = (ethertype == 0x0806);

    // 如果是給 ESP32 的單播，或者非常規 ARP 的通訊協議廣播，直接分流給本機 LwIP 協議棧
    if (is_for_esp32 || (is_broadcast && !is_arp)) {
        // 呼叫 LwIP 的標準接收介面
        esp_netif_receive(eth_netif, buffer, length, NULL);
        return ESP_OK; // 注意：esp_netif_receive 會自行負責內部 free 記憶體
    }

    // 2. 藍牙轉發通道：僅在手機連線且通過過濾時放行
    if (is_phone_connected) {
        bool is_for_phone = (memcmp(dest_mac, active_phone_mac, 6) == 0);
        
        if (is_for_phone || (is_broadcast && is_arp)) {
            eth_tx_packet_t pkt = { .buffer = buffer, .length = length };
            if (xQueueSend(eth_tx_queue, &pkt, 0) == pdTRUE) {
                btstack_run_loop_execute_on_main_thread(&tx_callback_registration);
                return ESP_OK;
            }
        }
    }

    free(buffer); 
    return ESP_OK;
}

// ==========================================
// 藍牙事件與 MAC 學習
// ==========================================
static void bt_packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size) {
    if (packet_type == BNEP_DATA_PACKET) {
        if (memcmp(active_phone_mac, packet + 6, 6) != 0) {
            memcpy(active_phone_mac, packet + 6, 6);
            ESP_LOGI(TAG, "🔄 數據鏈路層學習到手機網卡真實 MAC: %02X:%02X:%02X:%02X:%02X:%02X", 
                     active_phone_mac[0], active_phone_mac[1], active_phone_mac[2], 
                     active_phone_mac[3], active_phone_mac[4], active_phone_mac[5]);
        }
        if (eth_handle != NULL) {
            esp_eth_transmit(eth_handle, packet, size);
        }
    } else if (packet_type == HCI_EVENT_PACKET) {
        uint8_t event_type = hci_event_packet_get_type(packet);
        if (event_type == BNEP_EVENT_CHANNEL_OPENED) {
            uint16_t cid = bnep_event_channel_opened_get_bnep_cid(packet);
            uint8_t remote_mac[6];
            bnep_event_channel_opened_get_remote_address(packet, remote_mac);
            
            // 🛡️ 觸發防火牆防禦機制
            if (!validate_device_access(remote_mac)) {
                ESP_LOGW(TAG, "🔒 安全攔截：MAC %02X:%02X:%02X:%02X:%02X:%02X 未通過安全性驗證，強制斷開！",
                         remote_mac[0], remote_mac[1], remote_mac[2], remote_mac[3], remote_mac[4], remote_mac[5]);
                bnep_disconnect(remote_mac);
                return;
            }

            if (bnep_event_channel_opened_get_status(packet) == ERROR_CODE_SUCCESS) {
                current_bnep_cid = cid;
                memcpy(active_phone_mac, remote_mac, 6);
                is_phone_connected = true;
                ESP_LOGI(TAG, "🟢 藍牙 PAN 通道已安全建立！");
            }
        } else if (event_type == BNEP_EVENT_CHANNEL_CLOSED) {
            is_phone_connected = false;
            memset(active_phone_mac, 0, 6);
            ESP_LOGI(TAG, "🔴 藍牙 PAN 已斷開連線");
        } else if (event_type == BNEP_EVENT_CAN_SEND_NOW) {
            process_tx_queue(NULL);
        }
    }
}

// ==========================================
// Web 網頁後台管理伺服器
// ==========================================
static esp_err_t settings_get_handler(httpd_req_t *req) {
    char reply[2048];
    char current_mac_list[256] = {0};
    nvs_handle_t my_handle;
    
    if (nvs_open("storage", NVS_READONLY, &my_handle) == ESP_OK) {
        size_t req_sz = sizeof(current_mac_list);
        nvs_get_str(my_handle, "mac_list", current_mac_list, &req_sz);
        nvs_close(my_handle);
    }

    // 輸出全繁體中文的管理後台 UI
    snprintf(reply, sizeof(reply),
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"><title>ESP32 藍牙網橋閘道器</title>"
        "<style>body{font-family:sans-serif;margin:40px;background:#f4f6f9;color:#333;}"
        ".card{background:white;padding:30px;border-radius:10px;box-shadow:0 4px 15px rgba(0,0,0,0.05);max-width:600px;margin:auto;}"
        "h2{color:#1a73e8;border-bottom:2px solid #e0e0e0;padding-bottom:10px;}"
        "label{display:block;margin-top:15px;font-weight:bold;}"
        "input[type=text],select,textarea{width:100%%;padding:10px;margin-top:5px;border:1px solid #ccc;border-radius:5px;box-sizing:border-box;}"
        "input[type=submit]{background:#1a73e8;color:white;border:none;padding:12px 20px;margin-top:20px;border-radius:5px;cursor:pointer;font-size:16px;width:100%%;}"
        "input[type=submit]:hover{background:#1557b0;}</style></head><body>"
        "<div class=\"card\"><h2>🌐 藍牙二層網橋配置管理後台</h2>"
        "<form action=\"/save\" method=\"post\">"
        "<label>藍牙廣播名稱：</label><input type=\"text\" name=\"bt_name\" value=\"%s\" max_length=\"32\">"
        "<label>設備類型 (CoD 十六進制)：</label><input type=\"text\" name=\"bt_cod\" value=\"0x%06X\">"
        "<label>自定義藍牙 MAC 位址：</label><input type=\"text\" name=\"bt_mac\" value=\"%02X:%02X:%02X:%02X:%02X:%02X\">"
        "<label>防火牆防禦機制：</label><select name=\"filter_mode\">"
        "<option value=\"0\" %s>白名單模式（僅允許名單內設備連線）</option>"
        "<option value=\"1\" %s>黑名單模式（拒絕名單內設備連線）</option></select>"
        "<label>控制機制對象 MAC 列表 (每行一個)：</label><textarea name=\"mac_list\" rows=\"5\">%s</textarea>"
        "<input type=\"submit\" value=\"儲存配置並重新啟動設備\">"
        "</form></div></body></html>",
        g_bt_name, (unsigned int)g_bt_cod,
        g_bt_mac[0], g_bt_mac[1], g_bt_mac[2], g_bt_mac[3], g_bt_mac[4], g_bt_mac[5],
        g_filter_mode == 0 ? "selected" : "", g_filter_mode == 1 ? "selected" : "", current_mac_list);

    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, reply, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

static esp_err_t settings_post_handler(httpd_req_t *req) {
    char buf[1024] = {0};
    int ret = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (ret <= 0) return ESP_FAIL;

    char name[32] = {0}, cod_str[32] = {0}, mac_str[32] = {0}, mode_str[8] = {0}, raw_list[256] = {0};
    // 簡易的 URL 解碼與欄位分離擷取
    if (httpd_query_key_value(buf, "bt_name", name, sizeof(name)) == ESP_OK &&
        httpd_query_key_value(buf, "bt_cod", cod_str, sizeof(cod_str)) == ESP_OK &&
        httpd_query_key_value(buf, "bt_mac", mac_str, sizeof(mac_str)) == ESP_OK &&
        httpd_query_key_value(buf, "filter_mode", mode_str, sizeof(mode_str)) == ESP_OK) {
        
        httpd_query_key_value(buf, "mac_list", raw_list, sizeof(raw_list));

        url_decode(name);
        url_decode(mac_str);
        url_decode(raw_list);

        nvs_handle_t my_handle;
        if (nvs_open("storage", NVS_READWRITE, &my_handle) == ESP_OK) {
            nvs_set_str(my_handle, "bt_name", name);
            
            uint32_t cod_val = strtoul(cod_str, NULL, 16);
            nvs_set_u32(my_handle, "bt_cod", cod_val);

            int m[6];
            if (sscanf(mac_str, "%x:%x:%x:%x:%x:%x", &m[0], &m[1], &m[2], &m[3], &m[4], &m[5]) == 6) {
                uint8_t bin_mac[6];
                for(int i=0; i<6; i++) bin_mac[i] = (uint8_t)m[i];
                nvs_set_blob(my_handle, "bt_mac", bin_mac, 6);
            }
            
            nvs_set_u8(my_handle, "filter_mode", atoi(mode_str));
            nvs_set_str(my_handle, "mac_list", raw_list);
            nvs_commit(my_handle);
            nvs_close(my_handle);
        }
    }

    const char *success_msg = "<html><head><meta charset=\"utf-8\"></head><body><h2>配置成功！設備正在重新啟動以套用新參數...</h2></body></html>";
    httpd_resp_send(req, success_msg, HTTPD_RESP_USE_STRLEN);
    
    vTaskDelay(pdMS_TO_TICKS(1500));
    esp_restart(); // 重新啟動以重載藍牙底層射頻、MAC 和安全名單
    return ESP_OK;
}

void start_web_server(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;

    if (httpd_start(&server, &config) == ESP_OK) {
        httpd_uri_t get_uri = { .uri = "/", .method = HTTP_GET, .handler = settings_get_handler };
        httpd_register_uri_handler(server, &get_uri);
        httpd_uri_t post_uri = { .uri = "/save", .method = HTTP_POST, .handler = settings_post_handler };
        httpd_register_uri_handler(server, &post_uri);
        ESP_LOGI(TAG, "🚀 嵌入式 HTTP 網頁伺服器啟動成功，監聽 80 埠。");
    }
}

// ==========================================
// 硬體驅動與系統地基初始化
// ==========================================
void init_ethernet_and_lwip(void) {
    // 1. 初始化三層網絡協議棧
    ESP_ERROR_CHECK(esp_netif_init());
    
    // 2. 建立專屬於 LwIP 的預設乙太網 Netif 實例
    esp_netif_config_t cfg = ESP_NETIF_DEFAULT_ETH();
    eth_netif = esp_netif_new(&cfg);

    gpio_set_direction(ETH_PHY_RST_GPIO, GPIO_MODE_OUTPUT);
    gpio_set_level(ETH_PHY_RST_GPIO, 1);
    vTaskDelay(pdMS_TO_TICKS(100));

    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    eth_esp32_emac_config_t esp32_emac_config = ETH_ESP32_EMAC_DEFAULT_CONFIG();
    
    esp32_emac_config.smi_gpio.mdc_num = ETH_MDC_GPIO;
    esp32_emac_config.smi_gpio.mdio_num = ETH_MDIO_GPIO;
    esp32_emac_config.clock_config.rmii.clock_mode = EMAC_CLK_EXT_IN;
    esp32_emac_config.clock_config.rmii.clock_gpio = 0;

    esp_eth_mac_t *mac = esp_eth_mac_new_esp32(&esp32_emac_config, &mac_config);

    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.phy_addr = ETH_PHY_ADDR;
    phy_config.reset_gpio_num = -1; 
    esp_eth_phy_t *phy = esp_eth_phy_new_lan87xx(&phy_config);

    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    ESP_ERROR_CHECK(esp_eth_driver_install(&eth_config, &eth_handle));
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));
    
    // 獲取本機乙太網真實 MAC 地址
    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_G_MAC_ADDR, esp32_eth_mac));
    ESP_LOGI(TAG, "本機乙太網硬體 MAC 地址: %02X:%02X:%02X:%02X:%02X:%02X",
             esp32_eth_mac[0], esp32_eth_mac[1], esp32_eth_mac[2], esp32_eth_mac[3], esp32_eth_mac[4], esp32_eth_mac[5]);

    // 關鍵：將輸入路径掛載到我們的客製化二層分流轉發器上
    ESP_ERROR_CHECK(esp_eth_update_input_path(eth_handle, eth_to_bt_forwarder, NULL));
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));

    bool promisc_mode = true;
    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_PROMISCUOUS, &promisc_mode));
    ESP_LOGI(TAG, "🌐 乙太網驅動加載完畢，全面開啟混雜監聽模式！");
}

void init_btstack_gateway(void) {
    l2cap_init();
    sdp_init();
    
    bnep_init();
    bnep_register_service(&bt_packet_handler, 0x1116, 1691); 
    
    memset(pan_nap_sdp_record, 0, sizeof(pan_nap_sdp_record));
    pan_create_nap_sdp_record(
        pan_nap_sdp_record, 
        0x10001, 
        network_packet_types, 
        g_bt_name, 
        "Ethernet Bridge Gateway", 
        0,                         
        PAN_NET_ACCESS_TYPE_OTHER, 
        1000000,                   
        NULL,                      
        NULL                       
    );
    sdp_register_service(pan_nap_sdp_record);

    // 應用 NVS 讀出的動態配置項
    gap_set_local_name(g_bt_name);
    gap_set_class_of_device(g_bt_cod);
    gap_discoverable_control(1);
    
    hci_power_control(HCI_POWER_ON);
    ESP_LOGI(TAG, "📡 藍牙安全防禦網關初始化成功。當前設備類型: 0x%06X", (unsigned int)g_bt_cod);
}

// 監聽系統網路事件（例如自動獲取到 IP）
static void on_ip_event(void *arg, esp_event_base_t base, int32_t id, void *data) {
    if (id == IP_EVENT_ETH_GOT_IP) {
        ip_event_got_ip_t *event = (ip_event_got_ip_t *)data;
        ESP_LOGI(TAG, "🎉 閘道器已成功獲取自身 IP 地址: " IPSTR ", 請在瀏覽器中輸入此 IP 登入管理後台！", IP2STR(&event->ip_info.ip));
    }
}

void app_main(void) {
    // 1. 初始化 NVS 閃存
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    // 2. 優先載入用戶設定參數
    load_settings_from_nvs();

    // 3. 建立系統默認事件循環並監聽 IP 事件
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    ESP_ERROR_CHECK(esp_event_handler_instance_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &on_ip_event, NULL, NULL));

    // 4. 動態自定義藍牙物理層 MAC (如果有 NVS 記錄)
    uint8_t zero_mac[6] = {0};
    if (memcmp(g_bt_mac, zero_mac, 6) != 0) {
        esp_base_mac_addr_set(g_bt_mac);
    }

    // 5. 初始化安全通信隊列
    eth_tx_queue = xQueueCreate(50, sizeof(eth_tx_packet_t));
    tx_callback_registration.callback = &process_tx_queue;

    ESP_LOGI(TAG, "🚀 === 啟動二三層自適應高防藍牙網橋閘道器 === 🚀");
    
    // 6. 啟動底層網路與 Web 伺服器
    init_ethernet_and_lwip();
    start_web_server();
    
    // 7. 喚醒藍牙協議棧
    btstack_init(); 
    init_btstack_gateway();
    
    ESP_LOGI(TAG, "🔄 核心監聽事件循環已就緒...");
    btstack_run_loop_execute(); 
}