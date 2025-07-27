#define _GNU_SOURCE
#include <SDL2/SDL.h>
#include <SDL2/SDL_ttf.h>
#include <SDL2/SDL_mixer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <pthread.h>
#include <math.h> // Needed for sin() in sound generation

// --- Platform-specific headers from our previous C scanner ---
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
// #pragma comment directives are not needed as linking is handled in the Makefile
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#endif

// --- Configuration ---
#define SCREEN_WIDTH 800
#define SCREEN_HEIGHT 600
#define DEFAULT_SUBNET "192.168.1." // Fallback subnet
#define INTERNET_CHECK_IP "8.8.8.8" // Google's public DNS for internet check
#define START_HOST 1
#define END_HOST 254
#define NUM_THREADS 50
#define CONNECT_TIMEOUT_MS 200
#define MONITOR_INTERVAL_S 5
#define PING_FAIL_THRESHOLD 3
#define SAMPLE_RATE 44100 // For audio generation
#define FONT_SIZE 14 // Reduced font size
#define NUM_STARS 500 // Number of stars for the background activity indicator

// --- Layout Defines for Tabulation ---
#define COLUMN_STATUS_ICON_X 15
#define COLUMN_IP_ADDR_X 45
#define COLUMN_HOSTNAME_X 280      // FIX: Pushed further right for better spacing
#define COLUMN_STATUS_TEXT_X 620   // Kept the same as per request

const int COMMON_PORTS[] = {21, 22, 23, 80, 443, 445, 3389, 8080};
const int NUM_COMMON_PORTS = sizeof(COMMON_PORTS) / sizeof(COMMON_PORTS[0]);

// --- Enums and Structs ---
typedef enum {
    STATUS_SCANNING,
    STATUS_UP,
    STATUS_UNSTABLE,
    STATUS_DOWN
} HostStatus;

typedef struct {
    char ip[16];
    char hostname[256]; // Field for resolved hostname
    HostStatus status;
    int consecutive_failures;
    float flash_timer; // For status change animation
} MonitoredHost;

typedef struct {
    int start_host;
    int end_host;
    char subnet[16]; // Pass the detected subnet to each thread
} DiscoveryThreadArgs;

typedef struct {
    float x, y, z;
} Star;


// --- Globals ---
SDL_Window* window = NULL;
SDL_Renderer* renderer = NULL;
TTF_Font* font = NULL;
Mix_Chunk* alert_sound = NULL;

MonitoredHost* discovered_hosts = NULL;
int discovered_hosts_count = 0;
int discovered_hosts_capacity = 0;
bool discovery_complete = false;
Star stars[NUM_STARS];
char active_subnet[16] = ""; // Store the detected subnet globally for display

pthread_mutex_t host_list_mutex;
volatile bool app_is_running = true; // FIX: Global flag for graceful thread shutdown

// --- Function Prototypes ---
bool init_sdl();
void init_stars();
bool load_media();
void create_alert_sound();
void cleanup();
void* network_thread_main(void* arg);
bool check_port(const char* ip, int port);
int compare_hosts(const void* a, const void* b);
void render_text(const char* text, int x, int y, SDL_Color color);
void update_and_render_stars();
bool get_local_ip_and_subnet(char* subnet_buffer, size_t buffer_size);


// --- Main Application ---
int main(int argc, char* argv[]) {
    // Check for command-line argument for the subnet
    if (argc > 1) {
        // Basic validation: ensure it's a reasonable length and ends with a dot
        size_t len = strlen(argv[1]);
        if (len > 0 && len < 16 && argv[1][len - 1] == '.') {
            strncpy(active_subnet, argv[1], sizeof(active_subnet) - 1);
            printf("Using user-provided subnet: %s\n", active_subnet);
        } else {
            printf("Invalid subnet format provided: '%s'. It should be like '192.168.1.'\n", argv[1]);
            return 1;
        }
    }


#ifdef _WIN32
    WSADATA wsaData;
    int wsa_res = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsa_res != 0) {
        printf("WSAStartup failed: %d\n", wsa_res);
        return 1;
    }
#endif

    if (!init_sdl() || !load_media()) {
        cleanup();
        return 1;
    }

    init_stars();
    pthread_mutex_init(&host_list_mutex, NULL);

    pthread_t network_thread;
    if (pthread_create(&network_thread, NULL, network_thread_main, NULL) != 0) {
        printf("Failed to create network thread!\n");
        cleanup();
        return 1;
    }

    SDL_Event e;

    while (app_is_running) {
        while (SDL_PollEvent(&e) != 0) {
            if (e.type == SDL_QUIT) {
                app_is_running = false; // Signal threads to exit
            }
        }

        // --- Rendering ---
        SDL_SetRenderDrawColor(renderer, 20, 30, 40, 255); // Dark blue background
        SDL_RenderClear(renderer);

        update_and_render_stars();

        pthread_mutex_lock(&host_list_mutex);

        int y_offset = 10;
        char buffer[128];
        SDL_Color white = {255, 255, 255, 255};
        SDL_Color gray = {150, 150, 150, 255};
        SDL_Color green = {34, 197, 94, 255};
        SDL_Color amber = {245, 158, 11, 255};
        SDL_Color red = {239, 68, 68, 255};

        int online_count = 0, unstable_count = 0, down_count = 0;
        for (int i = 0; i < discovered_hosts_count; i++) {
            if (strcmp(discovered_hosts[i].ip, INTERNET_CHECK_IP) == 0) continue; // Don't include internet in summary
            if (discovered_hosts[i].status == STATUS_UP) online_count++;
            else if (discovered_hosts[i].status == STATUS_UNSTABLE) unstable_count++;
            else if (discovered_hosts[i].status == STATUS_DOWN) down_count++;
        }

        if (!discovery_complete) {
            snprintf(buffer, sizeof(buffer), "Discovering on %s0/24...", active_subnet);
        } else {
            snprintf(buffer, sizeof(buffer), "Monitoring %d hosts on %s0/24", discovered_hosts_count, active_subnet);
        }
        render_text(buffer, 10, y_offset, white);
        y_offset += FONT_SIZE + 5;

        // Render live summary
        snprintf(buffer, sizeof(buffer), "Online: %d", online_count);
        render_text(buffer, 10, y_offset, green);
        snprintf(buffer, sizeof(buffer), "Unstable: %d", unstable_count);
        render_text(buffer, 180, y_offset, amber); 
        snprintf(buffer, sizeof(buffer), "Down: %d", down_count);
        render_text(buffer, 350, y_offset, red); 
        y_offset += FONT_SIZE + 15;

        // Render column headers
        render_text("IP Address", COLUMN_IP_ADDR_X, y_offset, gray);
        render_text("Hostname", COLUMN_HOSTNAME_X, y_offset, gray);
        render_text("Status", COLUMN_STATUS_TEXT_X, y_offset, gray);
        y_offset += FONT_SIZE + 5;

        // Render each host
        for (int i = 0; i < discovered_hosts_count; i++) {
            SDL_Rect status_rect = {COLUMN_STATUS_ICON_X, y_offset, FONT_SIZE - 2, FONT_SIZE - 2};
            char status_desc[50];
            const char* status_text;
            SDL_Color status_color;

            switch (discovered_hosts[i].status) {
                case STATUS_UP:
                    status_color = green;
                    status_text = "Online";
                    break;
                case STATUS_UNSTABLE:
                    status_color = amber;
                    snprintf(status_desc, sizeof(status_desc), "Unstable (%d)", discovered_hosts[i].consecutive_failures);
                    status_text = status_desc;
                    break;
                case STATUS_DOWN:
                    status_color = red;
                    status_text = "DOWN";
                    break;
                default:
                    status_color = (SDL_Color){59, 130, 246, 255}; // Blue
                    status_text = "Scanning...";
                    break;
            }
            SDL_SetRenderDrawColor(renderer, status_color.r, status_color.g, status_color.b, 255);
            SDL_RenderFillRect(renderer, &status_rect);

            // Render text columns
            render_text(discovered_hosts[i].ip, COLUMN_IP_ADDR_X, y_offset, white);
            render_text(discovered_hosts[i].hostname, COLUMN_HOSTNAME_X, y_offset, white);
            render_text(status_text, COLUMN_STATUS_TEXT_X, y_offset, white);

            // Render flash effect on status change
            if (discovered_hosts[i].flash_timer > 0) {
                SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_BLEND);
                SDL_SetRenderDrawColor(renderer, status_color.r, status_color.g, status_color.b, (Uint8)(discovered_hosts[i].flash_timer * 100));
                SDL_Rect flash_rect = {0, y_offset - 2, SCREEN_WIDTH, FONT_SIZE + 4};
                SDL_RenderFillRect(renderer, &flash_rect);
                SDL_SetRenderDrawBlendMode(renderer, SDL_BLENDMODE_NONE);
                discovered_hosts[i].flash_timer -= 0.05f; // Decrease timer
            }

            y_offset += FONT_SIZE + 4;
        }
        pthread_mutex_unlock(&host_list_mutex);

        SDL_RenderPresent(renderer);
        SDL_Delay(16);
    }

    // FIX: Wait for the network thread to finish cleanly instead of cancelling it
    printf("Shutting down network thread...\n");
    pthread_join(network_thread, NULL);
    printf("Network thread joined. Exiting.\n");

    cleanup();
    return 0;
}

// --- Networking Thread Logic ---
void add_host_to_list(const char* ip, const char* hostname_override) {
    pthread_mutex_lock(&host_list_mutex);
    for (int i = 0; i < discovered_hosts_count; i++) {
        if (strcmp(discovered_hosts[i].ip, ip) == 0) {
            pthread_mutex_unlock(&host_list_mutex);
            return;
        }
    }

    if (discovered_hosts_count >= discovered_hosts_capacity) {
        discovered_hosts_capacity = (discovered_hosts_capacity == 0) ? 10 : discovered_hosts_capacity * 2;
        discovered_hosts = realloc(discovered_hosts, discovered_hosts_capacity * sizeof(MonitoredHost));
    }

    int index = discovered_hosts_count;
    strncpy(discovered_hosts[index].ip, ip, 15);
    discovered_hosts[index].ip[15] = '\0';
    discovered_hosts[index].status = STATUS_UP;
    discovered_hosts[index].consecutive_failures = 0;
    discovered_hosts[index].flash_timer = 1.0f; // Flash on discovery

    if (hostname_override) {
        strncpy(discovered_hosts[index].hostname, hostname_override, sizeof(discovered_hosts[index].hostname) - 1);
    } else {
        struct sockaddr_in sa;
        sa.sin_family = AF_INET;
        inet_pton(AF_INET, ip, &sa.sin_addr);
        if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), discovered_hosts[index].hostname, sizeof(discovered_hosts[index].hostname), NULL, 0, 0) != 0) {
            strcpy(discovered_hosts[index].hostname, "N/A");
        }
    }

    discovered_hosts_count++;
    
    pthread_mutex_unlock(&host_list_mutex);
}

void* discovery_worker(void* arg) {
    DiscoveryThreadArgs* args = (DiscoveryThreadArgs*)arg;
    for (int i = args->start_host; i <= args->end_host; i++) {
        if (!app_is_running) break; // Allow early exit
        char ip[16];
        snprintf(ip, sizeof(ip), "%s%d", args->subnet, i);
        for (int p = 0; p < NUM_COMMON_PORTS; p++) {
            if (check_port(ip, COMMON_PORTS[p])) {
                add_host_to_list(ip, NULL);
                break; 
            }
        }
    }
    free(args);
    return NULL;
}

void* network_thread_main(void* arg) {
    (void)arg;

    // --- Phase 1: Detect Subnet and Discover Hosts ---
    if (strlen(active_subnet) == 0) {
        if (!get_local_ip_and_subnet(active_subnet, sizeof(active_subnet))) {
            printf("Could not detect local subnet. Falling back to %s0/24\n", DEFAULT_SUBNET);
            strncpy(active_subnet, DEFAULT_SUBNET, sizeof(active_subnet) - 1);
        } else {
            printf("Detected local subnet. Scanning %s0/24\n", active_subnet);
        }
    }

    pthread_t threads[NUM_THREADS];
    int hosts_per_thread = (END_HOST - START_HOST + 1) / NUM_THREADS;

    for (int i = 0; i < NUM_THREADS; i++) {
        DiscoveryThreadArgs* args = malloc(sizeof(DiscoveryThreadArgs));
        strncpy(args->subnet, active_subnet, sizeof(args->subnet));
        args->start_host = START_HOST + (i * hosts_per_thread);
        args->end_host = (i == NUM_THREADS - 1) ? END_HOST : args->start_host + hosts_per_thread - 1;

        if (pthread_create(&threads[i], NULL, discovery_worker, args) != 0) {
            perror("Failed to create discovery thread");
            free(args);
        }
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }
    
    // --- Add Internet Check and Sort ---
    add_host_to_list(INTERNET_CHECK_IP, "INTERNET");
    pthread_mutex_lock(&host_list_mutex);
    qsort(discovered_hosts, discovered_hosts_count, sizeof(MonitoredHost), compare_hosts);
    pthread_mutex_unlock(&host_list_mutex);

    discovery_complete = true;

    // --- Phase 2: Monitoring ---
    while (app_is_running) { // FIX: Check the global running flag
        pthread_mutex_lock(&host_list_mutex);
        for (int i = 0; i < discovered_hosts_count; i++) {
            bool is_online = false;
            for (int p = 0; p < NUM_COMMON_PORTS; p++) {
                if (check_port(discovered_hosts[i].ip, COMMON_PORTS[p])) {
                    is_online = true;
                    break;
                }
            }

            HostStatus old_status = discovered_hosts[i].status;
            if (is_online) {
                discovered_hosts[i].status = STATUS_UP;
                discovered_hosts[i].consecutive_failures = 0;
            } else {
                discovered_hosts[i].consecutive_failures++;
                if (discovered_hosts[i].consecutive_failures >= PING_FAIL_THRESHOLD) {
                    if (discovered_hosts[i].status != STATUS_DOWN) {
                        Mix_PlayChannel(-1, alert_sound, 0);
                    }
                    discovered_hosts[i].status = STATUS_DOWN;
                } else {
                    discovered_hosts[i].status = STATUS_UNSTABLE;
                }
            }
            if (old_status != discovered_hosts[i].status) {
                discovered_hosts[i].flash_timer = 1.0f;
            }
        }
        pthread_mutex_unlock(&host_list_mutex);
        
        // Sleep for the interval, but check the running flag periodically for faster shutdown
        for (int i = 0; i < MONITOR_INTERVAL_S * 10; i++) {
            if (!app_is_running) break;
#ifdef _WIN32
            Sleep(100);
#else
            usleep(100000);
#endif
        }
    }
    return NULL;
}


// --- SDL and System Functions ---
bool init_sdl() {
    if (SDL_Init(SDL_INIT_VIDEO | SDL_INIT_AUDIO) < 0) return false;
    if (TTF_Init() == -1) return false;
    if (Mix_OpenAudio(SAMPLE_RATE, MIX_DEFAULT_FORMAT, 2, 2048) < 0) return false;
    window = SDL_CreateWindow("Network Host Monitor", SDL_WINDOWPOS_CENTERED, SDL_WINDOWPOS_CENTERED, SCREEN_WIDTH, SCREEN_HEIGHT, SDL_WINDOW_SHOWN);
    if (!window) return false;
    renderer = SDL_CreateRenderer(window, -1, SDL_RENDERER_ACCELERATED);
    if (!renderer) return false;
    return true;
}

void create_alert_sound() {
    int sound_len = SAMPLE_RATE / 4;
    Sint16* data = malloc(sound_len * sizeof(Sint16));
    if (!data) return;

    for (int i = 0; i < sound_len; ++i) {
        double time = (double)i / SAMPLE_RATE;
        if (time < 0.1) data[i] = (Sint16)(4000 * sin(2.0 * M_PI * 880.0 * time));
        else if (time < 0.15) data[i] = 0;
        else data[i] = (Sint16)(4000 * sin(2.0 * M_PI * 660.0 * time));
    }

    alert_sound = Mix_QuickLoad_RAW((Uint8*)data, sound_len * sizeof(Sint16));
    free(data);
}

bool load_media() {
    font = TTF_OpenFont("font.ttf", FONT_SIZE);
    if (!font) {
        printf("Failed to load font! TTF_Error: %s\nPlease provide 'font.ttf'.\n", TTF_GetError());
        return false;
    }
    create_alert_sound();
    if (!alert_sound) return false;
    return true;
}

void cleanup() {
    free(discovered_hosts);
    if (alert_sound) Mix_FreeChunk(alert_sound);
    if (font) TTF_CloseFont(font);
    if (renderer) SDL_DestroyRenderer(renderer);
    if (window) SDL_DestroyWindow(window);
    Mix_Quit();
    TTF_Quit();
    SDL_Quit();

#ifdef _WIN32
    WSACleanup();
#endif
}

// --- Utility Functions ---
void init_stars() {
    for (int i = 0; i < NUM_STARS; i++) {
        stars[i].x = (rand() % SCREEN_WIDTH) - (SCREEN_WIDTH / 2);
        stars[i].y = (rand() % SCREEN_HEIGHT) - (SCREEN_HEIGHT / 2);
        stars[i].z = rand() % (SCREEN_WIDTH / 2);
    }
}

void update_and_render_stars() {
    for (int i = 0; i < NUM_STARS; i++) {
        stars[i].z -= 0.5f;

        if (stars[i].z <= 0) {
            stars[i].x = (rand() % SCREEN_WIDTH) - (SCREEN_WIDTH / 2);
            stars[i].y = (rand() % SCREEN_HEIGHT) - (SCREEN_HEIGHT / 2);
            stars[i].z = (SCREEN_WIDTH / 2);
        }

        float k = 128.0f / stars[i].z;
        int sx = (int)(stars[i].x * k + SCREEN_WIDTH / 2);
        int sy = (int)(stars[i].y * k + SCREEN_HEIGHT / 2);

        if (sx > 0 && sx < SCREEN_WIDTH && sy > 0 && sy < SCREEN_HEIGHT) {
            float size = (1.0f - stars[i].z / (SCREEN_WIDTH / 2.0f)) * 3.0f;
            Uint8 color = (Uint8)((1.0f - stars[i].z / (SCREEN_WIDTH / 2.0f)) * 150);
            SDL_SetRenderDrawColor(renderer, color, color, color, 255);
            SDL_Rect star_rect = {sx, sy, (int)size, (int)size};
            SDL_RenderFillRect(renderer, &star_rect);
        }
    }
}


void render_text(const char* text, int x, int y, SDL_Color color) {
    SDL_Surface* surface = TTF_RenderText_Blended(font, text, color);
    SDL_Texture* texture = SDL_CreateTextureFromSurface(renderer, surface);
    SDL_Rect rect = {x, y, surface->w, surface->h};
    SDL_RenderCopy(renderer, texture, NULL, &rect);
    SDL_FreeSurface(surface);
    SDL_DestroyTexture(texture);
}

int compare_hosts(const void* a, const void* b) {
    const MonitoredHost* host_a = (const MonitoredHost*)a;
    const MonitoredHost* host_b = (const MonitoredHost*)b;
    // Special case for INTERNET to always be at the bottom
    if (strcmp(host_a->hostname, "INTERNET") == 0) return 1;
    if (strcmp(host_b->hostname, "INTERNET") == 0) return -1;
    
    // Convert full IP to integer for proper sorting
    struct in_addr addr_a, addr_b;
    inet_pton(AF_INET, host_a->ip, &addr_a);
    inet_pton(AF_INET, host_b->ip, &addr_b);

    if (addr_a.s_addr < addr_b.s_addr) return -1;
    if (addr_a.s_addr > addr_b.s_addr) return 1;
    return 0;
}

// --- Dynamic Subnet Detection ---
bool get_local_ip_and_subnet(char* subnet_buffer, size_t buffer_size) {
#ifdef _WIN32
    PIP_ADAPTER_ADDRESSES pAddresses = NULL;
    ULONG outBufLen = 15000;
    DWORD dwRetVal = 0;
    char ipstringbuffer[48];

    pAddresses = (IP_ADAPTER_ADDRESSES*)malloc(outBufLen);
    if (!pAddresses) return false;

    dwRetVal = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_PREFIX, NULL, pAddresses, &outBufLen);
    if (dwRetVal == NO_ERROR) {
        for (PIP_ADAPTER_ADDRESSES pCurrAddresses = pAddresses; pCurrAddresses != NULL; pCurrAddresses = pCurrAddresses->Next) {
            if (pCurrAddresses->IfType == IF_TYPE_ETHERNET_CSMACD || pCurrAddresses->IfType == IF_TYPE_IEEE80211) {
                if (pCurrAddresses->FirstUnicastAddress != NULL) {
                    LPSOCKADDR sockaddr_ip = pCurrAddresses->FirstUnicastAddress->Address.lpSockaddr;
                    if (sockaddr_ip->sa_family == AF_INET) {
                        struct sockaddr_in* addr_in = (struct sockaddr_in*)sockaddr_ip;
                        inet_ntop(AF_INET, &addr_in->sin_addr, ipstringbuffer, sizeof(ipstringbuffer));
                        char* last_dot = strrchr(ipstringbuffer, '.');
                        if (last_dot) {
                            size_t subnet_len = last_dot - ipstringbuffer + 1;
                            if (subnet_len < buffer_size) {
                                strncpy(subnet_buffer, ipstringbuffer, subnet_len);
                                subnet_buffer[subnet_len] = '\0';
                                free(pAddresses);
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    free(pAddresses);
    return false;
#else // Linux/macOS
    struct ifaddrs *ifaddr, *ifa;
    char host[NI_MAXHOST];

    if (getifaddrs(&ifaddr) == -1) return false;

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_INET) continue;
        
        if (strncmp(ifa->ifa_name, "en", 2) == 0 || strncmp(ifa->ifa_name, "eth", 3) == 0 || strncmp(ifa->ifa_name, "wl", 2) == 0) {
            if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) == 0) {
                char* last_dot = strrchr(host, '.');
                if (last_dot) {
                    size_t subnet_len = last_dot - host + 1;
                    if (subnet_len < buffer_size) {
                        strncpy(subnet_buffer, host, subnet_len);
                        subnet_buffer[subnet_len] = '\0';
                        freeifaddrs(ifaddr);
                        return true;
                    }
                }
            }
        }
    }
    freeifaddrs(ifaddr);
    return false;
#endif
}


// --- Networking Logic (from previous scanner) ---
bool check_port(const char* ip, int port) {
    int sock;
    struct sockaddr_in server_addr;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return false;

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server_addr.sin_addr);

#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) { closesocket(sock); return false; }
#else
    if (fcntl(sock, F_SETFL, O_NONBLOCK) < 0) { close(sock); return false; }
#endif

    connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr));
    
    fd_set fdset;
    struct timeval tv;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);
    tv.tv_sec = 0;
    tv.tv_usec = CONNECT_TIMEOUT_MS * 1000;

    if (select(sock + 1, NULL, &fdset, NULL, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof(so_error);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, (char*)&so_error, &len);
#ifdef _WIN32
        closesocket(sock);
#else
        close(sock);
#endif
        return so_error == 0;
    }

#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    return false;
}
