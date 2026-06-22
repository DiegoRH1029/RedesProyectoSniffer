#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace std;

// Estructura para guardar los paquetes en memoria y poder analizarlos después
struct PaqueteCapturado {
    int id;
    struct pcap_pkthdr header;
    vector<u_char> data;
    string src_ip;
    string dst_ip;
    string protocol;
    int src_port;
    int dst_port;
};

// Variables globales
vector<PaqueteCapturado> historial_paquetes;
int contador_paquetes = 0;

// FUNCION CALLBACK: Llena el AREA 1 y guarda en memoria 
void packet_handler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet);

// AREA 2: Información Estructurada
void mostrar_area_2(PaqueteCapturado &p);

// FUNCION AREA 3: Contenido RAW
void mostrar_area_3(PaqueteCapturado &p);

// Funcion para exportar a csv
void exportar_csv();

int main() {
    pcap_if_t *alldevs, *d;
    pcap_t *adhandle;
    char errbuf[PCAP_ERRBUF_SIZE];
    int inum, i = 0;

    cout << "******************************************\n";
    cout << "* PACKET SNIFFER - REDES          *\n";
    cout << "******************************************\n\n";

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return -1;

    for (d = alldevs; d != NULL; d = d->next) {
        printf("%d. %s", ++i, d->name);
        if (d->description) printf(" (%s)\n", d->description); else printf("\n");
    }

    if (i==0) return -1;

    cout << "\nSelecciona la interfaz de red (1-" << i << "): ";
    cin >> inum;

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

    if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf)) == NULL) return -1;
    pcap_freealldevs(alldevs);

    // --- MENU DE FILTROS---
    int opc_filtro;
    string filtro_str;
    cout << "\n--- TIPOS DE FILTRO DISPONIBLES ---\n";
    cout << "1. Solo trafico TCP\n";
    cout << "2. Solo trafico UDP\n";
    cout << "3. Filtrar por Puerto (Ej. 80, 443)\n";
    cout << "4. Filtrar por IP de Origen\n";
    cout << "Elige un filtro (1-4): ";
    cin >> opc_filtro;

    if (opc_filtro == 1) filtro_str = "tcp";
    else if (opc_filtro == 2) filtro_str = "udp";
    else if (opc_filtro == 3) {
        string puerto;
        cout << "Ingresa el puerto a filtrar: ";
        cin >> puerto;
        filtro_str = "port " + puerto;
    } 
    else if (opc_filtro == 4) {
        string ip;
        cout << "Ingresa la IP de origen (Ej. 192.168.1.5): ";
        cin >> ip;
        filtro_str = "src host " + ip;
    } else filtro_str = "tcp"; // Default

    struct bpf_program fcode;
    if (pcap_compile(adhandle, &fcode, filtro_str.c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0 || pcap_setfilter(adhandle, &fcode) < 0) {
        cout << "Error al compilar/aplicar filtro.\n";
        return -1;
    }

    // CAPTURA DE PAQUETES (AREA 1)
    cout << "\n--- AREA 1: TRAFICO CAPTURADO ---\n";
    cout << "Capturando 5 paquetes con el filtro: '" << filtro_str << "'...\n\n";
    
    // Captura exactamente 5 paquetes y luego se detiene solo
    pcap_loop(adhandle, 5, packet_handler, NULL);
    pcap_close(adhandle);

    exportar_csv();

    // MENU INTERACTIVO (AREAS 2 y 3)
    int pkt_seleccionado;
    do {
        cout << "\nIngresa el numero de ID del paquete para inspeccionar (1-5) o 0 para SALIR: ";
        cin >> pkt_seleccionado;

        if (pkt_seleccionado>0 && pkt_seleccionado<=15) {
            mostrar_area_2(historial_paquetes[pkt_seleccionado-1]);
            mostrar_area_3(historial_paquetes[pkt_seleccionado-1]);
        }
    } while (pkt_seleccionado != 0);

    cout << "\nSaliendo del Packet Sniffer.\n";
    return 0;
}

//FUNCIONES
void exportar_csv() {
    ofstream archivo("sniffer_resultados.csv");
    archivo << "ID,Protocolo,IP_Origen,Puerto_Origen,IP_Destino,Puerto_Destino,Longitud\n";
    for (auto &p : historial_paquetes) {
        archivo << p.id <<","<<p.protocol<<","<<p.src_ip<<","<< p.src_port<<","<<p.dst_ip<<","<< p.dst_port<<","<<p.header.len << "\n";
    }
    archivo.close();
    cout << "\n[+] Trafico exportado exitosamente a 'sniffer_resultados.csv'.\n";
}

// FUNCIONES
void packet_handler(u_char *args,const struct pcap_pkthdr *header,const u_char *packet) {
    contador_paquetes++;
    PaqueteCapturado p;
    p.id = contador_paquetes;
    p.header = *header;
    p.data = vector<u_char>(packet, packet + header->caplen);
    p.protocol = "Otro";
    p.src_port = 0;
    p.dst_port = 0;

    struct ip *ip_header = (struct ip*)(packet + 14);
    p.src_ip = inet_ntoa(ip_header->ip_src);
    p.dst_ip = inet_ntoa(ip_header->ip_dst);

    if (ip_header->ip_p == IPPROTO_TCP) {
        p.protocol = "TCP";
        int ip_len = ip_header->ip_hl * 4;
        struct tcphdr *tcp_header = (struct tcphdr*)(packet + 14 + ip_len);
        p.src_port = ntohs(tcp_header->source);
        p.dst_port = ntohs(tcp_header->dest);
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        p.protocol = "UDP";
        int ip_len = ip_header->ip_hl * 4;
        struct udphdr *udp_header = (struct udphdr*)(packet + 14 + ip_len);
        p.src_port = ntohs(udp_header->source);
        p.dst_port = ntohs(udp_header->dest);
    }

    historial_paquetes.push_back(p);

    // AREA 1
    printf("[Paquete %02d] | %-4s | SRC: %-15s (P: %-5d) -> DST: %-15s (P: %-5d) | Len: %d bytes\n", 
           p.id, p.protocol.c_str(), p.src_ip.c_str(), p.src_port, p.dst_ip.c_str(), p.dst_port, header->len);
}

// AREA 2
void mostrar_area_2(PaqueteCapturado &p) {
    cout << "\n=======================================================\n";
    cout << "  AREA 2: INFORMACION ESTRUCTURADA DEL PAQUETE #" << p.id << "\n";
    cout << "=======================================================\n";
    
    struct ether_header *eth = (struct ether_header*)p.data.data();
    cout << "[Capa 2 - Enlace] Ethernet\n";
    printf("  MAC Destino: %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2], eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);
    printf("  MAC Origen : %02x:%02x:%02x:%02x:%02x:%02x\n", eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2], eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);

    struct ip *ip_h = (struct ip*)(p.data.data() + 14);
    cout<< "\n[Capa 3 - Red] IPv4\n";
    cout<< "  IP Origen  : " << p.src_ip << "\n";
    cout<< "  IP Destino : " << p.dst_ip << "\n";
    cout << "  TTL        : " << (int)ip_h->ip_ttl<<"\n";
    cout<< "  ID         : " << ntohs(ip_h->ip_id)<<"\n";

    cout << "\n[Capa 4 - Transporte] " << p.protocol<<"\n";
    if (p.protocol != "Otro") {
        cout << "  Puerto Origen  : " << p.src_port<<"\n";
        cout << "  Puerto Destino : " << p.dst_port<<"\n";
    }
}

// Contenido RAW (Hexadecimal) ---
void mostrar_area_3(PaqueteCapturado &p) {
    cout << "\n=======================================================\n";
    cout << "  AREA 3: CONTENIDO RAW (HEXADECIMAL) DEL PAQUETE #" << p.id << "\n";
    cout << "=======================================================\n";
    
    for (size_t i=0; i<p.data.size(); i++) {
        printf("%02X ", p.data[i]);
        if ((i + 1) % 16 == 0) cout << "\n"; // Salto de lInea cada 16 bytes
    }
    cout << "\n=======================================================\n";
}