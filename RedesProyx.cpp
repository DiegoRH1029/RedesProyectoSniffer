// ============================================================
//  PACKET SNIFFER  -  PROYECTO REDES I
//  Compilar   : g++ RedesProy2.cpp -o RedesProy2 -lpcap
//  Ejecutar   : sudo ./RedesProy2
// ============================================================

#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <csignal>
#include <ctime>
#include <algorithm>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

using namespace std;


//  Estructura del paquete

struct PaqueteCapturado {
    int            id;
    pcap_pkthdr    header;
    vector<u_char> data;
    string         src_ip;
    string         dst_ip;
    string         protocol;
    int            src_port;
    int            dst_port;
    string         timestamp;
    uint8_t        ttl;
    uint16_t       ip_id;
    uint8_t        tcp_flags;
    uint16_t       checksum;
};


//  Globales

vector<PaqueteCapturado> historial_paquetes;
int     contador_paquetes = 0;
int     limite_captura    = 10;
bool    capturando        = false;
pcap_t *handle_global     = nullptr;
string  interfaz_nombre   = "";
string  filtro_activo     = "ip";

//prototipos
void   packet_handler(u_char*, const pcap_pkthdr*, const u_char*);
void   mostrar_banner();
void   separador(char c = '=', int n = 62);
string flags_tcp_str(uint8_t f);
void   imprimir_linea_area1(const PaqueteCapturado &p);
void   mostrar_area_1_tabla();
void   mostrar_area_2(const PaqueteCapturado &p);
void   mostrar_area_3(const PaqueteCapturado &p);
void   exportar_csv();
string construir_filtro(int opc, const string &v1, const string &v2);
pcap_t* seleccionar_interfaz();
void   flujo_configurar_captura(pcap_t *handle);
void   flujo_iniciar_captura(pcap_t *handle);
void   flujo_inspeccionar_paquetes();
void   flujo_filtrar_capturados();
void   menu_principal(pcap_t *handle);
void   signal_handler(int);


// Ctrl+C   detiene pcap_loop limpiamente
void signal_handler(int) {
    if (capturando && handle_global) {
        cout << "\n[!] Deteniendo captura...\n";
        pcap_breakloop(handle_global);
    }
}


//  Aca estan los helpers visuales

void separador(char c, int n) {
    for (int i = 0; i < n; i++) cout << c;
    cout << "\n";
}

void mostrar_banner() {
    cout << "\033[2J\033[H";   // limpiar pantalla
    separador('*', 62);
    cout << "*       PACKET SNIFFER  -  PROYECTO REDES I              *\n";
    cout << "*       Plataforma: Linux  |  Libreria: libpcap           *\n";
    separador('*', 62);
    if (!interfaz_nombre.empty())
        cout << "  Interfaz : " << interfaz_nombre << "\n";
    if (!filtro_activo.empty())
        cout << "  Filtro   : " << filtro_activo << "\n";
    cout << "  Paquetes capturados: " << historial_paquetes.size() << "\n";
    separador('-', 62);
    cout << "\n";
}

string flags_tcp_str(uint8_t f) {
    string s;
    if (f & 0x02) s += "SYN ";
    if (f & 0x10) s += "ACK ";
    if (f & 0x01) s += "FIN ";
    if (f & 0x04) s += "RST ";
    if (f & 0x08) s += "PSH ";
    if (f & 0x20) s += "URG ";
    return s.empty() ? "NONE" : s;
}

// callback de captura
void packet_handler(u_char*, const pcap_pkthdr *hdr, const u_char *pkt) {
    // Timestamp
    char tbuf[20];
    struct tm *tm_i = localtime(&hdr->ts.tv_sec);
    strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm_i);
    string ts = string(tbuf) + "." + to_string(hdr->ts.tv_usec / 1000);

    contador_paquetes++;
    PaqueteCapturado p;
    p.id        = contador_paquetes;
    p.header    = *hdr;
    p.data      = vector<u_char>(pkt, pkt + hdr->caplen);
    p.protocol  = "Otro";
    p.src_port  = 0;
    p.dst_port  = 0;
    p.tcp_flags = 0;
    p.checksum  = 0;
    p.timestamp = ts;
    p.ttl       = 0;
    p.ip_id     = 0;

    if (hdr->caplen >= 34) {
        struct ip *iph = (struct ip*)(pkt + 14);
        p.src_ip = inet_ntoa(iph->ip_src);
        p.dst_ip = inet_ntoa(iph->ip_dst);
        p.ttl    = iph->ip_ttl;
        p.ip_id  = ntohs(iph->ip_id);
        int ihl  = iph->ip_hl * 4;

        if (iph->ip_p == IPPROTO_TCP) {
            p.protocol = "TCP";
            if (hdr->caplen >= (unsigned)(14 + ihl + 20)) {
                struct tcphdr *th = (struct tcphdr*)(pkt + 14 + ihl);
                p.src_port  = ntohs(th->source);
                p.dst_port  = ntohs(th->dest);
                p.tcp_flags = (uint8_t)th->th_flags;
                p.checksum  = ntohs(th->check);
            }
        } else if (iph->ip_p == IPPROTO_UDP) {
            p.protocol = "UDP";
            if (hdr->caplen >= (unsigned)(14 + ihl + 8)) {
                struct udphdr *uh = (struct udphdr*)(pkt + 14 + ihl);
                p.src_port = ntohs(uh->source);
                p.dst_port = ntohs(uh->dest);
                p.checksum = ntohs(uh->check);
            }
        } else if (iph->ip_p == IPPROTO_ICMP) {
            p.protocol = "ICMP";
        }
    }

    historial_paquetes.push_back(p);
    imprimir_linea_area1(p);
}

//  AREA 1  -  lanea en vivo durante captura
void imprimir_linea_area1(const PaqueteCapturado &p) {
    printf("[%s] #%-3d %-5s  %-15s:%-5d -> %-15s:%-5d  %4u B",
           p.timestamp.c_str(), p.id, p.protocol.c_str(),
           p.src_ip.c_str(),  p.src_port,
           p.dst_ip.c_str(),  p.dst_port,
           p.header.len);
    if (p.protocol == "TCP")
        printf("  [%s]", flags_tcp_str(p.tcp_flags).c_str());
    printf("\n");
}


//  AREA 1  -  tabla resumen completa (despues de la captura)

void mostrar_area_1_tabla() {
    if (historial_paquetes.empty()) {
        cout << "  (No hay paquetes capturados)\n";
        return;
    }
    cout << "\n";
    separador('=', 62);
    cout << "  AREA 1: TABLA RESUMEN DE TRAFICO CAPTURADO\n";
    separador('=', 62);
    printf("  %-3s  %-10s  %-5s  %-15s %-6s  %-15s %-6s  %s\n",
           "ID", "Hora", "Proto",
           "IP Origen", "PtoS",
           "IP Destino", "PtoD", "Bytes");
    separador('-', 62);
    for (auto &p : historial_paquetes) {
        printf("  %-3d  %-10s  %-5s  %-15s %-6d  %-15s %-6d  %u\n",
               p.id, p.timestamp.c_str(), p.protocol.c_str(),
               p.src_ip.c_str(), p.src_port,
               p.dst_ip.c_str(), p.dst_port,
               p.header.len);
    }
    separador('-', 62);
    printf("  Total: %zu paquete(s)\n", historial_paquetes.size());
}


//  AREA 2  -  informacion estructurada por capas

void mostrar_area_2(const PaqueteCapturado &p) {
    cout << "\n";
    separador('=', 62);
    printf("  AREA 2: INFORMACION ESTRUCTURADA  -  Paquete #%d  [%s]\n",
           p.id, p.timestamp.c_str());
    separador('=', 62);

    // Capa 2: Ethernet
    if (p.data.size() >= 14) {
        auto *eth = (const ether_header*)p.data.data();
        cout << "\n[Capa 2 - Enlace] Ethernet\n";
        printf("  MAC Destino : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],
               eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
        printf("  MAC Origen  : %02x:%02x:%02x:%02x:%02x:%02x\n",
               eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],
               eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);
        uint16_t et = ntohs(eth->ether_type);
        printf("  EtherType   : 0x%04X  (%s)\n", et,
               et==0x0800?"IPv4": et==0x0806?"ARP": et==0x86DD?"IPv6":"Otro");
    }

    // Capa 3: IP
    if (p.data.size() >= 34) {
        auto *iph = (const struct ip*)(p.data.data() + 14);
        int ihl = iph->ip_hl * 4;
        uint16_t off = ntohs(iph->ip_off);
        cout << "\n[Capa 3 - Red] IPv4\n";
        printf("  IP Origen    : %s\n",  p.src_ip.c_str());
        printf("  IP Destino   : %s\n",  p.dst_ip.c_str());
        printf("  TTL          : %d\n",  (int)p.ttl);
        printf("  ID           : %u (0x%04X)\n", p.ip_id, p.ip_id);
        printf("  Protocolo    : %d (%s)\n", iph->ip_p, p.protocol.c_str());
        printf("  Long. Total  : %u bytes  (IHL: %d bytes)\n",
               ntohs(iph->ip_len), ihl);
        printf("  Checksum IP  : 0x%04X\n", ntohs(iph->ip_sum));
        printf("  Flags IP     : DF=%d  MF=%d  Offset=%d\n",
               (off&IP_DF)?1:0, (off&IP_MF)?1:0, (int)(off&IP_OFFMASK));

        // Capa 4: TCP
        if (p.protocol == "TCP" &&
            p.data.size() >= (size_t)(14 + ihl + 20)) {
            auto *th = (const tcphdr*)(p.data.data() + 14 + ihl);
            int doff = th->doff * 4;
            cout << "\n[Capa 4 - Transporte] TCP\n";
            printf("  Puerto Origen  : %d\n",   p.src_port);
            printf("  Puerto Destino : %d\n",   p.dst_port);
            printf("  Seq Number     : %u\n",   ntohl(th->seq));
            printf("  Ack Number     : %u\n",   ntohl(th->ack_seq));
            printf("  Header Length  : %d bytes\n", doff);
            printf("  Flags          : 0x%02X  [%s]\n",
                   p.tcp_flags, flags_tcp_str(p.tcp_flags).c_str());
            printf("  Window Size    : %u\n",   ntohs(th->window));
            printf("  Checksum TCP   : 0x%04X\n", p.checksum);
            printf("  Urgent Pointer : %u\n",   ntohs(th->urg_ptr));
            int pay = (int)p.data.size() - (14 + ihl + doff);
            printf("  Payload        : %d bytes\n", pay > 0 ? pay : 0);
        }

        // Capa 4: UDP
        if (p.protocol == "UDP" &&
            p.data.size() >= (size_t)(14 + ihl + 8)) {
            auto *uh = (const udphdr*)(p.data.data() + 14 + ihl);
            cout << "\n[Capa 4 - Transporte] UDP\n";
            printf("  Puerto Origen  : %d\n",  p.src_port);
            printf("  Puerto Destino : %d\n",  p.dst_port);
            printf("  Longitud UDP   : %u bytes\n", ntohs(uh->len));
            printf("  Checksum UDP   : 0x%04X\n", p.checksum);
        }

        // Capa 4: ICMP
        if (p.protocol == "ICMP" &&
            p.data.size() >= (size_t)(14 + ihl + 4)) {
            const u_char *ic = p.data.data() + 14 + ihl;
            cout << "\n[Capa 4 - Transporte] ICMP\n";
            printf("  Tipo   : %u\n", ic[0]);
            printf("  Codigo : %u\n", ic[1]);
        }
    }
    separador('=', 62);
}


//  AREA 3  -  RAW hex + ASCII (estilo Wireshark)

void mostrar_area_3(const PaqueteCapturado &p) {
    cout << "\n";
    separador('=', 62);
    printf("  AREA 3: CONTENIDO RAW (HEX + ASCII)  -  Paquete #%d\n", p.id);
    separador('=', 62);
    printf("  Offset   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F"
           "   ASCII\n");
    separador('-', 62);

    size_t n = p.data.size();
    for (size_t i = 0; i < n; i += 16) {
        printf("  %04zX   ", i);
        for (size_t j = 0; j < 16; j++) {
            if (j == 8) printf(" ");
            if (i+j < n) printf("%02X ", p.data[i+j]);
            else         printf("   ");
        }
        printf("  ");
        for (size_t j = 0; j < 16 && (i+j) < n; j++) {
            unsigned char c = p.data[i+j];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        printf("\n");
    }
    separador('=', 62);
}


//  EXPORTAR CSV

void exportar_csv() {
    if (historial_paquetes.empty()) {
        cout << "  [!] No hay paquetes para exportar.\n";
        return;
    }
    ofstream f("sniffer_resultados.csv");
    f << "ID,Timestamp,Protocolo,IP_Origen,Puerto_Origen,"
         "IP_Destino,Puerto_Destino,TTL,IP_ID,Flags_TCP,Checksum,Longitud\n";
    for (auto &p : historial_paquetes) {
        f << p.id         << ","
          << p.timestamp  << ","
          << p.protocol   << ","
          << p.src_ip     << ","
          << p.src_port   << ","
          << p.dst_ip     << ","
          << p.dst_port   << ","
          << (int)p.ttl   << ","
          << p.ip_id      << ","
          << flags_tcp_str(p.tcp_flags) << ","
          << p.checksum   << ","
          << p.header.len << "\n";
    }
    f.close();
    cout << "\n  [+] Exportado a 'sniffer_resultados.csv'  ("
         << historial_paquetes.size() << " paquetes).\n";
}


//  CONSTRUIR FILTRO BPF

string construir_filtro(int opc, const string &v1, const string &v2) {
    switch (opc) {
        case 1:  return "tcp";
        case 2:  return "udp";
        case 3:  return "icmp";
        case 4:  return "port "     + v1;
        case 5:  return "src host " + v1;
        case 6:  return "dst host " + v1;
        case 7:  return "src port " + v1;
        case 8:  return "dst port " + v1;
        case 9:  return "host "     + v1 + " and port " + v2;
        default: return "ip";
    }
}


//  SELECCIONAR INTERFAZ

pcap_t* seleccionar_interfaz() {
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        cerr << "  Error listando interfaces: " << errbuf << "\n";
        return nullptr;
    }

    int i = 0;
    cout << "  Interfaces de red disponibles:\n";
    separador('-', 40);
    for (d = alldevs; d; d = d->next) {
        printf("  %d. %s", ++i, d->name);
        if (d->description) printf("  (%s)", d->description);
        printf("\n");
    }
    if (i == 0) {
        cerr << "  No se encontraron interfaces. Ejecuta con sudo.\n";
        pcap_freealldevs(alldevs);
        return nullptr;
    }

    int inum;
    cout << "\n  Selecciona interfaz (1-" << i << "): ";
    cin >> inum;
    if (inum < 1 || inum > i) {
        cerr << "  Opcion invalida.\n";
        pcap_freealldevs(alldevs);
        return nullptr;
    }

    for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
    interfaz_nombre = d->name;

    pcap_t *handle = pcap_open_live(d->name, 65536, 1, 1000, errbuf);
    pcap_freealldevs(alldevs);

    if (!handle) {
        cerr << "  No se pudo abrir la interfaz: " << errbuf << "\n";
        return nullptr;
    }
    handle_global = handle;
    cout << "  [+] Interfaz '" << interfaz_nombre << "' abierta.\n";
    return handle;
}


//  FLUJO: configurar filtro y l

void flujo_configurar_captura(pcap_t *handle) {
    cout << "\n";
    separador('-', 62);
    cout << "  CONFIGURAR FILTRO DE CAPTURA\n";
    separador('-', 62);
    cout << "  1. Solo TCP\n";
    cout << "  2. Solo UDP\n";
    cout << "  3. Solo ICMP\n";
    cout << "  4. Puerto especifico (src o dst)\n";
    cout << "  5. IP de Origen\n";
    cout << "  6. IP de Destino\n";
    cout << "  7. Puerto de Origen\n";
    cout << "  8. Puerto de Destino\n";
    cout << "  9. IP + Puerto combinados\n";
    cout << "  0. Sin filtro (todo el trafico IP)\n";
    separador('-', 62);
    cout << "  Elige filtro: ";

    int opc; cin >> opc;
    string v1, v2;

    if (opc == 4 || opc == 7 || opc == 8) {
        cout << "  Puerto: "; cin >> v1;
    } else if (opc == 5 || opc == 6) {
        cout << "  IP (ej. 192.168.1.5): "; cin >> v1;
    } else if (opc == 9) {
        cout << "  IP (ej. 192.168.1.5): "; cin >> v1;
        cout << "  Puerto: ";               cin >> v2;
    }

    filtro_activo = construir_filtro(opc, v1, v2);

    struct bpf_program fcode;
    if (pcap_compile(handle, &fcode, filtro_activo.c_str(), 1,
                     PCAP_NETMASK_UNKNOWN) < 0 ||
        pcap_setfilter(handle, &fcode) < 0) {
        cout << "  [!] Error aplicando filtro. Se usara 'ip'.\n";
        filtro_activo = "ip";
        pcap_compile(handle, &fcode, "ip", 1, PCAP_NETMASK_UNKNOWN);
        pcap_setfilter(handle, &fcode);
    } else {
        cout << "  [+] Filtro aplicado: \"" << filtro_activo << "\"\n";
    }

    cout << "  Cuantos paquetes capturar? (0 = hasta Ctrl+C): ";
    cin >> limite_captura;
    cout << "  [+] Limite: "
         << (limite_captura > 0 ? to_string(limite_captura) : "ilimitado")
         << "\n";
}


//  flujo: iniciar captura

void flujo_iniciar_captura(pcap_t *handle) {
    if (!handle) {
        cout << "  Primero selecciona una interfaz.\n";
        return;
    }

    // Limpiar sesion anterior
    historial_paquetes.clear();
    contador_paquetes = 0;
    capturando = true;

    cout << "\n";
    separador('=', 62);
    cout << "  AREA 1: TRAFICO EN VIVO  |  Filtro: \""
         << filtro_activo << "\"\n";
    if (limite_captura > 0)
        cout << "  Capturando " << limite_captura
             << " paquete(s)... (Ctrl+C para detener antes)\n";
    else
        cout << "  Captura ilimitada... (Ctrl+C para detener)\n";
    separador('=', 62);
    printf("  %-10s %-3s %-5s  %-15s:%-5s -> %-15s:%-5s  %s\n",
           "Hora","ID","Proto","IP Origen","PtoS",
           "IP Destino","PtoD","Bytes");
    separador('-', 62);

    pcap_loop(handle,
              (limite_captura > 0) ? limite_captura : -1,
              packet_handler,
              nullptr);

    capturando = false;
    cout << "\n  [*] Captura detenida. "
         << historial_paquetes.size() << " paquete(s) en memoria.\n";
}


//  flujo: inspeccionar paquete por ID  (areas 2 y 3)

void flujo_inspeccionar_paquetes() {
    if (historial_paquetes.empty()) {
        cout << "  [!] No hay paquetes capturados aun.\n";
        return;
    }

    mostrar_area_1_tabla();

    int total = (int)historial_paquetes.size();
    int sel;
    do {
        cout << "\n  ID a inspeccionar (1-" << total
             << ")  |  0 = volver: ";
        cin >> sel;
        if (sel >= 1 && sel <= total) {
            mostrar_area_2(historial_paquetes[sel - 1]);
            mostrar_area_3(historial_paquetes[sel - 1]);
        } else if (sel != 0) {
            cout << "  [!] ID invalido. Rango: 1-" << total << "\n";
        }
    } while (sel != 0);
}


//  flujo: filtrar sobre paquetes YA capturados

void flujo_filtrar_capturados() {
    if (historial_paquetes.empty()) {
        cout << "   No hay paquetes capturados aun.\n";
        return;
    }

    cout << "\n";
    separador('-', 62);
    cout << "  FILTRAR PAQUETES CAPTURADOS\n";
    separador('-', 62);
    cout << "  1. Por protocolo  (TCP / UDP / ICMP / Otro)\n";
    cout << "  2. Por IP de origen\n";
    cout << "  3. Por IP de destino\n";
    cout << "  4. Por puerto de origen\n";
    cout << "  5. Por puerto de destino\n";
    cout << "  0. Cancelar\n";
    separador('-', 62);
    cout << "  Opcion: ";

    int opc; cin >> opc;
    if (opc == 0) return;

    string val;
    if (opc == 1) { cout << "  Protocolo (TCP/UDP/ICMP/Otro): "; cin >> val; }
    else if (opc == 2) { cout << "  IP origen  : "; cin >> val; }
    else if (opc == 3) { cout << "  IP destino : "; cin >> val; }
    else if (opc == 4) { cout << "  Puerto origen  : "; cin >> val; }
    else if (opc == 5) { cout << "  Puerto destino : "; cin >> val; }
    else { cout << "  Opcion invalida.\n"; return; }

    // Convertir protocolo a mayusculas para comparar
    string val_up = val;
    transform(val_up.begin(), val_up.end(), val_up.begin(), ::toupper);

    vector<PaqueteCapturado*> resultado;
    for (auto &p : historial_paquetes) {
        string proto_up = p.protocol;
        transform(proto_up.begin(), proto_up.end(), proto_up.begin(), ::toupper);

        bool match = false;
        if      (opc == 1) match = (proto_up == val_up);
        else if (opc == 2) match = (p.src_ip   == val);
        else if (opc == 3) match = (p.dst_ip   == val);
        else if (opc == 4) match = (p.src_port == stoi(val));
        else if (opc == 5) match = (p.dst_port == stoi(val));
        if (match) resultado.push_back(&p);
    }

    if (resultado.empty()) {
        cout << "  [!] Sin coincidencias para \"" << val << "\".\n";
        return;
    }

    cout << "\n";
    separador('=', 62);
    cout << "  RESULTADOS DEL FILTRO: \"" << val << "\"  ("
         << resultado.size() << " paquete(s))\n";
    separador('=', 62);
    printf("  %-3s  %-10s  %-5s  %-15s %-6s  %-15s %-6s  %s\n",
           "ID","Hora","Proto","IP Origen","PtoS",
           "IP Destino","PtoD","Bytes");
    separador('-', 62);
    for (auto *p : resultado) {
        printf("  %-3d  %-10s  %-5s  %-15s %-6d  %-15s %-6d  %u\n",
               p->id, p->timestamp.c_str(), p->protocol.c_str(),
               p->src_ip.c_str(), p->src_port,
               p->dst_ip.c_str(), p->dst_port,
               p->header.len);
    }
    separador('-', 62);

    // Opcion de inspeccionar uno de los resultados
    int sel;
    cout << "  ID a inspeccionar (de la lista de arriba) | 0 = volver: ";
    cin >> sel;
    if (sel != 0) {
        // Buscar por id en historial
        for (auto &p : historial_paquetes) {
            if (p.id == sel) {
                mostrar_area_2(p);
                mostrar_area_3(p);
                break;
            }
        }
    }
}


//  MENU PRINCIPAL

void menu_principal(pcap_t *handle) {
    int opc;
    do {
        mostrar_banner();
        cout << "  MENU PRINCIPAL\n";
        separador('-', 62);
        cout << "  1. Configurar filtro y cantidad de captura\n";
        cout << "  2. INICIAR captura\n";
        cout << "  3. Ver tabla de paquetes capturados (Area 1)\n";
        cout << "  4. Inspeccionar paquete - detalle (Areas 2 y 3)\n";
        cout << "  5. Filtrar sobre paquetes ya capturados\n";
        cout << "  6. Exportar resultados a CSV\n";
        cout << "  0. Salir\n";
        separador('-', 62);
        cout << "  Opcion: ";
        cin >> opc;

        switch (opc) {
            case 1: flujo_configurar_captura(handle); break;
            case 2: flujo_iniciar_captura(handle);    break;
            case 3: mostrar_area_1_tabla();           break;
            case 4: flujo_inspeccionar_paquetes();    break;
            case 5: flujo_filtrar_capturados();       break;
            case 6: exportar_csv();                   break;
            case 0: break;
            default: cout << "  [!] Opcion invalida.\n";
        }

        if (opc != 0) {
            cout << "\n  Presiona ENTER para continuar...";
            cin.ignore();
            cin.get();
        }

    } while (opc != 0);
}

// main
int main() {
    signal(SIGINT, signal_handler);

    cout << "\033[2J\033[H";
    separador('*', 62);
    cout << "*       PACKET SNIFFER  -  PROYECTO REDES I              *\n";
    cout << "*       Plataforma: Linux  |  Libreria: libpcap           *\n";
    separador('*', 62);
    cout << "\n";

    pcap_t *handle = seleccionar_interfaz();
    if (!handle) return -1;

    // Filtro como por defecto: todo IP
    struct bpf_program fcode;
    pcap_compile(handle, &fcode, "ip", 1, PCAP_NETMASK_UNKNOWN);
    pcap_setfilter(handle, &fcode);

    menu_principal(handle);

    pcap_close(handle);
    handle_global = nullptr;
    cout << "\n  [*] Saliendo. ¡Hasta pronto!\n\n";
    return 0;
}
