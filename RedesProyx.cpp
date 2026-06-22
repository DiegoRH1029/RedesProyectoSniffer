// ============================================================
//  PACKET SNIFFER  -  PROYECTO REDES I 
// ============================================================

#include <QtWidgets>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <fstream>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip6.h>   
#include <arpa/inet.h>

using namespace std;

// ============================================================
// 1. ESTRUCTURAS Y GLOBALES 
// ============================================================

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
    int            link_offset; 
};

vector<PaqueteCapturado> historial_paquetes;
int     contador_paquetes = 0;
bool    capturando        = false;
pcap_t *handle_global     = nullptr;
std::mutex mtx_paquetes; 

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

// ============================================================
// 2. GENERADORES DE TEXTO (TABLAS HTML + ARP/IPv6)
// ============================================================

QString filaTabla(QString titulo, QString valor, QString colorValor = "#ffffff") {
    return QString("<tr><td style='padding: 4px 10px; background-color: #0f172a; border-bottom: 1px solid #1e293b; color: #94a3b8; font-weight: bold; width: 130px;'>%1</td>"
                   "<td style='padding: 4px 10px; background-color: #0d1322; border-bottom: 1px solid #1e293b; color: %2;'>%3</td></tr>")
           .arg(titulo, colorValor, valor);
}

QString generar_area_2(const PaqueteCapturado &p) {
    QString out = QString("<h3 style='color:#ff007c; margin-bottom: 5px;'>ANÁLISIS DEL PAQUETE %1</h3>").arg(p.id);
    out += "<table width='100%' cellspacing='0' cellpadding='0' style='font-family: sans-serif; font-size: 12px;'>";

    // --- CAPA 2: ENLACE ---
    if (p.link_offset == 14 && p.data.size() >= 14) {
        auto *eth = (const ether_header*)p.data.data();
        out += "<tr><td colspan='2' style='background-color: #0077b6; color: white; padding: 5px; font-weight: bold;'>[Capa 2] ETHERNET</td></tr>";
        out += filaTabla("MAC Origen", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]), "#00ff41");
        out += filaTabla("MAC Destino", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]), "#00ff41");
        
        uint16_t et = ntohs(eth->ether_type);
        QString tipoStr = (et==0x0800) ? "IPv4" : (et==0x0806) ? "ARP" : (et==0x86DD) ? "IPv6" : "Otro";
        out += filaTabla("EtherType", QString("0x%1 (%2)").arg(QString::asprintf("%04X", et), tipoStr), "#ffb300");
    }

    // --- CAPA 3: PROTOCOLOS DE RED ---
    if (p.protocol == "ARP" && p.data.size() >= (size_t)(p.link_offset + sizeof(ether_arp))) {
        auto *arp = (const struct ether_arp*)(p.data.data() + p.link_offset);
        out += "<tr><td colspan='2' style='background-color: #b8860b; color: #ffffff; padding: 5px; font-weight: bold; margin-top: 10px;'>[Capa 3] ARP (Address Resolution Protocol)</td></tr>";
        
        uint16_t op = ntohs(arp->arp_op);
        QString opStr = (op == 1) ? "Request (Pregunta)" : (op == 2) ? "Reply (Respuesta)" : QString("Otro (%1)").arg(op);
        out += filaTabla("Operación", opStr, "#ffb300");
        out += filaTabla("IP Origen (Sender)", QString::fromStdString(p.src_ip), "#38ef7d");
        out += filaTabla("MAC Origen", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp->arp_sha[0],arp->arp_sha[1],arp->arp_sha[2],arp->arp_sha[3],arp->arp_sha[4],arp->arp_sha[5]), "#00ff41");
        out += filaTabla("IP Destino (Target)", QString::fromStdString(p.dst_ip), "#38ef7d");
        out += filaTabla("MAC Destino", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp->arp_tha[0],arp->arp_tha[1],arp->arp_tha[2],arp->arp_tha[3],arp->arp_tha[4],arp->arp_tha[5]), "#00ff41");
        
    } else if (p.protocol == "IPv6" && p.data.size() >= (size_t)(p.link_offset + sizeof(ip6_hdr))) {
        auto *ip6 = (const struct ip6_hdr*)(p.data.data() + p.link_offset);
        out += "<tr><td colspan='2' style='background-color: #6495ED; color: #ffffff; padding: 5px; font-weight: bold; margin-top: 10px;'>[Capa 3] IPv6 (Internet Protocol Version 6)</td></tr>";
        out += filaTabla("IP Origen", QString::fromStdString(p.src_ip), "#c896ff");
        out += filaTabla("IP Destino", QString::fromStdString(p.dst_ip), "#c896ff");
        out += filaTabla("Hop Limit", QString::number(ip6->ip6_hops), "#e2e8f0");
        out += filaTabla("Next Header", QString::number(ip6->ip6_nxt), "#ffb300");
        out += filaTabla("Longitud Payload", QString("%1 bytes").arg(ntohs(ip6->ip6_plen)), "#e2e8f0");
        
    } else if (p.data.size() >= (size_t)(p.link_offset + 20) && (p.protocol == "TCP" || p.protocol == "UDP" || p.protocol == "ICMP" || p.protocol == "IPv4" || p.protocol == "IGMP")) {
        auto *iph = (const struct ip*)(p.data.data() + p.link_offset);
        int ihl = iph->ip_hl * 4;
        
        out += "<tr><td colspan='2' style='background-color: #00b4d8; color: #03045e; padding: 5px; font-weight: bold; margin-top: 10px;'>[Capa 3] IPv4 (Internet Protocol)</td></tr>";
        out += filaTabla("IP Origen", QString::fromStdString(p.src_ip), "#38ef7d");
        out += filaTabla("IP Destino", QString::fromStdString(p.dst_ip), "#38ef7d");
        out += filaTabla("Protocolo", QString("%1 (%2)").arg(iph->ip_p).arg(p.protocol.c_str()), "#ffb300");
        out += filaTabla("Time To Live (TTL)", QString::number(p.ttl), "#e2e8f0");
        out += filaTabla("ID Paquete", QString("0x%1").arg(QString::asprintf("%04X", p.ip_id)), "#e2e8f0");
        
        // --- CAPA 4: TRANSPORTE ---
        if (p.protocol == "TCP" && p.data.size() >= (size_t)(p.link_offset + ihl + 20)) {
            auto *th = (const tcphdr*)(p.data.data() + p.link_offset + ihl);
            out += "<tr><td colspan='2' style='background-color: #4facfe; color: #00171f; padding: 5px; font-weight: bold;'>[Capa 4] TCP (Transmission Control Protocol)</td></tr>";
            out += filaTabla("Puerto Origen", QString::number(p.src_port), "#ff007c");
            out += filaTabla("Puerto Destino", QString::number(p.dst_port), "#ff007c");
            out += filaTabla("Secuencia (Seq)", QString::number(ntohl(th->seq)), "#e2e8f0");
            out += filaTabla("Acuse (Ack)", QString::number(ntohl(th->ack_seq)), "#e2e8f0");
            out += filaTabla("Flags TCP", QString("[%1]").arg(flags_tcp_str(p.tcp_flags).c_str()), "#ffb300");
            
        } else if (p.protocol == "UDP" && p.data.size() >= (size_t)(p.link_offset + ihl + 8)) {
            auto *uh = (const udphdr*)(p.data.data() + p.link_offset + ihl);
            out += "<tr><td colspan='2' style='background-color: #00f2fe; color: #00171f; padding: 5px; font-weight: bold;'>[Capa 4] UDP (User Datagram Protocol)</td></tr>";
            out += filaTabla("Puerto Origen", QString::number(p.src_port), "#ff007c");
            out += filaTabla("Puerto Destino", QString::number(p.dst_port), "#ff007c");
            out += filaTabla("Longitud", QString("%1 bytes").arg(ntohs(uh->len)), "#e2e8f0");
            
        } else if (p.protocol == "ICMP") {
            const u_char *ic = p.data.data() + p.link_offset + ihl;
            out += "<tr><td colspan='2' style='background-color: #ef473a; color: white; padding: 5px; font-weight: bold;'>[Capa 4] ICMP (Internet Control Protocol)</td></tr>";
            out += filaTabla("Tipo", QString::number(ic[0]), "#ffb300");
            out += filaTabla("Código", QString::number(ic[1]), "#ffb300");
        }
    }
    out += "</table>";
    return out;
}

QString generar_area_3(const PaqueteCapturado &p) {
    QString out = QString("<h3 style='color:#ffb300; margin-bottom: 5px;'>HEXADECIMAL - PAQUETE %1</h3>").arg(p.id);
    out += "<table width='100%' cellspacing='0' cellpadding='3' style='font-family: monospace; font-size: 12px;'>";
    out += "<tr style='background-color: #1e293b; color: #00b4d8; text-align: left;'>"
           "<th style='width: 60px;'>Offset</th><th>Hexadecimal</th><th style='width: 150px;'>ASCII</th></tr>";

    size_t n = p.data.size();
    for (size_t i = 0; i < n; i += 16) {
        QString offset = QString("%1").arg(i, 4, 16, QChar('0')).toUpper();
        QString asciiPart, hexPart;
        
        for (size_t j = 0; j < 16; j++) {
            if (j == 8) hexPart += "&nbsp;&nbsp;"; 
            if (i+j < n) {
                unsigned char c = p.data[i+j];
                hexPart += QString("%1 ").arg(c, 2, 16, QChar('0')).toUpper();
                char asciiChar = (c >= 32 && c < 127) ? c : '.';
                if (asciiChar == '<') asciiPart += "&lt;";
                else if (asciiChar == '>') asciiPart += "&gt;";
                else if (asciiChar == '&') asciiPart += "&amp;";
                else asciiPart += asciiChar;
            } else {
                hexPart += "&nbsp;&nbsp;&nbsp;";
            }
        }
        
        QString bgColor = (i % 32 == 0) ? "#0a0f1c" : "#0d1322"; 
        out += QString("<tr style='background-color: %1;'><td style='color:#00b4d8;'>%2</td><td style='color:#00ff41; letter-spacing: 1px;'>%3</td><td style='color:#e2e8f0;'>%4</td></tr>").arg(bgColor, offset, hexPart, asciiPart);
    }
    out += "</table>";
    return out;
}

// ============================================================
// 3. LA INTERFAZ GRÁFICA AVANZADA (GUI)
// ============================================================

class VentanaSniffer : public QMainWindow {
public:
    QTableWidget *tablaArea1;
    QTextEdit *textoArea2;
    QTextEdit *textoArea3;
    
    QComboBox *comboInterfaces;
    QComboBox *comboProtocolo;
    QComboBox *comboDirIP;     
    QComboBox *comboDirPto;    
    QLineEdit *txtIP;
    QLineEdit *txtPuerto;
    
    QPushButton *btnCapturar;
    QPushButton *btnPausar;    // NUEVO BOTÓN
    QPushButton *btnAnterior;
    QPushButton *btnSiguiente;
    QPushButton *btnExportar;

    std::thread hiloCaptura; 
    int link_offset = 14; 
    bool pausado = false;      // NUEVO ESTADO

    VentanaSniffer() {
        setWindowTitle("Packet Sniffer Pro - Ultra Premium Edition");
        resize(1300, 850);
        
        this->setStyleSheet(R"(
            QMainWindow { background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0a0f1c, stop:1 #1a233a); }
            QLabel { color: #00e5ff; font-weight: bold; font-size: 12px; text-transform: uppercase; }
            QTableWidget { background-color: #050b14; color: #e2e8f0; gridline-color: #1e293b; border: 2px solid #00e5ff; border-radius: 8px; selection-background-color: #38ef7d; selection-color: #000000; outline: 0; }
            QTableWidget::item:selected { font-weight: bold; }
            QHeaderView::section { background-color: #00b4d8; color: #03045e; font-weight: 900; border: 1px solid #0077b6; padding: 8px; }
            
            QPushButton { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #00f2fe, stop:1 #4facfe); color: #00171f; font-weight: 900; border-radius: 6px; padding: 8px 15px; border: 1px solid #00b4d8; }
            QPushButton:hover { background: #00e5ff; }
            QPushButton#btnIniciar { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #11998e, stop:1 #38ef7d); color: #000000; border: 1px solid #38ef7d; }
            QPushButton#btnDetener { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #cb2d3e, stop:1 #ef473a); color: #ffffff; border: 1px solid #ff4b2b; }
            QPushButton#btnExport { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #d4ff00, stop:1 #73ff00); color: #000000; border: 1px solid #73ff00; } 
            QPushButton#btnExport:hover { background: #d4ff00; }
            
            /* ESTILOS BOTÓN PAUSAR */
            QPushButton#btnPausar { background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #f6d365, stop:1 #fda085); color: #000000; border: 1px solid #ffb300; }
            QPushButton#btnPausar:disabled { background: #1e293b; color: #475569; border: 1px solid #334155; }
            
            QLineEdit, QComboBox { background-color: #0d1322; color: #00e5ff; border: 2px solid #0077b6; border-radius: 5px; padding: 5px; font-weight: bold; }
            QComboBox QAbstractItemView { background-color: #0a0f1c; color: #00e5ff; selection-background-color: #ff007c; selection-color: white; border: 1px solid #0077b6; }
            QTextEdit { background-color: #050b14; border-radius: 8px; padding: 12px; selection-background-color: #ff007c; selection-color: #ffffff; }
            QTextEdit#area2 { border: 2px solid #00ff41; } 
            QTextEdit#area3 { border: 2px solid #ffb300; } 
            
            QSplitter::handle { background-color: #00e5ff; }
            QSplitter::handle:horizontal { width: 4px; }
            QSplitter::handle:vertical { height: 4px; }
            QScrollBar:vertical { border: none; background: #0a0f1c; width: 12px; border-radius: 6px; }
            QScrollBar::handle:vertical { background: #00e5ff; min-height: 20px; border-radius: 6px; }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
            QScrollBar:horizontal { border: none; background: #0a0f1c; height: 12px; border-radius: 6px; }
            QScrollBar::handle:horizontal { background: #00e5ff; min-width: 20px; border-radius: 6px; }
            QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
        )");

        QWidget *centralWidget = new QWidget(this);
        QVBoxLayout *layoutPrincipal = new QVBoxLayout(centralWidget);

        // --- BARRA SUPERIOR ---
        QHBoxLayout *layoutTop = new QHBoxLayout();
        comboInterfaces = new QComboBox(); comboInterfaces->setMinimumWidth(110);
        char errbuf[PCAP_ERRBUF_SIZE]; pcap_if_t *alldevs, *d;
        if (pcap_findalldevs(&alldevs, errbuf) == 0) {
            for (d = alldevs; d; d = d->next) comboInterfaces->addItem(d->name);
            pcap_freealldevs(alldevs);
        }

        comboProtocolo = new QComboBox(); 
        comboProtocolo->addItems({"TODOS", "IPv4", "IPv6", "TCP (Todos)", "TCP IPv4", "TCP IPv6", "UDP (Todos)", "UDP IPv4", "UDP IPv6", "ICMP", "ARP"});
        
        comboDirIP = new QComboBox(); comboDirIP->addItems({"Cualquier IP", "IP Origen", "IP Destino"});
        txtIP = new QLineEdit(); txtIP->setPlaceholderText("192.168.1.1"); txtIP->setFixedWidth(110);
        comboDirPto = new QComboBox(); comboDirPto->addItems({"Cualquier Pto", "Pto Origen", "Pto Destino"});
        txtPuerto = new QLineEdit(); txtPuerto->setPlaceholderText("Ej: 80"); txtPuerto->setFixedWidth(60);

        btnCapturar = new QPushButton("▶ NUEVA CAPTURA"); btnCapturar->setObjectName("btnIniciar");
        
        btnPausar = new QPushButton("⏸ PAUSAR"); btnPausar->setObjectName("btnPausar");
        btnPausar->setEnabled(false); // Deshabilitado hasta que inicies captura

        btnExportar = new QPushButton("💾 CSV"); btnExportar->setObjectName("btnExport");

        layoutTop->addWidget(comboInterfaces); layoutTop->addSpacing(10);
        layoutTop->addWidget(comboProtocolo); layoutTop->addSpacing(10);
        layoutTop->addWidget(comboDirIP); layoutTop->addWidget(txtIP); layoutTop->addSpacing(10);
        layoutTop->addWidget(comboDirPto); layoutTop->addWidget(txtPuerto); layoutTop->addStretch();
        layoutTop->addWidget(btnCapturar); layoutTop->addWidget(btnPausar); layoutTop->addWidget(btnExportar);
        
        layoutPrincipal->addLayout(layoutTop);

        // --- SPLITTER VERTICAL ---
        QSplitter *splitterPrincipal = new QSplitter(Qt::Vertical);
        
        QWidget *topWidget = new QWidget();
        QVBoxLayout *topLayout = new QVBoxLayout(topWidget);
        topLayout->setContentsMargins(0, 0, 0, 0);

        tablaArea1 = new QTableWidget(0, 8);
        tablaArea1->setHorizontalHeaderLabels({"ID", "Hora", "Proto", "IP Origen", "PtoS", "IP Destino", "PtoD", "Bytes"});
        tablaArea1->setSelectionBehavior(QAbstractItemView::SelectRows);
        tablaArea1->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tablaArea1->verticalHeader()->setVisible(false);
        
        QHeaderView *header = tablaArea1->horizontalHeader();
        header->setSectionResizeMode(0, QHeaderView::ResizeToContents); 
        header->setSectionResizeMode(1, QHeaderView::ResizeToContents); 
        header->setSectionResizeMode(2, QHeaderView::ResizeToContents); 
        header->setSectionResizeMode(3, QHeaderView::Stretch);          
        header->setSectionResizeMode(4, QHeaderView::ResizeToContents); 
        header->setSectionResizeMode(5, QHeaderView::Stretch);          
        header->setSectionResizeMode(6, QHeaderView::ResizeToContents); 
        header->setSectionResizeMode(7, QHeaderView::ResizeToContents); 
        
        topLayout->addWidget(tablaArea1);

        QHBoxLayout *layoutFlechas = new QHBoxLayout();
        btnAnterior = new QPushButton("▲ ANTERIOR");
        btnSiguiente = new QPushButton("▼ SIGUIENTE");
        layoutFlechas->addWidget(btnAnterior);
        layoutFlechas->addWidget(btnSiguiente);
        layoutFlechas->addStretch();
        topLayout->addLayout(layoutFlechas);

        splitterPrincipal->addWidget(topWidget);

        QSplitter *splitterAbajo = new QSplitter(Qt::Horizontal);
        textoArea2 = new QTextEdit(); textoArea2->setReadOnly(true); textoArea2->setObjectName("area2"); 
        textoArea3 = new QTextEdit(); textoArea3->setReadOnly(true); textoArea3->setObjectName("area3"); 
        splitterAbajo->addWidget(textoArea2);
        splitterAbajo->addWidget(textoArea3);
        
        splitterPrincipal->addWidget(splitterAbajo);
        splitterPrincipal->setSizes({500, 300}); 
        
        layoutPrincipal->addWidget(splitterPrincipal);
        setCentralWidget(centralWidget);

        // --- EVENTOS ---
        connect(tablaArea1, &QTableWidget::itemSelectionChanged, [this]() {
            int fila = tablaArea1->currentRow();
            if (fila >= 0) {
                std::lock_guard<std::mutex> lock(mtx_paquetes);
                if (fila < historial_paquetes.size()) {
                    textoArea2->setHtml(generar_area_2(historial_paquetes[fila]));
                    textoArea3->setHtml(generar_area_3(historial_paquetes[fila]));
                }
            }
        });

        connect(btnAnterior, &QPushButton::clicked, [this]() {
            int f = tablaArea1->currentRow();
            if (f > 0) tablaArea1->setCurrentCell(f - 1, 0);
        });

        connect(btnSiguiente, &QPushButton::clicked, [this]() {
            int f = tablaArea1->currentRow();
            if (f < tablaArea1->rowCount() - 1) tablaArea1->setCurrentCell(f + 1, 0);
        });

        // Evento Boton Capturar (NUEVA o DETENER COMPLETO)
        connect(btnCapturar, &QPushButton::clicked, [this]() {
            if (capturando || pausado) {
                // Detener Todo
                capturando = false;
                pausado = false;
                if (handle_global) pcap_breakloop(handle_global);
                if (hiloCaptura.joinable()) hiloCaptura.join(); 
                if (handle_global) { pcap_close(handle_global); handle_global = nullptr; }

                btnCapturar->setText("▶ NUEVA CAPTURA"); btnCapturar->setObjectName("btnIniciar"); 
                this->setStyleSheet(this->styleSheet()); 
                
                btnPausar->setEnabled(false);
                btnPausar->setText("⏸ PAUSAR");
                
                comboInterfaces->setEnabled(true); comboProtocolo->setEnabled(true);
                comboDirIP->setEnabled(true); txtIP->setEnabled(true);
                comboDirPto->setEnabled(true); txtPuerto->setEnabled(true);
            } else {
                // Iniciar Nueva Captura desde Cero
                tablaArea1->setRowCount(0); 
                historial_paquetes.clear(); 
                contador_paquetes = 0;
                pausado = false;
                
                if (iniciarCapturaHilo()) {
                    btnCapturar->setText("■ DETENER"); btnCapturar->setObjectName("btnDetener"); 
                    this->setStyleSheet(this->styleSheet()); 
                    
                    btnPausar->setEnabled(true);
                    btnPausar->setText("⏸ PAUSAR");

                    comboInterfaces->setEnabled(false); comboProtocolo->setEnabled(false);
                    comboDirIP->setEnabled(false); txtIP->setEnabled(false);
                    comboDirPto->setEnabled(false); txtPuerto->setEnabled(false);
                }
            }
        });

        // Evento Botón Pausar / Reanudar
        connect(btnPausar, &QPushButton::clicked, [this]() {
            if (capturando && !pausado) {
                // Poner en Pausa
                capturando = false;
                pausado = true;
                if (handle_global) pcap_breakloop(handle_global);
                if (hiloCaptura.joinable()) hiloCaptura.join(); 
                if (handle_global) { pcap_close(handle_global); handle_global = nullptr; }

                btnPausar->setText("▶ REANUDAR");
            } else if (pausado) {
                // Reanudar sin limpiar tablas
                if (iniciarCapturaHilo()) {
                    pausado = false;
                    btnPausar->setText("⏸ PAUSAR");
                }
            }
        });

        connect(btnExportar, &QPushButton::clicked, [this]() {
            if (historial_paquetes.empty()) return;
            QString archivoDestino = QFileDialog::getSaveFileName(this, "Guardar", "sniffer.csv", "CSV (*.csv)");
            if (archivoDestino.isEmpty()) return;

            std::ofstream f(archivoDestino.toStdString());
            if (f.is_open()) {
                f << "ID,Timestamp,Protocolo,IP_Origen,Puerto_Origen,IP_Destino,Puerto_Destino,Flags_TCP,Checksum,Longitud\n";
                std::lock_guard<std::mutex> lock(mtx_paquetes);
                for (const auto &p : historial_paquetes) {
                    f << p.id << "," << p.timestamp << "," << p.protocol << "," << p.src_ip << "," << p.src_port << "," 
                      << p.dst_ip << "," << p.dst_port << "," << flags_tcp_str(p.tcp_flags) << "," << p.checksum << "," << p.header.len << "\n";
                }
                f.close();
                QMessageBox::information(this, "Éxito", "CSV guardado.");
            }
        });
    }

    void agregarFilaDesdeHilo(const PaqueteCapturado &p) {
        int row = tablaArea1->rowCount();
        tablaArea1->insertRow(row);
        
        QColor colorFondo(20, 25, 40);       
        QColor colorTexto(148, 163, 184);    

        if (p.protocol == "TCP") { colorFondo = QColor(15, 23, 65); colorTexto = QColor(130, 170, 255); } 
        else if (p.protocol == "UDP") { colorFondo = QColor(13, 35, 45); colorTexto = QColor(0, 255, 204); } 
        else if (p.protocol == "ICMP") { colorFondo = QColor(60, 15, 25); colorTexto = QColor(255, 120, 120); }
        else if (p.protocol == "ARP") { colorFondo = QColor(50, 40, 10); colorTexto = QColor(255, 204, 0); }
        else if (p.protocol == "IPv6") { colorFondo = QColor(35, 15, 55); colorTexto = QColor(200, 150, 255); }

        QString de[8] = {
            QString::number(p.id), QString::fromStdString(p.timestamp),
            QString::fromStdString(p.protocol), QString::fromStdString(p.src_ip),
            p.src_port > 0 ? QString::number(p.src_port) : "-", 
            QString::fromStdString(p.dst_ip),
            p.dst_port > 0 ? QString::number(p.dst_port) : "-", 
            QString::number(p.header.len)
        };

        for(int col = 0; col < 8; ++col) {
            QTableWidgetItem *item = new QTableWidgetItem(de[col]);
            item->setBackground(QBrush(colorFondo)); item->setForeground(QBrush(colorTexto)); 
            item->setTextAlignment(Qt::AlignCenter); 
            item->setFlags(item->flags() & ~Qt::ItemIsEditable);
            tablaArea1->setItem(row, col, item);
        }
        tablaArea1->scrollToBottom();
    }

    bool iniciarCapturaHilo() {
        QString dev = comboInterfaces->currentText();
        char errbuf[PCAP_ERRBUF_SIZE];
        handle_global = pcap_open_live(dev.toStdString().c_str(), 65536, 1, 1000, errbuf);
        if (!handle_global) { QMessageBox::critical(this, "Error", QString("Fallo al abrir: %1").arg(errbuf)); return false; }

        int linkType = pcap_datalink(handle_global);
        if (linkType == DLT_EN10MB) link_offset = 14; 
        else if (linkType == DLT_LINUX_SLL) link_offset = 16; 
        else { QMessageBox::warning(this, "Error", "Interfaz no Ethernet detectada."); pcap_close(handle_global); handle_global = nullptr; return false; }

        // --- NUEVOS FILTROS ESPECÍFICOS ---
        QStringList partesFiltro;
        QString protoCombo = comboProtocolo->currentText();
        QString bpfProto = "";
        
        if (protoCombo == "IPv4") bpfProto = "ip";
        else if (protoCombo == "IPv6") bpfProto = "ip6";
        else if (protoCombo == "TCP (Todos)") bpfProto = "tcp";
        else if (protoCombo == "TCP IPv4") bpfProto = "tcp and ip";
        else if (protoCombo == "TCP IPv6") bpfProto = "tcp and ip6";
        else if (protoCombo == "UDP (Todos)") bpfProto = "udp";
        else if (protoCombo == "UDP IPv4") bpfProto = "udp and ip";
        else if (protoCombo == "UDP IPv6") bpfProto = "udp and ip6";
        else if (protoCombo == "ICMP") bpfProto = "icmp";
        else if (protoCombo == "ARP") bpfProto = "arp";

        if (!bpfProto.isEmpty()) partesFiltro << "(" + bpfProto + ")";
        
        QString ipStr = txtIP->text().trimmed();
        if (!ipStr.isEmpty()) {
            int iDir = comboDirIP->currentIndex();
            if (iDir == 1) partesFiltro << "(src host " + ipStr + ")";
            else if (iDir == 2) partesFiltro << "(dst host " + ipStr + ")";
            else partesFiltro << "(host " + ipStr + ")";
        }

        QString ptoStr = txtPuerto->text().trimmed();
        if (!ptoStr.isEmpty()) {
            int pDir = comboDirPto->currentIndex();
            if (pDir == 1) partesFiltro << "(src port " + ptoStr + ")";
            else if (pDir == 2) partesFiltro << "(dst port " + ptoStr + ")";
            else partesFiltro << "(port " + ptoStr + ")";
        }
        
        QString filtroStr = partesFiltro.join(" and ");
        struct bpf_program fcode;
        if (!filtroStr.isEmpty() && pcap_compile(handle_global, &fcode, filtroStr.toStdString().c_str(), 1, PCAP_NETMASK_UNKNOWN) >= 0) {
            pcap_setfilter(handle_global, &fcode);
        }

        capturando = true;
        
        hiloCaptura = std::thread([this]() {
            pcap_loop(handle_global, -1, [](u_char *user, const pcap_pkthdr *hdr, const u_char *pkt) {
                VentanaSniffer *ventana = reinterpret_cast<VentanaSniffer*>(user);
                if (hdr->caplen < (unsigned)(ventana->link_offset)) return; 

                char tbuf[20]; struct tm *tm_i = localtime(&hdr->ts.tv_sec); strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm_i);
                string ts = string(tbuf) + "." + to_string(hdr->ts.tv_usec / 1000);

                PaqueteCapturado p;
                p.link_offset = ventana->link_offset; p.header = *hdr; 
                p.data = vector<u_char>(pkt, pkt + hdr->caplen);
                p.protocol = "Otro"; p.src_port = 0; p.dst_port = 0; p.tcp_flags = 0; p.checksum = 0;
                p.timestamp = ts; p.ttl = 0; p.ip_id = 0;

                uint16_t ether_type = 0;
                if (ventana->link_offset == 14) ether_type = ntohs(((struct ether_header*)pkt)->ether_type);
                else if (ventana->link_offset == 16) ether_type = ntohs(*(uint16_t*)(pkt + 14));

                if (ether_type == 0x0806 && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ether_arp))) {
                    p.protocol = "ARP";
                    struct ether_arp *arp = (struct ether_arp *)(pkt + ventana->link_offset);
                    p.src_ip = QString::asprintf("%d.%d.%d.%d", arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]).toStdString();
                    p.dst_ip = QString::asprintf("%d.%d.%d.%d", arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]).toStdString();
                
                } else if (ether_type == 0x86DD && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ip6_hdr))) {
                    p.protocol = "IPv6";
                    struct ip6_hdr *ip6 = (struct ip6_hdr *)(pkt + ventana->link_offset);
                    char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &ip6->ip6_src, src_str, sizeof(src_str));
                    inet_ntop(AF_INET6, &ip6->ip6_dst, dst_str, sizeof(dst_str));
                    p.src_ip = src_str;
                    p.dst_ip = dst_str;

                    // Si dentro de IPv6 hay TCP o UDP
                    if (ip6->ip6_nxt == IPPROTO_TCP && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ip6_hdr) + 20)) {
                        p.protocol = "TCP";
                        struct tcphdr *th = (struct tcphdr*)(pkt + ventana->link_offset + sizeof(ip6_hdr));
                        p.src_port = ntohs(th->source); p.dst_port = ntohs(th->dest);
                        p.tcp_flags = (uint8_t)th->th_flags;
                    } else if (ip6->ip6_nxt == IPPROTO_UDP && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ip6_hdr) + 8)) {
                        p.protocol = "UDP";
                        struct udphdr *uh = (struct udphdr*)(pkt + ventana->link_offset + sizeof(ip6_hdr));
                        p.src_port = ntohs(uh->source); p.dst_port = ntohs(uh->dest);
                    }

                } else if (ether_type == 0x0800 && hdr->caplen >= (unsigned)(ventana->link_offset + 20)) {
                    struct ip *iph = (struct ip*)(pkt + ventana->link_offset); 
                    p.src_ip = inet_ntoa(iph->ip_src); p.dst_ip = inet_ntoa(iph->ip_dst);
                    p.ttl = iph->ip_ttl; p.ip_id = ntohs(iph->ip_id);
                    int ihl = iph->ip_hl * 4;

                    if (iph->ip_p == IPPROTO_TCP) {
                        p.protocol = "TCP";
                        if (hdr->caplen >= (unsigned)(ventana->link_offset + ihl + 20)) {
                            struct tcphdr *th = (struct tcphdr*)(pkt + ventana->link_offset + ihl);
                            p.src_port = ntohs(th->source); p.dst_port = ntohs(th->dest);
                            p.tcp_flags = (uint8_t)th->th_flags; p.checksum = ntohs(th->check);
                        }
                    } else if (iph->ip_p == IPPROTO_UDP) {
                        p.protocol = "UDP";
                        if (hdr->caplen >= (unsigned)(ventana->link_offset + ihl + 8)) {
                            struct udphdr *uh = (struct udphdr*)(pkt + ventana->link_offset + ihl);
                            p.src_port = ntohs(uh->source); p.dst_port = ntohs(uh->dest); p.checksum = ntohs(uh->check);
                        }
                    } else if (iph->ip_p == IPPROTO_ICMP) p.protocol = "ICMP";
                    else if (iph->ip_p == 2) p.protocol = "IGMP";
                    else p.protocol = "IPv4";
                }

                {
                    std::lock_guard<std::mutex> lock(mtx_paquetes);
                    contador_paquetes++;
                    p.id = contador_paquetes;
                    historial_paquetes.push_back(p);
                }
                QMetaObject::invokeMethod(ventana, [ventana, p]() { ventana->agregarFilaDesdeHilo(p); }, Qt::QueuedConnection);
            }, reinterpret_cast<u_char*>(this));
        });
        
        return true;
    }
};

// ============================================================
// MAIN DE ARRANQUE 
// ============================================================
int main(int argc, char *argv[]) {
    QApplication app(argc, argv);
    app.setStyle("Fusion"); 
    VentanaSniffer ventana;
    ventana.show();
    return app.exec();
}