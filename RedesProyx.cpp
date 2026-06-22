// ============================================================
//  PACKET SNIFFER  -  PROYECTO REDES I (EDICIÓN ULTRA PREMIUM)
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
// 2. GENERADORES DE TEXTO (AHORA CON HTML PARA MULTI-COLOR)
// ============================================================

QString generar_area_2(const PaqueteCapturado &p) {
    // Usamos <pre> para respetar los espacios y alinear todo estilo terminal
    QString out = "<pre style='font-family: monospace; font-size: 10pt;'>";
    out += QString("<b style='color:#ff007c;'>==== CAPAS DEL PAQUETE #%1 ====</b>\n").arg(p.id);

    if (p.data.size() >= 14) {
        auto *eth = (const ether_header*)p.data.data();
        out += "\n<b style='color:#00b4d8;'>[Capa 2 - Enlace] ETHERNET</b>\n";
        out += QString("  <span style='color:#94a3b8;'>MAC Destino :</span> <span style='color:#00ff41;'>%1</span>\n")
               .arg(QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]));
        out += QString("  <span style='color:#94a3b8;'>MAC Origen  :</span> <span style='color:#00ff41;'>%1</span>\n")
               .arg(QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]));
        uint16_t et = ntohs(eth->ether_type);
        out += QString("  <span style='color:#94a3b8;'>EtherType   :</span> <span style='color:#ffb300;'>0x%1  (%2)</span>\n")
               .arg(QString::asprintf("%04X", et), et==0x0800?"IPv4": et==0x0806?"ARP": et==0x86DD?"IPv6":"Otro");
    }

    if (p.data.size() >= 34) {
        auto *iph = (const struct ip*)(p.data.data() + 14);
        int ihl = iph->ip_hl * 4;
        uint16_t off = ntohs(iph->ip_off);
        out += "\n<b style='color:#00b4d8;'>[Capa 3 - Red] IPv4 (Internet Protocol)</b>\n";
        out += QString("  <span style='color:#94a3b8;'>IP Origen   :</span> <span style='color:#38ef7d;'>%1</span>\n").arg(QString::fromStdString(p.src_ip));
        out += QString("  <span style='color:#94a3b8;'>IP Destino  :</span> <span style='color:#38ef7d;'>%1</span>\n").arg(QString::fromStdString(p.dst_ip));
        out += QString("  <span style='color:#94a3b8;'>TTL         :</span> <span style='color:#ffb300;'>%1</span>\n").arg((int)p.ttl);
        out += QString("  <span style='color:#94a3b8;'>ID IP       :</span> <span style='color:#ffb300;'>%1 (0x%2)</span>\n").arg(p.ip_id).arg(QString::asprintf("%04X", p.ip_id));
        out += QString("  <span style='color:#94a3b8;'>Protocolo   :</span> <span style='color:#ffb300;'>%1 (%2)</span>\n").arg(iph->ip_p).arg(p.protocol.c_str());
        out += QString("  <span style='color:#94a3b8;'>Checksum IP :</span> <span style='color:#ffb300;'>0x%1</span>\n").arg(QString::asprintf("%04X", ntohs(iph->ip_sum)));
        
        if (p.protocol == "TCP" && p.data.size() >= (size_t)(14 + ihl + 20)) {
            auto *th = (const tcphdr*)(p.data.data() + 14 + ihl);
            out += "\n<b style='color:#00b4d8;'>[Capa 4 - Transporte] TCP (Transmission Control Protocol)</b>\n";
            out += QString("  <span style='color:#94a3b8;'>Pto Origen  :</span> <span style='color:#ff007c;'>%1</span>\n").arg(p.src_port);
            out += QString("  <span style='color:#94a3b8;'>Pto Destino :</span> <span style='color:#ff007c;'>%1</span>\n").arg(p.dst_port);
            out += QString("  <span style='color:#94a3b8;'>Seq Number  :</span> <span style='color:#ffb300;'>%1</span>\n").arg(ntohl(th->seq));
            out += QString("  <span style='color:#94a3b8;'>Ack Number  :</span> <span style='color:#ffb300;'>%1</span>\n").arg(ntohl(th->ack_seq));
            out += QString("  <span style='color:#94a3b8;'>Flags TCP   :</span> <span style='color:#ffb300;'>0x%1  [%2]</span>\n").arg(QString::asprintf("%02X", p.tcp_flags), flags_tcp_str(p.tcp_flags).c_str());
        } else if (p.protocol == "UDP" && p.data.size() >= (size_t)(14 + ihl + 8)) {
            auto *uh = (const udphdr*)(p.data.data() + 14 + ihl);
            out += "\n<b style='color:#00b4d8;'>[Capa 4 - Transporte] UDP (User Datagram Protocol)</b>\n";
            out += QString("  <span style='color:#94a3b8;'>Pto Origen  :</span> <span style='color:#ff007c;'>%1</span>\n").arg(p.src_port);
            out += QString("  <span style='color:#94a3b8;'>Pto Destino :</span> <span style='color:#ff007c;'>%1</span>\n").arg(p.dst_port);
            out += QString("  <span style='color:#94a3b8;'>Longitud UDP:</span> <span style='color:#ffb300;'>%1 bytes</span>\n").arg(ntohs(uh->len));
        } else if (p.protocol == "ICMP") {
            const u_char *ic = p.data.data() + 14 + ihl;
            out += "\n<b style='color:#00b4d8;'>[Capa 4 - Transporte] ICMP (Internet Control Protocol)</b>\n";
            out += QString("  <span style='color:#94a3b8;'>Tipo        :</span> <span style='color:#ffb300;'>%1</span>\n").arg(ic[0]);
            out += QString("  <span style='color:#94a3b8;'>Código      :</span> <span style='color:#ffb300;'>%1</span>\n").arg(ic[1]);
        }
    }
    out += "</pre>";
    return out;
}

QString generar_area_3(const PaqueteCapturado &p) {
    QString out = "<pre style='font-family: monospace; font-size: 10pt;'>";
    out += QString("<b style='color:#ff007c;'>==== CONTENIDO RAW (HEX + ASCII) - PAQUETE #%1 ====</b>\n\n").arg(p.id);
    out += "<b style='color:#00b4d8;'>Offset   00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F   ASCII</b>\n";
    out += "<span style='color:#475569;'>-------------------------------------------------------------------</span>\n";

    size_t n = p.data.size();
    for (size_t i = 0; i < n; i += 16) {
        out += QString("<span style='color:#00b4d8;'>%1   </span>").arg(i, 4, 16, QChar('0')).toUpper();
        QString asciiPart;
        QString hexPart;
        
        for (size_t j = 0; j < 16; j++) {
            if (j == 8) hexPart += " ";
            if (i+j < n) {
                unsigned char c = p.data[i+j];
                hexPart += QString("%1 ").arg(c, 2, 16, QChar('0')).toUpper();
                
                // Evitar que el HTML confunda caracteres de red con código
                char asciiChar = (c >= 32 && c < 127) ? c : '.';
                if (asciiChar == '<') asciiPart += "&lt;";
                else if (asciiChar == '>') asciiPart += "&gt;";
                else if (asciiChar == '&') asciiPart += "&amp;";
                else asciiPart += asciiChar;
            } else {
                hexPart += "   ";
            }
        }
        out += QString("<span style='color:#00ff41;'>%1</span>  <span style='color:#ffb300;'>%2</span>\n").arg(hexPart, asciiPart);
    }
    out += "</pre>";
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
    QLineEdit *txtFiltro;
    QPushButton *btnCapturar;
    QPushButton *btnAnterior;
    QPushButton *btnSiguiente;
    QPushButton *btnExportar;

    VentanaSniffer() {
        setWindowTitle("Packet Sniffer Pro - Ultra Premium Edition");
        resize(1250, 850);
        
        // --- ESTILO TOTALMENTE REDISEÑADO CON GRADIENTES Y NEÓN ---
        this->setStyleSheet(R"(
            QMainWindow { 
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1, stop:0 #0a0f1c, stop:1 #1a233a); 
            }
            QLabel { color: #00e5ff; font-weight: bold; font-size: 13px; text-transform: uppercase; }
            
            QTableWidget { 
                background-color: #0d1322; 
                color: #e2e8f0; 
                gridline-color: #1e293b; 
                border: 2px solid #00e5ff; 
                border-radius: 8px;
                selection-background-color: #ff007c; 
                selection-color: #ffffff;
                outline: 0;
            }
            QTableWidget::item:selected {
                background-color: #ff007c; 
                color: #ffffff;
                font-weight: bold;
            }

            QHeaderView::section { 
                background-color: #00b4d8; 
                color: #03045e; 
                font-weight: 900; 
                border: 1px solid #0077b6; 
                padding: 8px;
            }
            
            /* BOTONES CON GRADIENTES ÉPICOS */
            QPushButton { 
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #00f2fe, stop:1 #4facfe); 
                color: #00171f; 
                font-weight: 900; 
                border-radius: 6px; 
                padding: 8px 15px; 
                border: 1px solid #00b4d8;
            }
            QPushButton:hover { background: #00e5ff; }
            
            QPushButton#btnIniciar { 
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #11998e, stop:1 #38ef7d); 
                color: #000000; border: 1px solid #38ef7d;
            }
            QPushButton#btnDetener { 
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #cb2d3e, stop:1 #ef473a); 
                color: #ffffff; border: 1px solid #ff4b2b;
            }
            /* BOTÓN EXPORTAR CSV (Verde Limón Neón) */
            QPushButton#btnExport { 
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #d4ff00, stop:1 #73ff00); 
                color: #000000; 
                border: 1px solid #73ff00;
            } 
            QPushButton#btnExport:hover { 
                background: #d4ff00; 
            }
            
            QLineEdit, QComboBox { 
                background-color: #0d1322; 
                color: #00e5ff; 
                border: 2px solid #0077b6; 
                border-radius: 5px; 
                padding: 6px; 
                font-weight: bold;
            }
            
            QComboBox QAbstractItemView {
                background-color: #0a0f1c;
                color: #00e5ff;
                selection-background-color: #ff007c;
                selection-color: white;
                border: 1px solid #0077b6;
            }
            
            /* TERMINALES MATRIX Y HEXADECIMAL */
            QTextEdit {
                background-color: #050b14;
                border-radius: 8px;
                padding: 12px;
                selection-background-color: #ff007c;
                selection-color: #ffffff;
            }
            QTextEdit#area2 { border: 2px solid #00ff41; } 
            QTextEdit#area3 { border: 2px solid #ffb300; } 

            /* SCROLLBARS MODERNAS */
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
        
        comboInterfaces = new QComboBox();
        comboInterfaces->setMinimumWidth(180);
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_if_t *alldevs, *d;
        if (pcap_findalldevs(&alldevs, errbuf) == 0) {
            for (d = alldevs; d; d = d->next) comboInterfaces->addItem(d->name);
            pcap_freealldevs(alldevs);
        }

        txtFiltro = new QLineEdit("ip");
        txtFiltro->setPlaceholderText("Ej: tcp, udp, port 80...");
        txtFiltro->setMinimumWidth(250);

        btnCapturar = new QPushButton("▶ INICIAR CAPTURA");
        btnCapturar->setObjectName("btnIniciar");

        btnExportar = new QPushButton("💾 EXPORTAR CSV");
        btnExportar->setObjectName("btnExport");

        layoutTop->addWidget(new QLabel("INTERFAZ:"));
        layoutTop->addWidget(comboInterfaces);
        layoutTop->addSpacing(20);
        layoutTop->addWidget(new QLabel("FILTRO BPF:"));
        layoutTop->addWidget(txtFiltro);
        layoutTop->addWidget(btnCapturar);
        layoutTop->addSpacing(10);
        layoutTop->addWidget(btnExportar);
        layoutTop->addStretch();
        layoutPrincipal->addLayout(layoutTop);

        // --- ÁREA 1: Tabla Principal ---
        tablaArea1 = new QTableWidget(0, 8);
        tablaArea1->setHorizontalHeaderLabels({"ID", "Hora", "Proto", "IP Origen", "PtoS", "IP Destino", "PtoD", "Bytes"});
        tablaArea1->setSelectionBehavior(QAbstractItemView::SelectRows);
        tablaArea1->setEditTriggers(QAbstractItemView::NoEditTriggers);
        tablaArea1->horizontalHeader()->setStretchLastSection(true);
        tablaArea1->verticalHeader()->setVisible(false);
        layoutPrincipal->addWidget(tablaArea1);

        // --- BARRA DE NAVEGACIÓN ---
        QHBoxLayout *layoutFlechas = new QHBoxLayout();
        btnAnterior = new QPushButton("▲ ANTERIOR");
        btnSiguiente = new QPushButton("▼ SIGUIENTE");
        
        layoutFlechas->addWidget(btnAnterior);
        layoutFlechas->addWidget(btnSiguiente);
        layoutFlechas->addStretch();
        layoutPrincipal->addLayout(layoutFlechas);

        // --- ÁREAS 2 y 3: Paneles Estilo Hacker ---
        QSplitter *splitterAbajo = new QSplitter(Qt::Horizontal);
        
        textoArea2 = new QTextEdit();
        textoArea2->setReadOnly(true);
        textoArea2->setObjectName("area2"); 
        // Ya no ponemos "setStyleSheet" con color aquí porque el HTML se encarga de los colores

        textoArea3 = new QTextEdit();
        textoArea3->setReadOnly(true);
        textoArea3->setObjectName("area3"); 

        splitterAbajo->addWidget(textoArea2);
        splitterAbajo->addWidget(textoArea3);
        layoutPrincipal->addWidget(splitterAbajo);

        setCentralWidget(centralWidget);

        // --- EVENTOS ---
        connect(tablaArea1, &QTableWidget::itemSelectionChanged, [this]() {
            int fila = tablaArea1->currentRow();
            if (fila >= 0) {
                std::lock_guard<std::mutex> lock(mtx_paquetes);
                if (fila < historial_paquetes.size()) {
                    // SE CAMBIA setText POR setHtml PARA QUE EL COLOR FUNCIONE
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

        connect(btnCapturar, &QPushButton::clicked, [this]() {
            if (capturando) {
                pcap_breakloop(handle_global);
                btnCapturar->setText("▶ INICIAR CAPTURA");
                btnCapturar->setObjectName("btnIniciar"); 
                this->setStyleSheet(this->styleSheet()); 
                txtFiltro->setEnabled(true);
                comboInterfaces->setEnabled(true);
            } else {
                tablaArea1->setRowCount(0); 
                historial_paquetes.clear();
                contador_paquetes = 0;
                
                if (iniciarCapturaHilo()) {
                    btnCapturar->setText("■ DETENER CAPTURA");
                    btnCapturar->setObjectName("btnDetener"); 
                    this->setStyleSheet(this->styleSheet()); 
                    txtFiltro->setEnabled(false);
                    comboInterfaces->setEnabled(false);
                }
            }
        });

        connect(btnExportar, &QPushButton::clicked, [this]() {
            if (historial_paquetes.empty()) {
                QMessageBox::warning(this, "Aviso", "No hay paquetes para exportar. Inicia una captura primero.");
                return;
            }

            QString archivoDestino = QFileDialog::getSaveFileName(this, "Guardar Resultados CSV", "sniffer_resultados.csv", "Archivos CSV (*.csv)");
            
            if (archivoDestino.isEmpty()) return;

            std::ofstream f(archivoDestino.toStdString());
            if (!f.is_open()) {
                QMessageBox::critical(this, "Error", "No se pudo crear el archivo. Revisa los permisos.");
                return;
            }

            f << "ID,Timestamp,Protocolo,IP_Origen,Puerto_Origen,IP_Destino,Puerto_Destino,Flags_TCP,Checksum,Longitud\n";
            
            std::lock_guard<std::mutex> lock(mtx_paquetes);
            for (const auto &p : historial_paquetes) {
                f << p.id << "," << p.timestamp << "," << p.protocol << ","
                  << p.src_ip << "," << p.src_port << "," << p.dst_ip << "," << p.dst_port << ","
                  << flags_tcp_str(p.tcp_flags) << "," << p.checksum << "," << p.header.len << "\n";
            }
            f.close();
            
            QMessageBox::information(this, "Éxito", "Exportación a CSV completada.\nGuardado en:\n" + archivoDestino);
        });
    }

    void agregarFilaDesdeHilo(const PaqueteCapturado &p) {
        int row = tablaArea1->rowCount();
        tablaArea1->insertRow(row);
        
        // --- COLORES VIVOS Y CONTRASTANTES ---
        QColor colorFondo(43, 45, 66);     // Gris/Azul oscuro base
        QColor colorTexto(237, 242, 244);  // Blanco crudo

        if (p.protocol == "TCP") {
            colorFondo = QColor(45, 0, 247);  // Índigo Brillante
            colorTexto = QColor(255, 255, 255); 
        } else if (p.protocol == "UDP") {
            colorFondo = QColor(0, 180, 216); // Azul Brillante
            colorTexto = QColor(0, 0, 0);     // Texto negro para legibilidad
        } else if (p.protocol == "ICMP") {
            colorFondo = QColor(217, 4, 41);  // Rojo Intenso
            colorTexto = QColor(255, 255, 255); 
        }

        QString de[8] = {
            QString::number(p.id), QString::fromStdString(p.timestamp),
            QString::fromStdString(p.protocol), QString::fromStdString(p.src_ip),
            QString::number(p.src_port), QString::fromStdString(p.dst_ip),
            QString::number(p.dst_port), QString::number(p.header.len)
        };

        for(int col = 0; col < 8; ++col) {
            QTableWidgetItem *item = new QTableWidgetItem(de[col]);
            item->setBackground(QBrush(colorFondo));
            item->setForeground(QBrush(colorTexto)); 
            item->setTextAlignment(Qt::AlignCenter); 
            tablaArea1->setItem(row, col, item);
        }
        
        tablaArea1->scrollToBottom();
    }

    bool iniciarCapturaHilo() {
        QString dev = comboInterfaces->currentText();
        QString filtroStr = txtFiltro->text().trimmed();
        char errbuf[PCAP_ERRBUF_SIZE];
        
        handle_global = pcap_open_live(dev.toStdString().c_str(), 65536, 1, 1000, errbuf);
        if (!handle_global) {
            QMessageBox::critical(this, "Error de Interfaz", 
                QString("No se pudo abrir '%1'.\nDetalle: %2").arg(dev, errbuf));
            return false;
        }

        struct bpf_program fcode;
        if (pcap_compile(handle_global, &fcode, filtroStr.toStdString().c_str(), 1, PCAP_NETMASK_UNKNOWN) < 0 ||
            pcap_setfilter(handle_global, &fcode) < 0) {
            pcap_compile(handle_global, &fcode, "ip", 1, PCAP_NETMASK_UNKNOWN);
            pcap_setfilter(handle_global, &fcode);
            txtFiltro->setText("ip");
        }

        capturando = true;
        
        std::thread([this]() {
            pcap_loop(handle_global, -1, [](u_char *user, const pcap_pkthdr *hdr, const u_char *pkt) {
                VentanaSniffer *ventana = reinterpret_cast<VentanaSniffer*>(user);
                char tbuf[20];
                struct tm *tm_i = localtime(&hdr->ts.tv_sec);
                strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm_i);
                string ts = string(tbuf) + "." + to_string(hdr->ts.tv_usec / 1000);

                PaqueteCapturado p;
                p.header = *hdr; p.data = vector<u_char>(pkt, pkt + hdr->caplen);
                p.protocol = "Otro"; p.src_port = 0; p.dst_port = 0; p.tcp_flags = 0; p.checksum = 0;
                p.timestamp = ts; p.ttl = 0; p.ip_id = 0;

                if (hdr->caplen >= 34) {
                    struct ip *iph = (struct ip*)(pkt + 14);
                    p.src_ip = inet_ntoa(iph->ip_src); p.dst_ip = inet_ntoa(iph->ip_dst);
                    p.ttl = iph->ip_ttl; p.ip_id = ntohs(iph->ip_id);
                    int ihl = iph->ip_hl * 4;

                    if (iph->ip_p == IPPROTO_TCP) {
                        p.protocol = "TCP";
                        if (hdr->caplen >= (unsigned)(14 + ihl + 20)) {
                            struct tcphdr *th = (struct tcphdr*)(pkt + 14 + ihl);
                            p.src_port = ntohs(th->source); p.dst_port = ntohs(th->dest);
                            p.tcp_flags = (uint8_t)th->th_flags; p.checksum = ntohs(th->check);
                        }
                    } else if (iph->ip_p == IPPROTO_UDP) {
                        p.protocol = "UDP";
                        if (hdr->caplen >= (unsigned)(14 + ihl + 8)) {
                            struct udphdr *uh = (struct udphdr*)(pkt + 14 + ihl);
                            p.src_port = ntohs(uh->source); p.dst_port = ntohs(uh->dest); p.checksum = ntohs(uh->check);
                        }
                    } else if (iph->ip_p == IPPROTO_ICMP) p.protocol = "ICMP";
                }

                {
                    std::lock_guard<std::mutex> lock(mtx_paquetes);
                    contador_paquetes++;
                    p.id = contador_paquetes;
                    historial_paquetes.push_back(p);
                }
                QMetaObject::invokeMethod(ventana, [ventana, p]() { ventana->agregarFilaDesdeHilo(p); }, Qt::QueuedConnection);
            }, reinterpret_cast<u_char*>(this));

            capturando = false;
        }).detach();
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
