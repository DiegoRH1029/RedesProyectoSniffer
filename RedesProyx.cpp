// --- PACKET SNIFFER - PROYECTO REDES ---
// Programa de captura y analisis profundo de paquetes de red.
// Utiliza libpcap para el modo promiscuo y Qt5 para la interfaz grafica.

// --- 1. LIBRERIAS (INCLUDES) ---
#include <QtWidgets>          // Todo lo necesario para dibujar la interfaz grafica en Qt
#include <vector>             // Para manejar arreglos dinamicos de memoria (historial)
#include <string>             // Para manipular cadenas de texto nativas de C++
#include <thread>             // Para ejecutar la captura en segundo plano sin congelar la app
#include <mutex>              // Para proteger variables compartidas entre los hilos (threads)
#include <fstream>            // Para crear y escribir archivos en el disco duro (Exportar CSV)
#include <pcap.h>             // Libreria core de Linux para capturar trafico de red

// Librerias de red de Linux (estructuras de datos para leer los bytes)
#include <netinet/in.h>       // Define familias de direcciones de red (AF_INET, etc)
#include <netinet/if_ether.h> // Define la cabecera Ethernet (Capa 2)
#include <netinet/ip.h>       // Define la cabecera IPv4 (Capa 3)
#include <netinet/tcp.h>      // Define la cabecera TCP (Capa 4)
#include <netinet/udp.h>      // Define la cabecera UDP (Capa 4)
#include <netinet/ip6.h>      // Define la cabecera IPv6 (Capa 3)
#include <arpa/inet.h>        // Funciones para convertir IPs de binario a texto legible

using namespace std;

// --- 2. ESTRUCTURAS (STRUCTS) ---

// Plantilla que usaremos para guardar la informacion util de cada paquete que atrapamos.
// En lugar de guardar basura, extraemos lo mas importante y lo metemos aqui.
struct PaqueteCapturado {
    int            id;          // Numero de paquete en la lista
    pcap_pkthdr    header;      // Metadatos de libpcap (hora en que llego, tamano en bytes)
    vector<u_char> data;        // Copia exacta de los bytes crudos del paquete
    string         src_ip;      // Direccion IP de origen ya convertida a texto
    string         dst_ip;      // Direccion IP de destino ya convertida a texto
    string         protocol;    // Nombre del protocolo en texto (TCP, UDP, ARP, etc)
    int            src_port;    // Puerto de salida
    int            dst_port;    // Puerto de llegada
    string         timestamp;   // Hora exacta en texto
    uint8_t        ttl;         // Tiempo de vida del paquete (Time To Live)
    uint16_t       ip_id;       // Identificador unico del paquete en la red
    uint8_t        tcp_flags;   // Banderas TCP crudas en 8 bits (SYN, ACK, FIN, etc)
    uint16_t       checksum;    // Suma de comprobacion para detectar errores
    int            link_offset; // Variable clave: 14 bytes si es Ethernet normal, 16 si es interfaz loopback
    int            ip_version;  // Etiqueta invisible: 4 si es IPv4, 6 si es IPv6, 0 si es otro (ARP)
};


// --- 3. VARIABLES GLOBALES ---

vector<PaqueteCapturado> historial_paquetes; // Arreglo que guarda todos los paquetes capturados
int     contador_paquetes = 0;               // Lleva la cuenta de cuantos llevamos
bool    capturando        = false;           // Bandera para saber si el motor esta activo
pcap_t *handle_global     = nullptr;         // Puntero maestro que mantiene la tarjeta de red abierta
std::mutex mtx_paquetes;                     // Candado de memoria para evitar que la interfaz y la captura choquen


// --- 4. PROTOTIPOS DE FUNCIONES ---

// Estas firmas le avisan al compilador que estas funciones existen y seran detalladas al final del archivo
string flags_tcp_str(uint8_t f);
QString filaTabla(QString titulo, QString valor, QString colorValor = "#d4d4d4");
QString generar_area_2(const PaqueteCapturado &p);
QString generar_area_3(const PaqueteCapturado &p);


// --- 5. ESQUELETO DE LA CLASE (DEFINICION) ---

class VentanaSniffer : public QMainWindow {
public:
    // Punteros a los componentes graficos de Qt
    QTableWidget *tablaArea1;
    QTextEdit *textoArea2;
    QTextEdit *textoArea3;
    
    QComboBox *comboInterfaces;
    QComboBox *comboProtocolo;
    QComboBox *comboDirIP;     
    QComboBox *comboDirPto;    
    QLineEdit *txtIP;
    QLineEdit *txtPuerto;
    
    QLineEdit *txtBusquedaRapida;
    QComboBox *comboFiltroVista;
    
    QPushButton *btnCapturar;
    QPushButton *btnPausar;    
    QPushButton *btnAnterior;
    QPushButton *btnSiguiente;
    QPushButton *btnExportar;
    QCheckBox   *chkAutoScroll; 

    std::thread hiloCaptura; // Objeto del hilo asincrono
    int link_offset;         // Tamano de la cabecera de la tarjeta actual
    bool pausado;            // Estado de la pausa

    // Prototipos de los metodos de esta clase (la logica fuerte va abajo)
    VentanaSniffer(); 
    void aplicarFiltroVista();
    void agregarFilaDesdeHilo(const PaqueteCapturado &p);
    bool iniciarCapturaHilo();
};


// --- 6. FUNCION PRINCIPAL (MAIN) ---

int main(int argc, char *argv[]) {
    // Inicializamos el motor grafico de Qt
    QApplication app(argc, argv);
    app.setStyle("Fusion"); // Obligamos a que el estilo base sea plano y moderno
    
    // Instanciamos la clase que definimos arriba
    VentanaSniffer ventana;
    ventana.show();
    
    // app.exec() se queda en un ciclo infinito escuchando los clicks del mouse del usuario
    return app.exec();
}


// --- 7. IMPLEMENTACION DE LOS METODOS DE LA CLASE ---

// Metodo Constructor de la ventana grafica (aqui dibujamos la interfaz)
VentanaSniffer::VentanaSniffer() {
    link_offset = 14; 
    pausado = false;
    
    setWindowTitle("Packet Sniffer Pro");
    resize(1300, 850);
    
    // Aplicamos CSS crudo para darle estilo oscuro moderno
    this->setStyleSheet(R"(
        QMainWindow { background-color: #1e1e1e; }
        QLabel { color: #cccccc; font-weight: normal; font-size: 11px; }
        QTableWidget { background-color: #1e1e1e; color: #d4d4d4; gridline-color: #3f3f46; border: 1px solid #3f3f46; border-radius: 4px; selection-background-color: #04395e; selection-color: #ffffff; outline: 0; font-family: 'Segoe UI', Arial; }
        QTableWidget::item:selected { background-color: #04395e; }
        QHeaderView::section { background-color: #2d2d30; color: #ffffff; font-weight: bold; border: 1px solid #3f3f46; padding: 4px; }
        QPushButton { background-color: #0e639c; color: #ffffff; font-weight: normal; border-radius: 4px; padding: 6px 15px; border: none; }
        QPushButton:hover { background-color: #1177bb; }
        QPushButton#btnIniciar { background-color: #238636; } 
        QPushButton#btnIniciar:hover { background-color: #2ea043; }
        QPushButton#btnDetener { background-color: #da3633; } 
        QPushButton#btnDetener:hover { background-color: #f85149; }
        QPushButton#btnPausar { background-color: #d29922; } 
        QPushButton#btnPausar:hover { background-color: #e3a92b; }
        QPushButton#btnPausar:disabled { background-color: #30363d; color: #8b949e; }
        QPushButton#btnExport { background-color: #21262d; border: 1px solid #30363d; } 
        QPushButton#btnExport:hover { background-color: #30363d; }
        QLineEdit, QComboBox { background-color: #3c3c3c; color: #cccccc; border: 1px solid #3f3f46; border-radius: 3px; padding: 4px; }
        QLineEdit:focus, QComboBox:focus { border: 1px solid #0e639c; }
        QComboBox QAbstractItemView { background-color: #252526; color: #cccccc; selection-background-color: #094771; }
        QTextEdit { background-color: #1e1e1e; color: #d4d4d4; border: 1px solid #3f3f46; border-radius: 4px; padding: 8px; }
        QCheckBox { color: #cccccc; spacing: 5px; }
        QCheckBox::indicator { width: 15px; height: 15px; }
        QSplitter::handle { background-color: #3f3f46; }
        QSplitter::handle:horizontal { width: 2px; }
        QSplitter::handle:vertical { height: 2px; }
        QScrollBar:vertical { border: none; background: #1e1e1e; width: 12px; }
        QScrollBar::handle:vertical { background: #424242; min-height: 20px; border-radius: 6px; }
        QScrollBar::handle:vertical:hover { background: #4f4f4f; }
        QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0px; }
        QScrollBar:horizontal { border: none; background: #1e1e1e; height: 12px; }
        QScrollBar::handle:horizontal { background: #424242; min-width: 20px; border-radius: 6px; }
        QScrollBar::handle:horizontal:hover { background: #4f4f4f; }
        QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal { width: 0px; }
    )");

    QWidget *centralWidget = new QWidget(this);
    QVBoxLayout *layoutPrincipal = new QVBoxLayout(centralWidget);

    // Barra 1: Controles para iniciar la captura en la tarjeta fisica
    QHBoxLayout *layoutTop = new QHBoxLayout();
    
    // Obtenemos dinamicamente que tarjetas de red tiene tu compu
    comboInterfaces = new QComboBox(); comboInterfaces->setMinimumWidth(110);
    char errbuf[PCAP_ERRBUF_SIZE]; pcap_if_t *alldevs, *d;
    if (pcap_findalldevs(&alldevs, errbuf) == 0) {
        for (d = alldevs; d; d = d->next) comboInterfaces->addItem(d->name);
        pcap_freealldevs(alldevs);
    }

    comboProtocolo = new QComboBox(); 
    comboProtocolo->addItems({"TODOS", "Solo IPv4", "Solo IPv6", "Solo TCP", "Solo UDP", "Solo ICMP", "Solo ARP"});
    
    comboDirIP = new QComboBox(); comboDirIP->addItems({"Cualquier IP", "IP Origen", "IP Destino"});
    txtIP = new QLineEdit(); txtIP->setPlaceholderText("192.168.1.1"); txtIP->setFixedWidth(110);
    comboDirPto = new QComboBox(); comboDirPto->addItems({"Cualquier Pto", "Pto Origen", "Pto Destino"});
    txtPuerto = new QLineEdit(); txtPuerto->setPlaceholderText("Ej: 80"); txtPuerto->setFixedWidth(60);

    btnCapturar = new QPushButton("NUEVA CAPTURA"); btnCapturar->setObjectName("btnIniciar");
    btnPausar = new QPushButton("PAUSAR"); btnPausar->setObjectName("btnPausar"); btnPausar->setEnabled(false); 
    btnExportar = new QPushButton("CSV"); btnExportar->setObjectName("btnExport");

    layoutTop->addWidget(comboInterfaces); layoutTop->addSpacing(10);
    layoutTop->addWidget(comboProtocolo); layoutTop->addSpacing(10);
    layoutTop->addWidget(comboDirIP); layoutTop->addWidget(txtIP); layoutTop->addSpacing(10);
    layoutTop->addWidget(comboDirPto); layoutTop->addWidget(txtPuerto); layoutTop->addStretch();
    layoutTop->addWidget(btnCapturar); layoutTop->addWidget(btnPausar); layoutTop->addWidget(btnExportar);
    
    layoutPrincipal->addLayout(layoutTop);

    // Barra 2: Controles logicos para buscar en la lista ya procesada
    QHBoxLayout *layoutFiltroVista = new QHBoxLayout();
    txtBusquedaRapida = new QLineEdit(); txtBusquedaRapida->setPlaceholderText("Buscar por IP, Puerto, Protocolo..."); txtBusquedaRapida->setMinimumWidth(300);
    comboFiltroVista = new QComboBox();
    comboFiltroVista->addItems({"Mostrar Todos", "Solo IPv4", "Solo IPv6", "Solo TCP", "Solo UDP", "Solo ICMP", "Solo ARP"});
    
    layoutFiltroVista->addWidget(new QLabel("BUSCAR EN CAPTURADOS:"));
    layoutFiltroVista->addWidget(txtBusquedaRapida);
    layoutFiltroVista->addSpacing(20);
    layoutFiltroVista->addWidget(new QLabel("FILTRO RAPIDO:"));
    layoutFiltroVista->addWidget(comboFiltroVista);
    layoutFiltroVista->addStretch();
    layoutPrincipal->addLayout(layoutFiltroVista);

    // Paneles: Division vertical principal
    QSplitter *splitterPrincipal = new QSplitter(Qt::Vertical);
    
    QWidget *topWidget = new QWidget();
    QVBoxLayout *topLayout = new QVBoxLayout(topWidget);
    topLayout->setContentsMargins(0, 0, 0, 0);

    // Creacion de la tabla y ajuste de columnas
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

    // Botones de navegacion de tabla
    QHBoxLayout *layoutFlechas = new QHBoxLayout();
    btnAnterior = new QPushButton("ANTERIOR");
    btnSiguiente = new QPushButton("SIGUIENTE");
    chkAutoScroll = new QCheckBox("Auto-Scroll");
    chkAutoScroll->setChecked(true); 

    layoutFlechas->addWidget(btnAnterior);
    layoutFlechas->addWidget(btnSiguiente);
    layoutFlechas->addSpacing(20);
    layoutFlechas->addWidget(chkAutoScroll);
    layoutFlechas->addStretch();
    topLayout->addLayout(layoutFlechas);

    splitterPrincipal->addWidget(topWidget);

    // Paneles de texto inferiores
    QSplitter *splitterAbajo = new QSplitter(Qt::Horizontal);
    textoArea2 = new QTextEdit(); textoArea2->setReadOnly(true); 
    textoArea3 = new QTextEdit(); textoArea3->setReadOnly(true); 
    splitterAbajo->addWidget(textoArea2);
    splitterAbajo->addWidget(textoArea3);
    
    splitterPrincipal->addWidget(splitterAbajo);
    splitterPrincipal->setSizes({500, 300}); 
    
    layoutPrincipal->addWidget(splitterPrincipal);
    setCentralWidget(centralWidget);


    // Conexiones de Eventos
    
    // Cada que el usuario escribe, llamamos a la funcion de filtrado
    connect(txtBusquedaRapida, &QLineEdit::textChanged, this, &VentanaSniffer::aplicarFiltroVista);
    connect(comboFiltroVista, &QComboBox::currentTextChanged, this, &VentanaSniffer::aplicarFiltroVista);

    // Cuando el usuario toca una fila, jalamos los datos crudos y generamos el HTML
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

    // Subir en la tabla ignorando filas que esten ocultas por el filtro
    connect(btnAnterior, &QPushButton::clicked, [this]() {
        int f = tablaArea1->currentRow();
        while (f > 0) {
            f--;
            if (!tablaArea1->isRowHidden(f)) { tablaArea1->setCurrentCell(f, 0); break; }
        }
    });

    // Bajar en la tabla ignorando ocultas
    connect(btnSiguiente, &QPushButton::clicked, [this]() {
        int f = tablaArea1->currentRow();
        while (f < tablaArea1->rowCount() - 1) {
            f++;
            if (!tablaArea1->isRowHidden(f)) { tablaArea1->setCurrentCell(f, 0); break; }
        }
    });

    // Boton de Capturar: Mata la captura existente o arranca una limpia de cero
    connect(btnCapturar, &QPushButton::clicked, [this]() {
        if (capturando || pausado) {
            capturando = false; pausado = false;
            if (handle_global) pcap_breakloop(handle_global); // Rompe el loop de la tarjeta
            if (hiloCaptura.joinable()) hiloCaptura.join();   // Espera a que muera el hilo
            if (handle_global) { pcap_close(handle_global); handle_global = nullptr; }

            btnCapturar->setText("NUEVA CAPTURA"); btnCapturar->setObjectName("btnIniciar"); 
            this->setStyleSheet(this->styleSheet()); 
            btnPausar->setEnabled(false); btnPausar->setText("PAUSAR");
            comboInterfaces->setEnabled(true); comboProtocolo->setEnabled(true);
            comboDirIP->setEnabled(true); txtIP->setEnabled(true);
            comboDirPto->setEnabled(true); txtPuerto->setEnabled(true);
        } else {
            tablaArea1->setRowCount(0); historial_paquetes.clear(); 
            contador_paquetes = 0; pausado = false;
            
            if (iniciarCapturaHilo()) {
                btnCapturar->setText("DETENER"); btnCapturar->setObjectName("btnDetener"); 
                this->setStyleSheet(this->styleSheet()); 
                btnPausar->setEnabled(true); btnPausar->setText("PAUSAR");
                comboInterfaces->setEnabled(false); comboProtocolo->setEnabled(false);
                comboDirIP->setEnabled(false); txtIP->setEnabled(false);
                comboDirPto->setEnabled(false); txtPuerto->setEnabled(false);
            }
        }
    });

    // Boton de Pausar: Detiene la escucha pero no borra la tabla actual
    connect(btnPausar, &QPushButton::clicked, [this]() {
        if (capturando && !pausado) {
            capturando = false; pausado = true;
            if (handle_global) pcap_breakloop(handle_global);
            if (hiloCaptura.joinable()) hiloCaptura.join(); 
            if (handle_global) { pcap_close(handle_global); handle_global = nullptr; }
            btnPausar->setText("REANUDAR");
        } else if (pausado) {
            if (iniciarCapturaHilo()) { pausado = false; btnPausar->setText("PAUSAR"); }
        }
    });

    // Crea un archivo en disco e imprime los datos separados por comas
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
            QMessageBox::information(this, "Exito", "CSV guardado.");
        }
    });
}


// Recorre toda la tabla y esconde/muestra filas segun lo escrito por el usuario
void VentanaSniffer::aplicarFiltroVista() {
    QString textoBusqueda = txtBusquedaRapida->text().toLower();
    QString protocoloFiltro = comboFiltroVista->currentText();

    std::lock_guard<std::mutex> lock(mtx_paquetes);

    for (int i = 0; i < tablaArea1->rowCount(); ++i) {
        if (i >= historial_paquetes.size()) break; 
        const PaqueteCapturado &p = historial_paquetes[i];
        
        bool coincideTexto = textoBusqueda.isEmpty();
        bool coincideProtocolo = true;

        if (!coincideTexto) {
            for (int col = 0; col < 8; ++col) {
                QTableWidgetItem *item = tablaArea1->item(i, col);
                if (item && item->text().toLower().contains(textoBusqueda)) {
                    coincideTexto = true; break;
                }
            }
        }

        // Filtro estricto evaluando nuestra etiqueta invisible de version IP
        if (protocoloFiltro != "Mostrar Todos") {
            if (protocoloFiltro == "Solo TCP" && p.protocol != "TCP") coincideProtocolo = false;
            else if (protocoloFiltro == "Solo UDP" && p.protocol != "UDP") coincideProtocolo = false;
            else if (protocoloFiltro == "Solo ICMP" && p.protocol != "ICMP") coincideProtocolo = false;
            else if (protocoloFiltro == "Solo ARP" && p.protocol != "ARP") coincideProtocolo = false;
            else if (protocoloFiltro == "Solo IPv4" && p.ip_version != 4) coincideProtocolo = false;
            else if (protocoloFiltro == "Solo IPv6" && p.ip_version != 6) coincideProtocolo = false;
        }

        tablaArea1->setRowHidden(i, !(coincideTexto && coincideProtocolo));
    }
}


// Este metodo es invocado por el hilo asincrono cuando atrapa un paquete
void VentanaSniffer::agregarFilaDesdeHilo(const PaqueteCapturado &p) {
    int row = tablaArea1->rowCount();
    tablaArea1->insertRow(row);
    
    QColor colorFondo(30, 30, 30);       
    QColor colorTexto(212, 212, 212);    

    if (p.protocol == "TCP") { colorFondo = QColor(14, 99, 156, 70); colorTexto = QColor(255, 255, 255); } 
    else if (p.protocol == "UDP") { colorFondo = QColor(32, 159, 216, 50); colorTexto = QColor(255, 255, 255); } 
    else if (p.protocol == "ICMP") { colorFondo = QColor(199, 70, 50, 70); colorTexto = QColor(255, 255, 255); }
    else if (p.protocol == "ARP") { colorFondo = QColor(220, 220, 170, 50); colorTexto = QColor(200, 200, 200); }
    else if (p.protocol == "IPv6") { colorFondo = QColor(197, 134, 192, 50); colorTexto = QColor(255, 255, 255); }

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
    
    // Revisamos si el nuevo paquete deberia ocultarse inmediatamente segun el filtro
    QString textoBusqueda = txtBusquedaRapida->text().toLower();
    QString protocoloFiltro = comboFiltroVista->currentText();
    bool ocultar = false;
    
    if (!textoBusqueda.isEmpty()) {
        bool found = false;
        for(int col=0; col<8; ++col) { if (de[col].toLower().contains(textoBusqueda)) { found = true; break; } }
        if (!found) ocultar = true;
    }
    
    if (!ocultar && protocoloFiltro != "Mostrar Todos") {
        if (protocoloFiltro == "Solo TCP" && p.protocol != "TCP") ocultar = true;
        else if (protocoloFiltro == "Solo UDP" && p.protocol != "UDP") ocultar = true;
        else if (protocoloFiltro == "Solo ICMP" && p.protocol != "ICMP") ocultar = true;
        else if (protocoloFiltro == "Solo ARP" && p.protocol != "ARP") ocultar = true;
        else if (protocoloFiltro == "Solo IPv4" && p.ip_version != 4) ocultar = true;
        else if (protocoloFiltro == "Solo IPv6" && p.ip_version != 6) ocultar = true;
    }
    
    tablaArea1->setRowHidden(row, ocultar);
    
    if (chkAutoScroll->isChecked() && !ocultar) {
        tablaArea1->scrollToBottom();
    }
}


// Arranca la comunicacion con el driver del kernel
bool VentanaSniffer::iniciarCapturaHilo() {
    QString dev = comboInterfaces->currentText();
    char errbuf[PCAP_ERRBUF_SIZE];
    
    // Abre la tarjeta seleccionada. 65536 bytes de snaplen, modo promiscuo activado (1)
    handle_global = pcap_open_live(dev.toStdString().c_str(), 65536, 1, 1000, errbuf);
    if (!handle_global) { QMessageBox::critical(this, "Error", QString("Fallo al abrir: %1").arg(errbuf)); return false; }

    // Evaluacion del tipo de interfaz para evitar crasheos (Segmentation Faults)
    int linkType = pcap_datalink(handle_global);
    if (linkType == DLT_EN10MB) link_offset = 14; // Ethernet comun
    else if (linkType == DLT_LINUX_SLL) link_offset = 16; // Interfaz loopback o any en Linux
    else { QMessageBox::warning(this, "Error", "Interfaz no Ethernet detectada."); pcap_close(handle_global); handle_global = nullptr; return false; }

    // Generador de cadenas de filtro BPF
    QStringList partesFiltro;
    QString protoCombo = comboProtocolo->currentText();
    QString bpfProto = "";
    
    // Traduccion de las opciones visuales a codigo que el kernel entienda
    if (protoCombo == "Solo IPv4") bpfProto = "ip";
    else if (protoCombo == "Solo IPv6") bpfProto = "ip6";
    else if (protoCombo == "Solo TCP") bpfProto = "tcp";
    else if (protoCombo == "Solo UDP") bpfProto = "udp";
    else if (protoCombo == "Solo ICMP") bpfProto = "icmp or icmp6";
    else if (protoCombo == "Solo ARP") bpfProto = "arp";

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
    
    // Compila el texto a opcodes binarios y se los inyecta a la tarjeta
    if (!filtroStr.isEmpty() && pcap_compile(handle_global, &fcode, filtroStr.toStdString().c_str(), 1, PCAP_NETMASK_UNKNOWN) >= 0) {
        pcap_setfilter(handle_global, &fcode);
    }

    capturando = true;
    
    // Declaracion del hilo secundario (Thread)
    hiloCaptura = std::thread([this]() {
        
        // pcap_loop secuestra este hilo infinitamente atrapando paquetes
        // Cuando llega uno, ejecuta esta funcion lambda ("[]()")
        pcap_loop(handle_global, -1, [](u_char *user, const pcap_pkthdr *hdr, const u_char *pkt) {
            
            // Casteamos la ventana principal para poder acceder a sus variables
            VentanaSniffer *ventana = reinterpret_cast<VentanaSniffer*>(user);
            
            // Si el paquete es mas pequeno que el encabezado base, es basura, lo ignoramos
            if (hdr->caplen < (unsigned)(ventana->link_offset)) return; 

            // Formateo de la hora UNIX a texto legible
            char tbuf[20]; struct tm *tm_i = localtime(&hdr->ts.tv_sec); strftime(tbuf, sizeof(tbuf), "%H:%M:%S", tm_i);
            string ts = string(tbuf) + "." + to_string(hdr->ts.tv_usec / 1000);

            // Creamos un molde limpio e inicializamos sus valores por defecto
            PaqueteCapturado p;
            p.link_offset = ventana->link_offset; p.header = *hdr; 
            p.data = vector<u_char>(pkt, pkt + hdr->caplen);
            p.protocol = "Otro"; p.src_port = 0; p.dst_port = 0; p.tcp_flags = 0; p.checksum = 0;
            p.timestamp = ts; p.ttl = 0; p.ip_id = 0; p.ip_version = 0; 

            // Para saber que protocolo es, leemos el campo "EtherType" en los bytes 12-13 (si es Ethernet)
            // Usamos ntohs (Network To Host Short) para ajustar el orden de bytes del procesador
            uint16_t ether_type = 0;
            if (ventana->link_offset == 14) ether_type = ntohs(((struct ether_header*)pkt)->ether_type);
            else if (ventana->link_offset == 16) ether_type = ntohs(*(uint16_t*)(pkt + 14));

            // Si es 0x0806, el protocolo nativo es ARP
            if (ether_type == 0x0806 && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ether_arp))) {
                p.protocol = "ARP";
                p.ip_version = 0; 
                struct ether_arp *arp = (struct ether_arp *)(pkt + ventana->link_offset);
                p.src_ip = QString::asprintf("%d.%d.%d.%d", arp->arp_spa[0], arp->arp_spa[1], arp->arp_spa[2], arp->arp_spa[3]).toStdString();
                p.dst_ip = QString::asprintf("%d.%d.%d.%d", arp->arp_tpa[0], arp->arp_tpa[1], arp->arp_tpa[2], arp->arp_tpa[3]).toStdString();
            
            // Si es 0x86DD, es trafico moderno IPv6
            } else if (ether_type == 0x86DD && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ip6_hdr))) {
                p.ip_version = 6; 
                p.protocol = "IPv6"; 
                struct ip6_hdr *ip6 = (struct ip6_hdr *)(pkt + ventana->link_offset);
                char src_str[INET6_ADDRSTRLEN], dst_str[INET6_ADDRSTRLEN];
                
                // inet_ntop convierte binario crudo IPv6 a la representacion comun con dos puntos (::)
                inet_ntop(AF_INET6, &ip6->ip6_src, src_str, sizeof(src_str));
                inet_ntop(AF_INET6, &ip6->ip6_dst, dst_str, sizeof(dst_str));
                p.src_ip = src_str;
                p.dst_ip = dst_str;

                // Verificamos si adentro del IPv6 viene un TCP o un UDP
                if (ip6->ip6_nxt == IPPROTO_TCP && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ip6_hdr) + 20)) {
                    p.protocol = "TCP";
                    struct tcphdr *th = (struct tcphdr*)(pkt + ventana->link_offset + sizeof(ip6_hdr));
                    p.src_port = ntohs(th->source); p.dst_port = ntohs(th->dest);
                    p.tcp_flags = (uint8_t)th->th_flags;
                } else if (ip6->ip6_nxt == IPPROTO_UDP && hdr->caplen >= (unsigned)(ventana->link_offset + sizeof(ip6_hdr) + 8)) {
                    p.protocol = "UDP";
                    struct udphdr *uh = (struct udphdr*)(pkt + ventana->link_offset + sizeof(ip6_hdr));
                    p.src_port = ntohs(uh->source); p.dst_port = ntohs(uh->dest);
                } else if (ip6->ip6_nxt == IPPROTO_ICMPV6 || ip6->ip6_nxt == 58) {
                    p.protocol = "ICMP";
                }

            // Si es 0x0800, es trafico estandar IPv4
            } else if (ether_type == 0x0800 && hdr->caplen >= (unsigned)(ventana->link_offset + 20)) {
                p.ip_version = 4; 
                struct ip *iph = (struct ip*)(pkt + ventana->link_offset); 
                p.src_ip = inet_ntoa(iph->ip_src); // inet_ntoa convierte a texto los 4 bloques
                p.dst_ip = inet_ntoa(iph->ip_dst);
                p.ttl = iph->ip_ttl; p.ip_id = ntohs(iph->ip_id);
                
                // Calculamos el tamano dinamico del encabezado IP (IHL * 4 bytes)
                int ihl = iph->ip_hl * 4;

                // Evaluamos los protocolos de transporte que viajan encima de IP
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

            // Guardamos el paquete en la memoria principal bloqueando a los demas hilos
            {
                std::lock_guard<std::mutex> lock(mtx_paquetes);
                contador_paquetes++;
                p.id = contador_paquetes;
                historial_paquetes.push_back(p);
            }
            
            // Le indicamos al hilo de Qt (Interfaz Grafica) que procese la escritura a la pantalla
            QMetaObject::invokeMethod(ventana, [ventana, p]() { ventana->agregarFilaDesdeHilo(p); }, Qt::QueuedConnection);
            
        }, reinterpret_cast<u_char*>(this)); // Pasamos 'this' (la ventana) al callback
    });
    
    return true;
}


// --- 8. IMPLEMENTACION DE FUNCIONES AUXILIARES GLOBALES ---

// Devuelve una cadena de texto en HTML dependiendo del byte evaluado
string flags_tcp_str(uint8_t f) {
    string s;
    if (f & 0x02) s += "SYN "; // Peticion de conexion
    if (f & 0x10) s += "ACK "; // Acuse de recibo
    if (f & 0x01) s += "FIN "; // Cierre de conexion
    if (f & 0x04) s += "RST "; // Reseteo forzado
    if (f & 0x08) s += "PSH "; // Push de datos
    if (f & 0x20) s += "URG "; // Dato urgente
    return s.empty() ? "NONE" : s;
}

// Crea una fila de tabla en HTML con colores tipo Visual Studio Code
QString filaTabla(QString titulo, QString valor, QString colorValor) {
    return QString("<tr><td style='padding: 4px 10px; background-color: #252526; border-bottom: 1px solid #333333; color: #858585; font-weight: bold; width: 130px;'>%1</td>"
                   "<td style='padding: 4px 10px; background-color: #1e1e1e; border-bottom: 1px solid #333333; color: %2;'>%3</td></tr>")
           .arg(titulo, colorValor, valor);
}

// Arma la tabla central que desglosa capa por capa (Enlace, Red y Transporte)
QString generar_area_2(const PaqueteCapturado &p) {
    QString out = QString("<h3 style='color:#cccccc; margin-bottom: 5px; font-weight: normal;'>Analisis del Paquete #%1</h3>").arg(p.id);
    out += "<table width='100%' cellspacing='0' cellpadding='0' style='font-family: \"Segoe UI\", sans-serif; font-size: 12px;'>";

    // Capa 2: Decodificando Ethernet (Solo si el offset es 14)
    if (p.link_offset == 14 && p.data.size() >= 14) {
        auto *eth = (const ether_header*)p.data.data();
        out += "<tr><td colspan='2' style='background-color: #333333; color: #ffffff; padding: 5px; font-weight: bold;'>[Capa 2] ETHERNET</td></tr>";
        out += filaTabla("MAC Origen", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]), "#b5cea8");
        out += filaTabla("MAC Destino", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]), "#b5cea8");
        
        uint16_t et = ntohs(eth->ether_type);
        QString tipoStr = (et==0x0800) ? "IPv4" : (et==0x0806) ? "ARP" : (et==0x86DD) ? "IPv6" : "Otro";
        out += filaTabla("EtherType", QString("0x%1 (%2)").arg(QString::asprintf("%04X", et), tipoStr), "#dcdcaa");
    }

    // Capa 3 para casos especiales como ARP
    if (p.protocol == "ARP" && p.data.size() >= (size_t)(p.link_offset + sizeof(ether_arp))) {
        auto *arp = (const struct ether_arp*)(p.data.data() + p.link_offset);
        out += "<tr><td colspan='2' style='background-color: #51504f; color: #ffffff; padding: 5px; font-weight: bold; margin-top: 10px;'>[Capa 3] ARP</td></tr>";
        
        uint16_t op = ntohs(arp->arp_op);
        QString opStr = (op == 1) ? "Request" : (op == 2) ? "Reply" : QString("Otro (%1)").arg(op);
        out += filaTabla("Operacion", opStr, "#dcdcaa");
        out += filaTabla("IP Origen", QString::fromStdString(p.src_ip), "#ce9178");
        out += filaTabla("MAC Origen", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp->arp_sha[0],arp->arp_sha[1],arp->arp_sha[2],arp->arp_sha[3],arp->arp_sha[4],arp->arp_sha[5]), "#b5cea8");
        out += filaTabla("IP Destino", QString::fromStdString(p.dst_ip), "#ce9178");
        out += filaTabla("MAC Destino", QString::asprintf("%02x:%02x:%02x:%02x:%02x:%02x", arp->arp_tha[0],arp->arp_tha[1],arp->arp_tha[2],arp->arp_tha[3],arp->arp_tha[4],arp->arp_tha[5]), "#b5cea8");
        
    // Capa 3 y 4 para trafico IPv6
    } else if (p.ip_version == 6 && p.data.size() >= (size_t)(p.link_offset + sizeof(ip6_hdr))) {
        auto *ip6 = (const struct ip6_hdr*)(p.data.data() + p.link_offset);
        out += "<tr><td colspan='2' style='background-color: #0e639c; color: #ffffff; padding: 5px; font-weight: bold; margin-top: 10px;'>[Capa 3] IPv6</td></tr>";
        out += filaTabla("IP Origen", QString::fromStdString(p.src_ip), "#c586c0");
        out += filaTabla("IP Destino", QString::fromStdString(p.dst_ip), "#c586c0");
        out += filaTabla("Hop Limit", QString::number(ip6->ip6_hops), "#d4d4d4");
        out += filaTabla("Next Header", QString::number(ip6->ip6_nxt), "#dcdcaa");
        out += filaTabla("Longitud Payload", QString("%1 bytes").arg(ntohs(ip6->ip6_plen)), "#d4d4d4");
        
        if (p.protocol == "TCP" && p.data.size() >= (size_t)(p.link_offset + sizeof(ip6_hdr) + 20)) {
            auto *th = (const tcphdr*)(p.data.data() + p.link_offset + sizeof(ip6_hdr));
            out += "<tr><td colspan='2' style='background-color: #1177bb; color: #ffffff; padding: 5px; font-weight: bold;'>[Capa 4] TCP</td></tr>";
            out += filaTabla("Puerto Origen", QString::number(p.src_port), "#4fc1ff");
            out += filaTabla("Puerto Destino", QString::number(p.dst_port), "#4fc1ff");
            out += filaTabla("Flags TCP", QString("[%1]").arg(flags_tcp_str(p.tcp_flags).c_str()), "#dcdcaa");
        } else if (p.protocol == "UDP" && p.data.size() >= (size_t)(p.link_offset + sizeof(ip6_hdr) + 8)) {
            auto *uh = (const udphdr*)(p.data.data() + p.link_offset + sizeof(ip6_hdr));
            out += "<tr><td colspan='2' style='background-color: #209fd8; color: #ffffff; padding: 5px; font-weight: bold;'>[Capa 4] UDP</td></tr>";
            out += filaTabla("Puerto Origen", QString::number(p.src_port), "#4fc1ff");
            out += filaTabla("Puerto Destino", QString::number(p.dst_port), "#4fc1ff");
        }
        
    // Capa 3 y 4 para trafico IPv4
    } else if (p.ip_version == 4 && p.data.size() >= (size_t)(p.link_offset + 20)) {
        auto *iph = (const struct ip*)(p.data.data() + p.link_offset);
        int ihl = iph->ip_hl * 4;
        
        out += "<tr><td colspan='2' style='background-color: #0e639c; color: #ffffff; padding: 5px; font-weight: bold; margin-top: 10px;'>[Capa 3] IPv4</td></tr>";
        out += filaTabla("IP Origen", QString::fromStdString(p.src_ip), "#ce9178");
        out += filaTabla("IP Destino", QString::fromStdString(p.dst_ip), "#ce9178");
        out += filaTabla("Protocolo", QString("%1 (%2)").arg(iph->ip_p).arg(p.protocol.c_str()), "#dcdcaa");
        out += filaTabla("TTL", QString::number(p.ttl), "#d4d4d4");
        out += filaTabla("ID Paquete", QString("0x%1").arg(QString::asprintf("%04X", p.ip_id)), "#d4d4d4");
        
        if (p.protocol == "TCP" && p.data.size() >= (size_t)(p.link_offset + ihl + 20)) {
            auto *th = (const tcphdr*)(p.data.data() + p.link_offset + ihl);
            out += "<tr><td colspan='2' style='background-color: #1177bb; color: #ffffff; padding: 5px; font-weight: bold;'>[Capa 4] TCP</td></tr>";
            out += filaTabla("Puerto Origen", QString::number(p.src_port), "#4fc1ff");
            out += filaTabla("Puerto Destino", QString::number(p.dst_port), "#4fc1ff");
            out += filaTabla("Secuencia", QString::number(ntohl(th->seq)), "#d4d4d4");
            out += filaTabla("Acuse (Ack)", QString::number(ntohl(th->ack_seq)), "#d4d4d4");
            out += filaTabla("Flags TCP", QString("[%1]").arg(flags_tcp_str(p.tcp_flags).c_str()), "#dcdcaa");
            
        } else if (p.protocol == "UDP" && p.data.size() >= (size_t)(p.link_offset + ihl + 8)) {
            auto *uh = (const udphdr*)(p.data.data() + p.link_offset + ihl);
            out += "<tr><td colspan='2' style='background-color: #209fd8; color: #ffffff; padding: 5px; font-weight: bold;'>[Capa 4] UDP</td></tr>";
            out += filaTabla("Puerto Origen", QString::number(p.src_port), "#4fc1ff");
            out += filaTabla("Puerto Destino", QString::number(p.dst_port), "#4fc1ff");
            out += filaTabla("Longitud", QString("%1 bytes").arg(ntohs(uh->len)), "#d4d4d4");
            
        } else if (p.protocol == "ICMP") {
            const u_char *ic = p.data.data() + p.link_offset + ihl;
            out += "<tr><td colspan='2' style='background-color: #c74632; color: white; padding: 5px; font-weight: bold;'>[Capa 4] ICMP</td></tr>";
            out += filaTabla("Tipo", QString::number(ic[0]), "#dcdcaa");
            out += filaTabla("Codigo", QString::number(ic[1]), "#dcdcaa");
        }
    }
    out += "</table>";
    return out;
}

// Extrae el paquete en puro hexadecimal y sus representaciones ASCII seguras
QString generar_area_3(const PaqueteCapturado &p) {
    QString out = QString("<h3 style='color:#cccccc; margin-bottom: 5px; font-weight: normal;'>Volcado Hexadecimal - Paquete #%1</h3>").arg(p.id);
    out += "<table width='100%' cellspacing='0' cellpadding='3' style='font-family: \"Consolas\", monospace; font-size: 12px;'>";
    out += "<tr style='background-color: #252526; color: #569cd6; text-align: left;'>"
           "<th style='width: 60px;'>Offset</th><th>Hexadecimal</th><th style='width: 150px;'>ASCII</th></tr>";

    size_t n = p.data.size();
    for (size_t i = 0; i < n; i += 16) {
        QString offset = QString("%1").arg(i, 4, 16, QChar('0')).toUpper();
        QString asciiPart, hexPart;
        
        for (size_t j = 0; j < 16; j++) {
            if (j == 8) hexPart += "&nbsp;&nbsp;"; // Doble espacio para separar bloques de 8 bytes
            if (i+j < n) {
                unsigned char c = p.data[i+j];
                hexPart += QString("%1 ").arg(c, 2, 16, QChar('0')).toUpper();
                // Limpieza del ASCII para evitar desastres visuales en HTML
                char asciiChar = (c >= 32 && c < 127) ? c : '.';
                if (asciiChar == '<') asciiPart += "&lt;";
                else if (asciiChar == '>') asciiPart += "&gt;";
                else if (asciiChar == '&') asciiPart += "&amp;";
                else asciiPart += asciiChar;
            } else {
                hexPart += "&nbsp;&nbsp;&nbsp;";
            }
        }
        
        QString bgColor = (i % 32 == 0) ? "#1e1e1e" : "#252526"; 
        out += QString("<tr style='background-color: %1;'><td style='color:#569cd6;'>%2</td><td style='color:#d4d4d4; letter-spacing: 1px;'>%3</td><td style='color:#ce9178;'>%4</td></tr>").arg(bgColor, offset, hexPart, asciiPart);
    }
    out += "</table>";
    return out;
}