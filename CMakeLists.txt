cmake_minimum_required(VERSION 3.10)
project(PacketSnifferGUI)

# Usar el estándar C++17
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Habilitar el manejo automático de archivos Qt
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Buscar la librería de Qt para hacer ventanas
find_package(Qt5 COMPONENTS Widgets REQUIRED)

# Buscar la librería pcap
find_library(PCAP_LIBRARY pcap)

# Crear el ejecutable apuntando a tu código
add_executable(SnifferApp RedesProyx.cpp)

# Conectar el ejecutable con Qt y libpcap
target_link_libraries(SnifferApp Qt5::Widgets ${PCAP_LIBRARY})
