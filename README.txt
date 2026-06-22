Requisitos para el Sistema
Antes de instalar, hay que asegurarse por tener:
•	Sistema operativo Ubuntu Linux (o distribución basada en Debian)
•	Acceso a internet para descargar las dependencias
•	Permisos de administrador (sudo)
Instalación Paso a Paso
Paso 1: Instalar las dependencias
Abre una terminal (Ctrl + Alt + T) y escribe el siguiente comando:
sudo apt update && sudo apt install build-essential cmake qtbase5-dev libpcap-dev
Cuando te pida la contraseña, escríbela y presiona Enter. Espera a que termine.

1.	Crea una carpeta nueva en tu escritorio. Podría llamarse SnifferApp.
2.	Copia dentro de esa carpeta los dos archivos siguientes:
•	RedesProyx.cpp (es el código fuente del programa)
•	CMakeLists.txt (son las instrucciones de compilación)

Paso 3: Compilar el proyecto
En la terminal, ve hasta tu carpeta y ejecuta estos comandos uno por uno:
•	cd ~/Desktop/SnifferApp
•	mkdir build
•	cd build
•	cmake ..
•	make

Paso 4: Para Ejecutar el programa
El sniffer como necesita permisos de administrador para acceder a la red. Se tiene que ejecutar este:
sudo ./SnifferApp

Es importante porque si no se ejecuta con sudo, el programa no va a poder abrir las interfaces de red y va a mostrar un error.
