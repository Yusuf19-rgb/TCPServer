#include "TCPServer.h"
#include <iostream>
#include <string>
#include <sstream>

using namespace std;

const int MAX_BUFFER_SIZE = 4096; //Nilai konstanta dari besar buffer = dimana data tempat penyimpanan diterima.

TCPServer::TCPServer() { }

TCPServer::TCPServer(string ipAddress, int port)
	: listenerIPAddress(ipAddress), listenerPort(port) {
}

TCPServer::~TCPServer() {
	cleanupWinsock();	//Pembersihan Wissock saat server mati. 
}

//Berfungsi untuk memeriksa apakah dapat menginisialisasi Winsock & memulai server. 
bool TCPServer::initWinsock() {

	WSADATA data;
	WORD ver = MAKEWORD(2, 2);

	int wsInit = WSAStartup(ver, &data);

	if (wsInit != 0) {
		std::cout << "Error: Winsock tidak bisa diinisialisai." << endl;
		return false;
	}
	return true;
}


//Fungsi yang membuat soket Listening. 
SOCKET TCPServer::createSocket() {

	SOCKET listeningSocket = socket(AF_INET, SOCK_STREAM, 0);	//AF_INET = IPv4. 

	if (listeningSocket != INVALID_SOCKET) {

		sockaddr_in hint;		//Struktur bind IP address & port ke socket tertentu. 
		hint.sin_family = AF_INET;		//pemberian petunjuk untuk IPv4 addresses. 
		hint.sin_port = htons(listenerPort);	//memberi tahu pentuk pada port yang digunakan.
		inet_pton(AF_INET, listenerIPAddress.c_str(), &hint.sin_addr); 	//mengkonverter IP string to bytes & lalu diberi petunjuk. hint.sin_addr is the buffer. 

		int bindCheck = bind(listeningSocket, (sockaddr*)&hint, sizeof(hint));	//Bind listeningSocket pentunjuk struktur.

		if (bindCheck != SOCKET_ERROR) {			//pengecekan jika bind error:

			int listenCheck = listen(listeningSocket, SOMAXCONN);	//pemeberithuan socket listening. 
			if (listenCheck == SOCKET_ERROR) {
				return -1;
			}
		}

		else {
			return -1;
		}
		return listeningSocket;

	}
}
//Function akan melakukan pekerjaan utama server -> eval sockets & menerima data. 
void TCPServer::run() {

	char buf[MAX_BUFFER_SIZE];		//membuat buufer untuk menerima data clients. 
	SOCKET listeningSocket = createSocket();		//buat listening dari socket server. 

	while (true) {

		if (listeningSocket == INVALID_SOCKET) {
			break;
		}

		fd_set master;				//File descriptor menyipan semu socket.
		FD_ZERO(&master);			//file descriptor kosong. 

		FD_SET(listeningSocket, &master);		//penambhan listening dari socket file descriptor. 

		while (true) {

			fd_set copy = master;	// file baru descriptor karena file descriptor bisa hancur setiap saar 
			int socketCount = select(0, &copy, nullptr, nullptr, nullptr);	//Select() menetukan status socket & return socket "work". 

			for (int i = 0; i < socketCount; i++) {	//Server hanya bisa menerima koneksi & menerima pesan dari client. 

				SOCKET sock = copy.fd_array[i];					//Loop semua sockets melalui file descriptor, lalu identifikasi "active". 

				if (sock == listeningSocket) {				//Case 1: membuat koneksi baru.

					SOCKET client = accept(listeningSocket, nullptr, nullptr);		//menerima koneksi & identisikasi new client. 
					FD_SET(client, &master);		//penambahan koneksi baru ke daftar sockets.  
					string welcomeMsg = "\tSelamat Datang Guest.\n";			//Notify client saat mulai obrolan. 
					send(client, welcomeMsg.c_str(), welcomeMsg.size() + 1, 0);
					std::cout << "Guest Chat." << std::endl;			//Log connection pada sisi server. 

				}
				else {										//Case 2: pesan diterima.	

					ZeroMemory(buf, MAX_BUFFER_SIZE);		//bersihkan buffer sebelum mengirim data. 
					int bytesReceived = recv(sock, buf, MAX_BUFFER_SIZE, 0);	//menerima data kedalam buf & memasukkan bytes. 

					if (bytesReceived <= 0) {	//tidak ada pesa = drop client. 
						closesocket(sock);
						FD_CLR(sock, &master);	//Remove connection dari file director.
					}
					else {						//kirim pesan kelain client & tidap pakai listening socket. 

						for (int i = 0; i < master.fd_count; i++) {			//Loop melaui socket. 
							SOCKET outSock = master.fd_array[i];

							if (outSock != listeningSocket) {

								if (outSock == sock) {		//memberi tahu socket akan mengirim pesan.
									string msgSent = "Pesan terkirirm.";
									send(outSock, msgSent.c_str(), msgSent.size() + 1, 0);	//beri tahu client dapat diterima.	
								}
								else {						//memberi tahu saat ini buka pengirim -> maka pesan bisa diterima. 
									send(outSock, buf, bytesReceived, 0);		//kirim pesan ke current socket. 
								}
							}
						}
						std::cout << string(buf, 0, bytesReceived) << endl;			//Log pesan pada sisi server. 

					}

				}
			}
		}

	}
}

//Fungsi untuk mengirim client kebih spesifik. 
void TCPServer::sendMsg(int clientSocket, string msg) {
	send(clientSocket, msg.c_str(), msg.size() + 1, 0);
}

void TCPServer::cleanupWinsock() {
	WSACleanup();
}