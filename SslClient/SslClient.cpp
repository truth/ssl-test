// SslClient.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")          //add ws2_32.lib  
#pragma comment(lib, "openssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#define MAXBUF 1024  //注意宏定义格式
#pragma warning(disable : 4996)
#ifdef __cplusplus
extern "C"
{
#include <openssl/applink.c>
};
#endif
void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;

	cert = SSL_get_peer_certificate(ssl);
	if (cert != NULL) {
		printf("数字证书信息：\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("证书：%s\n", line);
		//free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("颁发者：%s\n", line);
		//free(line);
		X509_free(cert);
	}
	else
		printf("无证书信息！\n");
}
#define BigEndian 1
#define LittleEndian 0
inline bool BigEndianTest()
{
	unsigned int usData = 0x12345678;
	unsigned char *pucData = (unsigned char*)&usData;
	return *pucData == 0x78 ? LittleEndian : BigEndian;
}
#define Swap16(s) ((((s) & 0xff) << 8) | (((s) >> 8) & 0xff))
#define Swap32(l) (((l) >> 24) |(((l) &0x00ff0000) >> 8)|(((l) &0x0000ff00) << 8) |((l) << 24))
#define Swap64(ll) (((ll) >> 56) |(((ll) & 0x00ff000000000000LL) >> 40) |(((ll) & 0x0000ff0000000000LL) >> 24) |(((ll) & 0x000000ff00000000LL) >> 8)|(((ll) & 0x00000000ff000000LL) << 8) |(((ll) & 0x0000000000ff0000LL) << 24) |(((ll) & 0x000000000000ff00LL) << 40) |(((ll) << 56)))


#define BigEndian_16(s) BigEndianTest() ? s : Swap16(s)
#define LittleEndian_16(s) BigEndianTest() ? Swap16(s) : s
#define BigEndian_32(l) BigEndianTest() ? l : Swap32(l)
#define LittleEndian_32(l) BigEndianTest() ? Swap32(l) : l
#define BigEndian_64(ll) BigEndianTest() ? ll : Swap64(ll)
#define LittleEndian_64(ll) BigEndianTest() ? Swap64(ll) : ll
int main(int argc, char **argv)
{
	if (argc < 5) {
		printf("usage:\n  SslClient.exe 127.0.0.1 20000 ,big:%d\n", BigEndianTest());
		//exit(0);
	}
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	err = WSAStartup(wVersionRequested, &wsaData);
	if (err != 0)
	{
		printf("WSAStartup failed with error: %d\n", err);
		return 1;
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2)
	{
		printf("Could not find a usable version of Winsock.dll\n");
		WSACleanup();
		return 1;
	}
	else
	{
		printf("The Winsock 2.2 dll was found okay\n");
	}
	int sockfd, len;
	struct sockaddr_in dest;
	char buffer[MAXBUF + 1];
	SSL_CTX *ctx;//定义两个结构体数据https://www.cnblogs.com/274914765qq/p/4513236.html
	SSL *ssl;
	if (argc != 3)
	{
		printf("please input correct parameter,just like:\n./a.out ipaddress port\n");
		//exit(0);
	}
	SSL_library_init();
	OpenSSL_add_all_algorithms();
	SSL_load_error_strings();
	ctx = SSL_CTX_new(SSLv23_client_method());
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);//  将错误打印到FILE中
		exit(1);
	}
	//创建socket用于tcp通信
	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0))<0) {
		perror("socket");
		exit(errno);
	}
	printf("socket created\n");
	memset(&dest, 0, sizeof(struct sockaddr_in));
	dest.sin_family = AF_INET;
	dest.sin_port = htons(4443);// htons(atoi(argv[2]));//ascii to integer  字符串转化为整形数
										 //inet_aton 将字符串IP地址转化为32位的网络序列地址
	dest.sin_addr.s_addr = inet_addr("192.168.3.205"); //argv[1]
	if (dest.sin_addr.s_addr == 0)
	{
		printf("error ");
		exit(errno);
	}
	printf("socket created");
	//连接服务器
	if (connect(sockfd, (struct sockaddr*)&dest, sizeof(dest)) != 0)
	{
		perror("Connect ");
		exit(errno);
	}
	printf("server connected\n");

	//基于ctx产生一个新的ssl,建立SSL连接
	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	if (SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else {
		printf("connect with %s encryption\n", SSL_get_cipher(ssl));
		ShowCerts(ssl);
	}
	memset(buffer,0, MAXBUF + 1);
	//fgets(buffer, MAXBUF + 1, stdin);
	char authMsg[256] = "{\"Type\":\"Auth\",\"Payload\":{\"Version\":\"2\",\"MmVersion\":\"1.7\",\"User\":\"\",\"Password\":\"\",\"OS\":\"windows\",\"Arch\":\"amd64\",\"ClientId\":\"\"}}";

#ifdef WIN32
	unsigned __int64 packlen;
#else
	unsigned long long packlen;
#endif
	packlen = strlen(authMsg);
	packlen = LittleEndian_64(packlen);
	memcpy(buffer, &packlen, 8);
	memcpy(buffer + 8, authMsg, strlen(authMsg));
	len = SSL_write(ssl, buffer, strlen(authMsg)+8);
	if (len<0)
		printf("memsage send failure");
	else
		printf("memsage '%s',%d send success\n", authMsg,len);
	memset(buffer, 0, MAXBUF + 1);
	len = SSL_read(ssl, buffer, MAXBUF);
	if (len > 0)
	{
		unsigned long long ll;
		memcpy(&ll, buffer, 8);
		printf("receive msg's length:%lld,len:%d\n", ll, len);
		int leave = ll;
		
		do{
			len = SSL_read(ssl, buffer+(ll- leave), leave);
			leave -= len;
		} while (leave > 0);
		if (len > 0)
		{
			printf("receive %s,len:%d\n", buffer, len);
		}
	}
	else {
		printf("receive data failure ,error reason:\n%d :%s ", errno, strerror(errno));
		goto finish;
	}
finish:
	SSL_shutdown(ssl);
	SSL_free(ssl);
	closesocket(sockfd);
	SSL_CTX_free(ctx);
	return 0;
}
