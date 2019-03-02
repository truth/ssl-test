// SslTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"


#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")          //add ws2_32.lib  
#pragma comment(lib, "openssl.lib")
#pragma comment(lib, "libcrypto.lib")
#pragma comment(lib, "libssl.lib")
#define MAXBUF 1024
#pragma warning(disable : 4996)
#ifdef __cplusplus
extern "C"
{
#include <openssl/applink.c>
};
#endif
/************���ڱ��ĵ�********************************************
*filename: ssl-server.c
*purpose: ��ʾ���� OpenSSL ����л��� IP��� SSL ����ͨѶ�ķ��������Ƿ�����������
* �Ƽ�վ�ھ��˵ļ���Ͻ������죡��л�п�Դǰ���Ĺ��ף�
*********************************************************************/
int main(int argc, char **argv)
{
	if (argc < 5) {
		printf("usage:\n  SslTest.exe 20000 2 127.0.0.1 .\cacert.pem .\privkey.pem\n");
		exit(0);
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

	SOCKET sockSrv = socket(AF_INET, SOCK_DGRAM, 0); //����һ��socket���;
	if (sockSrv == INVALID_SOCKET)
	{
		printf("socket() fail:%d\n", WSAGetLastError());
		return -2;
	}

	int sockfd, new_fd;
	socklen_t len;
	struct sockaddr_in my_addr, their_addr;
	unsigned int myport, lisnum;
	char buf[MAXBUF + 1];
	SSL_CTX *ctx;

	if (argv[1])
		myport = atoi(argv[1]);
	else
		myport = 7838;

	if (argv[2])
		lisnum = atoi(argv[2]);
	else
		lisnum = 2;

	/* SSL ���ʼ�� */
	SSL_library_init();
	/* �������� SSL �㷨 */
	OpenSSL_add_all_algorithms();
	/* �������� SSL ������Ϣ */
	SSL_load_error_strings();
	/* �� SSL V2 �� V3 ��׼���ݷ�ʽ����һ�� SSL_CTX ���� SSL Content Text */
	ctx = SSL_CTX_new(SSLv23_server_method());
	/* Ҳ������ SSLv2_server_method() �� SSLv3_server_method() ������ʾ V2 �� V3��׼ */
	if (ctx == NULL) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* �����û�������֤�飬 ��֤���������͸��ͻ��ˡ� ֤��������й�Կ */
	printf("certificate:%s\n", argv[4]);
	if (SSL_CTX_use_certificate_file(ctx, argv[4], SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* �����û�˽Կ */
	printf("privateKey:%s\n", argv[5]);
	if (SSL_CTX_use_PrivateKey_file(ctx, argv[5], SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}
	/* ����û�˽Կ�Ƿ���ȷ */
	if (!SSL_CTX_check_private_key(ctx)) {
		ERR_print_errors_fp(stdout);
		exit(1);
	}

	/* ����һ�� socket ���� */
	if ((sockfd = socket(PF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket");
		exit(1);
	}
	else
		printf("socket created\n");

	memset(&my_addr, 0,sizeof(my_addr));
	my_addr.sin_family = PF_INET;
	my_addr.sin_port = htons(myport);
	if (argv[3])
		my_addr.sin_addr.s_addr = inet_addr(argv[3]);
	else
		my_addr.sin_addr.s_addr = INADDR_ANY;

	if (bind(sockfd, (struct sockaddr *) &my_addr, sizeof(struct sockaddr))
		== -1) {
		perror("bind");
		exit(1);
	}
	else
		printf("binded\n");

	if (listen(sockfd, lisnum) == -1) {
		perror("listen");
		exit(1);
	}
	else
		printf("begin listen\n");
	while (1) {
		SSL *ssl;
		len = sizeof(struct sockaddr);
		/* �ȴ��ͻ��������� */
		if ((new_fd = accept(sockfd, (struct sockaddr *) &their_addr, &len)) == -1) {
			perror("accept");
			exit(errno);
		}
		else
			printf("server: got connection from %s, port %d, socket %d\n",
				inet_ntoa(their_addr.sin_addr),
				ntohs(their_addr.sin_port), new_fd);

		/* ���� ctx ����һ���µ� SSL */
		ssl = SSL_new(ctx);
		/* �������û��� socket ���뵽 SSL */
		SSL_set_fd(ssl, new_fd);
		/* ���� SSL ���� */
		if (SSL_accept(ssl) == -1) {
			perror("accept");
			closesocket(new_fd);
			break;
		}

		/* ��ʼ����ÿ���������ϵ������շ� */
		//  strcpy(buf, "hello world!");

		/* ���տͻ��˵���Ϣ */
		memset(buf,0, MAXBUF + 1);
		len = SSL_read(ssl, buf, MAXBUF);
		if (len > 0)
			printf("memsage '%s' received successful! total %d bytes data received\n",
				buf, len);
		else
			printf
			("receive memsage failure��error number %d��error reason:'%s'\n",
				errno, strerror(errno));
		//������Ϣ
		memset(buf, 0, MAXBUF + 1);
		fgets(buf, MAXBUF + 1, stdin);
		len = SSL_write(ssl, buf, strlen(buf));
		if (len <= 0) {
			printf
			("memsage'%s'send failure��error number:%d��error reason:'%s'\n",
				buf, errno, strerror(errno));
			goto finish;
		}
		else
			printf("memsage '%s' send successful��total send %d bytes data��\n", buf, len);

		/* ����ÿ���������ϵ������շ����� */
	finish:
		/* �ر� SSL ���� */
		SSL_shutdown(ssl);
		/* �ͷ� SSL */
		SSL_free(ssl);
		/* �ر� socket */
		closesocket(new_fd);
	}

	/* �رռ����� socket */
	closesocket(sockfd);
	/* �ͷ� CTX */
	SSL_CTX_free(ctx);

	WSACleanup();
	return 0;
}
