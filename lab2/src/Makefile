all: simpletun simpletun_udp_task1 minivpn_task2 minivpn_task3_server minivpn_task3_client minivpn_task6_server minivpn_task6_client

simpletun: simpletun.c
	gcc $^ -o $@

simpletun_udp_task1: simpletun_udp_task1.c
	gcc $^ -o $@

minivpn_task2: minivpn_task2.c openssl_utils.h
	gcc $^ -o $@ -lssl -lcrypto

minivpn_task3_server: minivpn_task3_server.c openssl_utils.h
	gcc $^ -o $@ -lssl -lcrypto

minivpn_task3_client: minivpn_task3_client.c openssl_utils.h
	gcc $^ -o $@ -lssl -lcrypto

minivpn_task6_server: minivpn_task6_server.c openssl_utils.h
	gcc $^ -o $@ -lssl -lcrypto

minivpn_task6_client: minivpn_task6_client.c openssl_utils.h
	gcc $^ -o $@ -lssl -lcrypto

clean:
	rm -f simpletun simpletun_udp_task1 minivpn_task2 minivpn_task3_server minivpn_task3_client minivpn_task6_server minivpn_task6_client
