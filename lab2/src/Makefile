all: simpletun simpletun_udp_task1 minivpn_task2.c

simpletun: simpletun.c
	gcc $^ -o $@

simpletun_udp_task1: simpletun_udp_task1.c
	gcc $^ -o $@

minivpn_task2: minivpn_task2.c
	gcc $^ -o $@ -lssl -lcrypto

clean:
	rm -f simpletun simpletun_udp_task1 minivpn_task2
