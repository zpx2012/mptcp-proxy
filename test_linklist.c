#include <stdio.h>
#include "list.h"
#include <stdlib.h>
#include <string.h>


typedef unsigned int uint32_t;
typedef unsigned short int uint16_t;

struct dss_map_list_node {//index = tsn
	struct list_head list;
	uint32_t tsn;
	uint32_t dan;
	uint32_t dsn;
};

struct rcv_data_list_node {//index = dsn
	struct list_head list;
	uint32_t dsn;
	uint16_t len;
	char *payload;
};

struct list_index_helper {
	struct list_head list;
	uint32_t index;
};

void add_err_msg(char* msg) {
	printf("[Error] %s\n", msg);
}



int main()
{
/*
	//Test dss_map
	struct dss_map_list_node head;
	init_head_dsn_map_list(&head);
	insert_dsn_map_list(&head,1200,2200,3200);
	insert_dsn_map_list(&head,1000,2000,3000);
	insert_dsn_map_list(&head,1400,2400,3400);
	insert_dsn_map_list(&head,1300,2300,3300);
//test
	struct dss_map_list_node* rslt = NULL;
	find_dss_map_list(&head,1300,&rslt);
	find_dss_map_list(&head,1000,&rslt);

	print_dss_map_list(&head);

	del_dss_map_list(&head,1200);

	print_dss_map_list(&head);
*/
	//Test rcv_data_list
	struct rcv_data_list_node head;
	init_head_rcv_data_list(&head);

	char* s = "test string 1";
	int dsn = 220, len = strlen(s);
	insert_rcv_payload_list(&head, dsn, s, len);

	s = "this is second test string";
	dsn += len;
	len = strlen(s);
	insert_rcv_payload_list(&head, dsn, s, len);
	
	s = "this is the 3rd test string";
	dsn += len;
	len = strlen(s);
	insert_rcv_payload_list(&head, dsn, s, len);

	s = "turn down 4 what";
	dsn += len;
	len = strlen(s);
	insert_rcv_payload_list(&head, dsn, s, len);

	find_data_ack(&head);

    return 0;
}

