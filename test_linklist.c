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

int list_node_add_ordered(struct list_head *head, struct list_head *new_node, uint32_t index) {

	if (!head) {
		add_err_msg("list_node_add_ordered:null head");
		return -1;
	}

	struct list_index_helper *iter;
	list_for_each_entry(iter, head, list) {
		if (iter->index > index) {
			break;
		}
		else if (iter->index == index) {
			add_err_msg("list_node_add_ordered:iter->index == index");
			return -1;
		}
	}
	//insert before iter
	__list_add(new_node, iter->list.prev, &iter->list);
	return 0;
}

int init_head_dsn_map_list(struct dss_map_list_node *head) {

	if (!head) {
		add_err_msg("init_head_dsn_map_list:null head");
		return -1;
	}

	head->tsn = 0;
	head->dsn = 0;
	head->dan = 0;
	INIT_LIST_HEAD(&head->list);
	return 0;
}

int init_head_rcv_data_list(struct rcv_data_list_node *head) {

	if (!head) {
		add_err_msg("init_head_rcv_data_list:null head");
		return -1;
	}

	head->dsn = 0;
	head->len = 0;
	head->payload = NULL;
	INIT_LIST_HEAD(&head->list);
	return 0;
}


int insert_dsn_map_list(struct dss_map_list_node* head, uint32_t tsn, uint32_t dan, uint32_t dsn) {

	if (!head) {
		add_err_msg("insert_dsn_map_list:null head");
		return -1;
	}

	struct dss_map_list_node* new_node = malloc(sizeof(struct dss_map_list_node));
	new_node->tsn = tsn;
	new_node->dsn = dsn;
	new_node->dan = dan;
	list_node_add_ordered(&head->list, &new_node->list, tsn);

	return 0;
}



int find_dss_map_list(struct dss_map_list_node *head, uint32_t tsn, struct dss_map_list_node **result) {

	if (!head) {
		add_err_msg("find_dss_map_list:null head");
		return -1;
	}

	struct dss_map_list_node *iter;
	list_for_each_entry(iter, &head->list, list) {
		if (iter->tsn == tsn) {
			*result = iter;
			printf("found: tsn: %d, dsn: %d, dan %d\n", iter->tsn, iter->dsn, iter->dan);
			return 0;
		}
	}
	return -1;
}

int print_dss_map_list(struct dss_map_list_node *head){

	if (!head) {
		add_err_msg("print_dss_map_list:null head");
		return -1;
	}
	
	struct dss_map_list_node *iter;
	printf("dss map list:\ntsn dan dsn\n");
	list_for_each_entry(iter, &head->list, list) {
		printf("%d %d %d\n",iter->tsn,iter->dan,iter->dsn);
	}
	return 0;
}

int del_dss_map_list(struct dss_map_list_node *head, uint32_t index) {

	if (!head) {
		add_err_msg("del_dss_map_list:null head");
		return -1;
	}

	struct dss_map_list_node* result = NULL;
	find_dss_map_list(head, index, &result);
	if (result) {
		list_del(&result->list);
		free(result);
		printf("delete node: tsn = %d\n",result->tsn);
		return 0;
	}
	else {
		add_err_msg("del_dss_map_list: not found");
		return -1;
	}
}



int insert_rcv_payload_list(struct rcv_data_list_node *head, uint32_t dsn, const char *payload, uint16_t paylen) {

	if (!head) {
		add_err_msg("insert_rcv_payload_list:null head");
		return -1;
	}

	struct rcv_data_list_node* new_node = (struct rcv_data_list_node*)malloc(sizeof(struct rcv_data_list_node));
	new_node->dsn = dsn;
	new_node->len = paylen;
	new_node->payload = (char *)malloc(paylen);
	strncpy(new_node->payload, payload, paylen);

	list_node_add_ordered(&head->list, &new_node->list, dsn);

	return 0;
}


//find the maximum consecutive dsn in rcv_payload list 
uint32_t find_data_ack(struct rcv_data_list_node *head) {

	if (!head) {
		add_err_msg("find_data_ack:null head");
		return -1;
	}

	struct rcv_data_list_node *iter, *next;
	list_for_each_entry(iter, &head->list, list) {
		next = list_entry(iter->list.next, struct rcv_data_list_node, list);
		if ((iter->dsn + iter->len) != next->dsn)
			break;
		printf("find_data_ack: dsn:%d, len:%d\n", iter->dsn, iter->len);
	}
	return iter->dsn + iter->len;
}

int print_rcv_payload_list(struct rcv_data_list_node* head){
	
	if (!head) {
		add_err_msg("print_dss_map_list:null head");
		return -1;
	}
	
	struct rcv_data_list_node *iter;
	printf("rcv data list:\ndsn len data\n");
	list_for_each_entry(iter, &head->list, list) {
		printf("%d %d %s\n",iter->dsn,iter->len,iter->payload);
	}
	return 0;
}


int del_below_rcv_payload_list(struct rcv_data_list_node *head, uint32_t dan) {

	if (!head) {
		add_err_msg("del_below_rcv_payload:null head");
		return -1;
	}

	struct rcv_data_list_node *iter, *next;
	list_for_each_entry(iter, &head->list, list) {
		if (iter->dsn < dan) {
			list_del(&iter->list);
			free(iter->payload);
			free(iter);
			printf("delete node: dsn = %d\n",iter->dsn);
		}
	}
	return 0;
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

