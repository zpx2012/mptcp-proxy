//*****************************************************
//*****************************************************
//
// mangleman.h 
// Project: mptcp_proxy
//
//*****************************************************
//*****************************************************
//
// GEORG HAMPEL - Bell Labs/NJ/USA: All Rights Reserved
//
//*****************************************************
//*****************************************************
//***************************************************** 


//++++++++++++++++++++++++++++++++++++++++++++++++
//Filter: set verdict
//  sets verdict, data_update_flag and size_update_flag
//++++++++++++++++++++++++++++++++++++++++++++++++
extern void set_verdict(size_t verdict, size_t data_update, size_t size_update);

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_reset_output()
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_reset_output();

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_data_reset_input(): Used when DSS option on input carries R
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_data_reset_input();


//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_reset_input()
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_reset_input();

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_timestamp()
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_timestamp();

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_conn_level_data()
//  updates connection level data
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_conn_level_data();

//++++++++++++++++++++++++++++++++++++++++++++++++
//determine_thruway_subflow()
//  thruway refers to packet returned to netfilter
//++++++++++++++++++++++++++++++++++++++++++++++++
void determine_thruway_subflow();

//++++++++++++++++++++++++++++++++++++++++++++++++
//void find_side_acks()
//++++++++++++++++++++++++++++++++++++++++++++++++
void find_side_acks();

//++++++++++++++++++++++++++++++++++++++++++++++++
//int update_thruway()
//  returns 0 if packet terminates here
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_thruway_subflow();

//++++++++++++++++++++++++++++++++++++++++++++++++
//send_side_acks()
//++++++++++++++++++++++++++++++++++++++++++++++++
void send_side_acks();

//++++++++++++++++++++++++++++++++++++++++++++++++
//set_dss_and_prio()
//++++++++++++++++++++++++++++++++++++++++++++++++
void set_dss_and_prio();

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_packet()
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_packet_output();

//++++++++++++++++++++++++++++++++++++++++++++++++
//update_subflow_level_data()
//++++++++++++++++++++++++++++++++++++++++++++++++
void update_subflow_level_data();

//++++++++++++++++++++++++++++++++++++++++++++++++
//process_dss() 
//++++++++++++++++++++++++++++++++++++++++++++++++
void process_dss();

//++++++++++++++++++++++++++++++++++++++++++++++++
//process_prio() 
//++++++++++++++++++++++++++++++++++++++++++++++++
void process_prio();

//++++++++++++++++++++++++++++++++++++++++++++++++
//process_remove_addr() 
//++++++++++++++++++++++++++++++++++++++++++++++++
void process_remove_addr();

//++++++++++++++++++++++++++++++++++++++++++++++++
//int update_subflow_control_plane()
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_subflow_control_plane();

//++++++++++++++++++++++++++++++++++++++++++++++++
//int update_session_control_plane()
//++++++++++++++++++++++++++++++++++++++++++++++++
int update_session_control_plane();



//++++++++++++++++++++++++++++++++++++++++++++++++
//eval states
//++++++++++++++++++++++++++++++++++++++++++++++++
extern int mangle_packet();

int Send(int sockfd, const void * buf, size_t len, int flags);

int set_dss();

int subflow_send_data(struct subflow* sfl, unsigned char *buf, uint16_t len, uint32_t dan, uint32_t dsn);

int split_browser_data_send();

int list_node_add_ordered(struct list_head *head, struct list_head *new_node, uint32_t index);

int init_head_dsn_map_list(struct dss_map_list_node *head);

int init_head_rcv_data_list(struct rcv_data_list_node *head);

int insert_dsn_map_list(struct dss_map_list_node * head, uint32_t tsn, uint32_t dan, uint32_t dsn);

int find_dss_map_list(struct dss_map_list_node * head, uint32_t tsn, struct dss_map_list_node ** result);

int print_dss_map_list(struct dss_map_list_node * head);

int del_dss_map_list(struct dss_map_list_node * head, uint32_t index);

int insert_rcv_payload_list(struct rcv_data_list_node * head, uint32_t dan, uint32_t dsn, const unsigned char * payload, uint16_t paylen);

uint32_t find_data_ack(struct rcv_data_list_node *head);

int print_rcv_payload_list(struct rcv_data_list_node * head);

int del_below_rcv_payload_list(struct rcv_data_list_node * head, uint32_t dan);


