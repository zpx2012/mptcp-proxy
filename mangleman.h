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

int mangle_datatransfer_session_output();

int mangle_datatransfer_session_input();

int mangle_datatransfer_subflow_output();

int mangle_datatransfer_subflow_input();

int Send(int sockfd, const void * buf, size_t len, int flags);

int set_dss();

int subflow_send_data(struct subflow* sfl, unsigned char *buf, uint16_t len, uint32_t dan, uint32_t dsn);

int ship_data_to_browser(struct session * sess, uint32_t dan, uint32_t dsn, unsigned char * payload, int paylen);

int split_browser_data_send();

int init_head_snd_map_list(struct snd_map_list *head);

int init_head_rcv_buff_list(struct rcv_buff_list *head);

int insert_snd_map_list(struct snd_map_list * head, uint32_t tsn, uint32_t dan, uint32_t dsn);

int find_snd_map_list(struct snd_map_list * head, uint32_t tsn, struct snd_map_list ** result);

int print_snd_map_list(struct snd_map_list * head);

int del_below_snd_map_list(struct snd_map_list * head, uint32_t index);

int insert_rcv_buff_list(struct rcv_buff_list * head, uint32_t dan, uint32_t dsn, const unsigned char * payload, uint16_t paylen);

uint32_t find_data_ack(struct rcv_buff_list *head);

int print_rcv_buff_list(struct rcv_buff_list * head);

int add_ip_white_list_array(uint32_t ip);

int is_in_ip_white_list_array(uint32_t ip);

int del_below_rcv_buff_list(struct rcv_buff_list * head, uint32_t dan);


