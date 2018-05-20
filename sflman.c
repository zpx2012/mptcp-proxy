//*****************************************************
//*****************************************************
//
// sflman.c 
// Project: mptcp_proxy
//
//*****************************************************
//*****************************************************
//*****************************************************
//*****************************************************
//
// sflman.c 
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


#include "mptcpproxy_util.h"
#include "tp_heap.h"
#include "mptcp_proxy.h"
#include "packman.h"
#include "sflman.h"
#include "sessman.h"
#include "conman.h"
#include "mangleman.h"
#include "map_table.h"

struct subflow *sfl_hash = NULL;
struct subflow_index *sfl_index_hash = NULL;
struct subflow_pnt *sfl_pnt_hash = NULL;

//++++++++++++++++++++++++++++++++++++++++++++++++
//SUFLOW: int subflow_completed(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
inline int subflow_completed(struct subflow *sfl) {
	//can return 1 if session's TX map indicates that there
	// are no outstanding data
	return sn_smaller(sfl->highest_sn_loc, sfl->highest_an_loc);
}

int create_new_subflow_output_slave(){
	
		//create socket
	int sockfd;
	struct fourtuple ft_sfl;
	struct fourtuple* ft = &ft_sfl;
	ft_sfl.ip_loc = packd.ft.ip_loc;
	ft_sfl.ip_rem = packd.ft.ip_rem;
	ft_sfl.prt_rem = packd.ft.prt_rem;
	ft_sfl.prt_loc = 0;

	create_subflow_socket(ft,&sockfd);

	//find local addrid. If not there, create it
	unsigned i = 0;
	unsigned char addr_id_loc;
	struct session* sess = packd.sess;
	while(i < sess->pA_addrid_loc.number && ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->addr != ft->ip_loc) i++;

	if( i == sess->pA_addrid_loc.number || ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->addr != ft->ip_loc) {

		struct addrid *addrid_loc = malloc(sizeof(struct addrid));
		addrid_loc->addr = ft->ip_loc;
		sess->largest_addr_id_loc++;
		addrid_loc->id = sess->largest_addr_id_loc;
		add_pnt_pA(&sess->pA_addrid_loc, addrid_loc);
		addr_id_loc = addrid_loc->id;
	} else {
		addr_id_loc = ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->id;
	}


	snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: finding local addrid=%u", addr_id_loc );
	add_msg(msg_buf);

	//find remote addrid. Must be there.
	i = 0;
	while(i < sess->pA_addrid_rem.number && ((struct addrid*) get_pnt_pA(&sess->pA_addrid_rem, i))->addr != ft->ip_rem) i++;
	unsigned char addr_id_rem = ((struct addrid*) get_pnt_pA(&sess->pA_addrid_rem, i))->id;

	snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: finding remote addrid=%u", addr_id_rem );
	add_msg(msg_buf);
	
	//Check if ft->ip_loc is supported (if not return 0)
	int found = 0;
	for(unsigned i=0; i<if_tab1.nb_if; ++i) {
		if(ft->ip_loc == if_tab1.ipaddr[i]) {
			found = 1;
			break;
		}
	}
	if(found==0){
		char buf_ip[34];
		sprintIPaddr(buf_ip, ft->ip_loc);
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: local IP=%s not found - ABORT", buf_ip);
		add_msg(msg_buf);
		return 0;
	}

	//Scan all subflows of sess:
	//      Check if subflow has at least one different value in loc IP, rem IP, loc PRT or rem PRT
	//      Check if (remIP, remPort) is contained in at least one subflow.
	//           If not, check if (rem IP, rem PRT) is contained in ADD_ADDR list
	//      	If not, return 0

	struct subflow *curr_sfl;
	int same = 0;
	int dst_known = 0;
	for(unsigned i=0; i < sess->pA_sflows.number; i++) {
		curr_sfl = (struct subflow*) get_pnt_pA(&sess->pA_sflows, i); 

		if( memcmp( &curr_sfl->ft, &ft, sizeof(struct fourtuple)) == 0) same = 1;
		if( (curr_sfl->ft.ip_rem == ft->ip_rem) &&  (curr_sfl->ft.prt_rem == ft->prt_rem) ) dst_known = 1;
	}

 	if(same == 1) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: fourtuple already exists - ABORT");
		add_msg(msg_buf);
		return 0;
	}
 	if(dst_known == 0) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: ip_rem or prt_rem not known - ABORT");
		add_msg(msg_buf);
		return 0;
	}


	//create subflow, add to session
	struct subflow  *sfl1;
	sfl1 = create_subflow(
		 ft,
		 addr_id_loc+1,//addr id loc, the currently number of subflows in this session is sued for this purpose
		 addr_id_rem,//addr id remote
		 sockfd,
		 PRE_SYN_SENT,
		 CANDIDATE,
		 0,//loc ISN
		 0,//rem ISN
		 0,//loc offset
		 0,//remote offset
		 get_rand(),
		 0,//rand number rem: comes later	
		 0);
	if(sfl1 == NULL) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: returns NULL when creating subflow");
		add_msg(msg_buf);
		return 0;
	}

	add_subflow_to_session(sfl1, sess);
	sess->slav_subflow = sfl1;

	call_connect(sfl1);
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: initiate_cand_subflow()
//++++++++++++++++++++++++++++++++++++++++++++++++
int initiate_cand_subflow(struct session *sess, struct fourtuple *ft, unsigned char backup) {
	//reset conman state
	sess->conman_state = '0';

	//find local addrid. If not there, create it
	unsigned i = 0;
	unsigned char addr_id_loc;
	while(i < sess->pA_addrid_loc.number && ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->addr != ft->ip_loc) i++;

	if( i == sess->pA_addrid_loc.number || ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->addr != ft->ip_loc) {

		struct addrid *addrid_loc = malloc(sizeof(struct addrid));
		addrid_loc->addr = ft->ip_loc;
		sess->largest_addr_id_loc++;
		addrid_loc->id = sess->largest_addr_id_loc;
		add_pnt_pA(&sess->pA_addrid_loc, addrid_loc);
		addr_id_loc = addrid_loc->id;
	} else {
		addr_id_loc = ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->id;
	}


	snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: finding local addrid=%u", addr_id_loc );
	add_msg(msg_buf);

	//find remote addrid. Must be there.
	i = 0;
	while(i < sess->pA_addrid_rem.number && ((struct addrid*) get_pnt_pA(&sess->pA_addrid_rem, i))->addr != ft->ip_rem) i++;
	unsigned char addr_id_rem = ((struct addrid*) get_pnt_pA(&sess->pA_addrid_rem, i))->id;

	snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: finding remote addrid=%u", addr_id_rem );
	add_msg(msg_buf);

	//create tcp option: option sent during initial subflow + TP_JOIN
	unsigned char opt_buf[60];
	uint16_t opt_len = sess->init_top_len;
	memmove(opt_buf, sess->init_top_data, opt_len);

	if(sess->timestamp_flag) set_timestamps(opt_buf, opt_len, sess->tsval, 0, 1);


	//attach TP_JOIN + pad
	uint32_t rand_nmb_loc = get_rand();
	create_MPjoin_syn(opt_buf, &opt_len, sess->token_rem, rand_nmb_loc, addr_id_loc, backup);


	uint16_t npad = pad_options_buffer(opt_buf, opt_len);
	opt_len = npad;

	//check if length is ok:
	if(opt_len > 40) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: option length=%u is too long - ABORT", opt_len);
		add_msg(msg_buf);
		return 0;
	}


	//Check if ft->ip_loc is supported (if not return 0)
	int found = 0;
	for(unsigned i=0; i<if_tab1.nb_if; ++i) {
		if(ft->ip_loc == if_tab1.ipaddr[i]) {
			found = 1;
			break;
		}
	}
	if(found==0){
		char buf_ip[34];
		sprintIPaddr(buf_ip, ft->ip_loc);
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: local IP=%s not found - ABORT", buf_ip);
		add_msg(msg_buf);
		return 0;
	}

	//Scan all subflows of sess:
	//      Check if subflow has at least one different value in loc IP, rem IP, loc PRT or rem PRT
	//      Check if (remIP, remPort) is contained in at least one subflow.
	//           If not, check if (rem IP, rem PRT) is contained in ADD_ADDR list
	//      	If not, return 0

	struct subflow *curr_sfl;
	int same = 0;
	int dst_known = 0;
	for(unsigned i=0; i < sess->pA_sflows.number; i++) {
		curr_sfl = (struct subflow*) get_pnt_pA(&sess->pA_sflows, i); 

		if( memcmp( &curr_sfl->ft, &ft, sizeof(struct fourtuple)) == 0) same = 1;
		if( (curr_sfl->ft.ip_rem == ft->ip_rem) &&  (curr_sfl->ft.prt_rem == ft->prt_rem) ) dst_known = 1;
	}

 	if(same == 1) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: fourtuple already exists - ABORT");
		add_msg(msg_buf);
		return 0;
	}
 	if(dst_known == 0) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: ip_rem or prt_rem not known - ABORT");
		add_msg(msg_buf);
		return 0;
	}


	//create subflow, add to session
	// overwrite = 1 in case subflow already exists
	uint32_t ISSNloc = create_issn();

	struct subflow  *sfl1;
	sfl1 = create_subflow(
		 ft,
		 addr_id_loc,//addr id loc, the currently number of subflows in this session is sued for this purpose
		 addr_id_rem,//addr id remote
		 0,
		 SYN_SENT,
		 CANDIDATE,
		 ISSNloc,//loc ISN
		 0,//rem ISN
		 sess->idsn_loc - ISSNloc,//loc offset
		 0,//remote offset
		 rand_nmb_loc,
		 0,//rand number rem: comes later	
		 0);
	if(sfl1 == NULL) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: returns NULL when creating subflow");
		add_msg(msg_buf);
		return 0;
	}
	sfl1->highest_sn_loc = ISSNloc;		
	sfl1->highest_an_loc = ISSNloc;	
	sfl1->highest_an_loc = 0;
	sfl1->tsecr = 0;


	//check subflow sack support based on copied header
	sfl1->sack_flag = find_tcp_option(opt_buf, opt_len, 4);
	

	add_subflow_to_session(sfl1, sess);

	uint16_t pack_len;
	create_packet(raw_buf, &pack_len, 
		ft, 
		htonl(ISSNloc),//ISSN src 
		0,//ISSN rem
		2,//SYN
		htons(sess->init_window_loc), 
		opt_buf, 
		opt_len);

	snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: sending SYN packet, sfl_id=%zu, sess_id=%zu", sfl1->index, sess->index);
	add_msg(msg_buf);

	//send syn packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(ft->ip_rem))<0) {
		
		delete_subflow(ft);
		snprintf(msg_buf,MAX_MSG_LENGTH, "initiate_cand_subflow: send_raw_packet returns error, sfl_id=%zu, sess_id=%zu", sfl1->index, sess->index);
		add_msg(msg_buf);
		return 0;
	}


	if(PRINT_FILE) load_print_line(packd.id, 3, sess->index, sfl1->index, 
		0, 0, 2, //rex/len/flags
		0, 0, //ssn/san
		0, 0, 
		0, packd.sack_in, 0, packd.sack_in, 1);


	//create retransmit event and add to queue (1 sec, 0 usec)
	create_rex_event(ft, sfl1->tcp_state, raw_buf, pack_len);
	
	return 1;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//int create_new_subflow_input()
//  creates new subflow when hook=1 and TPjoin
//++++++++++++++++++++++++++++++++++++++++++++++++
int create_new_subflow_input(struct session *sess, unsigned char addr_id_rem, unsigned char backup, uint32_t rand_nmb_rem) {
	//create subflow, add to session
	struct fourtuple ft = packd.ft;
	
	//find remote addrid. If not there, create it
	unsigned i = 0;
	while(i < sess->pA_addrid_rem.number && ((struct addrid*) get_pnt_pA(&sess->pA_addrid_rem, i))->addr != ft.ip_rem) i++;

	if(i == sess->pA_addrid_rem.number || ((struct addrid*) get_pnt_pA(&sess->pA_addrid_rem, i))->addr != ft.ip_rem) {
		struct addrid *addrid_rem = malloc(sizeof(struct addrid));
		addrid_rem->addr = ft.ip_rem;
		addrid_rem->id = addr_id_rem;
		add_pnt_pA(&sess->pA_addrid_rem, addrid_rem);
	}
	snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: finding remote addrid=%u", addr_id_rem );
	add_msg(msg_buf);


	//find local addrid. Must be there.
	i = 0;
	while(i < sess->pA_addrid_loc.number && ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->addr != ft.ip_loc) i++;
	unsigned char addr_id_loc = ((struct addrid*) get_pnt_pA(&sess->pA_addrid_loc, i))->id;

	snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: finding local addrid=%u", addr_id_loc );
	add_msg(msg_buf);


	//create tcp option: option sent during initial subflow + TP_JOIN
	unsigned char opt_buf[60];
	uint16_t opt_len = sess->init_top_len;

	memmove(opt_buf, sess->init_top_data, opt_len);
	uint32_t tsecr = 0;
	if(sess->timestamp_flag) { 
		tsecr = get_timestamp(packd.buf + packd.pos_thead + 20, packd.tcplen-20, 0);//copy TSval to TSecr
		set_timestamps(opt_buf, opt_len, sess->tsval, tsecr, 1);
	}

	//attach TP_JOIN + pad
	uint32_t rand_nmb_loc = get_rand();
	uint32_t mac[5];
	create_mac(sess->key_loc, sess->key_rem, rand_nmb_loc, rand_nmb_rem, mac);
 	create_MPjoin_synack(opt_buf, &opt_len, mac, rand_nmb_loc, addr_id_loc, backup);

	uint16_t npad = pad_options_buffer(opt_buf, opt_len);
	opt_len = npad;

	//check if length is ok:
	if(opt_len > 40) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: option length=%u is too long - ABORT", opt_len);
		add_msg(msg_buf);
		return 0;
	}

	//Scan all subflows of sess:
	//      Check if subflow has at least one different value in loc IP, rem IP, loc PRT or rem PRT
	//      Check if (locIP, locPort) is contained in at least one subflow.
	//           If not, check if (loc IP, loc PRT) is contained in ADD_ADDR list
	//      	If not, return 0

	struct subflow *curr_sfl;
	int same = 0;
	int src_known = 0;


	for(unsigned i=0; i < sess->pA_sflows.number; i++) {
		curr_sfl = (struct subflow*) get_pnt_pA(&sess->pA_sflows, i); 

		if( memcmp( &curr_sfl->ft, &ft, sizeof(struct fourtuple)) == 0) same = 1;
		if( (curr_sfl->ft.ip_loc == ft.ip_loc) &&  (curr_sfl->ft.prt_loc == ft.prt_loc) ) src_known = 1;

	}
 	if(same == 1) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: fourtuple already exists - ABORT");
		add_msg(msg_buf);
		return 0;
	}
 	if(src_known == 0) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: ip_loc=%lu, prt_loc=%u not known - ABORT", (long unsigned int) ft.ip_loc, ft.prt_rem);
		add_msg(msg_buf);
		return 0;
	}

	uint32_t ISSNloc = create_issn();
	uint32_t ISSNrem = ntohl(packd.tcph->th_seq);
	struct subflow  *sfl1;
	sfl1 = create_subflow(
		 &ft,
		 addr_id_loc,//address id loc
		 addr_id_rem,//address id rem
		 0,
		 SYN_REC,
		 CANDIDATE,
		 ISSNloc,//loc ISN
		 ISSNrem,//rem ISN
		 sess->idsn_loc - ISSNloc,//loc offset
		 sess->idsn_rem - ISSNrem,//remote offset
		 rand_nmb_loc,
		 rand_nmb_rem,
		 0);//overwrite
	if(sfl1 == NULL) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: returns NULL when creating subflow");
		add_msg(msg_buf);
		return 0;
	}

	add_subflow_to_session(sfl1, sess);
	if(sess->timestamp_flag) sfl1->tsecr = tsecr;

	//create syn/ack packet
	uint16_t pack_len;
	sfl1->highest_sn_loc = ISSNloc;
	sfl1->highest_an_loc = ISSNloc;
	sfl1->highest_an_rem = sfl1->highest_sn_rem + 1;
	sfl1->sack_flag = find_tcp_option(packd.buf+packd.pos_thead+20, packd.tcplen-20, 4) && DO_SACK;

	create_packet(raw_buf, &pack_len, 
		&ft, 
		htonl(ISSNloc),//ISSN src 
		htonl(sfl1->highest_an_rem),
		18,//SYN/ACK
		htons(sess->init_window_loc), 
		opt_buf, 
		opt_len);


	snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: sending SYN/ACK packet, sfl_id=%zu, sess_id=%zu", sfl1->index, sess->index);
	add_msg(msg_buf);

	//send syn packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(ft.ip_rem))<0) {
		delete_subflow(&ft);
		snprintf(msg_buf,MAX_MSG_LENGTH, "create_new_subflow_input: send_raw_packet returns error");
		add_msg(msg_buf);
		return 0;
	}

	if(PRINT_FILE) load_print_line(packd.id, 3, sess->index, sfl1->index, 
		0, 0, 18, 
		0, 1, 
		0, 0, 
		0, packd.sack_in, 0, packd.sack_in, 1);

	packd.sfl = sfl1;	

	//create retransmit event and add to queue (1 sec, 0 usec)
	create_rex_event(&ft, sfl1->tcp_state, raw_buf, pack_len);

	return 1;

}


//++++new

void* connect_handler(void *args) {

	struct sockaddr_in sin_rem;
	struct connect_args* p_cn;

	pthread_detach(pthread_self());

	p_cn = (struct connect_args*)args;

	//connect to dst
	sin_rem.sin_addr.s_addr = p_cn->ip_dst_n;
	sin_rem.sin_family = AF_INET;
	sin_rem.sin_port = p_cn->port_dst_n;

	//connect to remote server
	if (connect(p_cn->sockfd, (struct sockaddr *)&sin_rem, sizeof(sin_rem)) < 0) {
		printf("connect failed. Error");
		pthread_exit(NULL);
	}

	snprintf(msg_buf, MAX_MSG_LENGTH, "connect_handler:connect success return");
	add_msg(msg_buf);
	pthread_exit(NULL);
}


int create_subflow_socket(struct fourtuple* ft, int *p_sockfd) {

	int sockfd;
	struct sockaddr_in sin_loc;
	socklen_t sin_loc_len;
	
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		snprintf(msg_buf, MAX_MSG_LENGTH, "create_socket_call_connect:Could not create socket");
		add_msg(msg_buf);
		return -1;
	}

	//bind new port number
	sin_loc.sin_family = AF_INET;
	sin_loc.sin_port = 0;
	sin_loc.sin_addr.s_addr = ntohl(ft->ip_loc);
	if (bind(sockfd, (const struct sockaddr *)&sin_loc, sizeof(sin_loc)) == -1) {
		snprintf(msg_buf, MAX_MSG_LENGTH, "create_socket_call_connect:Failed to bind, errno %d", errno);
		add_msg(msg_buf);
		return -1;
	}
	sin_loc_len = sizeof(sin_loc);
	if (getsockname(sockfd, (struct sockaddr *)&sin_loc, &sin_loc_len) == -1) {
		snprintf(msg_buf, MAX_MSG_LENGTH, "create_socket_call_connect:getsockname() failed");
		add_msg(msg_buf);
		return -1;
	}

	//return
	*p_sockfd = sockfd;
	ft->prt_loc = ntohs(sin_loc.sin_port);
	return 0;

}

int clean_rec_buffer(void *args){
	int sockfd; 
	struct timeval tmOut;

	sockfd = (int )args;
	//set time interval to 0
	tmOut.tv_sec = 0;
	tmOut.tv_usec = 0;
	fd_set fds;
	FD_ZEROS(&fds);
	FD_SET(sockfd,&fds);
	int nRet;
	char tmp[2048];

	memset(tmp,0,sizeof(tmp));
	while(1) {
		nRet = select(FD_SETSIZE,&fds,NULL,NULL,&tmOut);
		if(nRet == 0) break;
		recv(sockfd,tmp,2048,0);
	}
}

int call_connect(struct subflow* sfl) {

	snprintf(msg_buf, MAX_MSG_LENGTH, "call_connect: %zu", sfl->index);
	add_msg(msg_buf);

	//call connect
	struct connect_args *p_cn = malloc(sizeof(struct connect_args));
	if (!p_cn) {
		snprintf(msg_buf, MAX_MSG_LENGTH, "malloc failed");
		add_msg(msg_buf);
		return -1;
	}
	p_cn->sockfd = sfl->sockfd;
	p_cn->ip_dst_n = ntohl(sfl->ft.ip_rem);
	p_cn->port_dst_n = ntohs(sfl->ft.prt_rem);

	pthread_t connect_thread;
	if (pthread_create(&connect_thread, NULL, connect_handler, p_cn) < 0)
	{
		snprintf(msg_buf, MAX_MSG_LENGTH, "Could not create server thread");
		add_msg(msg_buf);
		set_verdict(0, 0, 0);
		return -1;
	}
	
	pthread_t receive_thread; // thread to clean the receive buffer
	if(pthread_create(&receive_thread, NULL, clean_rec_buffer,p_cn->sockfd)>0)
	{
		snprintf(msg_buf, MAX_MSG_LENGTH, "Could not clean receiving buffer");
		add_msg(msg_buf);
		return -1;
	}
	return 0;

}



//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow PRE_SYN_SENT
//  Targe states: SYN_SENT
//  Currently, we omit simultaneous open
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_pre_syn_sent() {

	char func_name[] = "subflow_pre_syn_sent";

	if (packd.hook <= 1 || packd.fwd_type != T_TO_M || !packd.syn || packd.ack){
		log_error("%s: sanity check fails. Dropped", func_name);
		set_verdict(0, 0, 0);
		return 0;
	}

	snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_syn_sent: input tcp_seq=%lu, tcp_an=%lu",
		(long unsigned)ntohl(packd.tcph->th_seq),
		(long unsigned)ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);

	if (packd.is_master) {
		snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_syn_sent:master");
		add_msg(msg_buf);
		if (!create_MPcap(packd.mptcp_opt_buf, &packd.mptcp_opt_len, packd.sess->key_loc, NULL)) {
			snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_syn_sent: total option len too long, len=%u", packd.mptcp_opt_len);
			add_msg(msg_buf);
			return 0;
		}
		packd.sess->sess_state = SYN_SENT;
	}
	else {
		snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_syn_sent: slave");
		add_msg(msg_buf);
		if (!create_MPjoin_syn(packd.mptcp_opt_buf, &packd.mptcp_opt_len, packd.sess->token_rem, packd.sfl->rand_nmb_loc, packd.sfl->addr_id_loc, 0)) {
			snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_syn_sent: total option len too long, len=%u", packd.mptcp_opt_len);
			add_msg(msg_buf);
			return 0;
		}
	}

	if (!output_data_mptcp()) {
		set_verdict(1, 0, 0);
		execute_sess_teardown(packd.sess);
		snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_syn_sent: output_data_mptcp fails");
		add_msg(msg_buf);
		return 0;
	}

	packd.sfl->tcp_state = SYN_SENT;


	//update tsn
	packd.sfl->isn_loc = htonl(packd.tcph->th_seq);
	packd.sfl->highest_sn_loc = packd.sfl->isn_loc;
	packd.sfl->offset_loc = packd.sfl->isn_loc;

	//there is room for opimization: the first subflow does not have to be in IP tables
	//	after SYN/ACK handshake

	snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_syn_sent: isn_loc=%lu, isn_rem=%lu, idsn_loc=%lu, idsn_rem=%lu, sfl_seq=%lu, sfl_an=%lu",
		(long unsigned)packd.sfl->isn_loc, (long unsigned)packd.sfl->isn_rem,
		(long unsigned)packd.sess->idsn_loc, (long unsigned)packd.sess->idsn_rem,
		(long unsigned)ntohl(packd.tcph->th_seq),
		(long unsigned)ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);

	set_verdict(1, 1, 1);
	return 1;


}

//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow SYN_SENT
//  Targe states: PRE_EST
//  Currently, we omit simultaneous open
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_syn_sent() {

	char func_name[] = "subflow_syn_sent";

	//Check for INPUT (or FWD with M_TO_T) + SYN + ACK + MPTCP option
	if (packd.hook >= 3 || packd.fwd_type != M_TO_T || !packd.syn || !packd.ack) {
		log_error("%s: sanity check fails. Dropped", func_name);
		set_verdict(0, 0, 0);
		return 0;
	}

	//drop session if remote host does not speak MPTCP
	if (packd.nb_mptcp_options == 0) {
		snprintf(msg_buf, MAX_MSG_LENGTH, "session_syn_sent: no MPTCP options attached. Killing sfl_id=%zu and sess_id=%zu", packd.sfl->index, packd.sess->index);
		add_msg(msg_buf);
		delete_subflow(&packd.ft);
		delete_session_parm(packd.sess->token_loc);
		delete_session(&packd.sess->ft, 1);
		set_verdict(1, 0, 0);
		add_ip_whitelist_array(packd.sess->ft.ip_rem);
		return 0;
	}
	log("session_syn_sent: MPTCP options attached.");

	if (packd.is_master)
		subflow_syn_sent_master();
	else
		subflow_syn_sent_slave();

	snprintf(msg_buf, MAX_MSG_LENGTH, "syn_sent: isn_loc=%lu, isn_rem=%lu, idsn_loc=%lu, idsn_rem=%lu, tcp_seq=%lu, tcp_an=%lu",
		(long unsigned)packd.sfl->isn_loc, (long unsigned)packd.sfl->isn_rem,
		(long unsigned)packd.sess->idsn_loc, (long unsigned)packd.sess->idsn_rem,
		(long unsigned)ntohl(packd.tcph->th_seq),
		(long unsigned)ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow PRE_EST
//  Target states: ESTABLISHED
//  Add TP_CAP headers with both ISDNs
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_pre_est() {

	if (packd.hook <= 1 || packd.fwd_type != T_TO_M || packd.syn || !packd.ack || packd.fin) {
		log_error("subflow_pre_est: sanity check fails. Dropped.");
		set_verdict(0, 0, 0);
		return 0;
	}

	//	packd.sfl = packd.sess->act_subflow;

	//append IDSNloc and IDSNrem to packd.mptcp_opt_buf (which is still zero)
	//if too long, kill the whole MPTCP idea and fallback to ordinary TCP mode
	if (packd.is_master) {
		snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_est:master");
		add_msg(msg_buf);
		if (!create_MPcap(packd.mptcp_opt_buf, &packd.mptcp_opt_len, packd.sess->key_loc, packd.sess->key_rem)) {
			log_error("session_pre_est: create_MPcap fails. Killing sfl_id=%zu and sess_id=%zu", packd.sfl->index, packd.sess->index);
//			delete_subflow(&packd.ft);
//			delete_session_parm(packd.sess->token_loc);
//			delete_session(&packd.sess->ft, 1);
			set_verdict(0, 0, 0);//retry
			return 0;
		}
		
		packd.sess->highest_dsn_loc += 1;
		packd.sess->last_dan_loc = packd.sess->highest_dsn_loc;
		packd.sess->highest_dan_loc = packd.sess->highest_dsn_loc;
		packd.sess->curr_window_loc = ntohs(packd.tcph->th_win);
		packd.sess->sess_state = ESTABLISHED;

	}
	else {
		snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_est:slave");
		add_msg(msg_buf);

		uint32_t mac_test[5];
		create_mac(packd.sess->key_loc, packd.sess->key_rem, packd.sfl->rand_nmb_loc, packd.sfl->rand_nmb_rem, mac_test);
		if (!create_MPjoin_ack(packd.mptcp_opt_buf, &packd.mptcp_opt_len, mac_test)) {
			snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_est: create_MPjoin fails. Killing sfl_id=%zu and sess_id=%zu", packd.sfl->index, packd.sess->index);
			add_msg(msg_buf);
//			delete_subflow(&packd.ft);
//			delete_session_parm(packd.sess->token_loc);
//			delete_session(&packd.sess->ft, 1);
			set_verdict(0, 0, 0);//retry
			return 0;
		}

		//transmit pending packet
		struct rcv_buff_list *iter, *next, *head = packd.sess->snd_buff_list_head;
		list_for_each_entry_safe(iter, next, &head->list, list) {
			subflow_send_data(packd.sfl, iter->payload, iter->len, iter->dan, iter->dsn);
			log("send pending pack: dan %x, dsn %x, len %u", iter->dan, iter->dsn, iter->len);
		}
	}

	if (!output_data_mptcp()) {
		set_verdict(0, 0, 0);
		snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_est: output_data_mptcp fails, sess_id=%zu", packd.sess->index);
		add_msg(msg_buf);
		return 0;
	}

	packd.sfl->tcp_state = ESTABLISHED;

	snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_est: PRE_EST->ESTABLISHED - sess->sack=%d, sfl->sack=%d, sess_id=%zu, sfl_id=%zu",
		packd.sess->sack_flag, packd.sfl->sack_flag, packd.sess->index, packd.sfl->index);
	add_msg(msg_buf);
	set_verdict(1, 1, 1);

	snprintf(msg_buf, MAX_MSG_LENGTH, "session_pre_est: isn_loc=%u, isn_rem=%u, idsn_loc=%u, idsn_rem=%u, sfl_seq=%u, sfl_an=%u",
		packd.sfl->isn_loc, packd.sfl->isn_rem,
		packd.sess->idsn_loc, packd.sess->idsn_rem,
		ntohl(packd.tcph->th_seq),
		ntohl(packd.tcph->th_ack));
	add_msg(msg_buf);

	return 1;
}

int subflow_syn_sent_master(){

	//get rem IDSN from MPTCP CAP option
	uint32_t key_rem[2];
	uint32_t key_loc[2];
	if(!analyze_MPcap(mptopt, packd.nb_mptcp_options, key_loc, key_rem)) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "session_syn_sent: analyze_MPcap fails. Killing sfl_id=%zu and sess_id=%zu", packd.sfl->index, packd.sess->index);
		add_msg(msg_buf);
		delete_subflow(&packd.ft);
		delete_session_parm(packd.sess->token_loc);
		delete_session(&packd.sess->ft, 1);
		set_verdict(1,0,0);
		return 0;
	}

	//add or eliminate SACK based on DO_SACK
	int adjust_packet = 0;

	//check sack support for subflow
	unsigned char len = packd.tcplen-20;
	if(DO_SACK) {

		if(find_tcp_option(packd.buf+packd.pos_thead+20, len, 4)) {
		
			//everything fine; in case sess->sack_flag == 0, simply keep the sack_flag rolling
		} else{

			packd.sfl->sack_flag = 0;//no sfl sack support
			if( packd.sess->sack_flag) {

				//furnish with sack flag for subflow sack support
				if(append_sack(packd.buf+packd.pos_thead+20, &len)){
					packd.tcplen += 2;
					packd.pos_pay += 2;
					packd.totlen += 2;
					adjust_packet = 1;
				}
			}
		}
	} else {
		if(find_tcp_option(packd.buf+packd.pos_thead+20, len, 4)) {
			//ensure no sess->sack support
			if(eliminate_tcp_option(packd.buf+packd.pos_thead+20, &len, 4)){
				packd.tcplen -= 2;
				packd.pos_pay -= 2;
				packd.totlen -= 2;
				adjust_packet = 1;
			}
		} else {
			//everthing fine
		}
	}


	unsigned char init_len = packd.tcplen-20;
	unsigned char scaling_factor = find_window_scaling(packd.buf+packd.pos_thead+20, &init_len);
	packd.sess->init_window_rem = ntohs(packd.tcph->th_win);
	packd.sess->scaling_factor_rem = scaling_factor;
	packd.sess->curr_window_rem = (packd.sess->init_window_loc)>>scaling_factor;


	packd.sess->key_rem[0] = key_rem[0];
	packd.sess->key_rem[1] = key_rem[1];

	create_idsn_token(packd.sess->key_rem, &packd.sess->idsn_rem, &packd.sess->token_rem,NULL);


	packd.sess->highest_dsn_rem = packd.sess->idsn_rem+1;
	packd.sess->highest_dan_rem = packd.sess->idsn_rem+1;

	packd.sfl->isn_rem = ntohl(packd.tcph->th_seq); 
	packd.sfl->offset_rem = packd.sfl->isn_rem;
	packd.sess->offset_rem = 0;//sess seq_rem = idsn_rem 	

	packd.sfl->highest_sn_loc += 1;
	packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;		

	packd.sfl->tcp_state = PRE_EST;
	packd.sess->sess_state = PRE_EST;

	if(adjust_packet) {
		packd.mptcp_opt_len = 0;//since option is already attached
		if(!output_data_mptcp()) {
			set_verdict(1,0,0);
			execute_sess_teardown(packd.sess);
			snprintf(msg_buf,MAX_MSG_LENGTH, "session_syn_sent: output_data_mptcp fails for sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
			add_msg(msg_buf);

			return 0;
		}
		set_verdict(1,1,1);
	}
	else set_verdict(1,1,0);

//+++send syn/ack to browser
{
	packd.sess->rcv_buff_list_head->dsn = packd.sess->idsn_rem;
	packd.sess->rcv_buff_list_head->len = 1;
	
	create_raw_packet_send(&packd.sess->ft,
		1,
		htonl(packd.sess->idsn_rem), 
		htonl(packd.sess->idsn_loc + packd.sess->offset_loc + 1),
		18,//SYN/ACK
		htons(packd.sess->init_window_rem), 
		NULL, 
		0,
		NULL,
		0);
	
	add_msg("session_syn_sent: sending SYN/ACK packet to browser");
}
//---new

	return 0;
}

int subflow_syn_sent_slave(){

	unsigned char backup;
	unsigned char addr_id_rem;
	uint32_t rand_nmb_rem;
	uint32_t mac[2];
	if(!analyze_MPjoin_synack(mptopt, packd.nb_mptcp_options, mac, &rand_nmb_rem,  &addr_id_rem, &backup))
		return 0;
	
	//test if hmac is correct
	uint32_t mac_test[5];
	create_mac(packd.sess->key_rem, packd.sess->key_loc, rand_nmb_rem, packd.sfl->rand_nmb_loc, mac_test);
	if(memcmp(mac_test, mac, 8) != 0) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_syn_sent: MAC on SYN/ACK packet for sess id=%zu, sfl id=%zu is incorrect!",
				packd.sess->index, packd.sfl->index);
		add_msg(msg_buf);
		set_verdict(0,0,0);
		return 0; 

	}

	packd.sfl->isn_rem = ntohl(packd.tcph->th_seq);
	packd.sfl->highest_sn_rem = packd.sfl->isn_rem + 1;
	packd.sfl->highest_an_rem = packd.sfl->isn_rem + 1;
	packd.sfl->highest_sn_loc += 1;
	packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;
	packd.sfl->addr_id_rem = addr_id_rem;
	packd.sfl->rand_nmb_rem = rand_nmb_rem;
	packd.sfl->sack_flag = find_tcp_option(packd.buf+packd.pos_thead+20, packd.tcplen-20, 4) && DO_SACK;
	packd.sfl->tcp_state = PRE_EST;

	return 0;

}

/*
//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow SYN_SENT
//  Target states: ESTABLISHED
//  Expect SYN/ACK with TP_JOIN2, Send ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_syn_sent_old() {

	if(packd.hook>=3 || packd.fwd_type != M_TO_T || !packd.syn || !packd.ack || packd.nb_mptcp_options<=0)
		return 0;

	//target state ESTABLISHED
	if(PRINT_FILE) load_print_line(packd.id, 1, packd.sess->index, packd.sfl->index, 
			0, 0, 18, 
			0, 1, 
			0, 0, 
			0, packd.sack_in, 0, packd.sack_in, 1);


	unsigned char backup;
	unsigned char addr_id_rem;
	uint32_t rand_nmb_rem;
	uint32_t mac[2];
	if(!analyze_MPjoin_synack(mptopt, packd.nb_mptcp_options, mac, &rand_nmb_rem,  &addr_id_rem, &backup))
		return 0;

	uint32_t mac_test[5];
	create_mac(packd.sess->key_rem, packd.sess->key_loc, rand_nmb_rem, packd.sfl->rand_nmb_loc, mac_test);
	if(memcmp(mac_test, mac, 8) != 0) {

		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_syn_sent: MAC on SYN/ACK packet for sess id=%zu, sfl id=%zu is incorrect!",
				packd.sess->index, packd.sfl->index);
		add_msg(msg_buf);
		set_verdict(1,0,0);
		return 0; 

	}


	packd.sfl->isn_rem = ntohl(packd.tcph->th_seq);
	packd.sfl->offset_rem = packd.sess->idsn_rem - packd.sfl->isn_rem;
	packd.sfl->highest_sn_rem = packd.sfl->isn_rem + 1;
	packd.sfl->highest_an_rem = packd.sfl->isn_rem + 1;
	packd.sfl->highest_sn_loc += 1;
	packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;
	packd.sfl->addr_id_rem = addr_id_rem;
	packd.sfl->rand_nmb_rem = rand_nmb_rem;
	packd.sfl->sack_flag = find_tcp_option(packd.buf+packd.pos_thead+20, packd.tcplen-20, 4) && DO_SACK;


	//create new TPTCP option header: TPjoin_ack
	unsigned char opt_buf[60];
	uint16_t opt_len = 0;
	if(packd.sess->timestamp_flag) {
		opt_len = 10;
		add_timestamps(opt_buf, packd.sess->tsval, packd.sfl->tsecr);
	}

	create_mac(packd.sess->key_loc, packd.sess->key_rem, packd.sfl->rand_nmb_loc, packd.sfl->rand_nmb_rem, mac_test);
	create_MPjoin_ack(opt_buf, &opt_len, mac_test);

	opt_len = pad_options_buffer(opt_buf, opt_len);


	//create ack packet
	uint16_t pack_len;
	create_packet(raw_buf, &pack_len, 
			&packd.ft,
			htonl(packd.sfl->highest_sn_loc),
			htonl(packd.sfl->highest_an_rem),
			16,//ACK
			htons(packd.sess->curr_window_loc), 
			opt_buf, 
			opt_len);//opt len

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_syn_sent: sending ACK packet, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
	add_msg(msg_buf);

	//send ack packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(packd.ft.ip_rem))<0) {

		delete_subflow(&packd.ft);
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_syn_sent: send_raw_packet returns error");
		add_msg(msg_buf);
		return 0;
	}


	if(PRINT_FILE) load_print_line(packd.id, 3, packd.sess->index, packd.sfl->index, 
			0, 0, 16, 
			1, 1, 
			0, 0, 
			0, packd.sack_in, 0, packd.sack_in, 1);

	packd.sfl->tcp_state = ESTABLISHED;
	packd.sess->conman_state = '0';//this means: command to subflow establishment is reset
	set_verdict(0,0,0);//packet has to be terminated here

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_syn_sent: sess id=%zu, sfl id=%zu, TCP state changed to ESTABLISHED, sfl_sack=%d", packd.sess->index, packd.sfl->index, packd.sfl->sack_flag);
	add_msg(msg_buf);

	//in case of BREAK
	if(packd.sess->act_subflow->broken) {

		break_active_sfl(packd.sess, packd.sfl);

		//send break ack: TPprio for new subflow and REMOVE_ADDR on old address
		send_break_ack(packd.sess->act_subflow, packd.sess->last_subflow->addr_id_loc);

		if(packd.sess->act_subflow->addr_id_loc == packd.sess->last_subflow->addr_id_loc) send_reset_subflow(packd.sess->last_subflow);	

		create_prio_event(&packd.sess->ft, packd.sess->last_subflow->addr_id_loc);//to resend breal ack

	}
	return 1;
}
*/

//++++++++++++++++++++++++++++++++++++++++++++++++
//subflow SYN_RECEIVED
//  Target state: ESTABLISHED
//  Expect ACK with TP_JOIN3
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_syn_received() {
	if(packd.hook>=3 || packd.fwd_type != M_TO_T || packd.syn || !packd.ack || packd.nb_mptcp_options<=0)
		return 0;

	uint32_t mac[5];
	if(!analyze_MPjoin_ack(mptopt, packd.nb_mptcp_options, mac) )
		return 0;

	uint32_t mac_test[5];
	create_mac(packd.sess->key_rem, packd.sess->key_loc, packd.sfl->rand_nmb_rem, packd.sfl->rand_nmb_loc, mac_test);
	if(memcmp(mac_test, mac, 20) != 0){

		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_syn_received: MAC on ACK packet for sess id=%zu, sfl id=%zu is incorrect!",
				packd.sess->index, packd.sfl->index);
		add_msg(msg_buf);
		set_verdict(1,0,0);
		return 0; 
	}

	packd.sfl->tcp_state = ESTABLISHED;
	packd.sess->conman_state = '0';//this means: command to subflow establishment is reset
	packd.sfl->highest_sn_rem = packd.sfl->isn_rem + 1;
	packd.sfl->highest_an_rem = packd.sfl->isn_rem + 1;
	packd.sfl->highest_sn_loc += 1;
	packd.sfl->highest_an_loc = packd.sfl->highest_sn_loc;

	set_verdict(0,0,0);//packet has to be terminated here

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_syn_received: sess id=%zu, sfl id=%zu, TCP state changed to ESTABLISHED, sfl_sack_flag=%d", packd.sess->index, packd.sfl->index, packd.sfl->sack_flag);
	add_msg(msg_buf);	
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: terminate_subflow()
// Start state: ESTABLISHED
// Target state: FIN_WAIT_1
//++++++++++++++++++++++++++++++++++++++++++++++++
int terminate_subflow(struct session *sess, struct subflow *sfl) {


	//reset conman state
	sess->conman_state = '0';

	//check if subflow is in session
	if(sfl->sess != sess){
		snprintf(msg_buf,MAX_MSG_LENGTH, "terminate_cand_subflow: sfl->sess index=%zu does not match sess index=%zu", sfl->sess->index, sess->index);
		add_msg(msg_buf);
		return 0;
	}

	sfl->act_state = CANDIDATE;


	//create fin packet
	unsigned char opt_buf[20];
	uint16_t opt_len = 0;
	if(sess->timestamp_flag){
		opt_len = 10;
		add_timestamps(opt_buf, sess->tsval, sfl->tsecr);
	}

	unsigned char flags = 17;
	if(sfl->tcp_state == CLOSE_WAIT) flags = 16;

	create_dummy_dssopt(opt_buf + opt_len);
	opt_len += 4;
	uint16_t pack_len;
	create_packet(raw_buf, &pack_len, 
		&(sfl->ft),
		htonl(sfl->highest_sn_loc),//highest loc sn that has been acked 
		htonl(sfl->highest_an_rem),
		flags,//FIN
		htons(sess->curr_window_loc), 
		opt_buf, 
		opt_len);//opt len

	snprintf(msg_buf,MAX_MSG_LENGTH, "terminate_cand_subflow: sending FIN packet, sfl_id=%zu, sess_id=%zu", sfl->index, sess->index);
	add_msg(msg_buf);


	//send packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(sfl->ft.ip_rem))<0){
		
		delete_subflow(&sfl->ft);
		snprintf(msg_buf,MAX_MSG_LENGTH,"terminate_cand_subflow: send_raw_packet returns error");
		add_msg(msg_buf);
		return 0;
	}

	if(sfl->tcp_state == CLOSE_WAIT) {
		sfl->tcp_state = LAST_ACK;
		snprintf(msg_buf,MAX_MSG_LENGTH,"terminate_subflow: state change to LAST_ACK");
		add_msg(msg_buf);
	}
	else{
		sfl->tcp_state = FIN_WAIT_1;
		snprintf(msg_buf,MAX_MSG_LENGTH,"terminate_subflow: state change to FIN_WAIT_1");
		add_msg(msg_buf);
	}


	//create retransmit event and add to queue (1 sec, 0 usec)
	create_rex_event(&sfl->ft, sfl->tcp_state, raw_buf, pack_len);
			
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_established()
// Start state: ESTABLISHED
// Target states: LAST_ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_established() {

	if(packd.fin != 1)
		return 1;

	//create FIN/ACK packet
	unsigned char opt_buf[20];
	uint16_t opt_len = 0;
	if(packd.sess->timestamp_flag) {
		opt_len = 10;
		add_timestamps(opt_buf, packd.sess->tsval, packd.sfl->tsecr);
	}
	create_dummy_dssopt(opt_buf + opt_len);
	opt_len += 4;


	unsigned char flags;
	if(packd.sfl->act_state == ACTIVE) flags = 16;//ACK
	else flags = 17;//FIN/ACK


	uint16_t pack_len;
	packd.sfl->highest_an_rem += 1;	
	create_packet(raw_buf, &pack_len, 
			&(packd.sfl->ft),
			htonl(packd.sfl->highest_sn_loc), 
			htonl(packd.sfl->highest_an_rem),
			flags,//FIN + ACK or ACK
			htons(packd.sess->curr_window_loc), 
			opt_buf, 
			opt_len);//opt len

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_established: sending FIN/ACK or ACK packet, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
	add_msg(msg_buf);


	//send packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(packd.sfl->ft.ip_rem))<0){

		delete_subflow(& (packd.sfl->ft));
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_established: send_raw_packet returns error");
		add_msg(msg_buf);
		set_verdict(0,0,0);//packet has to be terminated here
		return 0;
	}

	if(flags == 16) {//active subflow
		packd.sfl->tcp_state = CLOSE_WAIT;
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_established: state change to CLOSE_WAIT, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
		add_msg(msg_buf);
	} else {//candidate subflow
		packd.sfl->tcp_state = LAST_ACK;
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_established: state change to LAST_ACK, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
		add_msg(msg_buf);

	}
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_close_wait()
// Start state: CLOSE_WAIT
// Target states: LAST_ACK
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_close_wait() {
	if(packd.sfl->act_state != CANDIDATE)
		return 1;
	//create FIN packet
	unsigned char opt_buf[20];
	uint16_t opt_len = 0;
	if(packd.sess->timestamp_flag) {
		opt_len = 10;
		add_timestamps(opt_buf, packd.sess->tsval, packd.sfl->tsecr);
	}
	create_dummy_dssopt(opt_buf + opt_len);
	opt_len += 4;


	unsigned char flags = 17;

	uint16_t pack_len;
	create_packet(raw_buf, &pack_len, 
			&(packd.sfl->ft),
			htonl(packd.sfl->highest_sn_loc), 
			htonl(packd.sfl->highest_an_rem),
			flags,//FIN/ACK
			htons(packd.sess->curr_window_loc), 
			opt_buf, 
			opt_len);//opt len

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_established: sending FIN/ACK packet, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
	add_msg(msg_buf);


	//send packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(packd.sfl->ft.ip_rem))<0){

		delete_subflow(& (packd.sfl->ft));
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_established: send_raw_packet returns error");
		add_msg(msg_buf);
		set_verdict(0,0,0);//packet has to be terminated here
		return 0;
	}

	//create_rex_event(&packd.sfl->ft, packd.sfl->tcp_state, raw_buf, pack_len);
	packd.sfl->tcp_state = LAST_ACK;
	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_close_wait: state change to LAST_ACK, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
	add_msg(msg_buf);
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_last_ack()
// Start state: LAST_ACK
// Target states: NONE
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_last_ack() {

	if(packd.ack != 1)
		return 1;

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_last_ack: sess id=%zu, sfl id=%zu terminated", packd.sess->index, packd.sfl->index);
	add_msg(msg_buf);
	delete_subflow(&(packd.sfl->ft));
	set_verdict(0,0,0);//packet has to be terminated here
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_fin_wait_1()
// Start state: FIN_WAIT_1
// Target states: FIN_WAIT_2, CLOSING, TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
 int subflow_fin_wait_1() {


	if(packd.ack == 1 && packd.fin == 0){
		packd.sfl->highest_sn_loc += 1;	
		packd.sfl->tcp_state = FIN_WAIT_2;
		set_verdict(0,0,0);//packet has to be terminated here
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_fin_wait_1: state change to FIN_WAIT_2, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
		add_msg(msg_buf);		
	}

	if(packd.fin != 1)
		return 1;

	//create ACK packet
	unsigned char opt_buf[20];
	uint16_t opt_len = 0;
	if(packd.sess->timestamp_flag) {
		opt_len = 10;
		add_timestamps(opt_buf, packd.sess->tsval, packd.sfl->tsecr);
	}
	create_dummy_dssopt(opt_buf + opt_len);
	opt_len += 4;


	packd.sfl->highest_an_rem += 1;	
	packd.sfl->highest_sn_loc += 1;		

	uint16_t pack_len;
	create_packet(raw_buf, &pack_len, 
			&(packd.sfl->ft),
			htonl(packd.sfl->highest_sn_loc), 
			htonl(packd.sfl->highest_an_rem),
			16,//ACK
			htons(packd.sess->curr_window_loc), 
			opt_buf, 
			opt_len);//opt len

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_fin_wait_1: sending ACK packet, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
	add_msg(msg_buf);

	//send packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(packd.sfl->ft.ip_rem))<0) {

		delete_subflow(& (packd.sfl->ft));
		snprintf(msg_buf,MAX_MSG_LENGTH,"subflow_fin_wait_1: send_raw_packet returns error");
		add_msg(msg_buf);
		set_verdict(1,0,0);//packet has to be terminated here
		return 0;
	}

	if(packd.ack == 1) {
		packd.sfl->tcp_state = TIME_WAIT;
		create_sfl_close_event(&packd.sfl->ft);
		snprintf(msg_buf,MAX_MSG_LENGTH,"subflow_fin_wait_1:  sess id=%zu, sfl id=%zu entering TCP state TIME_WAIT", packd.sess->index, packd.sfl->index);
		add_msg(msg_buf);
	} else {
		packd.sfl->tcp_state = CLOSING;
		snprintf(msg_buf,MAX_MSG_LENGTH,"subflow_fin_wait_1: state change to CLOSING, sess id=%zu, sfl id=%zu ", packd.sess->index, packd.sfl->index);
		add_msg(msg_buf);
	}
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_fin_wait_2()
// Start state: FIN_WAIT_2
// Target states:  TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_fin_wait_2() {
	if(packd.fin != 1)
		return 1;

	//create ACK packet
	packd.sfl->highest_an_rem += 1;	

	unsigned char opt_buf[20];
	uint16_t opt_len = 0;
	if(packd.sess->timestamp_flag){
		opt_len = 10;
		add_timestamps(opt_buf, packd.sess->tsval, packd.sfl->tsecr);
	}
	create_dummy_dssopt(opt_buf + opt_len);
	opt_len += 4;


	create_dummy_dssopt(opt_buf);
	uint16_t pack_len;
	create_packet(raw_buf, &pack_len, 
			&(packd.sfl->ft),
			htonl(packd.sfl->highest_sn_loc), 
			htonl(packd.sfl->highest_an_rem),
			16,//ACK
			htons(packd.sess->curr_window_loc), 
			opt_buf, 
			opt_len);//opt len

	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_fin_wait_2: sending ACK packet, sfl_id=%zu, sess_id=%zu", packd.sfl->index, packd.sess->index);
	add_msg(msg_buf);

	//send packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(packd.sfl->ft.ip_rem))<0) {

		delete_subflow(&(packd.sfl->ft));
		snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_fin_wait_2: send_raw_packet returns error");
		add_msg(msg_buf);
		set_verdict(1,0,0);//packet has to be terminated here
		return 0;
	}
	packd.sfl->tcp_state = TIME_WAIT;
	create_sfl_close_event(&packd.sfl->ft);
	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_fin_wait_2: sess id=%zu, sfl id=%zu entering TCP state TIME_WAIT", packd.sess->index, packd.sfl->index);
	add_msg(msg_buf);
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: subflow_closing()
// Start state: CLOSING
// Target states: TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
int subflow_closing() {
	if(packd.ack != 1)
		return 1;

	packd.sfl->tcp_state = TIME_WAIT;
	create_sfl_close_event(&packd.sfl->ft);
	snprintf(msg_buf,MAX_MSG_LENGTH, "subflow_closing:  sess id=%zu, sfl id=%zu entering TCP state TIME_WAIT", packd.sess->index, packd.sfl->index);
	add_msg(msg_buf);
	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_traffic_ack()
// Sends ack on candidate subflow in parallel to traffic packet on active subflow
// Packet may serve to satisfy subflow SSN/SAN consistency.
// It may carries thruway tcp_options and DAN-DSS (8B) or MP_Prio
//++++++++++++++++++++++++++++++++++++++++++++++++
int send_traffic_ack(struct subflow *sfl) {

	//create ACK packet
	//char opt_buf[opt_len];
	uint16_t pack_len;

	create_packet(raw_buf, &pack_len, 
			&(sfl->ft),
			htonl(sfl->highest_sn_loc), 
			htonl(sfl->curr_an_rem),
			16,//ACK
			htons(packd.sess->curr_window_loc), 
			packd.tcp_opt_buf_ack, 
			packd.tcp_opt_len_ack);//opt len

	//send packet
	if(send_raw_packet(raw_sd, raw_buf,  pack_len, htonl(sfl->ft.ip_rem))<0){
		snprintf(msg_buf,MAX_MSG_LENGTH, "send_traffic_ack: send_raw_packet returns error");
		add_msg(msg_buf);
		return 0;
	}

	return 1;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_switch_ack()
// Sends ack on sfl with one to two tpprio options
// Currently, we do not care about timestamps 
//++++++++++++++++++++++++++++++++++++++++++++++++
int send_switch_ack(struct subflow *new_sfl, struct subflow *old_sfl) {
	if(new_sfl == NULL){
		snprintf(msg_buf,MAX_MSG_LENGTH, "send_switch_ack: new_subflow = NULL");
		add_msg(msg_buf);
		return 0;
	} 

	snprintf(msg_buf,MAX_MSG_LENGTH, "send_switch_ack: new subflow index = %zu", new_sfl->index);
	add_msg(msg_buf);

	if(old_sfl != NULL) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "send_switch_ack: old subflow index = %zu", old_sfl->index);
		add_msg(msg_buf);
	}


	//turn on active subflow
	unsigned char opt_buf[20];
	uint16_t opt_len = 0;

	if(new_sfl->sess->timestamp_flag) {
		opt_len = 10;
		add_timestamps(opt_buf, new_sfl->sess->tsval, new_sfl->tsecr);
	}

	create_MPprio3(opt_buf + opt_len, 0);//backup = 0
	opt_len +=4;
	opt_buf[opt_len-1] = 1; //pad


	//create ACK packet
	//char opt_buf[opt_len];
	uint16_t pack_len;
	create_packet(raw_buf, &pack_len, 
		&(new_sfl->ft),
		htonl(new_sfl->highest_sn_loc), 
		htonl(new_sfl->highest_an_rem),
		16,//ACK
		htons(new_sfl->sess->curr_window_loc), 
		opt_buf, 
		opt_len);//opt len

		//send packet
	if(send_raw_packet(raw_sd, raw_buf, pack_len, htonl(new_sfl->ft.ip_rem))<0) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "send_switch_ack: send_raw_packet returns error");
		add_msg(msg_buf);
		return 0;
	}

	//Switch old subflow to backup
	if(old_sfl == NULL) return 0;

	opt_len = 0;
	if(old_sfl->sess->timestamp_flag) {
		opt_len = 10;
		add_timestamps(opt_buf, old_sfl->sess->tsval, old_sfl->tsecr);
	}

	create_MPprio3(opt_buf + opt_len, 1);
	opt_len +=4;
	opt_buf[opt_len-1] = 1; //pad


	//create ACK packet
	//char opt_buf[opt_len];
	create_packet(raw_buf, &pack_len, 
		&(old_sfl->ft),
		htonl(old_sfl->highest_sn_loc), 
		htonl(old_sfl->highest_an_rem),
		16,//ACK
		htons(old_sfl->sess->curr_window_loc), 
		opt_buf, 
		opt_len);//opt len

		//send packet
	if(send_raw_packet(raw_sd, raw_buf, pack_len, htonl(old_sfl->ft.ip_rem))<0) {
		
		snprintf(msg_buf,MAX_MSG_LENGTH, "send_traffic_ack: send_raw_packet returns error");
		add_msg(msg_buf);
		return 0;
	}

	return 1;

}





//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_break_ack()
// Sends ack on sfl with tpprio and remove_addr attached
// Currently, we do not care about timestamps 
//++++++++++++++++++++++++++++++++++++++++++++++++
int send_break_ack(struct subflow *new_sfl, unsigned char addr_id_loc) {
	 if(new_sfl == NULL) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "send_break_ack: fails since sfl = NULL"); 
		add_msg(msg_buf);	
		return 0;
	 }		

	 snprintf(msg_buf,MAX_MSG_LENGTH, "send_break_ack: sess_id=%zu, new sfl_id = %zu", new_sfl->sess->index, new_sfl->index);
	 add_msg(msg_buf);

	 //turn on active subflow
	 unsigned char opt_buf[20];
	 uint16_t opt_len = 0;
	 if(new_sfl->sess->timestamp_flag) {
		 opt_len = 10;
		 add_timestamps(opt_buf, new_sfl->sess->tsval, new_sfl->tsecr);
	 }
	 create_MPprio3(opt_buf+opt_len, 0);
	 opt_len+=4;
	 opt_buf[opt_len-1] = 1; //pad

	 //turn off last subflow (which is the one to be deleted)
	 if(new_sfl->addr_id_loc != addr_id_loc) {
		 create_MPremove_addr(opt_buf+opt_len, addr_id_loc);
		 opt_len += 4;
	 }

	 //create ACK packet
	 //char opt_buf[opt_len];
	 uint16_t pack_len;

	 create_packet(raw_buf, &pack_len, 
			 &(new_sfl->ft),
			 htonl(new_sfl->highest_sn_loc), 
			 htonl(new_sfl->highest_an_rem),
			 16,//ACK
			 htons(new_sfl->sess->curr_window_loc), 
			 opt_buf, 
			 opt_len);//opt len

	 //send packet
	 if(send_raw_packet(raw_sd, raw_buf, pack_len, htonl(new_sfl->ft.ip_rem))<0){
		 snprintf(msg_buf,MAX_MSG_LENGTH, "send_break_ack: send_raw_packet returns error");
		 add_msg(msg_buf);
		 return 0;
	 }

	 return 1;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: handle_subflow_break(struct subflow *const sflx)
// this is used when ip address is discontinued
//++++++++++++++++++++++++++++++++++++++++++++++++
int handle_subflow_break(struct subflow *const sflx) {
	sflx->broken = 1;
	if(sflx->act_state == CANDIDATE){
		sflx->tcp_state = TIME_WAIT;
		start_sfl_teardown_timer(sflx);
		create_sfl_break_event(&sflx->ft);
		if(sflx->sess->conman_state == 'S' && sflx == sflx->sess->last_subflow) break_during_switch(sflx->sess);
		return 0;
	}
	return 1;
}




//++++++++++++++++++++++++++++++++++++++++++++++++
//SFLMAN: send_reset_subflow()
// Sends sest on subflow specified
//++++++++++++++++++++++++++++++++++++++++++++++++
 int send_reset_subflow(struct subflow *sfl) {
 	int ret = send_reset_fourtuple(&sfl->ft, sfl->highest_sn_loc);
	sfl->tcp_state = TIME_WAIT;
	create_sfl_close_event(&sfl->ft);

	return ret;
}





//++++++++++++++++++++++++++++++++++++++++++++++++
//create subflow
//	overwrite=0: Do not overwrite entry if subflow already exists and return -1, 
//      overwrite=1: Overwrite entry if subflow already exists and return 0
//++++++++++++++++++++++++++++++++++++++++++++++++
//TODO delete sess
struct subflow* create_subflow(struct fourtuple *ft1,
		 unsigned char addr_id_loc,
		 unsigned char addr_id_rem,
		 int sockfd,
		 int tcp_state,
		 int act_state,
		 uint32_t isn_loc,
		 uint32_t isn_rem,
		 uint32_t offset_loc,
		 uint32_t offset_rem,
		 uint32_t rand_nmb_loc,
		 uint32_t rand_nmb_rem,
		 size_t overwrite) {
		
	static unsigned int index = 0;

	struct subflow *sflx;
	HASH_FIND(hh, sfl_hash, ft1, sizeof(struct fourtuple), sflx);

	if(overwrite == 0 && sflx!=NULL) return NULL;

	char ifname_loc[10];
	if(find_interface(&if_tab1, ifname_loc, ft1->ip_loc) == 0) {
		snprintf(msg_buf,MAX_MSG_LENGTH, "create_subflow: interface \"%s\" not found", ifname_loc);
		add_msg(msg_buf);	
	}

	if(sflx==NULL) {
		sflx = malloc( sizeof(struct subflow));//create new subflow
		memset(sflx, 0, sizeof(struct subflow));
		sflx->ft = *ft1;
		HASH_ADD(hh, sfl_hash, ft, sizeof(struct fourtuple), sflx);
	
		struct subflow_pnt *sfl_pnt;
		HASH_FIND(hh, sfl_pnt_hash, &sflx, sizeof(struct subflow*), sfl_pnt);

		if(sfl_pnt == NULL){

			sfl_pnt = (struct subflow_pnt*) malloc( sizeof(struct subflow_pnt));
			sfl_pnt->sfl = sflx;
			HASH_ADD(hh, sfl_pnt_hash, sfl, sizeof(struct subflow*), sfl_pnt);
		}
	}
	//+++new
{
	sflx->snd_map_list_head = malloc(sizeof(struct snd_map_list));
	init_head_snd_map_list(sflx->snd_map_list_head);
	sflx->sockfd = sockfd;
}	
	
	sflx->index = index;
	index++;

	strcpy(sflx->ifname_loc, ifname_loc);

	sflx->tcp_state = tcp_state;
	sflx->act_state = act_state;
	sflx->broken = 0;
	sflx->ack_state = 0;
	sflx->sack_flag = DO_SACK;

	sflx->addr_id_loc = addr_id_loc;
	sflx->addr_id_rem = addr_id_rem;

	sflx->isn_loc = isn_loc;
	sflx->isn_rem = isn_rem;
	sflx->csn_loc = isn_loc;
	sflx->csn_rem = isn_rem;
	sflx->highest_sn_loc = isn_loc;
	sflx->highest_sn_rem = isn_rem;

	sflx->offset_loc = offset_loc;
	sflx->offset_rem = offset_rem;

	sflx->map_recv = malloc(sizeof(struct map_table));
	init_map(sflx->map_recv);

	sflx->map_send = malloc(sizeof(struct map_table));
	init_map(sflx->map_send);


	sflx->rand_nmb_loc = rand_nmb_loc;
	sflx->rand_nmb_rem = rand_nmb_rem;

	subflow_IPtables('A',1,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);
	subflow_IPtables('A',2,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);
	subflow_IPtables('A',2,ft1->ip_rem, ft1->prt_rem, ft1->ip_loc, ft1->prt_loc);
	subflow_IPtables('A',3,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);

	return sflx;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//delete subflow: deletes subflow from hashtable, session and memory
//	Returns 0 if delete successful
//	Returns -1 if subflow not found
//++++++++++++++++++++++++++++++++++++++++++++++++
int delete_subflow(struct fourtuple *ft1) {
	
	char* func_name = "delete_subflow";
	if (ft1 == NULL) {
		log_error("%s:null ft", func_name);
		return -1;
	}
	
	char buf_ft[100];
	sprintFourtuple(buf_ft, ft1);

	struct subflow *sflx;
	HASH_FIND(hh, sfl_hash, ft1, sizeof(struct fourtuple), sflx);
	if(!sflx) {
		log_error("%s: ft not found %s", func_name, buf_ft);
		return -1;
	}

	//find session this subflow belongs to and delete it there too
	struct session *sess = sflx->sess;

	if(memcmp(&sflx->ft, &sess->ft, sizeof(struct fourtuple)) != 0){
		subflow_IPtables('D',1,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);
		subflow_IPtables('D',2,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);
		subflow_IPtables('D',2,ft1->ip_rem, ft1->prt_rem, ft1->ip_loc, ft1->prt_loc);
		subflow_IPtables('D',3,ft1->ip_loc, ft1->prt_loc, ft1->ip_rem, ft1->prt_rem);
	}
	
	//if sfl = last_subflow or act_subflow, set them to NULL
	if(sflx == sess->act_subflow) sess->act_subflow = NULL;
	if(sflx == sess->last_subflow) sess->last_subflow = NULL;
	if(sflx == sess->slav_subflow) sess->slav_subflow = NULL;

	delete_map(sflx->map_recv);
	delete_map(sflx->map_send);
	
	
	//delete subflow from session
	del_pnt_pA(&sess->pA_sflows, sflx);
	if(sess->last_subflow == sflx) sess->last_subflow = NULL;

	//delete subflow_pnt
	struct subflow_pnt *sfl_pnt;
	HASH_FIND(hh, sfl_pnt_hash, &sflx, sizeof(struct subflow_pnt*), sfl_pnt);
	if(sfl_pnt != NULL) {
		HASH_DEL(sfl_pnt_hash, sfl_pnt);
		free(sfl_pnt);
	}

	//delete subflow from hash tables	
	HASH_DEL(sfl_hash, sflx);

	log("%s: delete subflow %p, ft %s", func_name, (void *)sflx, buf_ft);
	free(sflx->snd_map_list_head);
	sflx->snd_map_list_head = NULL;
	free(sflx);
	return 0;
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//create_rex_event: creates event for retransmission of this packet
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_rex_event(struct fourtuple *ft, int tcp_state, unsigned char *buf, uint16_t buf_len) {
	//create retransmit event data
	struct rex_event_data *rex = malloc(sizeof(struct rex_event_data));
	rex->count = 0;
	rex->tcp_state = tcp_state;
	rex->ft = *ft;
	rex->len = buf_len;
	rex->buf = malloc( buf_len * sizeof(unsigned char));
	memcpy(rex->buf, buf, buf_len);

	//create new tp_event and put packet on retransmit queue
	struct tp_event *evt = malloc( sizeof(struct tp_event) );
	evt->type = RETRANSMIT;
	evt->data = (void*) rex;

	//insert event
	time_t dsec = REX_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_rex_event: executes or terminates retransmission event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_rex_event(struct tp_event *evt) {
	struct rex_event_data *rex = (struct rex_event_data*) evt->data;

	struct subflow *sflx;
	HASH_FIND(hh, sfl_hash, &rex->ft, sizeof(struct fourtuple), sflx);
	if(!sflx) {
		delete_rex_event(evt);
		return;	
	}

	//terminate if sfl tcp state has changed
	if(sflx->tcp_state != rex->tcp_state) {
		delete_rex_event(evt);
		return;	
	}

	if(rex->count < MAX_RETRANSMIT) {
		//send packet - ignore sending failure
		send_raw_packet(raw_sd, rex->buf, rex->len, htonl(rex->ft.ip_rem));

		int dsec = REX_TIME_INTERVAL;
		if( rex->count < MAX_RETRANSMIT -1) dsec = dsec<<(rex->count);
		else dsec = REX_TIME_INTERVAL;
		snprintf(msg_buf,MAX_MSG_LENGTH, "handle_rex_event: retransmit on sfl_id=%zu in sess_id=%zu", sflx->index, sflx->sess->index);
		add_msg(msg_buf);	
		insert_event(evt, dsec, 0);

		rex->count++;
	} else {
		//tear down subflow
		//if canidate, only this subflow, otherwise the whole session.
		if(sflx->act_state == 0) {
			send_reset_subflow(sflx);
			snprintf(msg_buf,MAX_MSG_LENGTH, "handle_rex_event: reset sfl id=%zu in sess id=%zu", sflx->index, sflx->sess->index);
			add_msg(msg_buf);
			delete_subflow(&sflx->ft);
		} else {
			struct session *sess = sflx->sess;
			for(unsigned i=0; i< sess->pA_sflows.number; i++) {
				struct subflow *sfly = (struct subflow*) sess->pA_sflows.pnts[i];
				send_reset_subflow(sfly);
				snprintf(msg_buf,MAX_MSG_LENGTH, "handle_rex_event: reset sfl id=%zu and sess id=%zu", sfly->index, sfly->sess->index);
				add_msg(msg_buf);
			}
			delete_session_parm(sess->token_loc);
			delete_session(&sess->ft, 1);
		}	
		delete_rex_event(evt);
	}
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_rex_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_rex_event(struct tp_event *evt) {
	struct rex_event_data *rex = (struct rex_event_data*) evt->data;
	free( rex );
	free( evt );
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_sfl_close_event: creates event for closing session in TIME_WAIT
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sfl_close_event(struct fourtuple *ft) {
	//create close event data
	struct sfl_close_event_data *cls = malloc(sizeof(struct sfl_close_event_data));
	cls->ft = *ft;

	//create new tp_event and put packet on retransmit queue
	struct tp_event *evt = malloc( sizeof(struct tp_event) );
	evt->type = SFL_CLOSE;
	evt->data = (void*) cls;

	//insert event
	time_t dsec = CLOSE_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_sfl_close_event: executes or terminates close event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sfl_close_event(struct tp_event *evt) {
	struct sfl_close_event_data *cls = (struct sfl_close_event_data*) evt->data;

	struct subflow *sfl;
	HASH_FIND(hh, sfl_hash, &cls->ft, sizeof(struct fourtuple), sfl);
	delete_sfl_close_event(evt);
	if(!sfl) return;	

	snprintf(msg_buf,MAX_MSG_LENGTH, "handle_sfl_close_event: sess id=%zu, sfl id=%zu terminated", sfl->sess->index, sfl->index);
	add_msg(msg_buf);
	delete_subflow(&sfl->ft);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_sfl_close_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sfl_close_event(struct tp_event *evt) {
	struct sfl_close_event_data *cls = (struct sfl_close_event_data*) evt->data;
	free( cls );
	free( evt );
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//create_prio_event: creates event for retrnamission of MPPRIO and eventually REMOVE_ADDR
// Used when old subflow broke
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_prio_event(struct fourtuple *ft, unsigned char addr_id_loc) {
	//create close event data
	struct prio_event_data *prio = malloc(sizeof(struct prio_event_data));
	prio->ft = *ft;
	prio->addr_id_loc = addr_id_loc;
	prio->count = 0;

	//create new tp_event and put packet on retransmit queue
	struct tp_event *evt = malloc( sizeof(struct tp_event) );
	evt->type = PRIO;
	evt->data = (void*) prio;

	//insert event
	time_t dsec = PRIO_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_prio_event: executes or terminates prio event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_prio_event(struct tp_event *evt) {
	struct prio_event_data *prio = (struct prio_event_data*) evt->data;

	struct session *sess;
	HASH_FIND(hh, sess_hash, &prio->ft, sizeof(struct fourtuple), sess);

	//delete
	prio->count++;
	if(!sess || sess->act_subflow == NULL || prio->count >= MAX_PRIO_EVENTS || 1) {
		delete_prio_event(evt);
		return;	
	}

	snprintf(msg_buf,MAX_MSG_LENGTH, "handle_prio_event: send break ack for sess_id=%zu, addr_id=%u on act subflow id=%zu", 
			sess->index, prio->addr_id_loc, sess->act_subflow->index);
	add_msg(msg_buf);	
	send_break_ack(sess->act_subflow, prio->addr_id_loc);
	time_t dsec = PRIO_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_prio_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_prio_event(struct tp_event *evt) {
	struct prio_event_data *prio = (struct prio_event_data*) evt->data;
	free( prio );
	free( evt );
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//create_sfl_break_event: creates event when subflow is broken (e.g. local IP address disappeared)
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_sfl_break_event(struct fourtuple *ft) {
	//find sfl to ft
	struct subflow *sfl;
	HASH_FIND(hh, sfl_hash, ft, sizeof(struct fourtuple), sfl);
	if(!sfl) return;

	snprintf(msg_buf,MAX_MSG_LENGTH, "create_sfl_break_event: created for sfl_id=%zu, sess_id=%zu", sfl->index, sfl->sess->index);
	add_msg(msg_buf);

	//create break event data
	struct break_event_data *brk = malloc(sizeof(struct break_event_data));
	brk->ft = *ft;

	//create new tp_event and put packet on retransmit queue
	struct tp_event *evt = malloc( sizeof(struct tp_event) );
	evt->type = SFL_BREAK;
	evt->data = (void*) brk;

	//insert event
	time_t dsec = BREAK_TIME_INTERVAL; 
	insert_event(evt, dsec, 0);
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//handle_sfl_break_event: executes or terminates close event 
//++++++++++++++++++++++++++++++++++++++++++++++++
void handle_sfl_break_event(struct tp_event *evt) {
	struct break_event_data *brk = (struct break_event_data*) evt->data;

	struct subflow *sfl;
	HASH_FIND(hh, sfl_hash, &brk->ft, sizeof(struct fourtuple), sfl);
	if(!sfl) {
		delete_sfl_break_event(evt);
		return;	
	}

	if(sfl->broken){
		if(check_sfl_teardown_timer(sfl)) {
			snprintf(msg_buf,MAX_MSG_LENGTH, "handle_sfl_break_event: sess id=%zu, sfl id=%zu terminated", sfl->sess->index, sfl->index);
			add_msg(msg_buf);
			execute_sfl_teardown(sfl);
			delete_sfl_break_event(evt);	
		}
		else{
			//reinsert event
			time_t dsec = BREAK_TIME_INTERVAL; 
			insert_event(evt, dsec, 0);
		}
	}
	else delete_sfl_break_event(evt);
}



//++++++++++++++++++++++++++++++++++++++++++++++++
//delete_sfl_break_event
//++++++++++++++++++++++++++++++++++++++++++++++++
void delete_sfl_break_event(struct tp_event *evt) {
	struct break_event_data *brk = (struct break_event_data*) evt->data;
	free( brk );
	free( evt );
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//void start_sfl_teardown_timer(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
void start_sfl_teardown_timer(struct subflow *sfl) {
	if(sfl->broken) return;
	sfl->broken = 1;
	gettimeofday(&sfl->teardown_time, NULL);
	sfl->teardown_time.tv_sec += SFL_TEARDOWN_TIME_INTERVAL;
}


//++++++++++++++++++++++++++++++++++++++++++++++++
//int check_sfl_teardown_timer(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
int check_sfl_teardown_timer(struct subflow *sfl) {
	if(sfl->broken){
		struct timeval now;
		gettimeofday(&now, NULL);
		if(sfl->teardown_time.tv_sec <= now.tv_sec) return 1;
	}
	return 0;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//void execute_sfl_teardown(struct subflow *sfl)
//++++++++++++++++++++++++++++++++++++++++++++++++
void execute_sfl_teardown(struct subflow *sfl) {
	if(sfl == NULL) return;
	snprintf(msg_buf,MAX_MSG_LENGTH, "execute_sfl_teardown: sfl id=%zu is terminated", sfl->index);
	add_msg(msg_buf);
	delete_subflow(&sfl->ft);
}
