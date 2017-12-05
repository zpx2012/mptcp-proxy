#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include "sha1.h"
#include "my_checksum.h"

typedef unsigned char		uint8_t;
typedef unsigned short int	uint16_t;
typedef unsigned int		uint32_t;
typedef unsigned long int	uint64_t;

struct test_dss_option{
	uint32_t dsn_n;
	uint32_t ssn_n;
	uint16_t range_n;
};

int strhex_to_bytehex(char* strhex,int8_t* bytehexbuf,int len){

	char* strhex_ptr = strhex;
	int8_t* bytehexbuf_ptr = bytehexbuf;
	for(;bytehexbuf_ptr<bytehexbuf+len;bytehexbuf_ptr++){
		sscanf(strhex_ptr,"%02hhx",bytehexbuf_ptr);
		strhex_ptr +=2;
	}
	return 1;
}

//++++++++++++++++++++++++++++++++++++++++++++++++
//util: create IDSN: 32bit trunc of SHA1(key)
//++++++++++++++++++++++++++++++++++++++++++++++++
void create_idsn_token(uint32_t * const key, uint32_t *idsn, uint32_t *token, uint32_t *idsn_h) {
	uint32_t resblock[5];
	sha1_buffer ( (const char *) key, 8, (unsigned char *) resblock);
	*token = (resblock[0]);
	*idsn = ntohl( *( resblock+4) );
	if(idsn_h)
		*idsn_h = ntohl( *( resblock+3) );
}

int main()
{
	char* data = "474554202f20485454502f312e310d0a486f73743a206d756c7469706174682d7463702e6f72670d0a436f6e6e656374696f6e3a206b6565702d616c6976650d0a557067726164652d496e7365637572652d52657175657374733a20310d0a557365722d4167656e743a204d6f7a696c6c612f352e3020285831313b204c696e7578207838365f363429204170706c655765624b69742f3533372e333620284b48544d4c2c206c696b65204765636b6f29204368726f6d652f36322e302e333230322e3934205361666172692f3533372e33360d0a4163636570743a20746578742f68746d6c2c6170706c69636174696f6e2f7868746d6c2b786d6c2c6170706c69636174696f6e2f786d6c3b713d302e392c696d6167652f776562702c696d6167652f61706e672c2a2f2a3b713d302e380d0a4163636570742d456e636f64696e673a20677a69702c206465666c6174650d0a4163636570742d4c616e67756167653a207a682d434e2c7a683b713d302e392c656e3b713d302e380d0a436f6f6b69653a20696d7374696d653d313531323130343331313b205f5f75746d613d35393933313138352e323039393834373137312e313531323130343331332e313531323130343331332e313531323136363439382e323b205f5f75746d633d35393933313138353b205f5f75746d7a3d35393933313138352e313531323136363439382e322e322e75746d6373723d676f6f676c657c75746d63636e3d286f7267616e6963297c75746d636d643d6f7267616e69637c75746d6374723d286e6f7425323070726f7669646564290d0a0d0a";
	uint32_t key_loc_h[2] = {0xcf1459b9,0x847f3488};
	struct test_dss_option test_dss;
	test_dss.dsn_n = htonl(0x37d39b21);
	test_dss.ssn_n = htonl(1);
	test_dss.range_n = htons(594);
		
	uint32_t idsn_loc_h_my, idsn_h_loc_h_my;
	uint32_t token_loc;
	uint32_t key_loc_n[2];
	key_loc_n[0] = htonl(key_loc_h[0]);
	key_loc_n[1] = htonl(key_loc_h[1]);
	create_idsn_token(key_loc_n,&idsn_loc_h_my,&token_loc,&idsn_h_loc_h_my);
	printf("my:idsn_l %x, idsn_h %x\n",idsn_loc_h_my,idsn_h_loc_h_my);

	unsigned int data_len = strlen(data)/2;
	int8_t* buf_data = malloc(data_len*sizeof(uint8_t));
	memset(buf_data,0,data_len);
	strhex_to_bytehex(data,buf_data,data_len);

	printf("csum:%x\n",mpdsm_checksum((uint8_t*)&test_dss,idsn_h_loc_h_my,buf_data,data_len));
}

