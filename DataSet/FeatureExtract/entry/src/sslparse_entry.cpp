
#include "base_utils.h"
#include "ssl_utils.h"
#include "MESA/stream_inc/stream_base.h"
#include "MESA/stream_inc/stream_rawpkt.h"
#include "cjson/cJSON.h"
#include "openssl/x509.h"
#include "base64.h"
#include <algorithm>
#define STREAM_PACKET_COUNT_MAX 10000
#define TLS_MESSAGE_LEN_MAX 20000

void *g_logger = NULL;
FILE *g_fp = NULL;

struct tls_message_type{
    int message_type;
    int content_type;
    int handshake_type;
    const char *name;
};

struct tls_message_type g_tls_types[] = {
    {0, 22, 0, "hello_request_RESERVED"},
    {1, 22, 1, "client_hello"},
    {2, 22, 2, "server_hello"},
    {3, 22, 3, "hello_verify_request_RESERVED"},
    {4, 22, 4, "new_session_ticket"},
    {5, 22, 5, "end_of_early_data"},
    {6, 22, 6, "hello_retry_request_RESERVED"},
    {7, 22, 8, "encrypted_extensions"},
    {8, 22, 11, "certificate"},
    {9, 22, 12, "server_key_exchange_RESERVED"},
    {10, 22, 13, "certificate_request"},
    {11, 22, 14, "server_hello_done_RESERVED"},
    {12, 22, 15, "certificate_verify"},
    {13, 22, 16, "client_key_exchange_RESERVED"},
    {14, 22, 20, "finished"},
    {15, 22, 21, "certificate_url_RESERVED"},
    {16, 22, 22, "certificate_status_RESERVED"},
    {17, 22, 23, "supplemental_data_RESERVED"},
    {18, 22, 24, "key_update"},
    {19, 22, 25, "compressed_certificate"},
    {20, 22, 254, "message_hash"},
    {21, 20, 0, "change_cipher_spec"},
    {22, 21, 0, "alert"},
    {23, 23, 0, "application_data"},
    {24, 24, 0, "heartbeat"},
    {25, 25, 0, "tls12_cid"},
    {26, 22, -1, "handshake_unknown"},
};

struct tls_message_detail{
    int type;
    int len;
    unsigned char buff[TLS_MESSAGE_LEN_MAX];
    int buff_len;
};

struct tls_filtered_message{
    unsigned char buff[TLS_MESSAGE_LEN_MAX];
    int buff_len;
};

struct pkt_parsed_info{
    addr_type_t addr_type;
	union{
		struct iphdr *v4;
		struct ip6_hdr *v6;
	}iphdr;
	uint16_t iphdr_len;
	uint16_t ip_totlen;
	struct tcphdr *tcphdr;
	uint16_t tcphdr_len;
	char *data;
	uint16_t data_len;
};

struct pme_info{
    int _errno;
    char sip[INET_ADDRSTRLEN];
    int sport;
    char dip[INET_ADDRSTRLEN];
    int dport;
    struct ssl_chello chello;
    struct tls_message_detail cur_c2s_tls;
    struct tls_message_detail cur_s2c_tls;
    struct tls_filtered_message message_client_hello;
    struct tls_filtered_message message_client_hello_no_extensions;
    struct tls_filtered_message message_server_hello;
    struct tls_filtered_message message_server_hello_no_extensions;
    struct tls_filtered_message message_certificate;
    struct tls_filtered_message message_certificate_no_serial;
    int has_fin_rst;
};

int ipv4_header_parse(const void *a_packet, struct pkt_parsed_info* pktinfo){
    if(a_packet == NULL){
        return -1;
    }
	pktinfo->addr_type = ADDR_TYPE_IPV4;
	pktinfo->iphdr.v4 = (struct iphdr*)a_packet;
	pktinfo->iphdr_len = pktinfo->iphdr.v4->ihl * 4;
	pktinfo->ip_totlen = ntohs(pktinfo->iphdr.v4->tot_len);
	pktinfo->tcphdr = (struct tcphdr*)((char*)pktinfo->iphdr.v4 + pktinfo->iphdr_len);
	pktinfo->tcphdr_len = pktinfo->tcphdr->doff * 4;
	pktinfo->data = (char*)pktinfo->tcphdr + pktinfo->tcphdr_len;
	pktinfo->data_len = pktinfo->ip_totlen - pktinfo->iphdr_len - pktinfo->tcphdr_len;
    /*
    struct iphdr *_iphdr = pktinfo->iphdr.v4;
    int ttl = _iphdr->ttl;
    int ipid = ntohs(_iphdr->id);
    printf("ipv4: ipid = %02x, ttl = %d, data_len = %d\n", ipid, ttl, pktinfo->data_len);
    */
	return 0;
}


int chello_packet_parse(struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo){
    enum chello_parse_result chello_status = CHELLO_PARSE_INVALID_FORMAT;
    char *buff = pktinfo->data;
    int len = pktinfo->data_len;
    ssl_chello_parse(&(pmeinfo->chello), (const unsigned char*)buff, len, &chello_status);
	if(chello_status != CHELLO_PARSE_SUCCESS){
        LOG_ERROR(g_logger, "Error: chello parse failed\n");
        return -1;
	}
    return 0;
}

int get_tls_message_type(int content_type, int handshake_type){
    int type_count = sizeof(g_tls_types) / sizeof(struct tls_message_type);
    for(int i = 0; i < type_count; i++){
        if(g_tls_types[i].content_type == content_type && g_tls_types[i].handshake_type == handshake_type){
            return i;
        }
    }
    if(content_type == 22){
        return type_count - 1;
    }
    return -1;
}

int client_server_hello_get(unsigned char *buff, int len, struct pme_info *pmeinfo, int type){
    char buff1[TLS_MESSAGE_LEN_MAX];
    int i = 0, len1 = 0;
    memcpy(buff1 + len1, buff + i, 6);
    i += 6;
    len1 += 6;
    //random
    i += 32;
    //session_id
    int session_id_len = (uint8_t)buff[i];
    i += (1 + session_id_len);
    //cipher suites: type = 1, client hello; type = 2, server hello
    if(type == 1){
        int cipher_suites_len = (uint16_t)(buff[i] << 8) + (uint8_t)buff[i + 1];
        memcpy(buff1 + len1, buff + i, 2 + cipher_suites_len);
        i += (2 + cipher_suites_len);
        len1 += (2 + cipher_suites_len);
    }
    if(type == 2){
        memcpy(buff1 + len1, buff + i, 2);
        i += 2;
        len1 += 2;
    }
    //compression methods
    int compression_methods_len = (uint8_t)buff[i];
    memcpy(buff1 + len1, buff + i, 1 + compression_methods_len);
    i += (1 + compression_methods_len);
    len1 += (1 + compression_methods_len);
    int extensions_index = len1;
    //extensions
    int extensions_len = (uint16_t)(buff[i] << 8) + (uint8_t)buff[i + 1];
    memcpy(buff1 + len1, buff + i, 2);
    i += 2;
    len1 += 2;
    int i1 = i;
    for(; i + 3 < i1 + extensions_len;){
        int type = (uint16_t)(buff[i] << 8) + (uint8_t)buff[i + 1];
        int extension_len = (uint16_t)(buff[i + 2] << 8) + (uint8_t)buff[i + 3];
        if(type == 21){
            i += (4 + extension_len);
            continue;
        }
        memcpy(buff1 + len1, buff + i, 4 + extension_len);
        i += (4 + extension_len);
        len1 += (4 + extension_len);
    }
    if(len1 > len){
        return -1;
    }
    if(type == 1){
        memcpy(pmeinfo->message_client_hello.buff, buff1, len1);
        pmeinfo->message_client_hello.buff_len = len1;
        memcpy(pmeinfo->message_client_hello_no_extensions.buff, buff1, extensions_index);
        pmeinfo->message_client_hello_no_extensions.buff_len = extensions_index;
    }
    if(type == 2){
        memcpy(pmeinfo->message_server_hello.buff, buff1, len1);
        pmeinfo->message_server_hello.buff_len = len1;
        memcpy(pmeinfo->message_server_hello_no_extensions.buff, buff1, extensions_index);
        pmeinfo->message_server_hello_no_extensions.buff_len = extensions_index;
    }
    return 0;
}

int client_hello_get(struct pme_info* pmeinfo, unsigned char *buff, int len){
    int ret = client_server_hello_get(buff, len, pmeinfo, 1);
    if(ret < 0){
        LOG_ERROR(g_logger, "Invalid client hello");
        return -1;
    }
    /*
    printf("client_hello, buff_len = %d\n", pmeinfo->message_client_hello.buff_len);
    for(int i = 0; i < pmeinfo->message_client_hello.buff_len; i++){
        printf("%02x ", (uint8_t)pmeinfo->message_client_hello.buff[i]);
    }
    printf("\n");
    printf("client_hello_no_extensions, buff_len = %d\n", pmeinfo->message_client_hello_no_extensions.buff_len);
    for(int i = 0; i < pmeinfo->message_client_hello_no_extensions.buff_len; i++){
        printf("%02x ", (uint8_t)pmeinfo->message_client_hello_no_extensions.buff[i]);
    }
    printf("\n");
    */
    return 0;
}

int server_hello_get(struct pme_info* pmeinfo, unsigned char *buff, int len){
    int ret = client_server_hello_get(buff, len, pmeinfo, 2);
    if(ret < 0){
        LOG_ERROR(g_logger, "Invalid server hello");
        return -1;
    }
    /*
    printf("server_hello, buff_len = %d\n", pmeinfo->message_server_hello.buff_len);
    for(int i = 0; i < pmeinfo->message_server_hello.buff_len; i++){
        printf("%02x ", (uint8_t)pmeinfo->message_server_hello.buff[i]);
    }
    printf("\n");
    printf("server_hello_no_extensions, buff_len = %d\n", pmeinfo->message_server_hello_no_extensions.buff_len);
    for(int i = 0; i < pmeinfo->message_server_hello_no_extensions.buff_len; i++){
        printf("%02x ", (uint8_t)pmeinfo->message_server_hello_no_extensions.buff[i]);
    }
    printf("\n");
    */
    return 0;
}

int get_public_key(X509 *cert, unsigned char *public_key){
    //printf("call get_public_key\n");
    int public_key_len = 0;
    EVP_PKEY *pkey = X509_get_pubkey(cert);
    if(pkey == NULL){
        return -1;
    }
    unsigned char *p = NULL;
    public_key_len = i2d_PUBKEY(pkey, &p);
    public_key_len -= 24;
    memcpy(public_key, p + 24, public_key_len);
    /*
    printf("public_key_len = %d\n", public_key_len);
    for(int i = 0; i < public_key_len; i++){
        printf("%02x ", public_key[i]);
    }
    printf("\n");
    */
    EVP_PKEY_free(pkey);
    return public_key_len;
}

int find_sub_block(unsigned char *s1, int len1, unsigned char *s2, int len2){
    for(int i = 0; i + len2 < len1; i++){
        int j;
        for(j = 0; j < len2; j++){
            if(s1[i + j] != s2[j]){
                break;
            }
        }
        if(j == len2){
            return i;
        }
    }
    return -1;
}

int strip_data_from_buff(unsigned char *input, int input_len, int begin, int end, unsigned char *output){
    int output_len = 0;
    memcpy(output + output_len, input, begin);
    output_len += begin;
    memcpy(output + output_len, input + end, input_len - end);
    output_len += (input_len - end);
    return output_len;
}

int strip_encrypted_data(unsigned char *input, int input_len, unsigned char *output){
    int encrypted_data_begin = input_len - 24;
    int encrypted_data_end = input_len;
    return strip_data_from_buff(input, input_len, encrypted_data_begin, encrypted_data_end, output);
}

int strip_public_key(X509 *cert, unsigned char *input, int input_len, unsigned char *output){
    unsigned char public_key[TLS_MESSAGE_LEN_MAX];
    int public_key_len = get_public_key(cert, public_key);
    if(public_key_len < 0){
        return -1;
    }
    int public_key_begin = find_sub_block(input, input_len, public_key, public_key_len);
    //printf("public key begin = %d\n", public_key_begin);
    if(public_key_begin < 0){
        return -1;
    }
    int public_key_end = public_key_begin + public_key_len;
    return strip_data_from_buff(input, input_len, public_key_begin, public_key_end, output);
}


int get_serial_number(X509 *cert, unsigned char *serial_number){
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);
    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    int len = BN_num_bytes(bn);
    BN_bn2bin(bn, serial_number);
    /*
    printf("serial number len = %d\n", len);
    for(int i = 0; i < len; i++){
        printf("%02x ", serial_number[i]);
    }
    printf("\n");
    */
    return len;
}

int strip_serial_number(X509 *cert, unsigned char *input, int input_len, unsigned char *output){
    unsigned char serial_number[TLS_MESSAGE_LEN_MAX];
    int serial_number_len = get_serial_number(cert, serial_number);
    if(serial_number_len < 0){
        return -1;
    }
    int serial_number_begin = find_sub_block(input, input_len, serial_number, serial_number_len);
    //printf("serial number begin = %d\n", serial_number_begin);
    if(serial_number_begin < 0){
        return -1;
    }
    int serial_number_end = serial_number_begin + serial_number_len;
    return strip_data_from_buff(input, input_len, serial_number_begin, serial_number_end, output);
}

int certificate_get(struct pme_info* pmeinfo, unsigned char *buff, int len){
    //printf("call certificate_get\n");
    if(10 > len){
        return -1;
    }
    int cert_len = (buff[7] << 16) + (buff[8] << 8) + buff[9];
    int i = 10;
    if(i + cert_len > len){
        return -1;
    }
    unsigned char cert_buff[TLS_MESSAGE_LEN_MAX];
    memcpy(cert_buff, buff + i, cert_len);
    const unsigned char *p = cert_buff;
    X509 *cert = d2i_X509(NULL, &p, cert_len);
    if(cert == NULL){
        return -1;
    }
    unsigned char buff1[TLS_MESSAGE_LEN_MAX];
    unsigned char *input = cert_buff;
    int input_len = cert_len;
    unsigned char *output = buff1;
    int output_len = 0;
    output_len = strip_public_key(cert, input, input_len, output);
    std::swap(output, input);
    input_len = output_len;
    output_len = strip_encrypted_data(input, input_len, output);
    if(output_len >= 0){
        memcpy(pmeinfo->message_certificate.buff, output, output_len);
        pmeinfo->message_certificate.buff_len = output_len;
    }
    std::swap(output, input);
    input_len = output_len;
    output_len = strip_serial_number(cert, input, input_len, output);
    if(output_len >= 0){
        memcpy(pmeinfo->message_certificate_no_serial.buff, output, output_len);
        pmeinfo->message_certificate_no_serial.buff_len = output_len;
    }
    X509_free(cert);
    return 0;
}

int tls_header_parse(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo){
    int i = 0, len = pktinfo->data_len;
    int curdir = stream->curdir;
    struct tls_message_detail *cur_tls = NULL;
    if(curdir == 1){
        cur_tls = &(pmeinfo->cur_c2s_tls);
    }
    if(curdir == 2){
        cur_tls = &(pmeinfo->cur_s2c_tls);
    }
    int cp_len = 0;
    while(i < len){
        if(cur_tls->buff_len < 5){
            cp_len = MIN(5 - cur_tls->buff_len, len - i);
            memcpy(cur_tls->buff + cur_tls->buff_len, pktinfo->data + i, cp_len);
            cur_tls->buff_len += cp_len;
            i += cp_len;
            if(cur_tls->buff_len < 5){
                break;
            }
        }
        int content_type = cur_tls->buff[0];
        if(content_type == 0x16){
            if(cur_tls->buff_len < 6){
                cp_len = MIN(1, len - i);
                memcpy(cur_tls->buff + cur_tls->buff_len, pktinfo->data + i, cp_len);
                cur_tls->buff_len += cp_len;
                i += cp_len;
                if(cur_tls->buff_len < 6){
                    break;
                }
            }
        }
        int handshake_type = 0;
        if(content_type == 0x16){
            handshake_type = cur_tls->buff[5];
        }
        int message_type = get_tls_message_type(content_type, handshake_type);
        cur_tls->type = message_type;
        cur_tls->len = (uint16_t)(cur_tls->buff[3] << 8) + (uint8_t)cur_tls->buff[4];
        if(message_type < 0){
            LOG_ERROR(g_logger, "message_type unknown, content_type = %d, handshake_type = %d", content_type, handshake_type);
            memset(cur_tls, 0, sizeof(*cur_tls));
            break;
        }
        cp_len = MIN(cur_tls->len + 5 - cur_tls->buff_len, len - i);
        //client hello, server hello, certificate
        if(message_type == 1 || message_type == 2 || message_type == 8){
            memcpy(cur_tls->buff + cur_tls->buff_len, pktinfo->data + i, cp_len);
        }
        cur_tls->buff_len += cp_len;
        i += cp_len;
        if(cur_tls->len + 5 == cur_tls->buff_len){
            if(message_type == 1 || message_type == 2 || message_type == 8){
                switch (message_type){
                    case 1:
                        client_hello_get(pmeinfo, cur_tls->buff + 5, cur_tls->len);
                        break;
                    case 2:
                        server_hello_get(pmeinfo, cur_tls->buff + 5, cur_tls->len);
                        break;
                    case 8:
                        certificate_get(pmeinfo, cur_tls->buff + 5, cur_tls->len);
                        break;
                    default:
                        break;
                }
            }
            memset(cur_tls, 0, sizeof(*cur_tls));
        }
    }
    return 0;
}



int packet_need_filter(struct pkt_parsed_info *pktinfo){
    struct iphdr *_iphdr = pktinfo->iphdr.v4;
    int ttl = _iphdr->ttl;
    if(ttl == 70 || ttl == 75){
        //printf("packet_need_filter: ret = 1, ttl = %d\n", ttl);
        return 1;
    }
    int data_len = pktinfo->data_len;
    if(data_len == 0){
        //printf("packet_need_filter: ret 1, data_len = %d\n", data_len);
        return 1;
    }
    return 0;
}

char pending_opstate(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo){
    //printf("call pending_opstate\n");
    struct tcphdr *_tcphdr = pktinfo->tcphdr;
    if(_tcphdr->fin || _tcphdr->rst){
        pmeinfo->has_fin_rst = 1;
    }
    struct stream_tuple4_v4 *tuple4 = stream->addr.tuple4_v4;
    inet_ntop(AF_INET, &(tuple4->saddr), pmeinfo->sip, INET_ADDRSTRLEN);
    inet_ntop(AF_INET, &(tuple4->daddr), pmeinfo->dip, INET_ADDRSTRLEN);
    pmeinfo->sport = ntohs(tuple4->source);
    pmeinfo->dport = ntohs(tuple4->dest);
    if(packet_need_filter(pktinfo) == 1){
        return APP_STATE_FAWPKT | APP_STATE_GIVEME;
    }
    int ret = chello_packet_parse(pmeinfo, pktinfo);
    if(ret < 0){
        pmeinfo->_errno = -1;
        return APP_STATE_FAWPKT | APP_STATE_DROPME;
    }
    tls_header_parse(stream, pmeinfo, pktinfo);
    return APP_STATE_FAWPKT | APP_STATE_GIVEME;
}

char data_opstate(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo){
    struct tcphdr *_tcphdr = pktinfo->tcphdr;
    if(_tcphdr->fin || _tcphdr->rst){
        pmeinfo->has_fin_rst = 1;
    }
    if(packet_need_filter(pktinfo) == 0){
        tls_header_parse(stream, pmeinfo, pktinfo);
    }
    return APP_STATE_FAWPKT | APP_STATE_GIVEME;
}

void time_tostring(struct timeval tv, char *buf, int buflen){
    char tmbuf[64];
    time_t nowtime;
    struct tm *nowtm;
    nowtime = tv.tv_sec;
    //printf("nowtime = %lld\n", nowtime);
    nowtm = localtime(&nowtime);
    strftime(tmbuf, sizeof(tmbuf), "%Y-%m-%d %H:%M:%S", nowtm);
    snprintf(buf, buflen, "%s.%06ld", tmbuf, tv.tv_usec);
    return;
}

void print_tls_message(struct tls_filtered_message *message, const char *name){
    int len = message->buff_len;
    printf("%s: len = %d, data = \n", name, len);
    for(int i = 0; i < len; i++){
        printf("%02x ", message->buff[i]);
    }
    printf("\n");
}

void cjson_add_tls_message(cJSON *log_obj, struct tls_filtered_message *message, const char *tls_message_name){
    //print_tls_message(message, tls_message_name);
    unsigned char out_buff[TLS_MESSAGE_LEN_MAX];
    int out_len = b64_encode((const unsigned char*)message->buff, message->buff_len, out_buff);
    if(out_len > 0){
        memcpy(message->buff, out_buff, out_len);
        message->buff_len = out_len;
        cJSON *tls_message = cJSON_CreateObject();
        cJSON_AddStringToObject(tls_message, "data", (char*)message->buff);
        cJSON_AddNumberToObject(tls_message, "len", message->buff_len);
        cJSON_AddItemToObject(log_obj, tls_message_name, tls_message);
    }
    return;
}

void output_result(struct pme_info *pmeinfo){
    if(pmeinfo->has_fin_rst == 0){
        printf("not have fin or rst\n");
        return;
    }
    cJSON *log_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(log_obj, "sip", pmeinfo->sip);
    cJSON_AddNumberToObject(log_obj, "sport", pmeinfo->sport);
    cJSON_AddStringToObject(log_obj, "dip", pmeinfo->dip);
    cJSON_AddNumberToObject(log_obj, "dport", pmeinfo->dport);
    cJSON_AddStringToObject(log_obj, "proto", "tcp");
    cjson_add_tls_message(log_obj, &(pmeinfo->message_client_hello), "client_hello");
    cjson_add_tls_message(log_obj, &(pmeinfo->message_client_hello_no_extensions), "client_hello_no_extensions");
    cjson_add_tls_message(log_obj, &(pmeinfo->message_server_hello), "server_hello");
    cjson_add_tls_message(log_obj, &(pmeinfo->message_server_hello_no_extensions), "server_hello_no_extensions");
    cjson_add_tls_message(log_obj, &(pmeinfo->message_certificate), "certificate");
    cjson_add_tls_message(log_obj, &(pmeinfo->message_certificate_no_serial), "certificate_no_serial");
    char *log_msg = cJSON_PrintUnformatted(log_obj);
    //printf("%s\n\n", log_msg);
    fputs(log_msg, g_fp);
    fputs("\n", g_fp);
	cJSON_Delete(log_obj);
    cJSON_free(log_msg);
}

char close_opstate(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo, const void *a_packet){
    if(a_packet != NULL){
        struct tcphdr *_tcphdr = pktinfo->tcphdr;
        if(_tcphdr->fin || _tcphdr->rst){
            pmeinfo->has_fin_rst = 1;
        }
        if(packet_need_filter(pktinfo) == 0){
            tls_header_parse(stream, pmeinfo, pktinfo);
        }
    }
    return APP_STATE_FAWPKT | APP_STATE_DROPME;
}

void pme_info_destroy(struct pme_info *pmeinfo){
    FREE(&pmeinfo);
    pmeinfo = NULL;
}

extern "C" char sslparse_entry(struct streaminfo *stream, void** pme, int thread_seq, const void* a_packet){
	//printf("call sslparse_entry\n");
    char ret;
	struct pme_info *pmeinfo = *(struct pme_info **)pme;
    //printf("pmeinfo = %p, opstate = %d, a_packet = %p\n", pmeinfo, stream->opstate, a_packet);
	if(a_packet == NULL && stream->opstate != OP_STATE_CLOSE){
		return APP_STATE_FAWPKT | APP_STATE_GIVEME;
	}
    struct pkt_parsed_info pktinfo;
    memset(&pktinfo, 0, sizeof(pktinfo));
    ipv4_header_parse(a_packet, &pktinfo);
	switch(stream->opstate){
		case OP_STATE_PENDING:
            //printf("call pending\n");
            pmeinfo = ALLOC(struct pme_info, 1);
	        *pme = pmeinfo;
            ret = pending_opstate(stream, pmeinfo, &pktinfo);
			break;
		case OP_STATE_DATA:
            //printf("call data\n");
            ret = data_opstate(stream, pmeinfo, &pktinfo);
			break;
		case OP_STATE_CLOSE:
            //printf("call close\n");
			ret = close_opstate(stream, pmeinfo, &pktinfo, a_packet);
			break;
		default:
			break;
	}
    if((ret & APP_STATE_DROPME)){
        if(pmeinfo->_errno >= 0){
            output_result(pmeinfo);
        }
        pme_info_destroy(pmeinfo);
    }
	return ret;
}

extern "C" int sslparse_init(){
    char *log_path = (char*)"./ssl_parse_stat.log";
    int log_level = 10;
    g_logger = MESA_create_runtime_log_handle(log_path, log_level);
    g_fp = fopen("./ssl_parse_stat.txt", "a+");
    return 0;
}

extern "C" void sslparse_destroy(){

}
