
#include "base_utils.h"
#include "ssl_utils.h"
#include "MESA/stream_inc/stream_base.h"
#include "MESA/stream_inc/stream_rawpkt.h"
#include "cjson/cJSON.h"
#define STREAM_PACKET_COUNT_MAX 10000

/*
{
	"sip": "0.0.0.0", // IP source address 
	"dip": "255.255.255.255", // IP destination address 
	"proto": 17, // IP protocol number (17 = UDP) 
	"sport": 68, // UDP source port "dp": 
	"dport": 67, // UDP destination port 
	"c2s_bytes": 900, // c to s bytes
	"c2s__pkts": 3, // packets sent from c to s 
	"s2c_bytes": 900, // s to c bytes
	"s2c__pkts": 3, // packets sent from s to c 
	"duration": 456, // 456 ms
	"packets": [
		{
			"byte": 300, // bytes in UDP Data field 
			"dir": "c2s", // direction: sa -> da 
			"interval": 0 // inter-packet time: 0 ms since time_start
		}, ...
	],
	"tls":{
		"ssl_version": "tls1.3",
		"cipher_suite": [...],
        "sni" : "www.baidu.com",
        "alpn" : "http2",
		"extensions": [...]
	}
}
*/

void *g_logger = NULL;
FILE *g_fp = NULL;
int g_count = 0;
int g_stream_count = 0;
int g_stream_succ_count = 0;
int g_stream_fail_count = 0;
int g_log_succ_count = 0;
int g_exceed_max_pkts_count = 0;

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

struct pkt_stat_info{
    struct timeval pkt_time;
    int bytes;
    int dir;
    int interval;
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

struct tls_message_info{
    int dir;
    int type;
    int length;
};

struct pme_info{
    int _errno;
    char sip[INET_ADDRSTRLEN];
    int sport;
    char dip[INET_ADDRSTRLEN];
    int dport;
    int c2s_bytes;
    int s2c_bytes;
    int c2s_pkts;
    int s2c_pkts;
    int total_pkts;
    int duration;
    struct timeval start_time;
    struct timeval end_time;
    int last_c2s_pkt_index;
    int last_s2c_pkt_index;
    struct pkt_stat_info pkt_info_list[STREAM_PACKET_COUNT_MAX];
    struct ssl_chello chello;
    int tls_message_count;
    struct tls_message_info tls_info_list[STREAM_PACKET_COUNT_MAX];
    unsigned char c2s_tls_payload[1500];
    int c2s_tls_last_segment_len;
    int c2s_tls_current_segment_offset;
    unsigned char s2c_tls_payload[1500];
    int s2c_tls_last_segment_len;
    int s2c_tls_current_segment_offset;
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

int packet_stat(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info* pktinfo){
    if(pmeinfo->total_pkts == STREAM_PACKET_COUNT_MAX){
        LOG_INFO(g_logger, "packet nums > STREAM_PACKET_COUNT_MAX(%d)\n", STREAM_PACKET_COUNT_MAX);
        g_exceed_max_pkts_count++;
        return -1;
    }
    pmeinfo->pkt_info_list[pmeinfo->total_pkts].bytes = pktinfo->data_len;
    pmeinfo->pkt_info_list[pmeinfo->total_pkts].dir = stream->curdir;
    get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TIMESTAMP, &(pmeinfo->pkt_info_list[pmeinfo->total_pkts].pkt_time));
    int last_pkt_index = -1;
    if(stream->curdir == 1){
        pmeinfo->c2s_pkts++;
        pmeinfo->c2s_bytes += pktinfo->data_len;
        last_pkt_index = pmeinfo->last_c2s_pkt_index;
        pmeinfo->last_c2s_pkt_index = pmeinfo->total_pkts;
    }
    if(stream->curdir == 2){
        pmeinfo->s2c_pkts++;
        pmeinfo->s2c_bytes += pktinfo->data_len;
        last_pkt_index = pmeinfo->last_s2c_pkt_index;
        pmeinfo->last_s2c_pkt_index = pmeinfo->total_pkts;
    }
    if(last_pkt_index >= 0){
        pmeinfo->pkt_info_list[pmeinfo->total_pkts].interval = 
            (pmeinfo->pkt_info_list[pmeinfo->total_pkts].pkt_time.tv_sec - pmeinfo->pkt_info_list[last_pkt_index].pkt_time.tv_sec) * 1000 + 
            (pmeinfo->pkt_info_list[pmeinfo->total_pkts].pkt_time.tv_usec - pmeinfo->pkt_info_list[last_pkt_index].pkt_time.tv_usec) / 1000;
    }
    pmeinfo->total_pkts++;
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

int tls_header_parse(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo){
    int curdir = stream->curdir;
    unsigned char *buff = NULL;
    int len = 0;
    if(curdir == 1){
        if(pmeinfo->c2s_tls_current_segment_offset >= pktinfo->data_len){
            pmeinfo->c2s_tls_current_segment_offset -= pktinfo->data_len;
            return 0;
        }
        memcpy((char*)pmeinfo->c2s_tls_payload + pmeinfo->c2s_tls_last_segment_len, 
            pktinfo->data + pmeinfo->c2s_tls_current_segment_offset, pktinfo->data_len - pmeinfo->c2s_tls_current_segment_offset);
        buff = pmeinfo->c2s_tls_payload;
        len = pktinfo->data_len + pmeinfo->c2s_tls_last_segment_len - pmeinfo->c2s_tls_current_segment_offset;
    }
    if(curdir == 2){
        if(pmeinfo->s2c_tls_current_segment_offset >= pktinfo->data_len){
            pmeinfo->s2c_tls_current_segment_offset -= pktinfo->data_len;
            return 0;
        }
        memcpy((char*)pmeinfo->s2c_tls_payload + pmeinfo->s2c_tls_last_segment_len, 
            pktinfo->data + pmeinfo->s2c_tls_current_segment_offset, pktinfo->data_len - pmeinfo->s2c_tls_current_segment_offset);
        buff = pmeinfo->s2c_tls_payload;
        len = pktinfo->data_len + pmeinfo->s2c_tls_last_segment_len - pmeinfo->s2c_tls_current_segment_offset;
    }
    int i = 0;
    int flag = 0;
    while(i < len){
        if(i + 4 >= len){
            flag = 1;
            break;
        }
        int content_type = buff[i];
        int handshake_type = 0;
        if(buff[i] == 0x16){
            if(i + 5 >= len){
                flag = 1;
                break;
            }
            handshake_type = buff[i + 5];
        }
        int message_type = get_tls_message_type(content_type, handshake_type);
        if(message_type < 0){
            LOG_ERROR(g_logger, "message_type unknown, value = %02x %02x %02x %02x %02x\n", buff[i], buff[i + 1], buff[i + 2], buff[i + 3], buff[i + 4]);
            flag = 2;
            break;
        }
        int version = (uint16_t)(buff[i + 1] << 8) + (uint8_t)buff[i + 2];
        if(version < 0x0300 || version > 0x0304){
            LOG_ERROR(g_logger, "version unknown, value = %02x %02x\n", buff[i + 1], buff[i + 2]);
            flag = 2;
            break;
        }
        int len = (uint16_t)(buff[i + 3] << 8) + (uint8_t)buff[i + 4];
        pmeinfo->tls_info_list[pmeinfo->tls_message_count].dir = stream->curdir;
        pmeinfo->tls_info_list[pmeinfo->tls_message_count].type = message_type;
        pmeinfo->tls_info_list[pmeinfo->tls_message_count].length = len;
        pmeinfo->tls_message_count++;
        i += (5 + len);
    }
    if(flag == 1){
        if(curdir == 1){
            memcpy((char*)pmeinfo->c2s_tls_payload, pktinfo->data, len - i);
            pmeinfo->c2s_tls_last_segment_len = len - i;
            pmeinfo->c2s_tls_current_segment_offset = 0;
        }
        if(curdir == 2){
            memcpy((char*)pmeinfo->s2c_tls_payload, pktinfo->data, len - i);
            pmeinfo->s2c_tls_last_segment_len = len - i;
            pmeinfo->s2c_tls_current_segment_offset = 0;
        }
        return -1;
    }
    if(flag == 2){
        if(curdir == 1){
            pmeinfo->c2s_tls_last_segment_len = 0;
            pmeinfo->c2s_tls_current_segment_offset = 0;
        }
        if(curdir == 2){
            pmeinfo->s2c_tls_last_segment_len = 0;
            pmeinfo->s2c_tls_current_segment_offset = 0;
        }
        return -2;
    }
    if(curdir == 1){
        pmeinfo->c2s_tls_last_segment_len = 0;
        pmeinfo->c2s_tls_current_segment_offset = i - len;
    }
    if(curdir == 2){
        pmeinfo->s2c_tls_last_segment_len = 0;
        pmeinfo->s2c_tls_current_segment_offset = i - len;
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
    struct tcphdr *_tcphdr = pktinfo->tcphdr;
    if(_tcphdr->fin || _tcphdr->rst){
        pmeinfo->has_fin_rst = 1;
    }
    pmeinfo->last_c2s_pkt_index = -1;
    pmeinfo->last_s2c_pkt_index = -1;
    get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TIMESTAMP, &(pmeinfo->start_time));
    get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TIMESTAMP, &(pmeinfo->end_time));
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
    packet_stat(stream, pmeinfo, pktinfo);
    return APP_STATE_FAWPKT | APP_STATE_GIVEME;
}

char data_opstate(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo){
    get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TIMESTAMP, &(pmeinfo->end_time));
    struct tcphdr *_tcphdr = pktinfo->tcphdr;
    if(_tcphdr->fin || _tcphdr->rst){
        pmeinfo->has_fin_rst = 1;
    }
    if(packet_need_filter(pktinfo) == 0){
        tls_header_parse(stream, pmeinfo, pktinfo);
        int ret = packet_stat(stream, pmeinfo, pktinfo);
        if(ret == -1){
            return APP_STATE_FAWPKT | APP_STATE_DROPME;
        }
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

void output_result(struct pme_info *pmeinfo){
    if(pmeinfo->has_fin_rst == 0){
        return;
    }
    cJSON *log_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(log_obj, "sip", pmeinfo->sip);
    cJSON_AddNumberToObject(log_obj, "sport", pmeinfo->sport);
    cJSON_AddStringToObject(log_obj, "dip", pmeinfo->dip);
    cJSON_AddNumberToObject(log_obj, "dport", pmeinfo->dport);
    cJSON_AddStringToObject(log_obj, "proto", "tcp");
    cJSON_AddNumberToObject(log_obj, "c2s_bytes", pmeinfo->c2s_bytes);
    cJSON_AddNumberToObject(log_obj, "s2c_bytes", pmeinfo->s2c_bytes);
    cJSON_AddNumberToObject(log_obj, "c2s_pkts", pmeinfo->c2s_pkts);
    cJSON_AddNumberToObject(log_obj, "s2c_pkts", pmeinfo->s2c_pkts);
    cJSON_AddNumberToObject(log_obj, "total_pkts", pmeinfo->total_pkts);
    char time_str[64] = {};
    time_tostring(pmeinfo->start_time, time_str, sizeof(time_str));
    cJSON_AddStringToObject(log_obj, "start_time", time_str);
    time_tostring(pmeinfo->end_time, time_str, sizeof(time_str));
    cJSON_AddStringToObject(log_obj, "end_time", time_str);
    pmeinfo->duration = (pmeinfo->end_time.tv_sec - pmeinfo->start_time.tv_sec) * 1000 + (pmeinfo->end_time.tv_usec - pmeinfo->start_time.tv_usec) / 1000;
    cJSON_AddNumberToObject(log_obj, "duration", pmeinfo->duration);
    cJSON *pkt_info_list = cJSON_CreateArray();
    for(int i = 0; i < pmeinfo->total_pkts; i++){
        cJSON *pkt_info = cJSON_CreateObject();
        cJSON_AddNumberToObject(pkt_info, "bytes", pmeinfo->pkt_info_list[i].bytes);
        cJSON_AddNumberToObject(pkt_info, "dir", pmeinfo->pkt_info_list[i].dir);
        cJSON_AddNumberToObject(pkt_info, "interval", pmeinfo->pkt_info_list[i].interval);
        time_tostring(pmeinfo->pkt_info_list[i].pkt_time, time_str, sizeof(time_str));
        cJSON_AddStringToObject(pkt_info, "pkt_time", time_str);
        cJSON_AddItemToArray(pkt_info_list, pkt_info);
    }
    cJSON_AddItemToObject(log_obj, "packets", pkt_info_list);
    cJSON *tls_info = cJSON_CreateObject();
    cJSON_AddStringToObject(tls_info, "version", pmeinfo->chello.max_version.str_format);
    cJSON_AddStringToObject(tls_info, "sni", pmeinfo->chello.sni);
    cJSON_AddStringToObject(tls_info, "alpn", pmeinfo->chello.alpn);
    cJSON *cipher_suite_list = cJSON_CreateArray();
    for(int i = 0; i < pmeinfo->chello.cipher_suites_count; i++){
        char cipher_suite_str[4] = {0};
        sprintf(cipher_suite_str, "%04x", pmeinfo->chello.cipher_suite_list[i]);
        cJSON_AddItemToArray(cipher_suite_list, cJSON_CreateString(cipher_suite_str));
    }
    cJSON_AddItemToObject(tls_info, "cipher_suites", cipher_suite_list);
    cJSON *extensions_list = cJSON_CreateArray();
    for(int i = 0; i < pmeinfo->chello.extension_count; i++){
        cJSON_AddItemToArray(extensions_list, cJSON_CreateNumber(pmeinfo->chello.extension_list[i]));
    }
    cJSON_AddItemToObject(tls_info, "extensions_list", extensions_list);
    cJSON_AddItemToObject(log_obj, "tls", tls_info);

    cJSON *tls_message_list = cJSON_CreateArray();
    cJSON_AddItemToObject(tls_info, "tls_message_list", tls_message_list);
    for(int i = 0; i < pmeinfo->tls_message_count; i++){
        cJSON *tls_message = cJSON_CreateObject();
        cJSON_AddNumberToObject(tls_message, "dir", pmeinfo->tls_info_list[i].dir);
        cJSON_AddNumberToObject(tls_message, "type", pmeinfo->tls_info_list[i].type);
        cJSON_AddNumberToObject(tls_message, "length", pmeinfo->tls_info_list[i].length);
        cJSON_AddItemToArray(tls_message_list, tls_message);
    }

    char *log_msg = cJSON_PrintUnformatted(log_obj);
    //printf("%s\n\n", log_msg);
    LOG_INFO(g_logger, log_msg);
    fputs(log_msg, g_fp);
    fputs("\n", g_fp);
    g_log_succ_count++;
	cJSON_Delete(log_obj);
    cJSON_free(log_msg);
}

char close_opstate(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo, const void *a_packet){
    if(a_packet != NULL){
        get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TIMESTAMP, &(pmeinfo->end_time));
        struct tcphdr *_tcphdr = pktinfo->tcphdr;
        if(_tcphdr->fin || _tcphdr->rst){
            pmeinfo->has_fin_rst = 1;
        }
        if(packet_need_filter(pktinfo) == 0){
            tls_header_parse(stream, pmeinfo, pktinfo);
            packet_stat(stream, pmeinfo, pktinfo);
        }
    }
    return APP_STATE_FAWPKT | APP_STATE_DROPME;
}

void pme_info_destroy(struct pme_info *pmeinfo){
    FREE(&pmeinfo);
    pmeinfo = NULL;
}

extern "C" char stmstat_entry(struct streaminfo *stream, void** pme, int thread_seq, const void* a_packet){
    if(g_count % 10 == 5){
        LOG_DEBUG(g_logger, "handle %d packets\n", g_count);
        LOG_DEBUG(g_logger, "stream_count: %d\nsucc_count: %d\nfail_count: %d\ng_log_succ_count: %d, g_exceed_max_pkts_count: %d\n", 
            g_stream_count, g_stream_succ_count, g_stream_fail_count, g_log_succ_count, g_exceed_max_pkts_count);
    }
    g_count++;
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
            g_stream_count++;
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
            g_stream_succ_count++;
            output_result(pmeinfo);
        }
        else{
            g_stream_fail_count++;
        }
        pme_info_destroy(pmeinfo);
    }
	return ret;
}

extern "C" int stmstat_init(){
    char *log_path = (char*)"./stream_stat.log";
    int log_level = 10;
    g_logger = MESA_create_runtime_log_handle(log_path, log_level);
    g_fp = fopen("./stream_stat.txt", "a+");
    return 0;
}

extern "C" void stmstat_destroy(){
    printf("stream_count: %d\nsucc_count: %d\nfail_count: %d\n", g_stream_count, g_stream_succ_count, g_stream_fail_count);
}
