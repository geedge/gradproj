
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
        printf("packet nums > STREAM_PACKET_COUNT_MAX\n");
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
		printf("Error: chello parse failed\n");
        return -1;
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
    pmeinfo->last_c2s_pkt_index = -1;
    pmeinfo->last_s2c_pkt_index = -1;
    get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TIMESTAMP, &(pmeinfo->start_time));
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
    packet_stat(stream, pmeinfo, pktinfo);
    return APP_STATE_FAWPKT | APP_STATE_GIVEME;
}

char data_opstate(struct streaminfo *stream, struct pme_info *pmeinfo, struct pkt_parsed_info *pktinfo){
    if(packet_need_filter(pktinfo) == 0){
        int ret = packet_stat(stream, pmeinfo, pktinfo);
        if(ret == -1){
            return APP_STATE_FAWPKT | APP_STATE_DROPME;
        }
    }
    return APP_STATE_FAWPKT | APP_STATE_GIVEME;
}

void output_result(struct pme_info *pmeinfo){
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
    cJSON_AddNumberToObject(log_obj, "duration", pmeinfo->duration);
    cJSON *pkt_info_list = cJSON_CreateArray();
    for(int i = 0; i < pmeinfo->total_pkts; i++){
        cJSON *pkt_info = cJSON_CreateObject();
        cJSON_AddNumberToObject(pkt_info, "bytes", pmeinfo->pkt_info_list[i].bytes);
        cJSON_AddNumberToObject(pkt_info, "dir", pmeinfo->pkt_info_list[i].dir);
        cJSON_AddNumberToObject(pkt_info, "interval", pmeinfo->pkt_info_list[i].interval);
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
        if(packet_need_filter(pktinfo) == 0){
            packet_stat(stream, pmeinfo, pktinfo);
        }
    }
    get_rawpkt_opt_from_streaminfo(stream, RAW_PKT_GET_TIMESTAMP, &(pmeinfo->end_time));
    pmeinfo->duration = (pmeinfo->end_time.tv_sec - pmeinfo->start_time.tv_sec) * 1000 + (pmeinfo->end_time.tv_usec - pmeinfo->start_time.tv_usec) / 1000;
    return APP_STATE_FAWPKT | APP_STATE_DROPME;
}

void pme_info_destroy(struct pme_info *pmeinfo){
    FREE(&pmeinfo);
    pmeinfo = NULL;
}

extern "C" char stmstat_entry(struct streaminfo *stream, void** pme, int thread_seq, const void* a_packet){
    if(g_count % 10 == 5){
        printf("handle %d packets\n", g_count);
        printf("stream_count: %d\nsucc_count: %d\nfail_count: %d\ng_log_succ_count: %d, g_exceed_max_pkts_count: %d\n", 
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
    g_fp = fopen("./stream_stat.txt", "w+");
    return 0;
}

extern "C" void stmstat_destroy(){
    printf("stream_count: %d\nsucc_count: %d\nfail_count: %d\n", g_stream_count, g_stream_succ_count, g_stream_fail_count);
}
