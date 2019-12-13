


#include "base_utils.h"
#include "stream_inc/stream_base.h"
#include "stream_inc/stream_entry.h"
#include "ssl.h"
#include "cjson/cJSON.h"

#define CERT_COUNT_MAX 16

struct ssl_context{
    char sip[INET_ADDRSTRLEN];
    int sport;
    char dip[INET_ADDRSTRLEN];
    int dport;
    unsigned char *sni;
    char *san;
    int cert_count;
    cert_chain_t certs[CERT_COUNT_MAX];
};

FILE *g_fp = NULL;

static char *ssl_assemble_san(st_cert_t *cert){
	int tmp_buflen = 0, total_buflen = 0;
	char *san_buf = NULL;
	for (int i = 0; i < cert->SSLSubAltName->count; i++){
		tmp_buflen = strlen(cert->SSLSubAltName->san_array[i].san);
		san_buf = (char *)realloc(san_buf, total_buflen + tmp_buflen + 1);
		san_buf[total_buflen + tmp_buflen] = ';';
		memcpy(san_buf + total_buflen, cert->SSLSubAltName->san_array[i].san, tmp_buflen);
		total_buflen += tmp_buflen + 1;
	}
	san_buf[total_buflen - 1] = '\0';
	return san_buf;
}

void ssl_ctx_close(struct ssl_context *ctx, struct streaminfo *stream, ssl_stream *a_ssl){
	if (ctx != NULL){
        cJSON *log_obj = cJSON_CreateObject();
        cJSON_AddStringToObject(log_obj, "sip", ctx->sip);
        cJSON_AddNumberToObject(log_obj, "sport", ctx->sport);
        cJSON_AddStringToObject(log_obj, "dip", ctx->dip);
        cJSON_AddNumberToObject(log_obj, "dport", ctx->dport);
        cJSON_AddStringToObject(log_obj, "proto", "tcp");
        cJSON_AddStringToObject(log_obj, "sni", (const char*)ctx->sni);
        cJSON_AddStringToObject(log_obj, "san", ctx->san);
        //cert
        cJSON *Cert = cJSON_CreateObject();
        cJSON_AddNumberToObject(Cert, "cert_count", ctx->cert_count);
        cJSON *cert_info_list = cJSON_CreateArray();
        for(int i = 0; i < ctx->cert_count; i++){
            cJSON *cert_info = cJSON_CreateObject();
            cJSON_AddNumberToObject(cert_info, "length", ctx->certs[i].cert_len);
            if(i == 0){
                cJSON_AddStringToObject(cert_info, "type", "individual");
            }
            else{
                cJSON_AddStringToObject(cert_info, "type", "no-individual");
            }
            cJSON_AddItemToArray(cert_info_list, cert_info);
        }
        cJSON_AddItemToObject(Cert, "cert_list", cert_info_list);
        cJSON_AddItemToObject(log_obj, "Cert", Cert);
        char *log_msg = cJSON_PrintUnformatted(log_obj);
        fputs(log_msg, g_fp);
        fputs("\n", g_fp);
        cJSON_Delete(log_obj);
        cJSON_free(log_msg);
        FREE(&(ctx->san))
		FREE(&ctx);
	}
	return;
}

extern "C" unsigned char sslstat_entry(stSessionInfo *session_info, void **param, int thread_seq, struct streaminfo *stream, void *a_packet){
	ssl_stream *a_ssl = (ssl_stream *)(session_info->app_info);
    struct ssl_context *ctx = (ssl_context *)*param;
	if ((session_info->session_state & SESSION_STATE_PENDING) == SESSION_STATE_PENDING){
        ctx = ALLOC(struct ssl_context, 1);
        *param = ctx;
        struct stream_tuple4_v4 *tuple4 = stream->addr.tuple4_v4;
        inet_ntop(AF_INET, &(tuple4->saddr), ctx->sip, INET_ADDRSTRLEN);
        inet_ntop(AF_INET, &(tuple4->daddr), ctx->dip, INET_ADDRSTRLEN);
        ctx->sport = ntohs(tuple4->source);
        ctx->dport = ntohs(tuple4->dest);
	}
	switch (session_info->prot_flag){
		case SSL_CLIENT_HELLO:
			if (a_ssl != NULL && a_ssl->stClientHello != NULL){
                    ctx->sni = a_ssl->stClientHello->server_name;
			}
			break;
        case SSL_CERTIFICATE:
            ctx->cert_count = ssl_read_all_cert((const char*)session_info->buf, session_info->buflen, ctx->certs, CERT_COUNT_MAX);
		case SSL_CERTIFICATE_DETAIL:
			if (a_ssl != NULL && a_ssl->stSSLCert != NULL && stream->curdir == DIR_S2C){
				st_cert_t *cert = a_ssl->stSSLCert;
				if (cert->cert_type == CERT_TYPE_INDIVIDUAL){
					if (cert->SSLSubAltName != NULL && cert->SSLSubAltName->count > 0){
						char *san_buf = ssl_assemble_san(cert);
                        ctx->san = san_buf;
					}
				}
			}
			break;
		case SSL_APPLICATION_DATA:
			break;
		default:
			break;
	}

	if ((session_info->session_state & SESSION_STATE_CLOSE) == SESSION_STATE_CLOSE){

//close_ssl:
		ssl_ctx_close(ctx, stream, (ssl_stream *)session_info->app_info);
		return PROT_STATE_DROPME;
	}
	return PROT_STATE_GIVEME;
}


extern "C" int sslstat_init(){
    g_fp = fopen("./ssl_stat.txt", "w+");
    return 0;
}

extern "C" void sslstat_destroy(void){
	return;
}