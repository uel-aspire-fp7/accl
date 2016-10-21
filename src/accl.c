/* This research is supported by the European Union Seventh Framework Programme (FP7/2007-2013), project ASPIRE (Advanced  Software Protection: Integration, Research, and Exploitation), under grant agreement no. 609734; on-line at https://aspire-fp7.eu/. */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <curl/curl.h>
#include <accl.h>

/*
	ACCL Simple Request Protocol Implementation
	see D1.04 sections 2.2 and 2.4.1 for documentation and API specification
	see also accl.h for a brief description and parameters explanation
*/

static char endpoint[1024] = "X";
static char application_id[1024] = "X";

static void GetAspirePortalEndpoint(){
  if (endpoint[0]!='X') return;
  FILE * endpointfile = fopen(ACCL_FILE_PATH "/ASPIREendpoint","r");
  if (!endpointfile)
    {
      strncpy(endpoint,ACCL_ASPIRE_PORTAL_ENDPOINT,1024);
    }
  else
  {
    fscanf(endpointfile,"%s",endpoint);
    fclose(endpointfile);
  }

#ifndef NDEBUG
  acclLOG("initialize_endpoint",
	  "%s",
	  ACCL_LOG_LEVEL_DEBUG,
	  endpoint);
#endif

  return;
}

static char* GetAspireApplicationId() {
	if (application_id[0] == 'X') {
		char* app_start_address = (char*)&application_id;

		getApplicationId(&app_start_address);
	}


	return application_id;
}

#ifndef EXTERNAL_GET_APPLICATION_ID

// for debugging purposes
void getApplicationId(char** ptr_to_string_to_be_filled) {
	char* return_buff = *ptr_to_string_to_be_filled;

	strcpy(return_buff, ASPIRE_APPLICATION_ID);
};

#endif

int acclExchange (
	const int T_ID,
	const int payloadBufferSize,
	const char* pPayloadBuffer,
	unsigned* returnBufferSize,
	char** pReturnBuffer) {

	CURL *curl;
  	CURLcode res;
  	accl_payload_transfer payload;
  	accl_response response;
  	struct curl_slist *chunk = NULL;
  	char aspire_portal_uri[1024];
  	long http_response_code = 0;

#ifndef NDEBUG
	acclLOG("ACCL", "Exchange API invocation.", ACCL_LOG_LEVEL_INFO);
#endif

	// PARAMETERS SANITY CHECK

	// buffer size check
	if (payloadBufferSize <= 0){

#ifndef NDEBUG
		acclLOG("acclExchange",
			"payload buffer size not valid (%d bytes specified)",
			ACCL_LOG_LEVEL_ERROR,
			payloadBufferSize);
#endif

		return ACCL_INPUT_BUFFER_ERROR;
	}

	if (payloadBufferSize > ACCL_MAX_BUFFER_SIZE) {
#ifndef NDEBUG
		acclLOG("acclExchange",
			"payload maximum size is %d bytes, %d bytes provided",
			ACCL_LOG_LEVEL_ERROR,
			ACCL_MAX_BUFFER_SIZE,
			payloadBufferSize);
#endif
		return ACCL_INPUT_BUFFER_MAX_SIZE_EXCEEDED;
	}

	// technique id check
	switch (T_ID) {
	case ACCL_TID_CODE_SPLITTING:
	case ACCL_TID_CODE_MOBILITY:
		/* let's inizialize renewability if enabled */
#ifdef APPLY_RENEWABILITY
		renewabilityInit();
#endif
	case ACCL_TID_WBS:
	case ACCL_TID_MTC_CRYPTO_SERVER:
	case ACCL_TID_CG_HASH_RANDOMIZATION:
	case ACCL_TID_CG_HASH_VERIFICATION:
	case ACCL_TID_CFGT_REMOVE_VERIFIER:
	case ACCL_TID_AC_DECISION_LOGIC:
	case ACCL_TID_AC_STATUS_LOGIC:
	case ACCL_TID_RA_REACTION_MANAGER:
	case ACCL_TID_RA_VERIFIER:
	case ACCL_TID_TEST:
		break;
	default:
#ifndef NDEBUG
		acclLOG("acclExchange",
			"unknown technique id: %d",
			ACCL_LOG_LEVEL_ERROR,
			T_ID);
#endif
		return ACCL_UNKNOWN_TECHNIQUE_ID;
	}

	// cURL initialization
	res = curl_global_init(CURL_GLOBAL_DEFAULT);

	// Check for errors
	if(res != CURLE_OK) {
#ifndef NDEBUG
		acclLOG("acclExchange",
			"curl_global_init() failed: %s",
			ACCL_LOG_LEVEL_ERROR,
			curl_easy_strerror(res));
#endif
		return ACCL_CURL_INITIALIZATION_ERROR;
	}

	GetAspirePortalEndpoint();

	// requests to ASPIRE Portal include 
	// 	- endpoint (ASPIRE Portal URL)
	//	- request type (exchange | send)
	//	- technique ID
	//	- application ID
	sprintf(aspire_portal_uri, "%s/exchange/%d/%s", endpoint, T_ID, GetAspireApplicationId());

	curl = curl_easy_init();

	if (curl) {
		// payload structure initialization
		payload.technique_id = T_ID;
		payload.application_id = GetAspireApplicationId();
		payload.payload_size = payloadBufferSize;
		payload.payload_buffer = (char*)pPayloadBuffer;
		payload.transmit_offset = 0;
		payload.error = ACCL_SUCCESS;

		// response structure initialization
		response.output_buffer_size = 0;
		response.output_buffer = 0;
		response.error = ACCL_SUCCESS;

		// first set the Aspire Portal Endpoint
		curl_easy_setopt(curl, CURLOPT_URL, aspire_portal_uri);

		// data will be POST-ed
		curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.payload_size);

		// follow redirections
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	 	curl_easy_setopt(curl, CURLOPT_POSTREDIR, 3);

   		// data sending callback setup and point to pass it
		curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
		curl_easy_setopt(curl, CURLOPT_READDATA, &payload);

    	// data receiving callback setup and point to pass it
    	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
		curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    	// cURL verbosity for debug purposes
    	if (ACCL_LOG_LEVEL < ACCL_LOG_LEVEL_DEBUG)
		    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);

   		// Perform the request, res will get the return code
   		res = curl_easy_perform(curl);

   		curl_slist_free_all(chunk);

   		// Check for errors
   		if(res != CURLE_OK){
#ifndef NDEBUG
			acclLOG("acclExchange",
				"curl_easy_perform() failed: %s\n",
				ACCL_LOG_LEVEL_ERROR,
				curl_easy_strerror(res));
#endif
			if (response.error != ACCL_SUCCESS)
				return response.error;

			return ACCL_GENERIC_ERROR;
		} else {

			// verify response code
			curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE,
				&http_response_code);

#ifndef NDEBUG
			acclLOG("ACCL", "Response received from server RETURN CODE: %d.",
				ACCL_LOG_LEVEL_INFO, http_response_code);
#endif

			if (http_response_code == 200 && res != CURLE_ABORTED_BY_CALLBACK) {
			    	// return output buffer
				*pReturnBuffer = response.output_buffer;

				// return output buffer actual size
				memcpy ((void*)returnBufferSize,
					(void*)&response.output_buffer_size,
					sizeof(unsigned int));
#ifndef NDEBUG
				acclLOG("ACCL", "%d bytes copied into internal buffer.",
					ACCL_LOG_LEVEL_INFO, response.output_buffer_size);
#endif
			} else {
#ifndef NDEBUG
				acclLOG("acclExchange",
                                	"server error: %s\n",
                                	ACCL_LOG_LEVEL_ERROR,
                                	curl_easy_strerror(res));
#endif
			     	return ACCL_SERVER_ERROR;
			}
		}

   		// cleanup
   		curl_easy_cleanup(curl);

   		return ACCL_SUCCESS;
	} else {
		return ACCL_CURL_INITIALIZATION_ERROR;
	}
}

/*
	ACCL Simple Request Protocol Implementation
	see D1.04 sections 2.2 and 2.4.1 for documentation and API specification	
	see also accl.h for a brief description and parameters explanation
*/
int acclSend (
        const int T_ID,
        const int payloadBufferSize,
        const char* pPayloadBuffer){

	CURL *curl;
  	CURLcode res;
  	accl_payload_transfer payload;
  	struct curl_slist *chunk = NULL;
  	char aspire_portal_uri[1024];
  	long http_response_code = 0;
  	int returnValue = ACCL_SUCCESS;

#ifndef NDEBUG
	acclLOG("ACCL", "Send API invocation.", ACCL_LOG_LEVEL_INFO);
#endif

	// PARAMETERS SANITY CHECK
	
	// buffer size check
	if (payloadBufferSize <= 0){
#ifndef NDEBUG
		acclLOG("acclSend", 
			"payload buffer size not valid (%d bytes specified)", 
			ACCL_LOG_LEVEL_ERROR,
			payloadBufferSize);
#endif
		return ACCL_INPUT_BUFFER_ERROR;
	}

	if (payloadBufferSize > ACCL_MAX_BUFFER_SIZE) {
#ifndef NDEBUG
		acclLOG("acclSend", 
			"payload maximum size is %d bytes, %d bytes provided", 
			ACCL_LOG_LEVEL_ERROR,
			ACCL_MAX_BUFFER_SIZE,
			payloadBufferSize);
#endif
		return ACCL_INPUT_BUFFER_MAX_SIZE_EXCEEDED;	
	}

	// technique id check
	switch (T_ID) {
	case ACCL_TID_CODE_SPLITTING:
	case ACCL_TID_CODE_MOBILITY:
	case ACCL_TID_WBS:
	case ACCL_TID_MTC_CRYPTO_SERVER:
	case ACCL_TID_CG_HASH_RANDOMIZATION:
	case ACCL_TID_CG_HASH_VERIFICATION:
	case ACCL_TID_CFGT_REMOVE_VERIFIER:
	case ACCL_TID_AC_DECISION_LOGIC:
	case ACCL_TID_AC_STATUS_LOGIC:
	case ACCL_TID_RA_REACTION_MANAGER:
	case ACCL_TID_RA_VERIFIER:
	case ACCL_TID_TEST:
		break;		
	default:
#ifndef NDEBUG
		acclLOG("acclSend", 
			"unknown technique id: %d", 
			ACCL_LOG_LEVEL_ERROR,
			T_ID);
#endif
		return ACCL_UNKNOWN_TECHNIQUE_ID;
	}
	
	// cURL initialization
	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	
	// Check for errors
	if(res != CURLE_OK) {
#ifndef NDEBUG
		acclLOG("acclSend", 
			"curl_global_init() failed: %s",
			ACCL_LOG_LEVEL_ERROR,
			curl_easy_strerror(res));
#endif
		return ACCL_CURL_INITIALIZATION_ERROR;
	}
	
	GetAspirePortalEndpoint();

	sprintf(aspire_portal_uri, "%s/send/%d/%s", endpoint, T_ID, GetAspireApplicationId());

	curl = curl_easy_init();
	
	if (curl) {
		// payload structure initialization
		payload.technique_id = T_ID;
		payload.application_id = GetAspireApplicationId();
		payload.payload_size = payloadBufferSize;
		payload.payload_buffer = (char*)pPayloadBuffer;	
		payload.transmit_offset = 0;
		payload.error = ACCL_SUCCESS;
	
		// first set the Aspire Portal Endpoint
		curl_easy_setopt(curl, CURLOPT_URL, aspire_portal_uri);
		
		// data will be POST-ed 
	    curl_easy_setopt(curl, CURLOPT_POST, 1L);
		curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, payload.payload_size);
		
		// follow redirections
		curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	 	curl_easy_setopt(curl, CURLOPT_POSTREDIR, 3);
	 	    			   		   		
   		// data sending callback setup and point to pass it
	    curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
	    curl_easy_setopt(curl, CURLOPT_READDATA, &payload);

	    // cURL verbosity for debug purposes
	    if (ACCL_LOG_LEVEL < ACCL_LOG_LEVEL_DEBUG)
		    curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		
   		// Perform the request, res will get the return code
   		res = curl_easy_perform(curl);
   		
   		curl_slist_free_all(chunk);

   		// Check for errors
   		if(res != CURLE_OK){
#ifndef NDEBUG
			acclLOG("acclSend", 
				"curl_easy_perform() failed: %s\n",
				ACCL_LOG_LEVEL_ERROR,
				curl_easy_strerror(res));
#endif
			return ACCL_GENERIC_ERROR;
		} 
		
		// verify response code
		curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE,
			&http_response_code);

#ifndef NDEBUG
		acclLOG("ACCL", "Response received from server RETURN CODE: %d.",
			ACCL_LOG_LEVEL_INFO, http_response_code);
#endif

		if (http_response_code == 200)
			returnValue = ACCL_SUCCESS;
		else
			returnValue = ACCL_SERVER_ERROR;

   		// cleanup
   		curl_easy_cleanup(curl);
   		
   		return returnValue;
	} else {
		return ACCL_CURL_INITIALIZATION_ERROR;	
	}
}

/*
	Custom data sending callback (invoked by libcurl)
*/
size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp){
	accl_payload_transfer *data = (accl_payload_transfer *)userp;

#ifndef NDEBUG
	acclLOG("read_callback",
		"size %d payload size %d",
		ACCL_LOG_LEVEL_DEBUG,
		(int)size * (int)nmemb,
		data->payload_size);
#endif

	// callback called for no actual data transfer
	if (size * nmemb < 1) {
#ifndef NDEBUG
		acclLOG("read_callback", "size * nmemb < 1", ACCL_LOG_LEVEL_DEBUG);
#endif
		return 0;
	}

	if (data->payload_size > data->transmit_offset) {
		// compute how much data to senda is left
		int bytes_to_transfer = MIN(data->payload_size - data->transmit_offset,
									ACCL_BLOCK_SIZE);

		// copy data from input buffer
		memcpy (ptr,
				data->payload_buffer + data->transmit_offset,
				bytes_to_transfer);

		// advances transmission offset
		data->transmit_offset += bytes_to_transfer;

		return bytes_to_transfer;
	} else {
		return 0;
	}
}

/*
	Custom data receiving callback (invoked by libcurl)
*/
size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
	accl_response* response = (accl_response*)userdata;

#ifndef NDEBUG
	acclLOG("write_callback",
		"size=%d offset=%d",
		ACCL_LOG_LEVEL_DEBUG,
		size * nmemb,
		response->output_buffer_size);
#endif

	// maximum buffer size check
	if (size * nmemb + response->output_buffer_size > ACCL_MAX_BUFFER_SIZE) {

#ifndef NDEBUG
		acclLOG("write_callback", "return buffer size exceeded (%d requested)",
			ACCL_LOG_LEVEL_ERROR,
			size * nmemb + response->output_buffer_size);
#endif
		response->error = ACCL_OUTPUT_BUFFER_MAX_SIZE_EXCEEDED;

		// cause curl abort current transfer
		return -1;
	}

	// allocates necessary memory
	if (0 == response->output_buffer) {
		// return buffer should be initialized
		response->output_buffer = (char*)malloc(size * nmemb);
	} else {
		// return buffer should be reallocated adding size * nmemb bytes
		response->output_buffer = (char*)realloc(
						(void*)response->output_buffer,
						size * nmemb + response->output_buffer_size);
	}

	if (0 == response->output_buffer) {
		response->error = ACCL_OUTPUT_BUFFER_ALLOCATION_ERROR;

		// cause curl abort current transfer
		return -1;
	}

	// copy data to return structure
	memcpy (response->output_buffer + response->output_buffer_size,
				ptr,
				size * nmemb);

	// advance receiving offset
	response->output_buffer_size += (int)(nmemb * size);

	return (nmemb * size);
}

#ifndef NDEBUG

/* TODO make logging thread safe: 
	good start point 
http://stackoverflow.com/questions/14903555/c-thread-safe-logging-to-a-file */

/*
	Logging utility
*/
void acclLOG(const char* tag, const char* fmt, int lvl, ...) {
	FILE * fp;
	time_t now;
	
	va_list ap;                                /* special type for variable */
	char format[ACCL_MSG_STRING_LENGTH];       /* argument lists            */
	int count = 0;
	int i, j;                                  /* Need all these to store   */
	char c;                                    /* values below in switch    */
	double d;
	unsigned u;
	char *s;
	void *v;
	
	if (lvl < ACCL_LOG_LEVEL)
		return;
	
	fp = fopen (ACCL_FILE_PATH "/" ACCL_LOG_FILE, "a");
	
	if (NULL == fp) {
		fprintf(stderr, "ERROR: Unable to log to file accl.log\n");
		return;	
	}
	
	if ((time_t)-1 == time(&now)) {
		fprintf(stderr, "ERROR: Unable to retrieve current time.log\n");
		fclose(fp);
		return;	
	}
  	fprintf(fp, "%.24s [%s] ", ctime(&now), tag);

	va_start(ap, lvl);                         /* must be called before work */
  
	while (*fmt) {
		for (j = 0; fmt[j] && fmt[j] != '%'; j++)
			format[j] = fmt[j];                    /* not a format string          */
		
		if (j) {
			format[j] = '\0';
			count += fprintf(fp, format, "");    /* log it verbatim              */
			fmt += j;
		} else {
			for (j = 0; !isalpha(fmt[j]); j++) {   /* find end of format specifier */
				format[j] = fmt[j];
				if (j && fmt[j] == '%')              /* special case printing '%'    */
				break;
			}
		
			format[j] = fmt[j];                    /* finish writing specifier     */
			format[j + 1] = '\0';                  /* don't forget NULL terminator */
			fmt += j + 1;
			
			switch (format[j]) {                   /* cases for all specifiers     */
			case 'd':
			case 'i':                              /* many use identical actions   */
				i = va_arg(ap, int);                 /* process the argument         */
				count += fprintf(fp, format, i); /* and log it                 */
				break;
			case 'o':
			case 'x':
			case 'X':
			case 'u':
				u = va_arg(ap, unsigned);
				count += fprintf(fp, format, u);
				break;
			case 'c':
				c = (char) va_arg(ap, int);          /* must cast!  */
				count += fprintf(fp, format, c);
				break;
			case 's':
				s = va_arg(ap, char *);
				count += fprintf(fp, format, s);
				break;
			case 'f':
			case 'e':
			case 'E':
			case 'g':
			case 'G':
				d = va_arg(ap, double);
				count += fprintf(fp, format, d);
				break;
			case 'p':
				v = va_arg(ap, void *);
				count += fprintf(fp, format, v);
				break;
			case 'n':
				count += fprintf(fp, "%d", count);
				break;
			case '%':
				count += fprintf(fp, "%%");
				break;
			default:
				fprintf(stderr, "Invalid format specifier in acclLOG().\n");
			}
		}
	}
	
	fprintf(fp, "\n");
	
	va_end(ap);  // clean up
		
	fclose(fp);
}
#endif

/* 
	ASPIRE CLIENT COMMUNICATION LOGIC - WEBSOCKET PROTOCOL
	
*/

#ifndef WITHOUT_WEBSOCKETS

/* array containing spawned WS loop threads */
//ws_channel accl_ws_tids[ACCL_MAX_WS_THREADS];

/* array containing connections status */
int accl_ws_connections_status[ACCL_MAX_WS_THREADS];

/* index of the first available WS channel slot */
//static int current_ws_tid = 0;

/* list of supported protocols and callbacks */
static struct libwebsocket_protocols protocols[] = {
	{
		"accl-communication-protocol",
		callback_accl_communication,
		sizeof(int),
	},
	{  
		/* end of list */
		NULL,
		NULL,
		0
	}
};

/* general callback for websockets events */
int callback_accl_communication(
	struct libwebsocket_context *this,
	struct libwebsocket *wsi,
	enum libwebsocket_callback_reasons reason,
	void *user,
	void *in, 
	size_t len)
{
	int m;

	//pid_t pid_id = syscall(SYS_gettid);

#ifndef NDEBUG
	//lwsl_notice("ACCL %x: callback_accl_communication() entered\n", pid_id);
#endif

	struct accl_context_buffer* user_context;

	if (NULL != this) {
		//lwsl_notice("ACCL %x: callback_accl_communication() entered %x\n", pid_id, this);

		user_context = (struct accl_context_buffer*)libwebsocket_context_user(this);
	} else {
#ifndef NDEBUG
		//lwsl_notice("ACCL %x: callback_accl_communication - CONTEXT CREATION FAILURE (null)\n", pid_id);
#endif
	}

#ifndef NDEBUG
	lwsl_notice("ACCL: callback_accl_communication - context created\n");
#endif

	// output buffer has to be pre and post padded
	// [ ... PRE-PADDING ... | ACTUAL BUFFER CONTENT | ... POST-PADDING ... ]
	unsigned char write_buffer[LWS_SEND_BUFFER_PRE_PADDING + ACCL_MAX_WS_BUFFER_SIZE + LWS_SEND_BUFFER_POST_PADDING];

#ifndef NDEBUG
	lwsl_notice("ACCL: callback_accl_communication - write buffer created\n");
#endif

	// pointer to output buffer actual start offset
	unsigned char *write_buffer_pointer = &write_buffer[LWS_SEND_BUFFER_PRE_PADDING];

#ifndef NDEBUG
	lwsl_notice("ACCL: callback_accl_communication - write buffer pointer created\n");
#endif

	/* TODO use current context's tid */
	switch (reason) {
		case LWS_CALLBACK_CLIENT_ESTABLISHED:
#ifndef NDEBUG
			/* connection has been established */
			lwsl_notice("ACCL: LWS_CALLBACK_CLIENT_ESTABLISHED\n");
#endif
			user_context->initialization_complete = 1;

			break;
		case LWS_CALLBACK_CLIENT_CONNECTION_ERROR:
#ifndef NDEBUG
			lwsl_err("ACCL: LWS_CALLBACK_CLIENT_CONNECTION_ERROR (TID: %d)\n", user_context->technique_id);
#endif
			user_context->initialization_complete = 2;

			break;
		case LWS_CALLBACK_CLOSED:
#ifndef NDEBUG
			lwsl_err("ACCL: LWS_CALLBACK_CLOSED (TID: %d)\n", user_context->technique_id);
#endif
			break;
		case LWS_CALLBACK_CLIENT_WRITEABLE:

			if (0 == user_context->initialization_complete){
#ifndef NDEBUG
				lwsl_notice("ACCL: LWS_CALLBACK_CLIENT_WRITEABLE: send function called before a complete initialization\n");
#endif
                return 0;
			}

			if (2 == user_context->initialization_complete){
#ifndef NDEBUG
				lwsl_notice("ACCL: LWS_CALLBACK_CLIENT_WRITEABLE: send function called on a closed channel\n");
#endif
				return 0;
			}

			if (0 == user_context->buffer_size)
				return 0;
#ifndef NDEBUG
			lwsl_notice("ACCL: LWS_CALLBACK_CLIENT_WRITEABLE (%d bytes to transmit)\n", user_context->buffer_size);
#endif
			/**
			 * Outgoing data can be:
			 * - response to server initiated Exchange
			 * - client initiated Exchange
			 * - client initiated Send
			 */

			// fill in the padded output buffer
			memcpy (write_buffer_pointer, user_context->buffer_ptr, user_context->buffer_size);

			// send data though the channel
			m = libwebsocket_write(wsi, write_buffer_pointer, user_context->buffer_size, LWS_WRITE_BINARY);

			if (m < user_context->buffer_size) {
				// incomplete transfer
#ifndef NDEBUG
				lwsl_err("ACCL: LWS_CALLBACK_CLIENT_WRITEABLE (%d bytes transmitted instead of %d bytes)\n", m, user_context->buffer_size);
#endif
			} else {
				user_context->send_in_progress = 0;
			}

			break;
		case LWS_CALLBACK_CLIENT_RECEIVE:
#ifndef NDEBUG
			lwsl_notice("LWS_CALLBACK_CLIENT_RECEIVE %d '%s'\n", (int)len, (char *)in);
#endif
			/* data received from server */

			// data can be:
			// - server initiated communication payload (wait_for_response=0)
			// - server response to client initiated exchange (wait_for_response=1)

			if (NULL != user_context) {
				if (user_context->wait_for_response) {
#ifndef NDEBUG
					lwsl_notice("RECEIVED EXCHANGE RESPONSE FROM SERVER\n");
#endif
					if (len <= user_context->response_buffer_size) {
						memcpy(user_context->response_buffer_ptr, in, len);

						// reset the wait for response flag (this unlocks waiting threads on acclWebSocketsExchange)
						user_context->wait_for_response = 0;
					} else {
#ifndef NDEBUG
						lwsl_err("Exchange response buffer (%d bytes) too small: received (%d bytes)\n", user_context->response_buffer_size, len);
#endif
						return -1;
					}
				} else {
#ifndef NDEBUG
					lwsl_notice("ACCL - Data received from server, invoking the callback\n");
#endif
					user_context->callback(in, len);
				}
			}
			
			break;
		case LWS_CALLBACK_CLIENT_CONFIRM_EXTENSION_SUPPORTED:

			break;
		default:
			break;
	}

#ifndef NDEBUG
	lwsl_notice("ACCL: callback_accl_communication() exit\n");
#endif

	return 0;
}

void acclGetWebSocketUri(char *uri, int technique_id, char *application_id) {
	// ASPIRE Portal URI parameters
	//	- T_ID: technique ID
	//	- A_ID: application ID
	sprintf(uri, "/%d/%s", technique_id, application_id);
}

int acclGetWebSocketPort(int technique_id) {
	int port;

	switch (technique_id) {
		case ACCL_TID_CODE_SPLITTING:
			port = 8082;
			break;
		case ACCL_TID_RA_REACTION_MANAGER:
			port = 8083;
			break;
		case ACCL_TID_RA_VERIFIER:
			port = 8084;
			break;
		case ACCL_RA_ATTESTATOR_0:
		case ACCL_RA_ATTESTATOR_1:
		case ACCL_RA_ATTESTATOR_2:
		case ACCL_RA_ATTESTATOR_3:
		case ACCL_RA_ATTESTATOR_4:
		case ACCL_RA_ATTESTATOR_5:
		case ACCL_RA_ATTESTATOR_6:
		case ACCL_RA_ATTESTATOR_7:
		case ACCL_RA_ATTESTATOR_8:
		case ACCL_RA_ATTESTATOR_9:
			port = technique_id - 9000 + 8090;
			break;
		case ACCL_RENEWABILITY:
			port = 18001;
			break;
		default:
			port = ACCL_WS_ASPIRE_PORTAL_PORT;
			break;
	}

	return port;
}

/*
	ACCL WebSockets initialization
*/
struct libwebsocket_context* acclWebSocketInit (const int T_ID, void* (* callback)(void*, size_t)) {
	int use_ssl=0, ietf_version=-1, port;

	struct lws_context_creation_info info;
	struct libwebsocket_context *context;
	struct libwebsocket *wsi_accl;
	struct accl_context_buffer* user_context;
	struct libwebsocket_protocols *context_protocols;

	char aspire_portal_uri[1024];

	acclGetWebSocketUri(aspire_portal_uri, T_ID, GetAspireApplicationId());
	port = acclGetWebSocketPort(T_ID);

	memset(&info, 0, sizeof info);

	// user context information
	user_context = (struct accl_context_buffer*)malloc(sizeof(struct accl_context_buffer));
	user_context->buffer_ptr = malloc(ACCL_MAX_WS_BUFFER_SIZE);
	user_context->technique_id = T_ID;
	user_context->buffer_size = 0;
	user_context->callback = callback;
	user_context->initialization_complete = 0;
	user_context->send_in_progress = 0;

	if (NULL == user_context->buffer_ptr)
		return NULL;

	/**
	 * since libwebsockets is not nativevely thread safe we need to make sure that each connection use its own
	 * protocols array
	 *
	 * https://github.com/warmcat/libwebsockets/issues/145
	 * https://github.com/warmcat/libwebsockets/issues/566
	 */
	context_protocols = (struct libwebsocket_protocols*)malloc(sizeof(struct libwebsocket_protocols) * 2);
	memcpy(context_protocols, protocols, sizeof(struct libwebsocket_protocols) * 2);

	user_context->protocols = context_protocols;

	info.iface = NULL;
	info.ssl_cert_filepath = NULL;
	info.ssl_private_key_filepath = NULL;
	info.port = CONTEXT_PORT_NO_LISTEN;
	info.protocols = context_protocols;
	info.gid = -1;
	info.uid = -1;
	info.options = 0;
	info.user = (void*)user_context;

	context = libwebsocket_create_context(&info);

#ifndef NDEBUG
	lwsl_notice("ACCL - acclWebSocketInit() - context created\n");
#endif

	if (NULL == context) {
#ifndef NDEBUG
		lwsl_err("Creating libwebsocket context failed\n");
#endif
		return NULL;
	}

	char host[1024];
	FILE * hostfile = fopen(ACCL_FILE_PATH "/ASPIREhost","r");
	if (!hostfile)
	{
	      strncpy(host,ACCL_WS_ASPIRE_PORTAL_HOST,1024);
	}
	else
	{
	      fscanf(hostfile,"%s",host);
	      fclose(hostfile);
	}

	// establish connection to server
	wsi_accl = libwebsocket_client_connect(
		context,
		host,
		port,
		use_ssl,
		aspire_portal_uri,
		host,
		host,
		protocols[PROTOCOL_ACCL_COMMUNICATION].name,
		ietf_version
	);

#ifndef NDEBUG
	lwsl_notice("ACCL - acclWebSocketInit() - client_connected\n");
#endif

	if (wsi_accl == NULL) {
#ifndef NDEBUG
		lwsl_err("ACCL - libwebsocket connection to ASPIRE Portal %s failed\n", aspire_portal_uri);
#endif
		return NULL;
	} else {
		// wait for channel initialization
		while (0 == user_context->initialization_complete) {
			libwebsocket_service(context, 50);
		}

#ifndef NDEBUG
		lwsl_err("ACCL - acclWebSocketInit() - initialization complete\n");
#endif

		if (user_context->initialization_complete == 2) {
			acclWebSocketShutdown(context);
#ifndef NDEBUG
			lwsl_err("ACCL - WebSockets CLIENT CONNECTION ERROR\n");
#endif
			return NULL;
		}
#ifndef NDEBUG
		lwsl_notice("ACCL - libwebsocket connection to ASPIRE Portal %s succeeded.\n", aspire_portal_uri);
#endif
		return context;
	}
}

/**
 * Terminates the channel associated to the specified context
 */
int acclWebSocketShutdown (struct libwebsocket_context* context) {

	if (NULL != context) {
		struct accl_context_buffer* user_context = (struct accl_context_buffer*)libwebsocket_context_user(context);

		if (NULL != user_context)
			free(user_context);

		libwebsocket_cancel_service(context);
		libwebsocket_context_destroy(context);

		return ACCL_SUCCESS;
	}

	return ACCL_WS_INVALID_CONTEXT;
}

/**
 * Internal communication helper
 */
int _acclWebSocketCommunication (int wait_for_response, struct libwebsocket_context* context, const unsigned int payloadBufferSize, const char* pPayloadBuffer, unsigned int returnBufferSize, char* pReturnBuffer) {
	char* out_buffer = (char*)malloc(sizeof(char) * (payloadBufferSize + 1));

	if (NULL == context)
		return ACCL_WS_INVALID_CONTEXT;

	// prepare user context for sending callback
	struct accl_context_buffer* user_context = (struct accl_context_buffer*)libwebsocket_context_user(context);

	if (NULL != user_context) {
		// the first byte is used to identify the type of call (0=send / 1=exchange)
		out_buffer[0] = wait_for_response;

		// let's copy the payload to the output buffer
		memcpy(out_buffer + 1, pPayloadBuffer, payloadBufferSize);

		user_context->buffer_ptr = (void*)out_buffer;
		user_context->buffer_size = payloadBufferSize + 1;
		user_context->wait_for_response = wait_for_response;
		user_context->response_buffer_ptr = pReturnBuffer;
		user_context->response_buffer_size = returnBufferSize;
		user_context->send_in_progress = 1;

#ifndef NDEBUG
		lwsl_notice("request write on channel\n");
#endif
		/* request a write callback to libwebsocket */
		libwebsocket_callback_on_writable_all_protocol(user_context->protocols);

		while (1 == user_context->send_in_progress) {
			libwebsocket_service(context, 50);
		}

		while (1 == user_context->wait_for_response) {
			libwebsocket_service(context, 50);
		}
#ifndef NDEBUG
		lwsl_notice("send terminated\n");
#endif
		return ACCL_SUCCESS;
	}

	return ACCL_GENERIC_ERROR;
}

/**
 * Send API primitive
 */
int acclWebSocketSend (struct libwebsocket_context* context, const unsigned int payloadBufferSize, const char* pPayloadBuffer) {
#ifndef NDEBUG
	lwsl_notice("ACCL - acclWebSocketSend enter\n");
#endif
	return _acclWebSocketCommunication(0, context, payloadBufferSize, pPayloadBuffer, 0, NULL);
}

/**
 * Exchange API primitive
 */
int acclWebSocketExchange (struct libwebsocket_context* context, const unsigned int payloadBufferSize, const char* pPayloadBuffer, unsigned int returnBufferSize, char*	pReturnBuffer) {
#ifndef NDEBUG
	lwsl_notice("ACCL - acclWebSocketExchange enter\n");
#endif
	return _acclWebSocketCommunication(1, context, payloadBufferSize, pPayloadBuffer, returnBufferSize, pReturnBuffer);
}

#endif /* WITHOUT_WEBSOCKETS */