/* This research is supported by the European Union Seventh Framework Programme (FP7/2007-2013), project ASPIRE (Advanced  Software Protection: Integration, Research, and Exploitation), under grant agreement no. 609734; on-line at https://aspire-fp7.eu/. */

/*
	ASPIRE Client-side Communication Logic

	accl.h - Prototypes and defines
*/

#ifndef ACCL__
#define ACCL__

#include <stdbool.h>

#ifndef ACCL_EXTERN
#define ACCL_EXTERN
#endif 

/*******************************************************************
* NAME :            acclExchange
*
* DESCRIPTION :     Send a request to the ASPIRE aspire-portal expecting a return value
*
* INPUTS :
*       PARAMETERS:
*			const int	T_ID					[in] technique unique identifier
*			const int   payloadBufferSize		[in] payload buff. size in bytes
*			const char* pPayloadBuffer			[in] payload buffer
*       GLOBALS :
*	    None
* OUTPUTS :
*       PARAMETERS:
*           const unsigned int returnBufferSize [out] return buff. size in bytes
*           const char** returnPayloadBuffer     [out] return buffer
*       GLOBALS :
*            None
*       RETURN :
*            Type:   	int                 Error code:
*            Values: 	ACCL_SUCCESS        0
*		     			ACCL_ERROR		    Anything else
* PROCESS :
*	[1]  Send payload to the ASPIRE aspire-portal
*	[2]  Wait for a response (for ACCL_RESPONSE_TIMEOUT seconds)
*	[3]  Fill the return buffer with response data
*/
ACCL_EXTERN int acclExchange (
	const int T_ID,
	const int payloadBufferSize,
	const char* pPayloadBuffer,
	unsigned int* returnBufferSize,
	char** 	pReturnBuffer
);

/*******************************************************************
* NAME :            acclSend
*
* DESCRIPTION :     Send a request to the ASPIRE aspire-portal without
*		    expecting a return value
*
* INPUTS :
*       PARAMETERS:
*           const int   T_ID                    technique unique identifier
*           const int   payloadBufferSize       payload buffer size in bytes
*           const char* pPayloadBuffer          payload buffer
*       GLOBALS :
*           None
* OUTPUTS :
*       PARAMETERS:
*	     None
*       GLOBALS :
*            None
*       RETURN :
*            Type:   int                    Error code:
*            Values: ACCL_SUCCESS            0
*                    ACCL_ERROR              Anything else
* PROCESS :
*                   [1]  Send payload to the ASPIRE aspire-portal
*/
ACCL_EXTERN int acclSend (
	const int T_ID,
	const int payloadBufferSize,
	const char* pPayloadBuffer
);

// comment this out to implement your own getApplicationId
//#define EXTERNAL_GET_APPLICATION_ID

#ifndef ASPIRE_APPLICATION_ID
	#define ASPIRE_APPLICATION_ID	"ACCL-TEST-APPLICATION"
#endif

#ifdef EXTERNAL_GET_APPLICATION_ID

extern void getApplicationId(char** ptr_to_string_to_be_filled);

#else

// for debugging purposes
void getApplicationId(char** ptr_to_string_to_be_filled);

#endif

#ifndef WITHOUT_WEBSOCKETS

	#include <limits.h>
	#include <pthread.h>
	#include <libwebsockets.h>

	/* Maximum number of active WebSocket channels per application */
	#define ACCL_MAX_WS_THREADS	64

	/*
	 * The ACCL component implements a communication protocol via websocket
	 *  'accl-communication-protocol': receives data from the ASPIRE Portal
	 */
	enum accl_protocols {
		PROTOCOL_ACCL_COMMUNICATION,

		/* always last */
		ACCL_WS_PROTOCOL_COUNT
	};

	typedef struct ws_channel {
		pthread_t tid;
		pthread_mutex_t mutex;
		void* (* callback)(void*, size_t);
		int closed;
		int technique_id;
	} ws_channel;

	/*
		WS protocol initialization, takes technique id, a callback to be called
		and returns a ws handle to the channel
	*/
	ACCL_EXTERN struct libwebsocket_context*  acclWebSocketInit (
		const int T_ID,
		void* (* callback)(void*, size_t)
	);

	ACCL_EXTERN int acclWebSocketSend (
		struct libwebsocket_context* context,
		const unsigned int payloadBufferSize,
		const char* pPayloadBuffer
	);

	ACCL_EXTERN int acclWebSocketExchange (
		struct libwebsocket_context* context,
		const unsigned int payloadBufferSize,
		const char* pPayloadBuffer,
		unsigned int responseSize,
		char* response
	);

	ACCL_EXTERN int acclWebSocketShutdown (
		struct libwebsocket_context* context
	);

	/* general callback for websockets events */
	ACCL_EXTERN int callback_accl_communication(
		struct libwebsocket_context *this,
		struct libwebsocket *wsi,
		enum libwebsocket_callback_reasons reason,
		void *user,
		void *in, 
		size_t len);

	/* ASCL data sending logic */
	struct accl_context_buffer {
		/* sending buffer */
		void* buffer_ptr;
		size_t buffer_size;

		/* receiving buffer */
		void* response_buffer_ptr;
		size_t response_buffer_size;

		int wait_for_response;
		int technique_id;
		void* (* callback)(void*, size_t);

		int initialization_complete;
		int send_in_progress;

		struct libwebsocket_protocols* protocols;
	};
#endif	/* WITHOUT_WEBSOCKETS */

/* Techniques unique IDentifiers */
#define ACCL_TID_CODE_SPLITTING			10
#define ACCL_TID_CODE_MOBILITY			20
#define ACCL_TID_DATA_MOBILITY			21
#define ACCL_TID_WBS					30
#define ACCL_TID_MTC_CRYPTO_SERVER		40
#define ACCL_TID_DIVERSIFIED_CRYPTO		41
#define ACCL_TID_CG_HASH_RANDOMIZATION	50
#define ACCL_TID_CG_HASH_VERIFICATION	55
#define ACCL_TID_CFGT_REMOVE_VERIFIER	60
#define ACCL_TID_AC_DECISION_LOGIC		70
#define ACCL_TID_AC_STATUS_LOGIC		75
#define ACCL_TID_RA_REACTION_MANAGER 	80
#define ACCL_TID_RA_VERIFIER		 	90
#define ACCL_RENEWABILITY			 	500		/* NB this is not defined in D1.04 */
#define ACCL_RA_ATTESTATOR_0			9000
#define ACCL_RA_ATTESTATOR_1			9001
#define ACCL_RA_ATTESTATOR_2			9002
#define ACCL_RA_ATTESTATOR_3			9003
#define ACCL_RA_ATTESTATOR_4			9004
#define ACCL_RA_ATTESTATOR_5			9005
#define ACCL_RA_ATTESTATOR_6			9006
#define ACCL_RA_ATTESTATOR_7			9007
#define ACCL_RA_ATTESTATOR_8			9008
#define ACCL_RA_ATTESTATOR_9			9009
#define ACCL_TID_TEST					9999

/* Requests timeout */
#define ACCL_RESPONSE_TIMEOUT			10L

/* payload max size */
#define ACCL_MAX_BUFFER_SIZE			(1 << 22)
#define ACCL_BLOCK_SIZE					(1 << 22)
#define ACCL_MAX_WS_BUFFER_SIZE			16384

/* ACCL Return values */
#define ACCL_SUCCESS							0
#define ACCL_CURL_INITIALIZATION_ERROR			5
#define ACCL_INPUT_BUFFER_ERROR					10
#define ACCL_INPUT_BUFFER_MAX_SIZE_EXCEEDED		11
#define ACCL_OUTPUT_BUFFER_MAX_SIZE_EXCEEDED	12
#define ACCL_OUTPUT_BUFFER_ALLOCATION_ERROR		15
#define ACCL_UNKNOWN_TECHNIQUE_ID				20

#define ACCL_SERVER_ERROR						100

/* WebSockets specific return values */
#define ACCL_WS_INVALID_CONTEXT					501
#define ACCL_WS_ALREADY_SHUT_DOWN				502

#define ACCL_GENERIC_ERROR						1000

/* maximum logging lenght */
#define ACCL_MSG_STRING_LENGTH					1024

/* logging levels */
#define ACCL_LOG_LEVEL_DEBUG	10
#define ACCL_LOG_LEVEL_INFO		20
#define ACCL_LOG_LEVEL_WARNING	30
#define ACCL_LOG_LEVEL_ERROR	40
#define ACCL_LOG_LEVEL_NONE		50

//#define NDEBUG 1

/* current logging level */
#ifndef ACCL_LOG_LEVEL
  #define ACCL_LOG_LEVEL			ACCL_LOG_LEVEL_NONE
#endif /* ACCL_LOG_LEVEL */

#ifndef NDEBUG
	#define ACCL_LOG_FILE			"accl.log"
#endif

/* current logging level */
#ifndef ACCL_LOG_LEVEL
  #define ACCL_LOG_LEVEL  ACCL_LOG_LEVEL_NONE
#endif /* ACCL_LOG_LEVEL */

/* file path; used for log (accl.log) and ini file (ASPIREendpoint) */
#ifndef ACCL_FILE_PATH
  #define ACCL_FILE_PATH       "."
#endif /* ACCL_FILE_PATH */

/* Aspire Portal Endpoint hostname or IP Address */
#ifndef ACCL_ASPIRE_PORTAL_ENDPOINT
	#define ACCL_ASPIRE_PORTAL_ENDPOINT "http://127.0.0.1:8088/"
#endif

#ifndef ACCL_WS_ASPIRE_PORTAL_HOST
	#define ACCL_WS_ASPIRE_PORTAL_HOST	"127.0.0.1"
#endif

#define ACCL_WS_ASPIRE_PORTAL_PORT	8081

#ifndef MIN
#define MIN(a,b) (((a)<(b))?(a):(b))
#endif

/* structure used for receiving data from server see: cURL CURLOPT_READDATA  */
typedef struct accl_payload_transfer {
	int technique_id;			/* technique id */
	char* application_id;			/* application id */
	unsigned int payload_size;	/* payload size */
	char* payload_buffer;		/* payload buffer */
	int transmit_offset;		/* current offset in data transmitting */
	int error;					/* will eventually contain error code */
} accl_payload_transfer;

/* structure used as userdata see: cURL CURLOPT_WRITEDATA  */
typedef struct accl_response {
	unsigned int output_buffer_size;	/* output buffer size */
	char* output_buffer;				/* output buffer */
	int error;							/* will eventually contain error code */
} accl_response;

//#undef NDEBUG

/* internal ACCL procedures */
#ifndef NDEBUG
	void acclLOG(const char* tag, const char* fmt, int lvl, ...);
#endif

size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);
size_t read_callback(void *ptr, size_t size, size_t nmemb, void *userp);
#endif
