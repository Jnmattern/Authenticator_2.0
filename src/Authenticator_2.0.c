#include <pebble.h>
#include <string.h>

/********CONFIGURE THIS********/

//Number of secrets defined
#define MAX_SECRETS 4

enum {
	CONFIG_KEY_TIMEOFFSET	= 0x4A6E6D01,
	CONFIG_KEY_KEYNAMES		= 0x4A6E6D02,
	CONFIG_KEY_KEYVALUES 	= 0x4A6E6D03
};

char otplabels[MAX_SECRETS][20];
char otpKeys_base32[MAX_SECRETS][17] ;
unsigned char otpkeys[MAX_SECRETS][10];

/******************************/


// Truncate n decimal digits to 2^n for 6 digits
#define DIGITS_TRUNCATE 1000000

#define SHA1_SIZE 20

Window *window;
Layer *rootLayer;
TextLayer *label;
TextLayer *token;
TextLayer *ticker;
int curToken = 0;

int timeZoneOffset = 0;
int numKeys = 0;
char msg[256];



/* from sha1.c from liboauth */

/* This code is public-domain - it is based on libcrypt 
 * placed in the public domain by Wei Dai and other contributors.
 */

/* header */

#define HASH_LENGTH 20
#define BLOCK_LENGTH 64

union _buffer {
	uint8_t b[BLOCK_LENGTH];
	uint32_t w[BLOCK_LENGTH/4];
};

union _state {
	uint8_t b[HASH_LENGTH];
	uint32_t w[HASH_LENGTH/4];
};

typedef struct sha1nfo {
	union _buffer buffer;
	uint8_t bufferOffset;
	union _state state;
	uint32_t byteCount;
	uint8_t keyBuffer[BLOCK_LENGTH];
	uint8_t innerHash[HASH_LENGTH];
} sha1nfo;

/* public API - prototypes - TODO: doxygen*/

/*
void sha1_init(sha1nfo *s);
void sha1_writebyte(sha1nfo *s, uint8_t data);
void sha1_write(sha1nfo *s, const char *data, size_t len);
uint8_t* sha1_result(sha1nfo *s);
void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength);
uint8_t* sha1_resultHmac(sha1nfo *s);
*/

/* code */
#define SHA1_K0 0x5a827999
#define SHA1_K20 0x6ed9eba1
#define SHA1_K40 0x8f1bbcdc
#define SHA1_K60 0xca62c1d6

const uint8_t sha1InitState[] = {
	0x01,0x23,0x45,0x67, // H0
	0x89,0xab,0xcd,0xef, // H1
	0xfe,0xdc,0xba,0x98, // H2
	0x76,0x54,0x32,0x10, // H3
	0xf0,0xe1,0xd2,0xc3  // H4
};

void sha1_init(sha1nfo *s) {
	memcpy(s->state.b,sha1InitState,HASH_LENGTH);
	s->byteCount = 0;
	s->bufferOffset = 0;
}

uint32_t sha1_rol32(uint32_t number, uint8_t bits) {
	return ((number << bits) | (number >> (32-bits)));
}

void sha1_hashBlock(sha1nfo *s) {
	uint8_t i;
	uint32_t a,b,c,d,e,t;

	a=s->state.w[0];
	b=s->state.w[1];
	c=s->state.w[2];
	d=s->state.w[3];
	e=s->state.w[4];
	for (i=0; i<80; i++) {
		if (i>=16) {
			t = s->buffer.w[(i+13)&15] ^ s->buffer.w[(i+8)&15] ^ s->buffer.w[(i+2)&15] ^ s->buffer.w[i&15];
			s->buffer.w[i&15] = sha1_rol32(t,1);
		}
		if (i<20) {
			t = (d ^ (b & (c ^ d))) + SHA1_K0;
		} else if (i<40) {
			t = (b ^ c ^ d) + SHA1_K20;
		} else if (i<60) {
			t = ((b & c) | (d & (b | c))) + SHA1_K40;
		} else {
			t = (b ^ c ^ d) + SHA1_K60;
		}
		t+=sha1_rol32(a,5) + e + s->buffer.w[i&15];
		e=d;
		d=c;
		c=sha1_rol32(b,30);
		b=a;
		a=t;
	}
	s->state.w[0] += a;
	s->state.w[1] += b;
	s->state.w[2] += c;
	s->state.w[3] += d;
	s->state.w[4] += e;
}

void sha1_addUncounted(sha1nfo *s, uint8_t data) {
	s->buffer.b[s->bufferOffset ^ 3] = data;
	s->bufferOffset++;
	if (s->bufferOffset == BLOCK_LENGTH) {
		sha1_hashBlock(s);
		s->bufferOffset = 0;
	}
}

void sha1_writebyte(sha1nfo *s, uint8_t data) {
	++s->byteCount;
	sha1_addUncounted(s, data);
}

void sha1_write(sha1nfo *s, const char *data, size_t len) {
	for (;len--;) sha1_writebyte(s, (uint8_t) *data++);
}

void sha1_pad(sha1nfo *s) {
	// Implement SHA-1 padding (fips180-2 §5.1.1)

	// Pad with 0x80 followed by 0x00 until the end of the block
	sha1_addUncounted(s, 0x80);
	while (s->bufferOffset != 56) sha1_addUncounted(s, 0x00);

	// Append length in the last 8 bytes
	sha1_addUncounted(s, 0); // We're only using 32 bit lengths
	sha1_addUncounted(s, 0); // But SHA-1 supports 64 bit lengths
	sha1_addUncounted(s, 0); // So zero pad the top bits
	sha1_addUncounted(s, s->byteCount >> 29); // Shifting to multiply by 8
	sha1_addUncounted(s, s->byteCount >> 21); // as SHA-1 supports bitstreams as well as
	sha1_addUncounted(s, s->byteCount >> 13); // byte.
	sha1_addUncounted(s, s->byteCount >> 5);
	sha1_addUncounted(s, s->byteCount << 3);
}

uint8_t* sha1_result(sha1nfo *s) {
	int i;
	// Pad to complete the last block
	sha1_pad(s);

	// Swap byte order back
	for (i=0; i<5; i++) {
		uint32_t a,b;
		a=s->state.w[i];
		b=a<<24;
		b|=(a<<8) & 0x00ff0000;
		b|=(a>>8) & 0x0000ff00;
		b|=a>>24;
		s->state.w[i]=b;
	}

	// Return pointer to hash (20 characters)
	return s->state.b;
}

#define HMAC_IPAD 0x36
#define HMAC_OPAD 0x5c

void sha1_initHmac(sha1nfo *s, const uint8_t* key, int keyLength) {
	uint8_t i;
	memset(s->keyBuffer, 0, BLOCK_LENGTH);
	if (keyLength > BLOCK_LENGTH) {
		// Hash long keys
		sha1_init(s);
		for (;keyLength--;) sha1_writebyte(s, *key++);
		memcpy(s->keyBuffer, sha1_result(s), HASH_LENGTH);
	} else {
		// Block length keys are used as is
		memcpy(s->keyBuffer, key, keyLength);
	}
	// Start inner hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) {
		sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_IPAD);
	}
}

uint8_t* sha1_resultHmac(sha1nfo *s) {
	uint8_t i;
	// Complete inner hash
	memcpy(s->innerHash,sha1_result(s),HASH_LENGTH);
	// Calculate outer hash
	sha1_init(s);
	for (i=0; i<BLOCK_LENGTH; i++) sha1_writebyte(s, s->keyBuffer[i] ^ HMAC_OPAD);
	for (i=0; i<HASH_LENGTH; i++) sha1_writebyte(s, s->innerHash[i]);
	return sha1_result(s);
}


/* end sha1.c */

int indexOf(char c, char *s) {
	int i = 0, l = 0;

	l = strlen(s);

	for (i=0; i<l; i++) {
		if ( s[i] == c ) {
			return i;
		}
	}

	return -1;
}

void base32_decode(char *input, unsigned char *output, int *num) {
	static char *keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
	int val, buffer = 0, bitsLeft = 0, i = 0, count = 0, l = 0;

	l = strlen(input);

	for (i=0; i<l; i++) {
		val = indexOf(input[i], keyStr);

		if (val >= 0 && val < 32) {
			buffer <<= 5;
			buffer |= val;
			bitsLeft += 5;
			if (bitsLeft >= 8) {
				output[count++] = (buffer >> (bitsLeft -8)) & 0xFF;
				bitsLeft -= 8;
			}
		}
	}

	if (bitsLeft > 0) {
		buffer <<= 5;
		output[count++] = (buffer >> (bitsLeft - 3)) & 0xFF;
	}

	*num = count;
}

int curSeconds=0;

void handle_second_tick(struct tm *now, TimeUnits units_changed) {
	static char tokenText[] = "RYRYRY"; // Needs to be static because it's used by the system later.
	static char buf[] = "99"; // Seconds left before change
	time_t unix_time;
	sha1nfo s;
	uint8_t ofs;
	uint32_t otp;
	char sha1_time[8] = {0, 0, 0, 0, 0, 0, 0, 0};

	// TOTP uses seconds since epoch in the upper half of an 8 byte payload
	// TOTP is HOTP with a time based payload
	// HOTP is HMAC with a truncation function to get a short decimal key
	//unix_time = time(NULL) / 30;
	unix_time = time(NULL) + timeZoneOffset;

	unix_time /= 30;
	sha1_time[4] = (unix_time >> 24) & 0xFF;
	sha1_time[5] = (unix_time >> 16) & 0xFF;
	sha1_time[6] = (unix_time >> 8) & 0xFF;
	sha1_time[7] = unix_time & 0xFF;

	// First get the HMAC hash of the time payload with the shared key
	sha1_initHmac(&s, otpkeys[curToken], 10);
	sha1_write(&s, sha1_time, 8);
	sha1_resultHmac(&s);
	
	// Then do the HOTP truncation.  HOTP pulls its result from a 31-bit byte
	// aligned window in the HMAC result, then lops off digits to the left
	// over 6 digits.
	ofs=s.state.b[SHA1_SIZE-1] & 0xf;
	otp = 0;
	otp = ((s.state.b[ofs] & 0x7f) << 24) |
		((s.state.b[ofs + 1] & 0xff) << 16) |
		((s.state.b[ofs + 2] & 0xff) << 8) |
		(s.state.b[ofs + 3] & 0xff);
	otp %= DIGITS_TRUNCATE;
	
	// Convert result into a string.
	snprintf(tokenText, 7, "%.6d", (int)otp);

	text_layer_set_text(label, otplabels[curToken]);
	text_layer_set_text(token, tokenText);
	curSeconds = now->tm_sec;
	if ((curSeconds>=0) && (curSeconds<30)) {
		snprintf(buf, 3, "%d", 30-curSeconds);
	} else {
		snprintf(buf, 3, "%d", 60-curSeconds);
	}
	text_layer_set_text(ticker, buf);
}

void up_single_click_handler(ClickRecognizerRef recognizer, void *context) {
	if (numKeys > 0) {
		if (curToken==0) {
			curToken=numKeys-1;
		} else {
			curToken--;
		}
	}
}

void down_single_click_handler(ClickRecognizerRef recognizer, void *context) {
	if (numKeys > 0) {
		if ((curToken+1)==numKeys) {
			curToken=0;
		} else {
			curToken++;
		}
	}
}

void click_config_provider(void *context) {
	window_single_repeating_click_subscribe(BUTTON_ID_UP, 100, (ClickHandler) up_single_click_handler);
	window_single_repeating_click_subscribe(BUTTON_ID_DOWN, 100, (ClickHandler) down_single_click_handler);
}


void applyConfig() {
	int i;
	for (i=0; i< numKeys; i++) {
		int n = 0;
		base32_decode(otpKeys_base32[i], otpkeys[i], &n);
	}
	
}

static int decodeKeyNames(const char *src) {
	int i, j = 0, l, n = 0;
	
	//	snprintf(msg, 256, "decodeKeyNames(\"%s\")", src);
	//	APP_LOG(APP_LOG_LEVEL_DEBUG, msg);

	l = strlen(src);
	
	for (i=0; i<=l; i++) {
		if ((src[i] != '|') && (src[i] != (char)0)) {
			otplabels[n][j++] = src[i];
		} else {
			otplabels[n][j] = (char)0;
			// snprintf(msg, 256, "\totplabels[%d] = %s", n, otplabels[n]);
			// APP_LOG(APP_LOG_LEVEL_DEBUG, msg);
			n++;
			j = 0;
		}
	}
	
	return n;
}

static int decodeKeyValues(const char *src) {
	int i, j = 0, l, n = 0;
	
	//	snprintf(msg, 256, "decodeKeyValues(\"%s\")", src);
	//	APP_LOG(APP_LOG_LEVEL_DEBUG, msg);

	l = strlen(src);
	
	for (i=0; i<=l; i++) {
		if ((src[i] != '|') && (src[i] != (char)0)) {
			otpKeys_base32[n][j++] = src[i];
		} else {
			otpKeys_base32[n][j] = (char)0;
			// snprintf(msg, 256, "\totpKeys_base32[%d] = %s", n, otpKeys_base32[n]);
			// APP_LOG(APP_LOG_LEVEL_DEBUG, msg);
			n++;
			j = 0;
		}
	}
	
	return n;
}



bool checkAndSaveInt(int *var, int val, int key) {
	if (*var != val) {
		*var = val;
		persist_write_int(key, val);
		return true;
	} else {
		return false;
	}
}

bool checkAndSaveString(const char *buf, uint32_t key) {
	switch (key) {
	case CONFIG_KEY_KEYNAMES:
			numKeys = decodeKeyNames(buf);
		break;
		
	case CONFIG_KEY_KEYVALUES:
			numKeys = decodeKeyValues(buf);
		break;
	}
	
	//snprintf(msg, 256, "checkAndSaveString : numKeys = %d", numKeys);
	//APP_LOG(APP_LOG_LEVEL_DEBUG, msg);

	return true;
}

void logVariables(const char *s) {
	int i;
	snprintf(msg, 256, "MSG: %s", s);
	APP_LOG(APP_LOG_LEVEL_DEBUG, msg);
	snprintf(msg, 256, "\ttimeZoneOffset = %d", timeZoneOffset);
	APP_LOG(APP_LOG_LEVEL_DEBUG, msg);
	for (i=0; i<numKeys; i++) {
		snprintf(msg, 256, "\totplabels[%d] = %s | otpKeys_base32[%d] = %s", i, otplabels[i], i, otpKeys_base32[i]);
		APP_LOG(APP_LOG_LEVEL_DEBUG, msg);
	}
}


void in_dropped_handler(AppMessageResult reason, void *context) {
	snprintf(msg, 256, "ERROR: message dropped. Reason : %d", reason);
	APP_LOG(APP_LOG_LEVEL_DEBUG, msg);
}

void in_received_handler(DictionaryIterator *received, void *context) {
	bool somethingChanged = false;
	
	//APP_LOG(APP_LOG_LEVEL_DEBUG, "In received_Handler");

	Tuple *timeoffset = dict_find(received, CONFIG_KEY_TIMEOFFSET);
	Tuple *keynames = dict_find(received, CONFIG_KEY_KEYNAMES);
	Tuple *keyvalues = dict_find(received, CONFIG_KEY_KEYVALUES);
	
	if (timeoffset && keynames && keyvalues) {
		somethingChanged |= checkAndSaveInt(&timeZoneOffset, timeoffset->value->int32 * 60, CONFIG_KEY_TIMEOFFSET);
		somethingChanged |= checkAndSaveString(keynames->value->cstring, CONFIG_KEY_KEYNAMES);
		somethingChanged |= checkAndSaveString(keyvalues->value->cstring, CONFIG_KEY_KEYVALUES);
		
		logVariables("ReceiveHandler");
		
		if (somethingChanged) {
			applyConfig();
		}
	}
}

static void readConfig() {
	int numkeynames = 0, numkeyvalues = 0;
	
	if (persist_exists(CONFIG_KEY_TIMEOFFSET)) {
		timeZoneOffset = persist_read_int(CONFIG_KEY_TIMEOFFSET);
	} else {
		timeZoneOffset = 0;
	}
	
	if (persist_exists(CONFIG_KEY_KEYNAMES)) {
		persist_read_string(CONFIG_KEY_KEYNAMES, msg, 256);
		numkeynames = decodeKeyNames(msg);
	} else {
		numkeynames = 0;
	}
	
	if (persist_exists(CONFIG_KEY_KEYVALUES)) {
		persist_read_string(CONFIG_KEY_KEYVALUES, msg, 256);
		numkeyvalues = decodeKeyValues(msg);
	} else {
		numkeyvalues = 0;
	}
	
	if (numkeyvalues == numkeynames) {
		numKeys = numkeyvalues;
	} else {
		numKeys = 0;
	}
	
	logVariables("readConfig");
	
}


static void app_message_init(void) {
	app_message_register_inbox_received(in_received_handler);
	app_message_register_inbox_dropped(in_dropped_handler);
	app_message_open(256, 256);
}


void handle_init() {
	window = window_create();
	window_set_background_color(window, GColorBlack);
	window_stack_push(window, true);
	rootLayer = window_get_root_layer(window);

	app_message_init();
	readConfig();
	
	// Init the identifier label
	label = text_layer_create(GRect(0, 0, 144, 168-44));
	text_layer_set_text_color(label, GColorWhite);
	text_layer_set_background_color(label, GColorClear);
	text_layer_set_font(label, fonts_get_system_font(FONT_KEY_GOTHIC_28_BOLD));
	text_layer_set_text_alignment(label, GTextAlignmentCenter);

	// Init the token label
	token = text_layer_create(GRect(0, 60, 144, 168-44));
	text_layer_set_text_color(token, GColorWhite);
	text_layer_set_background_color(token, GColorClear);
	text_layer_set_font(token, fonts_get_system_font(FONT_KEY_BITHAM_34_MEDIUM_NUMBERS));
	text_layer_set_text_alignment(token, GTextAlignmentCenter);

	// Init the second ticker
	ticker = text_layer_create(GRect(0, 120, 144, 168-44));
	text_layer_set_text_color(ticker, GColorWhite);
	text_layer_set_background_color(ticker, GColorClear);
	text_layer_set_font(ticker, fonts_get_system_font(FONT_KEY_GOTHIC_18_BOLD));
	text_layer_set_text_alignment(ticker, GTextAlignmentCenter);

	layer_add_child(rootLayer, text_layer_get_layer(label));
	layer_add_child(rootLayer, text_layer_get_layer(token));
	layer_add_child(rootLayer, text_layer_get_layer(ticker));

	applyConfig();
	
	window_set_click_config_provider(window, (ClickConfigProvider) click_config_provider);

	tick_timer_service_subscribe(SECOND_UNIT, handle_second_tick);
}


void handle_deinit() {
	tick_timer_service_unsubscribe();
	text_layer_destroy(ticker);
	text_layer_destroy(token);
	text_layer_destroy(label);
	window_destroy(window);
}

int main(void) {
	handle_init();
	app_event_loop();
	handle_deinit();
}
