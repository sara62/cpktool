#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "CryptoObject.h"

/*
 *
   interface Crypto {
	readonly attribute DOMString version;
	DOMString random(in unsigned long num_bytes);
	DOMString digest(in DOMString algor, in DOMString message);
	DOMString encrypt(in DOMString algor, in DOMString message, in DOMString key);
	DOMString decrypt(in DOMString algor, in DOMString ciphertext, in DOMString key);
   };

 */

//FIXME: too many `prog' are defined
const char *prog = "    crypto";

static bool identifiersInitialized = false;

#define CRYPTO_VERSION			0.8

#define CRYPTO_PROPERTY_VERSION		0
#define CRYPTO_NUM_PROPERTIES		1

static NPIdentifier cryptoPropertyIdentifiers[CRYPTO_NUM_PROPERTIES];
static const NPUTF8 *cryptoPropertyNames[CRYPTO_NUM_PROPERTIES] = {
	"version",
};

#define CRYPTO_METHOD_RANDOM		0
#define CRYPTO_METHOD_DIGEST		1
#define CRYPTO_METHOD_ENCRYPT		2
#define CRYPTO_METHOD_DECRYPT		3
#define CRYPTO_NUM_METHODS		4

static NPIdentifier cryptoMethodIdentifiers[CRYPTO_NUM_METHODS];
static const NPUTF8 *cryptoMethodNames[CRYPTO_NUM_METHODS] = {
	"random",
	"digest",
	"encrypt",
	"decrypt",
};


#define CPK_NPAPI_GENERAL_ERROR			1
#define CPK_NPAPI_INVALID_ARGUMENT_TYPE		2
#define CPK_NPAPI_INVALID_ARGUMENT_VALUE	3


static bool my_random(const NPVariant nbytes, NPVariant *result);
static bool encrypt(const NPVariant message, const NPVariant recipient, NPVariant *result);
static bool decrypt(const NPVariant text, NPVariant *result);


static NPObject *cryptoAllocate(NPP npp, NPClass *theClass)
{
	CryptoObject *newInstance = 
		(CryptoObject *)malloc(sizeof(CryptoObject));

	fprintf(stderr, "cpkAllocate()\n");
	OpenSSL_add_all_algorithms();

	if (!identifiersInitialized) {
		browser->getstringidentifiers(cryptoPropertyNames,
			CRYPTO_NUM_PROPERTIES, cryptoPropertyIdentifiers);
		browser->getstringidentifiers(cryptoMethodNames,
			CRYPTO_NUM_METHODS, cryptoMethodIdentifiers);
		identifiersInitialized = true;
	}
	return &newInstance->header;
}

static void cryptoDeallocate(NPObject *obj) 
{
	free(obj);
}

static void cryptoInvalidate(NPObject *obj)
{
}

static bool cryptoHasMethod(NPObject *obj, NPIdentifier name)
{
	int i;
	fprintf(stderr, "cpkHashMethod(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < CRYPTO_NUM_METHODS; i++)
		if (name == cryptoMethodIdentifiers[i])
			return true;
	return false;
}

static bool cryptoInvoke(NPObject *obj, NPIdentifier name, const NPVariant *args,
	uint32_t argCount, NPVariant *variant)
{
	if (name == cryptoMethodIdentifiers[CRYPTO_METHOD_RANDOM]) {
		if (argCount != 1) {
			fprintf(stderr, "crypto.random(): bad arg count\n");
			return false;
		}		
		return my_random(args[0], variant);
	}
	if (name == cryptoMethodIdentifiers[CRYPTO_METHOD_DIGEST]) {
		if (argCount != 2) {
			fprintf(stderr, "%s: bad arguments", "prog");
			return false;
		}
		return digest(args[0], args[1], variant);
	}
	if (name == cryptoMethodIdentifiers[CRYPTO_METHOD_ENCRYPT]) {
		if (argCount != 3) {
			fprintf(stderr, "%s: bad arguments", "prog");
			return false;
		}
		return encrypt(args[0], args[1], args[2], variant);
	}
	if (name == cryptoMethodIdentifiers[CRYPTO_METHOD_DECRYPT]) {
		if (argCount != 3) {
			fprintf(stderr, "%s: bad argument count\n", "prog");
			return false;
		}
		return decrypt(args[0], args[1], args[2], variant);
	}

	return false;
}

static bool cryptoInvokeDefault(NPObject *obj, const NPVariant *args,
	uint32_t argCount, NPVariant *result)
{
	return false;
}

static bool cryptoHasProperty(NPObject *obj, NPIdentifier name)
{
	int i;
	fprintf(stderr, "cpkHasProperty(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < CRYPTO_NUM_PROPERTIES; i++)
		if (name == cryptoPropertyIdentifiers[i])
			return true;
	return false;
}

static bool cryptoGetProperty(NPObject *obj, NPIdentifier name, NPVariant *variant)
{
	CryptoObject *cryptoObject = (CryptoObject *)obj;
	//fprintf(stderr, "cryptoGetProperty(%s)\n", browser->utf8fromidentifier(name));
	if (name == cryptoPropertyIdentifiers[CRYPTO_PROPERTY_VERSION]) {
		DOUBLE_TO_NPVARIANT(CRYPTO_VERSION, *variant);
		return true;
	}
	return false;
}

static bool cryptoSetProperty(NPObject *obj, NPIdentifier name, 
	const NPVariant *variant)
{
	return false;
}

static NPClass cryptoClass = { 
	NP_CLASS_STRUCT_VERSION,
	cryptoAllocate, 
	cryptoDeallocate, 
	cryptoInvalidate,
	cryptoHasMethod,
	cryptoInvoke,
	cryptoInvokeDefault,
	cryptoHasProperty,
	cryptoGetProperty,
	cryptoSetProperty,
};

NPClass *getCryptoClass(void)
{
	return &cryptoClass;
}

static bool npstring_is_valid(const NPVariant variant)
{
	const char *prog = "cpk";
	if (!NPVARIANT_IS_STRING(variant)) {
		fprintf(stderr, "%s: argument is not String\n", prog);
		return false;
	}
	if (NPVARIANT_TO_STRING(variant).UTF8Characters == NULL) {
		fprintf(stderr, "%s: argument string has no content\n", prog);
		return false;
	}
	if (NPVARIANT_TO_STRING(variant).UTF8Length <= 0) {
		return false;
	}
	return true; 
}

static bool my_random(const NPVariant nbytes, NPVariant *result)
{
	unsigned char *buffer = NULL;
	char *ret = NULL;
	int length;

	if (!NPVARIANT_IS_INT32(nbytes)) {
		fprintf(stderr, "%s.random() argument should be integer\n", prog);
		goto end;
	}
	if ((length = NPVARIANT_TO_INT32(nbytes)) < 0) {
		fprintf(stderr, "%s.random() argument should be positive integer\n", prog);
		goto end;
	}
	if (length == 0) {
		STRINGZ_TO_NPVARIANT(NULL, *result);
		return true;
	}
	if (!(buffer = malloc(length))) {
	}
	
	RAND_bytes(buffer, length);
	
	// base64 encode

end:	
	return false;
}	

static bool encrypt(const NPVariant message, const NPVariant recipient, NPVariant *result)
{
	const char *msg = NULL;
	const char *rcpt = NULL;
	char *ret = NULL;

	if (!NPVARIANT_IS_STRING(message)) {
		fprintf(stderr, "%s.random() argument 1 should be ");
		goto end;
	}
	if (!(msg = NPVARIANT_TO_STRING(message).UTF8Characters)) {
		fprintf(stderr, "shit");
		goto end;
	}
	if (strlen(msg) <= 0) {
		fprintf(stderr, "shit");
		goto end;
	}

	rcpt = NPVARIANT_TO_STRING(recipient).UTF8Characters;
	
	if (!(ret = cpktool_encrypt_text(msg, -1, rcpt))) {
		fprintf(stderr, "shit");
		goto end;
	}

	STRINGZ_TO_NPVARIANT(ret, *result);
	return true;
end:
	NULL_TO_NPVARIANT(*result);
	return false;

}

static bool decrypt(const NPVariant text, NPVariant *result)
{
	char *ret = NULL;
	int len = 0;
	const char *pass = "12345678";

	if (!npstring_is_valid(text)) {
		fprintf(stderr, "%s: argument 1 is not valid\n", "cpk");
		return false;
	}
	if (!(ret = cpktool_decrypt_text(
		NPVARIANT_TO_STRING(text).UTF8Characters, &len, pass))) {
		fprintf(stderr, "%s: decrypt failed\n", "cpk");
		return false;
	}
	STRINGZ_TO_NPVARIANT(ret, *result);
	return true;
}

