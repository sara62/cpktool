#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "cpktool.h"
#include "CPKObject.h"

static bool identifiersInitialized = false;


#define CPK_PROPERTY_VERSION		0
#define CPK_PROPERTY_DOMAININFO		1
#define CPK_PROPERTY_IDENTITY		2
#define CPK_NUM_PROPERTIES		3

static NPIdentifier cpkPropertyIdentifiers[CPK_NUM_PROPERTIES];
static const NPUTF8 *cpkPropertyNames[CPK_NUM_PROPERTIES] = {
	"version",
	"domainInfo",
	"identity",
};


#define CPK_METHOD_SIGN			0
#define CPK_METHOD_VERIFY		1
#define CPK_METHOD_ENCRYPT		2
#define CPK_METHOD_DECRYPT		3
#define CPK_METHOD_ENVELOPE_ENCRYPT	4
#define CPK_METHOD_ENVELOPE_DECRYPT	5
#define CPK_NUM_METHODS			6

static NPIdentifier cpkMethodIdentifiers[CPK_NUM_METHODS];
static const NPUTF8 *cpkMethodNames[CPK_NUM_METHODS] = {
	"sign",
	"verify",
	"encrypt",
	"decrypt",
	"envelopeEncrypt",
	"envelopeDecrypt",
};


#define CPK_NPAPI_GENERAL_ERROR			1
#define CPK_NPAPI_INVALID_ARGUMENT_TYPE		2
#define CPK_NPAPI_INVALID_ARGUMENT_VALUE	3


static NPObject *cpkAllocate(NPP npp, NPClass *theClass)
{
	CPKObject *newInstance = (CPKObject *)malloc(sizeof(CPKObject));

	fprintf(stderr, "cpkAllocate()\n");
	cpktool_init(NULL, NULL, NULL, NULL);

	if (!identifiersInitialized) {
		browser->getstringidentifiers(cpkPropertyNames,
			CPK_NUM_PROPERTIES, cpkPropertyIdentifiers);
		browser->getstringidentifiers(cpkMethodNames,
			CPK_NUM_METHODS, cpkMethodIdentifiers);
		identifiersInitialized = true;
	}
	return &newInstance->header;
}

static void cpkDeallocate(NPObject *obj) 
{
	free(obj);
}

static void cpkInvalidate(NPObject *obj)
{
}

static bool cpkHasMethod(NPObject *obj, NPIdentifier name)
{
	int i;
	fprintf(stderr, "cpkHashMethod(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < CPK_NUM_METHODS; i++)
		if (name == cpkMethodIdentifiers[i])
			return true;
	return false;
}


static bool sign(const NPVariant message, NPVariant *result);
static bool encrypt(const NPVariant message, const NPVariant recipient, NPVariant *result);

static bool verify(const NPVariant message, const NPVariant signature,
	const NPVariant signer, NPVariant *result);

static bool decrypt(const NPVariant text, NPVariant *result);


static bool cpkInvoke(NPObject *obj, NPIdentifier name, const NPVariant *args,
	uint32_t argCount, NPVariant *variant)
{
	fprintf(stderr, "cpkInvoke(%s)\n", browser->utf8fromidentifier(name));

	char *id = cpktool_get_identity();
	if (!id)
		return false;
	if (strcmp(id, "alice@cpksecurity.com") != 0 && strcmp(id, "bob@cpksecurity.com") != 0) {
		fprintf(stderr, "%s: invalid identity %s\n", "cpk", id);
		free(id);
		return false;
	}
	free(id);

	
	if (name == cpkMethodIdentifiers[CPK_METHOD_SIGN]) {
		if (argCount != 1) {
			fprintf(stderr, "%s: bad npapi arguments", "CPK");
			return false;
		}		
		return sign(args[0], variant);
	}
	if (name == cpkMethodIdentifiers[CPK_METHOD_VERIFY]) {
		if (argCount != 3) {
			fprintf(stderr, "%s: bad arguments", "prog");
			return false;
		}
		
		return verify(args[0], args[1], args[2], variant);
	}
	if (name == cpkMethodIdentifiers[CPK_METHOD_ENCRYPT]) {
		if (argCount != 2) {
			fprintf(stderr, "%s: bad arguments", "prog");
			return false;
		}
		return encrypt(args[0], args[1], variant);
	}
	if (name == cpkMethodIdentifiers[CPK_METHOD_DECRYPT]) {
		if (argCount != 1) {
			fprintf(stderr, "%s: bad argument count\n", "prog");
			return false;
		}
		return decrypt(args[0], variant);
	}

	/*
	if (name == cpkMethodIdentifiers[CPK_METHOD_ENVELOPE_ENCRYPT]) {
		return 0;
	}

	if (name == cpkMethodIdentifiers[CPK_METHOD_ENVELOPE_DECRYPT]) {
		return 0;
	}
	*/

	return false;
}

static bool cpkInvokeDefault(NPObject *obj, const NPVariant *args,
	uint32_t argCount, NPVariant *result)
{
	return false;
}

static bool cpkHasProperty(NPObject *obj, NPIdentifier name)
{
	int i;
	fprintf(stderr, "cpkHasProperty(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < CPK_NUM_PROPERTIES; i++)
		if (name == cpkPropertyIdentifiers[i])
			return true;
	return false;
}

static bool cpkGetProperty(NPObject *obj, NPIdentifier name, NPVariant *variant)
{
	CPKObject *cpkObject = (CPKObject *)obj;

	fprintf(stderr, "cpkGetProperty(%s)\n", browser->utf8fromidentifier(name));
	if (name == cpkPropertyIdentifiers[CPK_PROPERTY_VERSION]) {
		// we need to return a string
		// we can print compile time to this place

		char buffer[128];
		snprintf(buffer, sizeof(buffer), "1.0 beta (%s %s)", __DATE__, __TIME__);
		char *ret = malloc(strlen(buffer) + 1);
		strcpy(ret, buffer);
		STRINGZ_TO_NPVARIANT(ret, *variant);
		return true;
		
	}
	if (name == cpkPropertyIdentifiers[CPK_PROPERTY_DOMAININFO]) {
		// we need a function to get domain_uri
		char buffer[1024];
		snprintf(buffer, sizeof(buffer), "{domainURI: \"http://infosec.pku.edu.cn\" }");
		char *ret = malloc(strlen(buffer) + 1);
		STRINGZ_TO_NPVARIANT(ret, *variant);
		return true;
	}
	if (name == cpkPropertyIdentifiers[CPK_PROPERTY_IDENTITY]) {
		char *id = NULL;
		
		if (!(id = cpktool_get_identity())) {
			fprintf(stderr, "cpk: cpktool_get_identity()\n");
			goto end;
		}
		
		STRINGZ_TO_NPVARIANT(id, *variant);
		return true;
	}
end:
	return false;
}

static bool cpkSetProperty(NPObject *obj, NPIdentifier name, 
	const NPVariant *variant)
{
    return false;
}

static NPClass cpkClass = { 
	NP_CLASS_STRUCT_VERSION,
	cpkAllocate, 
	cpkDeallocate, 
	cpkInvalidate,
	cpkHasMethod,
	cpkInvoke,
	cpkInvokeDefault,
	cpkHasProperty,
	cpkGetProperty,
	cpkSetProperty,
};

NPClass *getCPKClass(void)
{
	return &cpkClass;
}

const char *prog = "cpk";

static bool sign(const NPVariant message, NPVariant *result)
{
	const char *msg = NULL;
	const char *pass = "12345678";
	char *sig = NULL;
	uint32_t msglen;
	

	if (!NPVARIANT_IS_STRING(message)) {
		fprintf(stderr, "%s: type of argument 1 should be string\n", prog);
		goto end;
	}
	if (!(msg = NPVARIANT_TO_STRING(message).UTF8Characters)) {
		fprintf(stderr, "%s: invalid argument\n", prog);
		goto end;
	}
	msglen = NPVARIANT_TO_STRING(message).UTF8Length;
	fprintf(stderr, "message length = %u\n", msglen);	
	fprintf(stderr, "message = %s\n", msg);
	
	if (!(sig = cpktool_sign_text(msg, msglen, pass))) {
		fprintf(stderr, "%s: cpktool failed\n", prog);
		goto end;
	}
	STRINGZ_TO_NPVARIANT(sig, *result);
	return true;
end:	
	NULL_TO_NPVARIANT(*result);
	return false;
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

static bool verify(const NPVariant message, const NPVariant signature,
	const NPVariant signer, NPVariant *result)
{
	bool ret = false;

	if (!npstring_is_valid(message)) {
		fprintf(stderr, "%s: argument 1 is not valid\n", "cpk");
		return false;
	}
	if (!npstring_is_valid(signature)) {
		fprintf(stderr, "%s: argument 2 is not valid\n", "cpk");
		return false;
	}
	if (!npstring_is_valid(signer)) {
		fprintf(stderr, "%s: argument 3 is not valid\n", "cpk");
		return false;
	}

	if (cpktool_verify_text(
		NPVARIANT_TO_STRING(message).UTF8Characters,
		NPVARIANT_TO_STRING(message).UTF8Length,
		NPVARIANT_TO_STRING(signature).UTF8Characters,
		NPVARIANT_TO_STRING(signer).UTF8Characters) == 0) {
		ret = true;	
	}
	BOOLEAN_TO_NPVARIANT(ret, *result);
	return true;
}
	

static bool encrypt(const NPVariant message, const NPVariant recipient, NPVariant *result)
{
	const char *msg = NULL;
	const char *rcpt = NULL;
	char *ret = NULL;

	if (!NPVARIANT_IS_STRING(message)) {
		fprintf(stderr, "shit");
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

