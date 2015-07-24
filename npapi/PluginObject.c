#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "PluginObject.h"

static bool identifiersInitialized = false;

#define PLUGIN_PROPERTY_CRYPTO			0
#define PLUGIN_PROPERTY_CPK			1
#define PLUGIN_PROPERTY_TOKEN			2
#define PLUGIN_NUM_PROPERTIES			3

static NPIdentifier pluginPropertyIdentifiers[PLUGIN_NUM_PROPERTIES];
static const NPUTF8 *pluginPropertyNames[PLUGIN_NUM_PROPERTIES] = {
	"crypto",
	"cpk",
	"token",
};

#define PLUGIN_METHOD_GETTOKEN			0
#define PLUGIN_NUM_METHODS			1

static NPIdentifier pluginMethodIdentifiers[PLUGIN_NUM_METHODS];
static const NPUTF8 *pluginMethodNames[PLUGIN_NUM_METHODS] = {
	"getToken"
};

static void initializeIdentifiers(void)
{
	browser->getstringidentifiers(pluginPropertyNames,
		PLUGIN_NUM_PROPERTIES, pluginPropertyIdentifiers);
	browser->getstringidentifiers(pluginMethodNames,
		PLUGIN_NUM_METHODS, pluginMethodIdentifiers);
}

bool pluginHasProperty(NPObject *obj, NPIdentifier name)
{
	int i;
	fprintf(stderr, "pluginHasProperty(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < PLUGIN_NUM_PROPERTIES; i++)
		if (name == pluginPropertyIdentifiers[i])
			return true;
	return false;
}

bool pluginHasMethod(NPObject *obj, NPIdentifier name)
{
	int i;
	fprintf(stderr, "pluginHasMethod(%s)\n", browser->utf8fromidentifier(name));
	for (i = 0; i < PLUGIN_NUM_METHODS; i++)
		if (name == pluginMethodIdentifiers[i])
			return true;
	return false;
}

bool pluginGetProperty(NPObject *obj, NPIdentifier name, NPVariant *variant)
{
	PluginObject *plugin = (PluginObject *)obj;
	fprintf(stderr, "pluginGetProperty(%s)\n", browser->utf8fromidentifier(name));
	if (name == pluginPropertyIdentifiers[PLUGIN_PROPERTY_CRYPTO]) {
		fprintf(stderr, "webvision: get CryptoObject\n");
		NPObject *resultObj = &plugin->cpkObject->header;
		browser->retainobject(resultObj);
		
		
		char *s = browser->memalloc(100);
		strcpy(s, "hello");
		STRINGZ_TO_NPVARIANT(s, *variant);
		return true;
	}

        if (name == pluginPropertyIdentifiers[PLUGIN_PROPERTY_CPK]) {
                fprintf(stderr, "webvision: get CPKObject\n");
                NPObject *resultObj = &plugin->cpkObject->header;
                browser->retainobject(resultObj);
                OBJECT_TO_NPVARIANT(resultObj, *variant);
                return true;
        }	
	/*
	if (name == pluginPropertyIdentifiers[PLUGIN_PROPERTY_TOKEN]) {
		fprintf(stderr, "webvision: get TokenObject\n");
		NPObject *resultObj = &plugin->tokenObject->header;
		browser->retainobject(resultObj);
		OBJECT_TO_NPVARIANT(resultObj, *variant);
		return true;
	}
	*/
	return false;
}

bool pluginSetProperty(NPObject *obj, NPIdentifier name, const NPVariant *variant)
{
	return false;
}

bool pluginInvoke(NPObject *obj, NPIdentifier name, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return false;
}

bool pluginInvokeDefault(NPObject *obj, const NPVariant *args, uint32_t argCount, NPVariant *result)
{
	return false;
}

void pluginInvalidate(NPObject *obj)
{
	// Release any remaining references to JavaScript objects.
}

NPObject *pluginAllocate(NPP npp, NPClass *theClass)
{
	PluginObject *newInstance = malloc(sizeof(PluginObject));
	
	fprintf(stderr, "pluginAllocate()\n");

	if (!identifiersInitialized) {
		identifiersInitialized = true;
		initializeIdentifiers();
	}
	newInstance->cpkObject = 
		(CPKObject *)browser->createobject(npp, getCPKClass());
	/*
	newInstance->tokenObject =
		(TokenObject *)browser->createobject(npp, getTokenClass());
	*/
	newInstance->npp = npp;

	return &newInstance->header;
}

void pluginDeallocate(NPObject *obj) 
{
	free(obj);
}

static NPClass pluginClass = { 
	NP_CLASS_STRUCT_VERSION,
	pluginAllocate, 
	pluginDeallocate, 
	pluginInvalidate,
	pluginHasMethod,
	pluginInvoke,
	pluginInvokeDefault,
	pluginHasProperty,
	pluginGetProperty,
	pluginSetProperty,
};
 
NPClass *getPluginClass(void)
{
	return &pluginClass;
}
