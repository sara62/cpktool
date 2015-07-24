#define XP_UNIX 1

#include "PluginObject.h"
#include <stdio.h>


#define PLUGIN_NAME		"CPK Plugin"
#define PLUGIN_DESCRIPTION	"CPK Cryptography Plugin 1.0 (Trial) "
#define PLUGIN_MIME		"application/x-cpk::CPK Cryptography Plugin from Peking University"

NPNetscapeFuncs* browser;


NPError NPP_New(NPMIMEType pluginType, NPP instance, uint16 mode, int16 argc,
	char* argn[], char* argv[], NPSavedData* saved)
{
	fprintf(stderr, "NPP_New()\n");
	if (browser->version >= 14)
		instance->pdata = browser->createobject(instance, getPluginClass());
	return NPERR_NO_ERROR;
}

NPError NPP_Destroy(NPP instance, NPSavedData** save)
{
	return NPERR_NO_ERROR;
}

NPError NPP_SetWindow(NPP instance, NPWindow* window)
{
	return NPERR_NO_ERROR;
}

NPError NPP_NewStream(NPP instance, NPMIMEType type, NPStream* stream,
	NPBool seekable, uint16* stype)
{
	*stype = NP_ASFILEONLY;
	return NPERR_NO_ERROR;
}

NPError NPP_DestroyStream(NPP instance, NPStream* stream, NPReason reason)
{
	return NPERR_NO_ERROR;
}

int32 NPP_WriteReady(NPP instance, NPStream* stream)
{
	return 0;
}

int32 NPP_Write(NPP instance, NPStream* stream, int32 offset, int32 len,
	void* buffer)
{
	return 0;
}

void NPP_StreamAsFile(NPP instance, NPStream* stream, const char* fname)
{
}

void NPP_Print(NPP instance, NPPrint* platformPrint)
{
}

int16 NPP_HandleEvent(NPP instance, void* event)
{
	return 0;
}

void NPP_URLNotify(NPP instance, const char* url, NPReason reason,
	void* notifyData)
{
}

NPError NPP_GetValue(NPP instance, NPPVariable variable, void *value)
{
	switch (variable) {
	case NPPVpluginNameString:
		fprintf(stderr, "NPP_GetValue() NameString\n");
		*((char **)value) = PLUGIN_NAME;
		return NPERR_NO_ERROR;

	case NPPVpluginDescriptionString:
		fprintf(stderr, "NPP_GetValue() Desc\n");
		*((char **)value) = PLUGIN_DESCRIPTION;
		return NPERR_NO_ERROR;

	case NPPVpluginNeedsXEmbed:
		fprintf(stderr, "NPP_GetValue() XEmbed\n");
		*((NPBool *)value) = TRUE;
		return NPERR_NO_ERROR;

	case NPPVpluginScriptableNPObject:
		fprintf(stderr, "NPP_GetValue() NPObject\n");
		if (instance->pdata == NULL) {
			fprintf(stderr, "        return NULL\n");
		}
		browser->retainobject((NPObject*)instance->pdata);
		*((void **)value) = instance->pdata;
		return NPERR_NO_ERROR;
	}
	return NPERR_GENERIC_ERROR;
}

NPError NPP_SetValue(NPP instance, NPNVariable variable, void *value)
{
	return NPERR_GENERIC_ERROR;
}

NPError NP_GetValue(void* future, NPPVariable variable, void *value)
{
	return NPP_GetValue(future, variable, value);
}

NPError NP_GetEntryPoints(NPPluginFuncs* pluginFuncs)
{
	fprintf(stderr, "NP_GetEntry()\n");
	pluginFuncs->version		= 11;
	pluginFuncs->size		= sizeof(pluginFuncs);
	pluginFuncs->newp		= NPP_New;
	pluginFuncs->destroy		= NPP_Destroy;
	pluginFuncs->setwindow		= NPP_SetWindow;
	pluginFuncs->newstream		= NPP_NewStream;
	pluginFuncs->destroystream	= NPP_DestroyStream;
	pluginFuncs->asfile		= NPP_StreamAsFile;
	pluginFuncs->writeready		= NPP_WriteReady;
	pluginFuncs->write		= (NPP_WriteProcPtr)NPP_Write;
	pluginFuncs->print		= NPP_Print;
	pluginFuncs->event		= NPP_HandleEvent;
	pluginFuncs->urlnotify		= NPP_URLNotify;
	pluginFuncs->getvalue		= NPP_GetValue;
	pluginFuncs->setvalue		= NPP_SetValue;
	
	return NPERR_NO_ERROR;
}

#if defined(XP_UNIX)
NPError NP_Initialize(NPNetscapeFuncs* browserFuncs, NPPluginFuncs* pluginFuncs)
{
	fprintf(stderr, "NP_Init()\n");
	browser = browserFuncs;
	NP_GetEntryPoints(pluginFuncs);
	return NPERR_NO_ERROR;
}
#else
NPError NP_Initialize(NPNetscapeFuncs* browserFuncs)
{
    browser = browserFuncs;
    return NPERR_NO_ERROR;
}
#endif

char *NP_GetMIMEDescription(void)
{
	fprintf(stderr, "NP_GetMIME()\n");
	return (char *)PLUGIN_MIME;
}

void NP_Shutdown(void)
{
}

#pragma export on
#if defined(XP_UNIX)
NPError NP_Initialize(NPNetscapeFuncs* browserFuncs, NPPluginFuncs* pluginFuncs);
#else
NPError NP_Initialize(NPNetscapeFuncs *browserFuncs);
#endif
NPError NP_GetEntryPoints(NPPluginFuncs *pluginFuncs);
void NP_Shutdown(void);
#pragma export off

