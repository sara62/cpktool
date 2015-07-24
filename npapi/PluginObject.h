#ifndef HEADER_PLUGINOBJECT_H
#define HEADER_PLUGINOBJECT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "CPKObject.h"

typedef struct PluginObject {
	NPObject header;
	NPP npp;
	CPKObject *cpkObject;
} PluginObject;

NPClass *getPluginClass(void);

#ifdef __cplusplus
}
#endif
#endif
