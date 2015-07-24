#include "npapi/npapi.h"
#include "npapi/npruntime.h"
#include "npapi/npfunctions.h"

extern NPNetscapeFuncs* browser;

typedef struct CPKObject {
	NPObject header;
} CPKObject;

NPClass *getCPKClass(void);

