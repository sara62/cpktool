#include "npapi/npapi.h"
#include "npapi/npruntime.h"
#include "npapi/npfunctions.h"

extern NPNetscapeFuncs* browser;

typedef struct CryptoObject {
    NPObject header;
} CryptoObject;

NPClass *getCryptoClass(void);

