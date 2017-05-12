#ifndef _CONFIG_H_
#define _CONFIG_H_

#if defined(UNIX_IMPL) || defined(__APPLE__)
#include <stdlib.h>	/* Required to include random() */
#else
long int random(void);
#endif

#endif
