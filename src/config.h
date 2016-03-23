#ifndef _CONFIG_H_
#define _CONFIG_H_

#ifdef UNIX_IMPL
#include <stdlib.h>	/* Required to include random() */
#else
int random(void);
#endif

#endif
