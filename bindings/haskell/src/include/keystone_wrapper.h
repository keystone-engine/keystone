#ifndef KEYSTONE_WRAPPER_H
#define KEYSTONE_WRAPPER_H

#include <keystone/keystone.h>

/*
 * Wrap Keystone's ks_close function and ignore the returned error code.
 */
void ks_close_wrapper(ks_engine *ks);

#endif
