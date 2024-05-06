#ifndef TA_HEADER
#define TA_HEADER

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include "password_manager_ta.h"


void add_attr(size_t *attr_count, TEE_Attribute *attrs, uint32_t attr_id,
		    const void *buf, size_t len);




#endif