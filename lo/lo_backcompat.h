/*
 *  Copyright (C) 2004 Steve Harris
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  $Id$
 */

#ifndef LO_BACKCOMPAT_H
#define LO_BACKCOMPAT_H

#ifdef __cplusplus
extern "C" {
#endif

/* for back compatibility, deprecated, don't use */
typedef lo_address lo_target;

/* these calls have been deprecated and replaced with lo_address equivalents */
lo_target lo_target_new(const char *adddress, const char *port);
void lo_target_free(lo_target t);
int lo_target_errno(lo_target t);
const char *lo_target_errstr(lo_target t);

#ifdef __cplusplus
}
#endif

#endif
