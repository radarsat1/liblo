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

#ifndef LO_LOWLEVEL_H
#define LO_LOWLEVEL_H

#include "lo/lo_osc_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "lo/lo_types.h"
#include "lo/lo_errors.h"

/**
 * \defgroup liblolowlevel Low-level OSC API
 *
 * Use these functions if you require more precices control over OSC message
 * contruction or handling that what is provided in the high-level functions
 * described in liblo.
 * @{
 */

/**
 * \brief Type used to represent numerical values in conversions between OSC
 * types.
 */
typedef long double lo_hires;

/**
 * \brief send a lo_message object to target targ
 *
 * This is slightly more efficient than lo_send if you want to send a lot of
 * similar messages. The messages are constructed with the lo_message_new() and
 * lo_message_add*() functions.
 */
int lo_send_message(lo_address targ, const char *path, lo_message msg);

/**
 * \brief Create a new lo_message object
 */
lo_message lo_message_new();

/**
 * \brief Free memory allocated by lo_message_new and any subsequent
 * lo_message_add*() calls.
 */
void lo_message_free(lo_message m);

/**
 * \brief Append a data item and typechar of the specified type to a message.
 *
 * The data will be added in OSC byteorder (bigendian).
 *
 * \param m The message to be extended.
 * \param a The data item.
 */
void lo_message_add_int32(lo_message m, int32_t a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_float(lo_message m, float a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_string(lo_message m, char *a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_blob(lo_message m, lo_blob a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_int64(lo_message m, int64_t a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_timetag(lo_message m, lo_timetag a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_double(lo_message m, double a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_symbol(lo_message m, char *a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_char(lo_message m, char a);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_midi(lo_message m, uint8_t a[4]);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_true(lo_message m);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_false(lo_message m);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_nil(lo_message m);

/**
 * \brief  Append a data item and typechar of the specified type to a message.
 * See lo_message_add_int32() for details.
 */
void lo_message_add_infinitum(lo_message m);

/**
 * \brief return true if the type specified has a numerical value, such as
 * LO_INT32, LO_FLOAT etc.
 *
 * \param a The type to be tested.
 */
int lo_is_numerical_type(lo_type a);

/**
 * \brief return true if the type specified has a textual value, such as
 * LO_STRING or LO_SYMBOL.
 *
 * \param a The type to be tested.
 */
int lo_is_string_type(lo_type a);

/**
 * \brief attempt to convert one OSC type to another.
 *
 * Numerical types (eg LO_INT32, LO_FLOAT etc.) may be converted to other
 * numerical types and string types (LO_STRING and LO_SYMBOL) may be converted
 * to the other type. This is done automatically if a received message matches
 * the path, but not the exact types, and is coercible (ie. all numerical
 * types in numerical positions).
 *
 * On failure no translation occurs and false is returned.
 *
 * \param type_to   The type of the destination variable.
 * \param to        A pointer to the destination variable.
 * \param type_from The type of the source variable.
 * \param from      A pointer to the source variable.
 */
int lo_coerce(lo_type type_to, lo_arg *to, lo_type type_from, lo_arg *from);

/**
 * \brief return the numerical value of the given argument with the
 * maximum native system precision.
 */
lo_hires lo_hires_val(lo_type type, lo_arg *p);

/**
 * \brief Return the storage size, in bytes, of the given argument.
 */
size_t lo_arg_size(lo_type type, void *data);

/**
 * \brief Convert the speficed argument to host endianness where neccesary.
 *
 * \param type The OSC type of the data item (eg. LO_FLOAT).
 * \param data A pointer to the data item to be converted. It is change
 * in-place.
 */
void lo_arg_host_endian(lo_type type, void *data);

/**
 * \brief Create a new server instance.
 *
 * lo_servers block until they receive OSC messages. if you want non-blocking
 * behaviour see the lo_server_thread_* functions.
 *
 * \param port If NULL is passed then an unused UDP port will be chosen by the
 * system, its number may be retreived with lo_server_thread_get_port()
 * so it can be passed to clients. Otherwise a decimal port number, service
 * name or UNIX domain socket path may be passed.
 * \param err_h An error callback function that will be called if there is an
 * error in messge reception or server creation. Pass NULL if you do not want
 * error handling.
 */
lo_server lo_server_new(const char *port, lo_err_handler err_h);

/**
 * \brief Create a new server instance, specifying protocol.
 *
 * lo_servers block until they receive OSC messages. if you want non-blocking
 * behaviour see the lo_server_thread_* functions.
 *
 * \param port If using UDP then NULL may be passed to find an unused port.
 * Otherwise a decimal port number orservice name or may be passed.
 * If using UNIX domain sockets then a socket path should be passed here.
 * \param proto The protocol to use, should be one of LO_UDP, or LO_UNIX.
 * \param err_h An error callback function that will be called if there is an
 * error in messge reception or server creation. Pass NULL if you do not want
 * error handling.
 */
lo_server lo_server_new_with_proto(const char *port, int proto,
                                   lo_err_handler err_h);

/**
 * \brief Free up memory used by the lo_server object
 */
void lo_server_free(lo_server s);

/**
 * \brief Look for an OSC message waiting to be received
 *
 * \param s The server to wait for connections on.
 * \param timeout A timeout in milliseconds to wait for the incoming packet.
 * a value of 0 will return immediatly.
 *
 * The return value is the number of bytes in the received message or 0 is
 * there is no message. The message will be dispatched to a matching method
 * if one is found.
 */
int lo_server_recv_noblock(lo_server s, int timeout);

/**
 * \brief Block, waiting for an OSC message to be received
 *
 * The return value is the number of bytes in the received message. The message
 * will be dispatched to a matching method if one is found.
 */
int lo_server_recv(lo_server s);

/**
 * \brief Add an OSC method to the specifed server.
 *
 * \param s The server the method is to be added to.
 * \param path The OSC path to register the method to. If NULL is passed the
 * method will match all paths.
 * \param typespec The typespec the method accepts. Incoming messages with
 * similar typespecs (e.g. ones with numerical types in the same position) will
 * be coerced to the typespec given here.
 * \param h The method handler callback function that will be called it a
 * matching message is received
 * \param user_data A value that will be passed to the callback function, h,
 * when its invoked matching from this method.
 */
lo_method lo_server_add_method(lo_server s, const char *path,
                               const char *typespec, lo_method_handler h,
                               void *user_data);

/**
 * \brief Return the port number that the server has bound to.
 *
 * Useful when NULL is passed for the port number and you wish to know how to
 * address the server.
 */
int lo_server_get_port(lo_server s);

/**
 * \brief Return an OSC URL that can be used to contact the server.
 *
 * The return value should  bee free()'d when it is no longer needed.
 */
char *lo_server_get_url(lo_server s);

/**
 * \brief Return the protocol portion of an OSC URL, eg. udp, tcp.
 *
 * This library uses OSC URLs of the form: osc.prot://hostname:port/path if the
 * prot part is missing, UDP is assumed.
 *
 * The return value should  bee free()'d when it is no longer needed.
 */
char *lo_url_get_protocol(const char *url);

/**
 * \brief Return the hostname portion of an OSC URL.
 *
 * The return value should  bee free()'d when it is no longer needed.
 */
char *lo_url_get_hostname(const char *url);

/**
 * \brief Return the port portion of an OSC URL.
 *
 * The return value should  bee free()'d when it is no longer needed.
 */
char *lo_url_get_port(const char *url);

/**
 * \brief Return the path portion of an OSC URL.
 *
 * The return value should  bee free()'d when it is no longer needed.
 */
char *lo_url_get_path(const char *url);

/* utility functions */

/**
 * \brief A function to calculate the amount of OSC message space required by a
 * C char *.
 *
 * Returns the storage size in bytes, will always be a multiple of four.
 */
int lo_strsize(const char *s);

/**
 * \brief A function to calculate the amount of OSC message space required by a
 * lo_blob object.
 *
 * Returns the storage size in bytes, will always be a multiple of four.
 */
uint32_t lo_blobsize(lo_blob b);

/** \brief the real send function (don't call directly) */
int lo_send_internal(lo_address t, const char *file, const int line,
     const char *path, const char *types, ...);

/** @} */

/* prettyprinters */

/**
 * \defgroup pp Prettyprinting functions
 *
 * These functions all print an ASCII representation of thier argument to
 * stdout. Useful for debugging.
 * @{
 */
void lo_message_pp(lo_message m);
void lo_arg_pp(lo_type type, void *data);
void lo_server_pp(lo_server s);
void lo_method_pp(lo_method m);
void lo_method_pp_prefix(lo_method m, const char *p);
void lo_server_thread_pp(lo_server_thread st);
/** @} */

#ifdef __cplusplus
}
#endif

#endif
