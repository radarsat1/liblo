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

#include <stdarg.h>
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
 * \brief send a lo_message object to target targ from address of serv
 *
 * This is slightly more efficient than lo_send if you want to send a lot of
 * similar messages. The messages are constructed with the lo_message_new() and
 * lo_message_add*() functions.
 *
 * \param targ The address to send the message to
 * \param serv The server socket to send the message from
 *              (can be NULL to use new socket)
 * \param path The path to send the message to
 * \param msg  The bundle itself
 */
int lo_send_message_from(lo_address targ, lo_server serv, 
     const char *path, lo_message msg);

/**
 * \brief send a lo_bundle object to address targ
 *
 * Bundles are constructed with the
 * lo_bundle_new() and lo_bundle_add_message() functions.
 */
int lo_send_bundle(lo_address targ, lo_bundle b);

/**
 * \brief send a lo_bundle object to address targ from address of serv
 *
 * Bundles are constructed with the
 * lo_bundle_new() and lo_bundle_add_message() functions.
 *
 * \param targ The address to send the bundle to
 * \param serv The server socket to send the bundle from 
 *              (can be NULL to use new socket)
 * \param b    The bundle itself
 */
int lo_send_bundle_from(lo_address targ, lo_server serv, lo_bundle b);

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
 * \brief Append a number of arguments to a message.
 *
 * The data will be added in OSC byteorder (bigendian).
 *
 * \param m The message to be extended.
 * \param types The types of the data items in the message, types are defined in
 * lo_types_common.h
 * \param ... The data values to be transmitted. The types of the arguments
 * passed here must agree with the types specified in the type parameter.
 *
 * \return Less than 0 on failure, 0 on success.
 */
int lo_message_add(lo_message m, const char *types, ...);

/** \brief the real message_add function (don't call directly) */
int lo_message_add_internal(lo_message m,  const char *file, const int line,
                            const char *types, ...);

/**
 * \brief Append a varargs list to a message.
 *
 * The data will be added in OSC byteorder (bigendian).
 * IMPORTANT: args list must be terminated with LO_ARGS_END, or this call will
 * fail.  This is used to do simple error checking on the sizes of parameters
 * passed.
 *
 * \param m The message to be extended.
 * \param types The types of the data items in the message, types are defined in
 * lo_types_common.h
 * \param ap The va_list created by a C function declared with an
 * ellipsis (...) argument, and pre-initialised with
 * "va_start(ap)". The types of the arguments passed here must agree
 * with the types specified in the type parameter.
 *
 * \return Less than 0 on failure, 0 on success.
 */
int lo_message_add_varargs(lo_message m, const char *types, va_list ap);

/** \brief the real message_add_varargs function (don't call directly) */
int lo_message_add_varargs_internal(lo_message m, const char *types, va_list ap,
                                    const char *file, const int line);

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
void lo_message_add_string(lo_message m, const char *a);

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
void lo_message_add_symbol(lo_message m, const char *a);

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
 * \brief  Returns the source (lo_address) of an incoming message.
 *
 * Returns NULL if the message is outgoing. Do not free the returned address.
 */
lo_address lo_message_get_source(lo_message m);

/**
 * \brief  Return the length of a message in bytes.
 *
 * \param m The message to be sized
 * \param path The path the message will be sent to
 */
size_t lo_message_length(lo_message m, const char *path);

/**
 * \brief  Serialise the message object to an area of memory and return a
 * pointer to the serialised form.
 *
 * \param m The mesaage to be serialised
 * \param path The path the message will be sent to
 * \param to The address to serialise to, memory will be allocated if to is
 * NULL.
 * \param size If this pointer is non-NULL the size of the memory area
 * will be written here
 *
 * The returned form is suitable to be sent over a low level OSC transport,
 * having the correct endianess and bit-packed structure.
 */
void *lo_message_serialise(lo_message m, const char *path, void *to,
			   size_t *size);

/**
 * \brief  Return the hostname of a lo_address object
 *
 * Returned value most not be modified or free'd. Value will be a dotted quad,
 * colon'd IPV6 address, or resolvable name.
 */
const char *lo_address_get_hostname(lo_address a);

/**
 * \brief  Return the port/service name of a lo_address object
 *
 * Returned value most not be modified or free'd. Value will be a service name
 * or ASCII representation of the port number.
 */
const char *lo_address_get_port(lo_address a);

/**
 * \brief  Return the protocol of a lo_address object
 *
 * Returned value will be one of LO_UDP, LO_TCP or LO_UNIX.
 */
int lo_address_get_protocol(lo_address a);

/**
 * \brief  Return a URL representing an OSC address
 *
 * Returned value must be free'd.
 */
char *lo_address_get_url(lo_address a);

/**
 * \brief  Create a new bundle object.
 *
 * OSC Bundles ecapsulate one or more OSC messages and may include a timestamp
 * indicating when the bundle should be dispatched.
 *
 * \param tt The timestamp when the bundle should be handled by the receiver.
 *           Pass LO_TT_IMMEDIATE if you want the receiving server to dispatch
 *           the bundle as soon as it receives it.
 */
lo_bundle lo_bundle_new(lo_timetag tt);

/**
 * \brief  Adds an OSC message to an existing bundle.
 *
 * The message passsed is appended to the list of messages in the bundle to be
 * dispatched to 'path'.
 */
void lo_bundle_add_message(lo_bundle b, const char *path, lo_message m);

/**
 * \brief  Return the length of a bundle in bytes.
 *
 * Includes the marker and typetage length.
 *
 * \param b The bundle to be sized
 */
size_t lo_bundle_length(lo_bundle b);

/**
 * \brief  Serialise the bundle object to an area of memory and return a
 * pointer to the serialised form.
 *
 * \param b The bundle to be serialised
 * \param to The address to serialise to, memory will be allocated if to is
 * NULL.
 * \param size If this pointer is non-NULL the size of the memory area
 * will be written here
 *
 * The returned form is suitable to be sent over a low level OSC transport,
 * having the correct endianess and bit-packed structure.
 */
void *lo_bundle_serialise(lo_bundle b, void *to, size_t *size);

/**
 * \brief  Frees the memory taken by a bundle object.
*/
void lo_bundle_free(lo_bundle b);

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
 * \param proto The protocol to use, should be one of LO_UDP, LO_TCP or LO_UNIX.
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
 * \param h The method handler callback function that will be called if a
 * matching message is received
 * \param user_data A value that will be passed to the callback function, h,
 * when its invoked matching from this method.
 */
lo_method lo_server_add_method(lo_server s, const char *path,
                               const char *typespec, lo_method_handler h,
                               void *user_data);

/**
 * \brief Delete an OSC method from the specifed server.
 *
 * \param s The server the method is to be removed from.
 * \param path The OSC path of the method to delete. If NULL is passed the
 * method will match the generic handler.
 * \param typespec The typespec the method accepts.
 */
void lo_server_del_method(lo_server s, const char *path,
                               const char *typespec);

/**
 * \brief Return the file descriptor of the server socket.
 *
 * If the server protocol supports exposing the server's underlying
 * receive mechanism for monitoring with select() or poll(), this function
 * returns the file descriptor needed, otherwise, it returns -1.
 *
 * WARNING: when using this function beware that not all OSC packets that are
 * received are dispatched immediatly. lo_server_events_pending() and
 * lo_server_next_event_delay() can be used to tell if there are pending
 * events and how long before you should attempt to receive them.
 */
int lo_server_get_socket_fd(lo_server s);

/**
 * \brief Return the port number that the server has bound to.
 *
 * Useful when NULL is passed for the port number and you wish to know how to
 * address the server.
 */
int lo_server_get_port(lo_server s);

/**
 * \brief  Return the protocol that the server is using.
 *
 * Returned value will be one of LO_UDP, LO_TCP or LO_UNIX.
 */
int lo_server_get_protocol(lo_server s);

/**
 * \brief Return an OSC URL that can be used to contact the server.
 *
 * The return value should  bee free()'d when it is no longer needed.
 */
char *lo_server_get_url(lo_server s);

/** 
 * \brief Return true if there are scheduled events (eg. from bundles) 
 * waiting to be dispatched by the server
 */
int lo_server_events_pending(lo_server s);

/** 
 * \brief Return the time in seconds until the next scheduled event.
 *
 * If the delay is greater than 100 seconds then it will return 100.0.
 */
double lo_server_next_event_delay(lo_server s);

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

/**
 * \brief Test a string against an OSC pattern glob
 *
 * \param str The tring to test
 * \param p   The pattern to test against
 */
int lo_pattern_match(const char *str, const char *p);

/** \brief the real send function (don't call directly) */
int lo_send_internal(lo_address t, const char *file, const int line,
     const char *path, const char *types, ...);
/** \brief the real send_timestamped function (don't call directly) */
int lo_send_timestamped_internal(lo_address t, const char *file, const int line,
     lo_timetag ts, const char *path, const char *types, ...);
/** \brief the real lo_send_from function (don't call directly) */
int lo_send_from_internal(lo_address targ, lo_server from, const char *file, 
     const int line, const lo_timetag ts, 
     const char *path, const char *types, ...);


/** \brief Find the time difference between two timetags
 *
 * Returns a - b in seconds.
 */
double lo_timetag_diff(lo_timetag a, lo_timetag b);

/** \brief Return a timetag for the current time
 *
 * On exit the timetag pointed to by t is filled with the OSC represenation
 * of this instant in time.
 */
void lo_timetag_now(lo_timetag *t);

/** @} */

/* prettyprinters */

/**
 * \defgroup pp Prettyprinting functions
 *
 * These functions all print an ASCII representation of thier argument to
 * stdout. Useful for debugging.
 * @{
 */
void lo_bundle_pp(lo_bundle b);
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
