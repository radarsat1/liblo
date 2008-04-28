#ifndef LO_INTERNAL_H
#define LO_INTERNAL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <lo/lo_osc_types.h>

/**
 * \brief Return the storage size, in bytes, of the given argument.
 */
size_t lo_arg_size(lo_type type, void *data);

/**
 * \brief Given a raw OSC message, return the message path.
 *
 * \param data      A pointer to the raw OSC message data.
 * \param size      The size of data in bytes (total buffer bytes).
 *
 * Returns the message path or NULL if an error occurs.
 * Do not free() the returned pointer.
 */
char *lo_get_path(void *data, ssize_t size);

/**
 * \brief Validate raw OSC string data. Where applicable, data should be
 * in network byte order.
 *
 * This function is used internally to parse and validate raw OSC data.
 *
 * Returns length of string or < 0 if data is invalid.
 *
 * \param data      A pointer to the data.
 * \param size      The size of data in bytes (total bytes remaining).
 */
ssize_t lo_validate_string(void *data, ssize_t size);

/**
 * \brief Validate raw OSC blob data. Where applicable, data should be
 * in network byte order.
 *
 * This function is used internally to parse and validate raw OSC data.
 *
 * Returns length of blob or < 0 if data is invalid.
 *
 * \param data      A pointer to the data.
 * \param size      The size of data in bytes (total bytes remaining).
 */
ssize_t lo_validate_blob(void *data, ssize_t size);

/**
 * \brief Validate raw OSC bundle data. Where applicable, data should be
 * in network byte order.
 *
 * This function is used internally to parse and validate raw OSC data.
 *
 * Returns length of bundle or < 0 if data is invalid.
 *
 * \param data      A pointer to the data.
 * \param size      The size of data in bytes (total bytes remaining).
 */
ssize_t lo_validate_bundle(void *data, ssize_t size);

/**
 * \brief Validate raw OSC argument data. Where applicable, data should be
 * in network byte order.
 *
 * This function is used internally to parse and validate raw OSC data.
 *
 * Returns length of argument data or < 0 if data is invalid.
 *
 * \param type      The OSC type of the data item (eg. LO_FLOAT).
 * \param data      A pointer to the data.
 * \param size      The size of data in bytes (total bytes remaining).
 */
ssize_t lo_validate_arg(lo_type type, void *data, ssize_t size);

/**
 * \brief Convert the specified argument to host byte order where necessary.
 *
 * \param type The OSC type of the data item (eg. LO_FLOAT).
 * \param data A pointer to the data item to be converted. It is changed
 * in-place.
 */
void lo_arg_host_endian(lo_type type, void *data);

/**
 * \brief Convert the specified argument to network byte order where necessary.
 *
 * \param type The OSC type of the data item (eg. LO_FLOAT).
 * \param data A pointer to the data item to be converted. It is changed
 * in-place.
 */
void lo_arg_network_endian(lo_type type, void *data);

#endif
