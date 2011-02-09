#ifndef LO_INTERNAL_H
#define LO_INTERNAL_H

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <lo/lo_osc_types.h>

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

int lo_address_resolve(lo_address a);

/**
 * \internal \brief Look up a given interface by name or by IP and
 * store the found information in a lo_inaddr.  Usually either iface
 * or ip will be zero, but not both.
 *
 * \param t Location to store interface information.
 * \param fam Family, either AF_INET or AF_INET6.
 * \param iface The interface to look for by name.
 * \param ip The IP to find an interface for.
 */
int lo_inaddr_find_iface(lo_inaddr t, int fam,
                         const char *iface, const char *ip);

#endif
