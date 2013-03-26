/*
 *  Copyright (C) 2004 Steve Harris
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2.1
 *  of the License, or (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  $Id$
 */

#ifndef LO_OSC_TYPES_H
#define LO_OSC_TYPES_H

/**
 * \file lo_osc_types.h A liblo header defining OSC-related types and
 * constants.
 */

#ifdef _MSC_VER
#ifndef UINTSDEFINED
#define UINTSDEFINED
#define int32_t __int32
#define int64_t __int64
#define uint32_t unsigned __int32
#define uint64_t unsigned __int64
#define uint8_t unsigned __int8
#endif
#else
#include <stdint.h>
#endif

/**
 * \addtogroup liblo
 * @{
 */

/**
 * \brief A structure to store OSC TimeTag values.
 */
typedef struct {
	/** The number of seconds since Jan 1st 1900 in the UTC timezone. */
	uint32_t sec;
	/** The fractions of a second offset from above, expressed as 1/2^32nds
         * of a second */
	uint32_t frac;
} lo_timetag;

/**
 * \brief An enumeration of the OSC types liblo can send and receive.
 *
 * The value of the enumeration is the typechar used to tag messages and to
 * specify arguments with lo_send().
 */
typedef enum {
/* basic OSC types */
	/** 32 bit signed integer. */
	LO_INT32 =     'i',
	/** 32 bit IEEE-754 float. */
	LO_FLOAT =     'f',
	/** Standard C, NULL terminated string. */
	LO_STRING =    's',
	/** OSC binary blob type. Accessed using the lo_blob_*() functions. */
	LO_BLOB =      'b',

/* extended OSC types */
	/** 64 bit signed integer. */
	LO_INT64 =     'h',
	/** OSC TimeTag type, represented by the lo_timetag structure. */
	LO_TIMETAG =   't',
	/** 64 bit IEEE-754 double. */
	LO_DOUBLE =    'd',
	/** Standard C, NULL terminated, string. Used in systems which
	  * distinguish strings and symbols. */
	LO_SYMBOL =    'S',
	/** Standard C, 8 bit, char variable. */
	LO_CHAR =      'c',
	/** A 4 byte MIDI packet. */
	LO_MIDI =      'm',
	/** Sybol representing the value True. */
	LO_TRUE =      'T',
	/** Sybol representing the value False. */
	LO_FALSE =     'F',
	/** Sybol representing the value Nil. */
	LO_NIL =       'N',
	/** Sybol representing the value Infinitum. */
	LO_INFINITUM = 'I'
} lo_type;


/**
 * \brief Union used to read values from incoming messages.
 *
 * Types can generally be read using argv[n]->t where n is the argument number
 * and t is the type character, with the exception of strings and symbols which
 * must be read with &argv[n]->t.
 */
typedef union {
	/** 32 bit signed integer. */
    int32_t    i;
	/** 32 bit signed integer. */
    int32_t    i32;
	/** 64 bit signed integer. */
    int64_t    h;
	/** 64 bit signed integer. */
    int64_t    i64;
	/** 32 bit IEEE-754 float. */
    float      f;
	/** 32 bit IEEE-754 float. */
    float      f32;
	/** 64 bit IEEE-754 double. */
    double     d;
	/** 64 bit IEEE-754 double. */
    double     f64;
	/** Standard C, NULL terminated string. */
    char       s;
	/** Standard C, NULL terminated, string. Used in systems which
	  * distinguish strings and symbols. */
    char       S;
	/** Standard C, 8 bit, char. */
    unsigned char c;
	/** A 4 byte MIDI packet. */
    uint8_t    m[4];
	/** OSC TimeTag value. */
    lo_timetag t;
} lo_arg;

/* Note: No struct literals in MSVC */
#ifdef _MSC_VER
#ifndef USE_ANSI_C
#define USE_ANSI_C
#endif
#endif

#ifdef DLL_EXPORT
#ifndef USE_ANSI_C
#define USE_ANSI_C
#endif
#endif

/** \brief A timetag constant representing "now". */
#ifdef USE_ANSI_C
lo_timetag lo_get_tt_immediate();
#define LO_TT_IMMEDIATE lo_get_tt_immediate()
#else // !USE_ANSI_C
#define LO_TT_IMMEDIATE ((lo_timetag){0U,1U})
#endif // USE_ANSI_C

/** \brief Bitflags for optional protocol features, set by
 *         lo_address_set_flags(). */
typedef enum {
    LO_SLIP=0x01,     /*!< SLIP decoding */
    LO_NODELAY=0x02,  /*!< Set the TCP_NODELAY socket option. */
} lo_proto_flags;

/** \brief Bitflags for optional server features, set by
 *         lo_server_set_flags(). */
typedef enum {
    LO_SERVER_NO_FLAG=0x00,              /*!< default value */
    LO_SERVER_DISABLE_COERCION=0x01 /*!< default value */
} lo_server_flags;

/** @} */

#endif
