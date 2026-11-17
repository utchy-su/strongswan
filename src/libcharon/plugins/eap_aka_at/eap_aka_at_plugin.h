/*
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

/**
 * @defgroup eap_aka_at eap_aka_at
 * @ingroup cplugins
 *
 * @defgroup eap_aka_at_plugin eap_aka_at_plugin
 * @{ @ingroup eap_aka_at
 */

#ifndef EAP_AKA_AT_PLUGIN_H_
#define EAP_AKA_AT_PLUGIN_H_

#include <plugins/plugin.h>

typedef struct eap_aka_at_plugin_t eap_aka_at_plugin_t;

/**
 * Plugin to provide a USIM card via the AT command interface of a modem.
 */
struct eap_aka_at_plugin_t {

	/**
	 * implements plugin interface
	 */
	plugin_t plugin;
};

#endif /** EAP_AKA_AT_PLUGIN_H_ @}*/
