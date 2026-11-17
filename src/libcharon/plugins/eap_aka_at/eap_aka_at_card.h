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
 * @defgroup eap_aka_at_card eap_aka_at_card
 * @{ @ingroup eap_aka_at
 */

#ifndef EAP_AKA_AT_CARD_H_
#define EAP_AKA_AT_CARD_H_

#include <simaka_card.h>

typedef struct eap_aka_at_card_t eap_aka_at_card_t;

/**
 * USIM card implementation using the AT command interface of a modem
 * (3GPP TS 27.007 generic UICC logical channel access, AT+CCHO/CGLA/CCHC).
 */
struct eap_aka_at_card_t {

	/**
	 * Implements simaka_card_t interface
	 */
	simaka_card_t card;

	/**
	 * Destroy a eap_aka_at_card_t.
	 */
	void (*destroy)(eap_aka_at_card_t *this);
};

/**
 * Create a eap_aka_at_card instance.
 */
eap_aka_at_card_t *eap_aka_at_card_create();

#endif /** EAP_AKA_AT_CARD_H_ @}*/
