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

#include "eap_aka_at_plugin.h"
#include "eap_aka_at_card.h"

#include <daemon.h>

typedef struct private_eap_aka_at_plugin_t private_eap_aka_at_plugin_t;

/**
 * Private data of an eap_aka_at_plugin_t object.
 */
struct private_eap_aka_at_plugin_t {

	/**
	 * Public eap_aka_at_plugin_t interface.
	 */
	eap_aka_at_plugin_t public;

	/**
	 * USIM card
	 */
	eap_aka_at_card_t *card;
};

METHOD(plugin_t, get_name, char*,
	private_eap_aka_at_plugin_t *this)
{
	return "eap-aka-at";
}

/**
 * Callback providing our card to register
 */
static simaka_card_t* get_card(private_eap_aka_at_plugin_t *this)
{
	return &this->card->card;
}

METHOD(plugin_t, get_features, int,
	private_eap_aka_at_plugin_t *this, plugin_feature_t *features[])
{
	static plugin_feature_t f[] = {
		PLUGIN_CALLBACK(simaka_manager_register, get_card),
			PLUGIN_PROVIDE(CUSTOM, "aka-card"),
				PLUGIN_DEPENDS(CUSTOM, "aka-manager"),
	};
	*features = f;
	return countof(f);
}

METHOD(plugin_t, destroy, void,
	private_eap_aka_at_plugin_t *this)
{
	this->card->destroy(this->card);
	free(this);
}

/**
 * See header
 */
plugin_t *eap_aka_at_plugin_create()
{
	private_eap_aka_at_plugin_t *this;

	INIT(this,
		.public = {
			.plugin = {
				.get_name = _get_name,
				.get_features = _get_features,
				.destroy = _destroy,
			},
		},
		.card = eap_aka_at_card_create(),
	);

	return &this->public.plugin;
}
