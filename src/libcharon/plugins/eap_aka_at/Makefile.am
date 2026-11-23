AM_CPPFLAGS = \
	-I$(top_srcdir)/src/libstrongswan \
	-I$(top_srcdir)/src/libcharon \
	-I$(top_srcdir)/src/libsimaka

AM_CFLAGS = \
	$(PLUGIN_CFLAGS)

libstrongswan_eap_aka_at_la_LDFLAGS = -module -avoid-version
libstrongswan_eap_aka_at_la_LIBADD  =

if MONOLITHIC
noinst_LTLIBRARIES = libstrongswan-eap-aka-at.la
else
plugin_LTLIBRARIES = libstrongswan-eap-aka-at.la
libstrongswan_eap_aka_at_la_LIBADD += $(top_builddir)/src/libsimaka/libsimaka.la
endif

libstrongswan_eap_aka_at_la_SOURCES = \
	eap_aka_at_plugin.h eap_aka_at_plugin.c \
	eap_aka_at_card.h eap_aka_at_card.c
