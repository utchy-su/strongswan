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

#include "eap_aka_at_card.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/ioctl.h>

#include <library.h>
#include <utils/debug.h>
#include <threading/mutex.h>

/**
 * Default serial device providing the modem's AT command interface.
 */
#define AT_DEFAULT_DEVICE "/dev/ttyUSB2"

/**
 * Default timeout for a single AT command, in milliseconds.
 */
#define AT_DEFAULT_TIMEOUT 5000

/**
 * Maximum length of a single line received from the modem.
 */
#define AT_LINE_MAX 1024

/**
 * Maximum length of an APDU (command or response) we handle.
 */
#define APDU_MAX 261

/**
 * Highest logical channel we try to recover if the modem ran out of them.
 */
#define AT_RECOVER_CHANNELS 3

/**
 * Maximum length for an IMSI.
 */
#define SIM_IMSI_MAX_LEN 15

/**
 * Default USIM RID used as fallback if EF.DIR parsing fails.
 */
static const u_char default_usim_rid[] = { 0xA0, 0x00, 0x00, 0x00, 0x87 };

typedef struct private_eap_aka_at_card_t private_eap_aka_at_card_t;

/**
 * Private data of an eap_aka_at_card_t object.
 */
struct private_eap_aka_at_card_t {

	/**
	 * Public eap_aka_at_card_t interface.
	 */
	eap_aka_at_card_t public;

	/**
	 * Serializes access to the modem.
	 */
	mutex_t *mutex;

	/**
	 * Last identity for which AUTS is pending
	 */
	identification_t *pending_id;

	/**
	 * Last RAND for which AUTS is pending
	 */
	char pending_rand[AKA_RAND_LEN];

	/**
	 * AUTS to return via resync callback
	 */
	char pending_auts[AKA_AUTS_LEN];

	/**
	 * Whether pending AUTS information is valid
	 */
	bool pending_auts_valid;
};

/**
 * Milliseconds on the monotonic clock.
 */
static int64_t now_ms()
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/**
 * Open and configure the serial device of the modem.
 */
static int at_open(char *device)
{
	struct termios tio;
	int fd;

	fd = open(device, O_RDWR | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
	if (fd < 0)
	{
		DBG1(DBG_IKE, "opening AT device %s failed: %s", device,
			 strerror(errno));
		return -1;
	}
	if (ioctl(fd, TIOCEXCL) < 0)
	{
		DBG2(DBG_IKE, "unable to get exclusive access to %s: %s", device,
			 strerror(errno));
	}
	if (tcgetattr(fd, &tio) == 0)
	{
		cfmakeraw(&tio);
		cfsetispeed(&tio, B115200);
		cfsetospeed(&tio, B115200);
		tio.c_cflag |= CLOCAL | CREAD;
		tio.c_cflag &= ~CRTSCTS;
		tio.c_cc[VMIN] = 0;
		tio.c_cc[VTIME] = 0;
		if (tcsetattr(fd, TCSANOW, &tio) < 0)
		{
			DBG1(DBG_IKE, "configuring AT device %s failed: %s", device,
				 strerror(errno));
		}
	}
	tcflush(fd, TCIOFLUSH);
	return fd;
}

/**
 * Close the serial device.
 */
static void at_close(int fd)
{
	ioctl(fd, TIOCNXCL);
	close(fd);
}

/**
 * Write a complete buffer to the modem.
 */
static bool at_write(int fd, char *buf, size_t len, int64_t deadline)
{
	struct pollfd pfd = { .fd = fd, .events = POLLOUT };
	ssize_t written;
	int64_t left;

	while (len)
	{
		written = write(fd, buf, len);
		if (written > 0)
		{
			buf += written;
			len -= written;
			continue;
		}
		if (written < 0 && errno != EAGAIN && errno != EINTR)
		{
			DBG1(DBG_IKE, "writing AT command failed: %s", strerror(errno));
			return FALSE;
		}
		left = deadline - now_ms();
		if (left <= 0 || poll(&pfd, 1, left) < 0)
		{
			DBG1(DBG_IKE, "writing AT command timed out");
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Send an AT command and wait for its final result code.
 *
 * Information responses starting with the given prefix are returned in out,
 * with the prefix and leading whitespace removed. If no such line is seen,
 * a response consisting of a bare number (e.g. the IMSI) is returned instead.
 * Anything else (echo, unsolicited result codes) is ignored.
 */
static bool at_command(int fd, u_int timeout, char *prefix, char *out,
					   size_t out_len, char *fmt, ...)
{
	char cmd[AT_LINE_MAX], line[AT_LINE_MAX], c;
	struct pollfd pfd = { .fd = fd, .events = POLLIN };
	bool prefixed = FALSE;
	int64_t deadline, left;
	size_t line_len = 0;
	va_list args;
	ssize_t got;
	int len;

	va_start(args, fmt);
	len = vsnprintf(cmd, sizeof(cmd) - 1, fmt, args);
	va_end(args);
	if (len < 0 || len >= sizeof(cmd) - 1)
	{
		return FALSE;
	}
	if (out && out_len)
	{
		out[0] = '\0';
	}
	DBG3(DBG_IKE, "AT => %s", cmd);
	cmd[len++] = '\r';

	deadline = now_ms() + timeout;
	if (!at_write(fd, cmd, len, deadline))
	{
		return FALSE;
	}
	while (TRUE)
	{
		got = read(fd, &c, 1);
		if (got < 0 && errno != EAGAIN && errno != EINTR)
		{
			DBG1(DBG_IKE, "reading AT response failed: %s", strerror(errno));
			return FALSE;
		}
		if (got <= 0)
		{
			left = deadline - now_ms();
			if (left <= 0 || poll(&pfd, 1, left) <= 0)
			{
				DBG1(DBG_IKE, "AT command timed out after %ums", timeout);
				return FALSE;
			}
			continue;
		}
		if (c != '\r' && c != '\n')
		{
			if (line_len < sizeof(line) - 1)
			{
				line[line_len++] = c;
			}
			continue;
		}
		if (!line_len)
		{
			continue;
		}
		line[line_len] = '\0';
		line_len = 0;
		DBG3(DBG_IKE, "AT <= %s", line);

		if (streq(line, "OK"))
		{
			return TRUE;
		}
		if (streq(line, "ERROR") || strpfx(line, "+CME ERROR") ||
			strpfx(line, "+CMS ERROR"))
		{
			DBG2(DBG_IKE, "AT command failed: %s", line);
			return FALSE;
		}
		if (!out || !out_len)
		{
			continue;
		}
		if (prefix && strpfx(line, prefix))
		{
			char *pos = line + strlen(prefix);

			while (*pos == ' ')
			{
				pos++;
			}
			snprintf(out, out_len, "%s", pos);
			prefixed = TRUE;
		}
		else if (!prefixed && isdigit(line[0]))
		{
			snprintf(out, out_len, "%s", line);
		}
	}
}

/**
 * Extract the hex encoded data between the last pair of double quotes.
 */
static bool parse_quoted_hex(char *str, u_char *buf, size_t *len)
{
	char *start, *end;
	chunk_t hex;

	end = strrchr(str, '"');
	if (!end)
	{
		return FALSE;
	}
	*end = '\0';
	start = strrchr(str, '"');
	if (!start)
	{
		return FALSE;
	}
	start++;
	hex = chunk_from_str(start);
	if (hex.len % 2 || hex.len / 2 > *len)
	{
		return FALSE;
	}
	for (end = start; *end; end++)
	{
		if (!isxdigit(*end))
		{
			return FALSE;
		}
	}
	*len = chunk_from_hex(hex, buf).len;
	return TRUE;
}

/**
 * CLA byte for an interindustry command on the given logical channel.
 */
static u_char channel_cla(int channel)
{
	if (channel < 4)
	{
		return channel;
	}
	return 0x40 | (channel - 4);
}

/**
 * Exchange an APDU with the UICC on a logical channel using AT+CGLA.
 */
static bool at_apdu(int fd, u_int timeout, int channel, u_char *apdu,
					size_t apdu_len, u_char *resp, size_t *resp_len)
{
	char hex[2 * APDU_MAX + 1], line[AT_LINE_MAX];

	if (apdu_len > APDU_MAX)
	{
		return FALSE;
	}
	chunk_to_hex(chunk_create(apdu, apdu_len), hex, TRUE);
	if (!at_command(fd, timeout, "+CGLA:", line, sizeof(line),
					"AT+CGLA=%d,%zu,\"%s\"", channel, apdu_len * 2, hex))
	{
		DBG1(DBG_IKE, "AT+CGLA failed");
		return FALSE;
	}
	if (!parse_quoted_hex(line, resp, resp_len) || *resp_len < 2)
	{
		DBG1(DBG_IKE, "invalid AT+CGLA response");
		return FALSE;
	}
	return TRUE;
}

/**
 * Read the IMSI of the SIM.
 */
static bool at_get_imsi(int fd, u_int timeout, char imsi[SIM_IMSI_MAX_LEN + 1])
{
	char line[AT_LINE_MAX];
	size_t len, i;

	if (!at_command(fd, timeout, "+CIMI:", line, sizeof(line), "AT+CIMI"))
	{
		DBG1(DBG_IKE, "reading IMSI via AT+CIMI failed");
		return FALSE;
	}
	len = strlen(line);
	if (len < 6 || len > SIM_IMSI_MAX_LEN)
	{
		return FALSE;
	}
	for (i = 0; i < len; i++)
	{
		if (!isdigit(line[i]))
		{
			return FALSE;
		}
	}
	memcpy(imsi, line, len + 1);
	return TRUE;
}

/**
 * Read the USIM AID from EF.DIR using AT+CRSM. Returns the AID length or -1.
 */
static int at_get_usim_aid(int fd, u_int timeout, u_char *aid, size_t aid_max)
{
	char line[AT_LINE_MAX];
	u_char record[255];
	int rec;

	for (rec = 1; rec < 10; rec++)
	{
		size_t rec_len = sizeof(record), aid_len;

		/* READ RECORD (178) on EF.DIR (0x2F00), absolute mode */
		if (!at_command(fd, timeout, "+CRSM:", line, sizeof(line),
						"AT+CRSM=178,12032,%d,4,0", rec))
		{
			break;
		}
		if (atoi(line) != 0x90 && atoi(line) != 0x91)
		{
			break;
		}
		if (!parse_quoted_hex(line, record, &rec_len))
		{
			continue;
		}
		if (rec_len < 11 || record[0] != 0x61 || record[2] != 0x4F)
		{
			continue;
		}
		aid_len = record[3];
		if (aid_len < 7 || aid_len > 16 || 4 + aid_len > rec_len ||
			aid_len > aid_max)
		{
			continue;
		}
		/* application code 0x1002 indicates the 3G USIM application */
		if (memeq(record + 4, default_usim_rid, sizeof(default_usim_rid)) &&
			record[9] == 0x10 && record[10] == 0x02)
		{
			memcpy(aid, record + 4, aid_len);
			return aid_len;
		}
	}
	return -1;
}

/**
 * Open a logical channel to the application with the given AID.
 */
static int at_open_channel(int fd, u_int timeout, u_char *aid, size_t aid_len)
{
	char hex[2 * 16 + 1], line[AT_LINE_MAX];
	int attempt, channel;

	if (aid_len > 16)
	{
		return -1;
	}
	chunk_to_hex(chunk_create(aid, aid_len), hex, TRUE);

	for (attempt = 0; attempt < 2; attempt++)
	{
		if (at_command(fd, timeout, "+CCHO:", line, sizeof(line),
					   "AT+CCHO=\"%s\"", hex))
		{
			channel = atoi(line);
			if (channel > 0 && channel < 20)
			{
				return channel;
			}
			DBG1(DBG_IKE, "invalid AT+CCHO response: %s", line);
			return -1;
		}
		if (attempt == 0)
		{
			/* channels might have leaked if we got killed while using one */
			DBG1(DBG_IKE, "AT+CCHO failed, closing stale logical channels");
			for (channel = 1; channel <= AT_RECOVER_CHANNELS; channel++)
			{
				at_command(fd, timeout, NULL, NULL, 0, "AT+CCHC=%d", channel);
			}
		}
	}
	return -1;
}

/**
 * Run UMTS AKA authentication with RAND/AUTN on a logical channel.
 */
static status_t run_umts_auth(int fd, u_int timeout, int channel,
							  char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
							  char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
							  char res[AKA_RES_MAX], int *res_len,
							  char auts[AKA_AUTS_LEN])
{
	u_char cmd[5 + 1 + AKA_RAND_LEN + 1 + AKA_AUTN_LEN] = {
		channel_cla(channel), 0x88, 0x00, 0x81, 0x22,
	};
	u_char resp[APDU_MAX], *payload, *pos, *end;
	size_t resp_len = sizeof(resp), payload_len;

	cmd[5] = AKA_RAND_LEN;
	memcpy(cmd + 6, rand, AKA_RAND_LEN);
	cmd[6 + AKA_RAND_LEN] = AKA_AUTN_LEN;
	memcpy(cmd + 6 + AKA_RAND_LEN + 1, autn, AKA_AUTN_LEN);

	if (!at_apdu(fd, timeout, channel, cmd, sizeof(cmd), resp, &resp_len))
	{
		return FAILED;
	}
	if (resp_len == 2 && resp[0] == 0x98 && resp[1] == 0x62)
	{
		DBG1(DBG_IKE, "USIM UMTS auth failed (MAC != XMAC)");
		return FAILED;
	}
	if (resp_len == 2 &&
		(resp[0] == 0x61 || resp[0] == 0x6C || resp[0] == 0x9F))
	{
		/* response data has to be fetched with GET RESPONSE */
		u_char get[] = { channel_cla(channel), 0xC0, 0x00, 0x00, resp[1] };

		resp_len = sizeof(resp);
		if (!at_apdu(fd, timeout, channel, get, sizeof(get), resp, &resp_len))
		{
			return FAILED;
		}
	}
	if (resp_len <= 2 || resp[resp_len - 2] != 0x90 ||
		resp[resp_len - 1] != 0x00)
	{
		DBG1(DBG_IKE, "unexpected UMTS auth status %02x %02x",
			 resp[resp_len - 2], resp[resp_len - 1]);
		return FAILED;
	}
	payload = resp;
	payload_len = resp_len - 2;

	if (payload_len >= 2 + AKA_AUTS_LEN && payload[0] == 0xDC &&
		payload[1] == AKA_AUTS_LEN)
	{
		memcpy(auts, payload + 2, AKA_AUTS_LEN);
		DBG2(DBG_IKE, "USIM reported synchronization failure");
		return INVALID_STATE;
	}
	if (payload_len < 6 + AKA_IK_LEN + AKA_CK_LEN || payload[0] != 0xDB)
	{
		DBG1(DBG_IKE, "unrecognized UMTS auth payload");
		return FAILED;
	}

	pos = payload + 1;
	end = payload + payload_len;

	if (pos >= end || pos[0] > AKA_RES_MAX || pos[0] > end - pos - 1)
	{
		DBG1(DBG_IKE, "invalid RES in UMTS auth payload");
		return FAILED;
	}
	*res_len = *pos++;
	memcpy(res, pos, *res_len);
	pos += *res_len;

	if (pos >= end || pos[0] != AKA_CK_LEN || AKA_CK_LEN > end - pos - 1)
	{
		DBG1(DBG_IKE, "invalid CK in UMTS auth payload");
		return FAILED;
	}
	pos++;
	memcpy(ck, pos, AKA_CK_LEN);
	pos += AKA_CK_LEN;

	if (pos >= end || pos[0] != AKA_IK_LEN || AKA_IK_LEN > end - pos - 1)
	{
		DBG1(DBG_IKE, "invalid IK in UMTS auth payload");
		return FAILED;
	}
	pos++;
	memcpy(ik, pos, AKA_IK_LEN);

	memwipe(resp, sizeof(resp));
	return SUCCESS;
}

/**
 * Clear pending AUTS state.
 */
static void clear_pending_auts(private_eap_aka_at_card_t *this)
{
	DESTROY_IF(this->pending_id);
	this->pending_id = NULL;
	this->pending_auts_valid = FALSE;
}

/**
 * Store pending AUTS state for later resync callback.
 */
static void store_pending_auts(private_eap_aka_at_card_t *this,
							   identification_t *id, char rand[AKA_RAND_LEN],
							   char auts[AKA_AUTS_LEN])
{
	clear_pending_auts(this);
	this->pending_id = id->clone(id);
	memcpy(this->pending_rand, rand, AKA_RAND_LEN);
	memcpy(this->pending_auts, auts, AKA_AUTS_LEN);
	this->pending_auts_valid = TRUE;
}

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_aka_at_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	char full_nai[128], imsi[SIM_IMSI_MAX_LEN + 1], auts[AKA_AUTS_LEN];
	char *device, *aid_str;
	u_char aid[16];
	status_t status = FAILED;
	int fd, channel, aid_len = -1;
	u_int timeout;

	device = lib->settings->get_str(lib->settings,
							"%s.plugins.eap-aka-at.device", AT_DEFAULT_DEVICE,
							lib->ns);
	timeout = lib->settings->get_int(lib->settings,
							"%s.plugins.eap-aka-at.timeout", AT_DEFAULT_TIMEOUT,
							lib->ns);
	aid_str = lib->settings->get_str(lib->settings,
							"%s.plugins.eap-aka-at.aid", NULL, lib->ns);

	snprintf(full_nai, sizeof(full_nai), "%Y", id);

	this->mutex->lock(this->mutex);
	clear_pending_auts(this);

	DBG2(DBG_IKE, "looking for quintuplet via %s: %Y rand %b autn %b",
		 device, id, rand, AKA_RAND_LEN, autn, AKA_AUTN_LEN);

	fd = at_open(device);
	if (fd < 0)
	{
		this->mutex->unlock(this->mutex);
		return FAILED;
	}
	/* an empty command terminates anything pending, then disable echo */
	at_command(fd, 500, NULL, NULL, 0, "AT");
	if (!at_command(fd, timeout, NULL, NULL, 0, "ATE0"))
	{
		DBG1(DBG_IKE, "modem on %s does not respond to AT commands", device);
		goto done;
	}

	/* the IMSI could be post/prefixed in the full NAI, so just make sure
	 * it's in there */
	if (!at_get_imsi(fd, timeout, imsi))
	{
		goto done;
	}
	if (!strstr(full_nai, imsi))
	{
		DBG1(DBG_IKE, "SIM on %s does not match identity %Y", device, id);
		goto done;
	}

	if (aid_str)
	{
		chunk_t hex = chunk_from_str(aid_str);

		if (hex.len && hex.len % 2 == 0 && hex.len / 2 <= sizeof(aid))
		{
			aid_len = chunk_from_hex(hex, aid).len;
		}
		else
		{
			DBG1(DBG_IKE, "ignoring invalid USIM AID '%s'", aid_str);
		}
	}
	if (aid_len <= 0)
	{
		aid_len = at_get_usim_aid(fd, timeout, aid, sizeof(aid));
	}
	if (aid_len <= 0)
	{
		DBG1(DBG_IKE, "USIM AID not found in EF.DIR, using default RID");
		memcpy(aid, default_usim_rid, sizeof(default_usim_rid));
		aid_len = sizeof(default_usim_rid);
	}

	channel = at_open_channel(fd, timeout, aid, aid_len);
	if (channel < 0)
	{
		DBG1(DBG_IKE, "opening logical channel to USIM %b failed",
			 aid, (u_int)aid_len);
		goto done;
	}
	status = run_umts_auth(fd, timeout, channel, rand, autn, ck, ik, res,
						   res_len, auts);
	if (!at_command(fd, timeout, NULL, NULL, 0, "AT+CCHC=%d", channel))
	{
		DBG1(DBG_IKE, "closing logical channel %d failed", channel);
	}
	if (status == INVALID_STATE)
	{
		store_pending_auts(this, id, rand, auts);
	}

done:
	at_close(fd);
	this->mutex->unlock(this->mutex);
	return status;
}

METHOD(simaka_card_t, resync, bool,
	private_eap_aka_at_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	bool found = FALSE;

	this->mutex->lock(this->mutex);
	if (this->pending_auts_valid && this->pending_id &&
		this->pending_id->equals(this->pending_id, id) &&
		memeq(rand, this->pending_rand, AKA_RAND_LEN))
	{
		memcpy(auts, this->pending_auts, AKA_AUTS_LEN);
		clear_pending_auts(this);
		found = TRUE;
	}
	this->mutex->unlock(this->mutex);
	return found;
}

METHOD(eap_aka_at_card_t, destroy, void,
	private_eap_aka_at_card_t *this)
{
	clear_pending_auts(this);
	this->mutex->destroy(this->mutex);
	free(this);
}

/**
 * See header
 */
eap_aka_at_card_t *eap_aka_at_card_create()
{
	private_eap_aka_at_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = (void*)return_false,
				.get_quintuplet = _get_quintuplet,
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
		.mutex = mutex_create(MUTEX_TYPE_DEFAULT),
	);

	return &this->public;
}
