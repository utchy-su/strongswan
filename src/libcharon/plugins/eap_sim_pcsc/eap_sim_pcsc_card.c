/*
 * Copyright (C) 2011 Duncan Salerno
 *
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

#include "eap_sim_pcsc_card.h"

#include <PCSC/wintypes.h>
#include <PCSC/winscard.h>
#include <daemon.h>

typedef struct private_eap_sim_pcsc_card_t private_eap_sim_pcsc_card_t;

/**
 * Private data of an eap_sim_pcsc_card_t object.
 */
struct private_eap_sim_pcsc_card_t {

	/**
	 * Public eap_sim_pcsc_card_t interface.
	 */
	eap_sim_pcsc_card_t public;

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
 * Maximum length for an IMSI.
 */
#define SIM_IMSI_MAX_LEN 15

/**
 * Length of the status at the end of response APDUs.
 */
#define APDU_STATUS_LEN 2

/**
 * First byte of status word indicating success.
 */
#define APDU_SW1_SUCCESS 0x90

/**
 * First byte of status word indicating there is response data to be read.
 */
#define APDU_SW1_RESPONSE_DATA 0x9f

/**
 * Alternative response-data indicator used by USIM commands.
 */
#define APDU_SW1_RESPONSE_DATA_2 0x61

/**
 * SW1 that indicates wrong expected length and includes the right one in SW2.
 */
#define APDU_SW1_WRONG_LE 0x6c

/**
 * EF.DIR file id
 */
#define SCARD_FILE_EF_DIR 0x2F00

/**
 * Run USIM authentication command APDU header.
 */
static const BYTE pbRunUMTSAlgorithm[5] = { 0x00, 0x88, 0x00, 0x81, 0x22 };

/**
 * Default USIM RID used as fallback if EF.DIR parsing fails.
 */
static const BYTE default_usim_rid[] = { 0xA0, 0x00, 0x00, 0x00, 0x87 };

/**
 * Decode IMSI EF (Elementary File) into an ASCII string
 */
static bool decode_imsi_ef(unsigned char *input, int input_len, char *output)
{
	/* Only digits 0-9 valid in IMSIs */
	static const char bcd_num_digits[] = {
		'0', '1', '2', '3', '4', '5', '6', '7',
		'8', '9', '\0', '\0', '\0', '\0', '\0', '\0'
	};
	int i;

	/* Check length byte matches how many bytes we have, and that input
	 * is correct length for an IMSI */
	if (input[0] != input_len-1 || input_len < 2 || input_len > 9)
	{
		return FALSE;
	}

	/* Check type byte is IMSI (bottom 3 bits == 001) */
	if ((input[1] & 0x07) != 0x01)
	{
		return FALSE;
	}
	*output++ = bcd_num_digits[input[1] >> 4];

	for (i = 2; i < input_len; i++)
	{
		*output++ = bcd_num_digits[input[i] & 0xf];
		*output++ = bcd_num_digits[input[i] >> 4];
	}

	*output++ = '\0';
	return TRUE;
}

/**
 * Check whether SW1 indicates that response data is available via GET RESPONSE.
 */
static bool apdu_has_response_data(BYTE sw1)
{
	return sw1 == APDU_SW1_RESPONSE_DATA || sw1 == APDU_SW1_RESPONSE_DATA_2 ||
			sw1 == APDU_SW1_WRONG_LE;
}

/**
 * Send GET RESPONSE command.
 */
static bool apdu_get_response(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
						  SCARD_IO_REQUEST *recv_pci, BYTE cla, BYTE le,
						  BYTE *buf, DWORD *buf_len)
{
	BYTE cmd[] = { cla, 0xC0, 0x00, 0x00, le };
	LONG rv;

	rv = SCardTransmit(card, send_pci, cmd, sizeof(cmd), recv_pci, buf, buf_len);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardTransmit(GET RESPONSE): %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	return TRUE;
}

/**
 * Select a file by file id and read its FCP/response payload.
 */
static bool apdu_select_file(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
					 SCARD_IO_REQUEST *recv_pci, BYTE cla, uint16_t file_id,
					 BYTE *buf, DWORD *buf_len)
{
	BYTE cmd[] = { cla, 0xA4, 0x00, 0x00, 0x02,
			   (BYTE)(file_id >> 8), (BYTE)(file_id & 0xFF) };

	if (cla == 0x00)
	{
		/* USIM file selection uses P2=0x04 */
		cmd[3] = 0x04;
	}
	BYTE resp[8];
	DWORD resp_len = sizeof(resp);
	LONG rv;

	rv = SCardTransmit(card, send_pci, cmd, sizeof(cmd), recv_pci, resp, &resp_len);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardTransmit(SELECT FILE): %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	if (resp_len != 2)
	{
		DBG1(DBG_IKE, "SELECT FILE returned unexpected response length: %u", resp_len);
		return FALSE;
	}
	if (!apdu_has_response_data(resp[0]))
	{
		DBG1(DBG_IKE, "SELECT FILE unexpected SW1/SW2: %02x %02x", resp[0], resp[1]);
		return FALSE;
	}
	return apdu_get_response(card, send_pci, recv_pci, cla, resp[1], buf, buf_len);
}

/**
 * Select an application by AID and read its FCP/response payload.
 */
static bool apdu_select_aid(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
						SCARD_IO_REQUEST *recv_pci, BYTE cla,
						BYTE *aid, size_t aid_len, BYTE *buf, DWORD *buf_len)
{
	BYTE cmd[5 + 32] = { 0 };
	BYTE resp[8];
	DWORD resp_len;
	LONG rv;
	BYTE p2_values[] = { 0x04, 0x00 };
	size_t i;

	if (!aid || !aid_len || aid_len > 32)
	{
		return FALSE;
	}

	cmd[0] = cla;
	cmd[1] = 0xA4;
	cmd[2] = 0x04;
	cmd[4] = aid_len;
	memcpy(cmd + 5, aid, aid_len);

	for (i = 0; i < sizeof(p2_values) / sizeof(p2_values[0]); i++)
	{
		cmd[3] = p2_values[i];
		resp_len = sizeof(resp);
		rv = SCardTransmit(card, send_pci, cmd, 5 + aid_len, recv_pci, resp, &resp_len);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit(SELECT AID): %s", pcsc_stringify_error(rv));
			return FALSE;
		}
		if (resp_len != 2)
		{
			DBG1(DBG_IKE, "SELECT AID returned unexpected response length: %u", resp_len);
			return FALSE;
		}
		if (resp[0] == APDU_SW1_SUCCESS && resp[1] == 0x00)
		{
			*buf_len = 0;
			return TRUE;
		}
		if (apdu_has_response_data(resp[0]))
		{
			return apdu_get_response(card, send_pci, recv_pci, cla, resp[1], buf, buf_len);
		}
		if (i + 1 < sizeof(p2_values) / sizeof(p2_values[0]) && resp[0] == 0x6A &&
			(resp[1] == 0x82 || resp[1] == 0x86 || resp[1] == 0x00))
		{
			DBG1(DBG_IKE, "SELECT AID with P2=%02x failed (%02x %02x), retrying P2=%02x",
				 cmd[3], resp[0], resp[1], p2_values[i + 1]);
			continue;
		}
		DBG1(DBG_IKE, "SELECT AID unexpected SW1/SW2: %02x %02x", resp[0], resp[1]);
		return FALSE;
	}
	return FALSE;
}

/**
 * Determine EF record length.
 */
static int apdu_get_record_len(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
				       SCARD_IO_REQUEST *recv_pci, BYTE cla,
				       BYTE recnum)
{
	BYTE cmd[] = { cla, 0xB2, recnum, 0x04, 0xFF };
	BYTE resp[8];
	DWORD resp_len = sizeof(resp);
	LONG rv;

	rv = SCardTransmit(card, send_pci, cmd, sizeof(cmd), recv_pci, resp, &resp_len);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardTransmit(READ RECORD len): %s", pcsc_stringify_error(rv));
		return -1;
	}
	if (resp_len < 2 || (resp[0] != APDU_SW1_WRONG_LE && resp[0] != 0x67))
	{
		DBG1(DBG_IKE, "READ RECORD len unexpected SW1/SW2: %02x %02x", resp[0], resp[1]);
		return -1;
	}
	return resp[1];
}

/**
 * Read EF record in absolute mode.
 */
static bool apdu_read_record(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
				     SCARD_IO_REQUEST *recv_pci, BYTE cla,
				     BYTE recnum, BYTE *buf, size_t len)
{
	BYTE cmd[] = { cla, 0xB2, recnum, 0x04, (BYTE)len };
	BYTE data[260];
	DWORD data_len = sizeof(data);
	LONG rv;

	rv = SCardTransmit(card, send_pci, cmd, sizeof(cmd), recv_pci, data, &data_len);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardTransmit(READ RECORD): %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	if (data_len != len + 2)
	{
		DBG1(DBG_IKE, "READ RECORD unexpected length %u (expected %zu)", data_len, len + 2);
		return FALSE;
	}
	if (data[len] != APDU_SW1_SUCCESS || data[len + 1] != 0x00)
	{
		DBG1(DBG_IKE, "READ RECORD unexpected status %02x %02x", data[len], data[len + 1]);
		return FALSE;
	}
	memcpy(buf, data, len);
	return TRUE;
}

/**
 * Read USIM AID from EF.DIR. Returns AID length or -1 on failure.
 */
static int get_usim_aid(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
					SCARD_IO_REQUEST *recv_pci, BYTE *aid, size_t aid_max)
{
	BYTE header[127];
	DWORD header_len = sizeof(header);
	BYTE record[255];
	int rec;

	if (!apdu_select_file(card, send_pci, recv_pci, 0x00, SCARD_FILE_EF_DIR,
					  header, &header_len))
	{
		DBG1(DBG_IKE, "failed to select EF.DIR");
		return -1;
	}

	for (rec = 1; rec < 10; rec++)
	{
		int rec_len = apdu_get_record_len(card, send_pci, recv_pci, 0x00, rec);
		size_t aid_len;

		if (rec_len < 0 || rec_len > sizeof(record))
		{
			continue;
		}
		if (!apdu_read_record(card, send_pci, recv_pci, 0x00, rec,
					 record, rec_len))
		{
			continue;
		}
		if (rec_len < 11 || record[0] != 0x61 || record[2] != 0x4F)
		{
			continue;
		}
		aid_len = record[3];
		if (aid_len < 1 || aid_len > 16 || (4 + aid_len > (size_t)rec_len) ||
			aid_len > aid_max)
		{
			continue;
		}
		DBG1(DBG_IKE, "EF.DIR rec %d AID candidate len=%zu app_code=%02x%02x AID=%b",
			 rec, aid_len, aid_len >= 7 ? record[9] : 0, aid_len >= 7 ? record[10] : 0,
			 record + 4, (u_int)aid_len);

		/* application code 0x1002 indicates 3G USIM app */
		if (aid_len >= 7 && record[9] == 0x10 && record[10] == 0x02)
		{
			memcpy(aid, record + 4, aid_len);
			return aid_len;
		}
	}
	return -1;
}

/**
 * Select USIM application.
 */
static bool select_usim_app(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
					    SCARD_IO_REQUEST *recv_pci)
{
	BYTE buf[127];
	DWORD buf_len = sizeof(buf);
	BYTE aid[32];
	int aid_len;
	bool selected = FALSE;

	/* First verify USIM CLA/SELECT is supported */
	if (!apdu_select_file(card, send_pci, recv_pci, 0x00, 0x3F00, buf, &buf_len))
	{
		DBG1(DBG_IKE, "USIM CLA/SELECT not supported");
		return FALSE;
	}

	aid_len = get_usim_aid(card, send_pci, recv_pci, aid, sizeof(aid));

	/* Some cards require moving back to MF after EF.DIR access before SELECT by AID */
	buf_len = sizeof(buf);
	if (!apdu_select_file(card, send_pci, recv_pci, 0x00, 0x3F00, buf, &buf_len))
	{
		DBG1(DBG_IKE, "failed to re-select MF before AID selection");
		return FALSE;
	}

	if (aid_len > 0)
	{
		DBG1(DBG_IKE, "trying USIM AID from EF.DIR: %b", aid, aid_len);
		buf_len = sizeof(buf);
		selected = apdu_select_aid(card, send_pci, recv_pci, 0x00, aid, aid_len,
					   buf, &buf_len);
		if (!selected && aid_len > (int)sizeof(default_usim_rid) &&
			memcmp(aid, default_usim_rid, sizeof(default_usim_rid)) == 0)
		{
			DBG1(DBG_IKE, "retrying USIM selection with RID prefix only");
			buf_len = sizeof(buf);
			selected = apdu_select_aid(card, send_pci, recv_pci, 0x00,
						   (BYTE*)default_usim_rid, sizeof(default_usim_rid),
						   buf, &buf_len);
		}
	}

	if (!selected)
	{
		DBG1(DBG_IKE, "falling back to default USIM RID AID");
		buf_len = sizeof(buf);
		if (!apdu_select_aid(card, send_pci, recv_pci, 0x00,
					 (BYTE*)default_usim_rid, sizeof(default_usim_rid),
					 buf, &buf_len))
		{
			DBG1(DBG_IKE, "failed to select USIM app via AID");
			return FALSE;
		}
	}
	return TRUE;
}

/**
 * Run UMTS AKA authentication with RAND/AUTN.
 */
static status_t run_umts_auth(SCARDHANDLE card, const SCARD_IO_REQUEST *send_pci,
			      SCARD_IO_REQUEST *recv_pci,
			      char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN],
			      char ck[AKA_CK_LEN], char ik[AKA_IK_LEN],
			      char res[AKA_RES_MAX], int *res_len,
			      char auts[AKA_AUTS_LEN])
{
	BYTE cmd[5 + 1 + AKA_RAND_LEN + 1 + AKA_AUTN_LEN] = { 0 };
	BYTE resp[64];
	DWORD resp_len = sizeof(resp);
	LONG rv;
	BYTE payload[64];
	size_t payload_len = 0;
	BYTE *pos, *end;

	memcpy(cmd, pbRunUMTSAlgorithm, sizeof(pbRunUMTSAlgorithm));
	cmd[5] = AKA_RAND_LEN;
	memcpy(cmd + 6, rand, AKA_RAND_LEN);
	cmd[6 + AKA_RAND_LEN] = AKA_AUTN_LEN;
	memcpy(cmd + 6 + AKA_RAND_LEN + 1, autn, AKA_AUTN_LEN);

	rv = SCardTransmit(card, send_pci, cmd, sizeof(cmd), recv_pci, resp, &resp_len);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardTransmit(RUN UMTS ALG): %s", pcsc_stringify_error(rv));
		return FAILED;
	}

	if (resp_len == 2 && resp[0] == 0x98 && resp[1] == 0x62)
	{
		DBG1(DBG_IKE, "USIM UMTS auth failed (MAC != XMAC)");
		return FAILED;
	}
	if (resp_len == 2 && apdu_has_response_data(resp[0]))
	{
		DWORD len = sizeof(payload);
		if (!apdu_get_response(card, send_pci, recv_pci, 0x00, resp[1], payload, &len))
		{
			return FAILED;
		}
		payload_len = len;
	}
	else if (resp_len > 2 && resp[resp_len - 2] == APDU_SW1_SUCCESS &&
			 resp[resp_len - 1] == 0x00)
	{
		payload_len = resp_len - 2;
		if (payload_len > sizeof(payload))
		{
			return FAILED;
		}
		memcpy(payload, resp, payload_len);
	}
	else
	{
		DBG1(DBG_IKE, "unexpected UMTS auth initial response");
		return FAILED;
	}

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

	return SUCCESS;
}

/**
 * Clear pending AUTS state.
 */
static void clear_pending_auts(private_eap_sim_pcsc_card_t *this)
{
	if (this->pending_id)
	{
		this->pending_id->destroy(this->pending_id);
		this->pending_id = NULL;
	}
	this->pending_auts_valid = FALSE;
}

/**
 * Store pending AUTS state for later resync callback.
 */
static void store_pending_auts(private_eap_sim_pcsc_card_t *this,
			       identification_t *id,
			       char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	clear_pending_auts(this);
	this->pending_id = id->clone(id);
	memcpy(this->pending_rand, rand, AKA_RAND_LEN);
	memcpy(this->pending_auts, auts, AKA_AUTS_LEN);
	this->pending_auts_valid = TRUE;
}

METHOD(simaka_card_t, get_triplet, bool,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[SIM_RAND_LEN], char sres[SIM_SRES_LEN], char kc[SIM_KC_LEN])
{
	status_t found = FALSE;
	LONG rv;
	SCARDCONTEXT hContext;
	DWORD dwReaders;
	LPSTR mszReaders;
	char *cur_reader;
	char full_nai[128];
	SCARDHANDLE hCard;
	enum { DISCONNECTED, CONNECTED, TRANSACTION } hCard_status = DISCONNECTED;

	(void)this;

	snprintf(full_nai, sizeof(full_nai), "%Y", id);

	DBG2(DBG_IKE, "looking for triplet: %Y rand %b", id, rand, SIM_RAND_LEN);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardEstablishContext: %s", pcsc_stringify_error(rv));
		return FALSE;
	}

	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		return FALSE;
	}
	mszReaders = malloc(sizeof(char)*dwReaders);

	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		free(mszReaders);
		return FALSE;
	}

	/* mszReaders is a multi-string of readers, separated by '\0' and
	 * terminated by an additional '\0' */
	for (cur_reader = mszReaders; *cur_reader != '\0' && found == FALSE;
		 cur_reader += strlen(cur_reader) + 1)
	{
		DWORD dwActiveProtocol = -1;
		const SCARD_IO_REQUEST *pioSendPci;
		SCARD_IO_REQUEST pioRecvPci;
		BYTE pbRecvBuffer[64];
		DWORD dwRecvLength;
		char imsi[SIM_IMSI_MAX_LEN + 1];

		/* See GSM 11.11 for SIM APDUs */
		static const BYTE pbSelectMF[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x3f, 0x00 };
		static const BYTE pbSelectDFGSM[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x7f, 0x20 };
		static const BYTE pbSelectIMSI[] = { 0xa0, 0xa4, 0x00, 0x00, 0x02, 0x6f, 0x07 };
		static const BYTE pbReadBinary[] = { 0xa0, 0xb0, 0x00, 0x00, 0x09 };
		BYTE pbRunGSMAlgorithm[5 + SIM_RAND_LEN] = { 0xa0, 0x88, 0x00, 0x00, 0x10 };
		static const BYTE pbGetResponse[] = { 0xa0, 0xc0, 0x00, 0x00, 0x0c };

		/* If on 2nd or later reader, make sure we end the transaction
		 * and disconnect card in the previous reader */
		switch (hCard_status)
		{
			case TRANSACTION:
				SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case CONNECTED:
				SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case DISCONNECTED:
				hCard_status = DISCONNECTED;
		}

		/* Copy RAND into APDU */
		memcpy(pbRunGSMAlgorithm + 5, rand, SIM_RAND_LEN);

		rv = SCardConnect(hContext, cur_reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardConnect: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = CONNECTED;

		switch(dwActiveProtocol)
		{
			case SCARD_PROTOCOL_T0:
				pioSendPci = SCARD_PCI_T0;
				break;
			case SCARD_PROTOCOL_T1:
				pioSendPci = SCARD_PCI_T1;
				break;
			default:
				DBG1(DBG_IKE, "Unknown SCARD_PROTOCOL");
				continue;
		}

		/* Start transaction */
		rv = SCardBeginTransaction(hCard);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardBeginTransaction: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = TRANSACTION;

		/* APDU: Select MF */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectMF, sizeof(pbSelectMF),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select MF failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Select DF GSM */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectDFGSM, sizeof(pbSelectDFGSM),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select DF GSM failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Select IMSI */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectIMSI, sizeof(pbSelectIMSI),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Select IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Read Binary (of IMSI) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbReadBinary, sizeof(pbReadBinary),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Select IMSI failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		if (!decode_imsi_ef(pbRecvBuffer, dwRecvLength-APDU_STATUS_LEN, imsi))
		{
			DBG1(DBG_IKE, "Couldn't decode IMSI EF: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* The IMSI could be post/prefixed in the full NAI, so just make sure
		 * it's in there */
		if (!(strlen(full_nai) && strstr(full_nai, imsi)))
		{
			DBG1(DBG_IKE, "Not the SIM we're looking for, IMSI: %s", imsi);
			continue;
		}

		/* APDU: Run GSM Algorithm */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci,
						   pbRunGSMAlgorithm, sizeof(pbRunGSMAlgorithm),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}
		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_RESPONSE_DATA)
		{
			DBG1(DBG_IKE, "Run GSM Algorithm failed: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* APDU: Get Response (of Run GSM Algorithm) */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbGetResponse, sizeof(pbGetResponse),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardTransmit: %s", pcsc_stringify_error(rv));
			continue;
		}

		if (dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			DBG1(DBG_IKE, "Get Response failed: %b", pbRecvBuffer,
				 (u_int)dwRecvLength);
			continue;
		}

		/* Extract out Kc and SRES from response */
		if (dwRecvLength == SIM_SRES_LEN + SIM_KC_LEN + APDU_STATUS_LEN)
		{
			memcpy(sres, pbRecvBuffer, SIM_SRES_LEN);
			memcpy(kc, pbRecvBuffer+4, SIM_KC_LEN);
			/* This will also cause the loop to exit */
			found = TRUE;
		}
		else
		{
			DBG1(DBG_IKE, "Get Response incorrect length: %b",
				 pbRecvBuffer, (u_int)dwRecvLength);
			continue;
		}

		/* Transaction will be ended and card disconnected at the
		 * beginning of this loop or after this loop */
	}

	/* Make sure we end any previous transaction and disconnect card */
	switch (hCard_status)
	{
		case TRANSACTION:
			SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case CONNECTED:
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case DISCONNECTED:
			hCard_status = DISCONNECTED;
	}

	rv = SCardReleaseContext(hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardReleaseContext: %s", pcsc_stringify_error(rv));
	}

	free(mszReaders);
	return found;
}

METHOD(simaka_card_t, get_quintuplet, status_t,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char autn[AKA_AUTN_LEN], char ck[AKA_CK_LEN],
	char ik[AKA_IK_LEN], char res[AKA_RES_MAX], int *res_len)
{
	status_t status = FAILED;
	LONG rv;
	SCARDCONTEXT hContext;
	DWORD dwReaders;
	LPSTR mszReaders;
	char *cur_reader;
	char full_nai[128];
	SCARDHANDLE hCard;
	enum { DISCONNECTED, CONNECTED, TRANSACTION } hCard_status = DISCONNECTED;

	snprintf(full_nai, sizeof(full_nai), "%Y", id);
	clear_pending_auts(this);

	DBG2(DBG_IKE, "looking for quintuplet: %Y rand %b autn %b",
		 id, rand, AKA_RAND_LEN, autn, AKA_AUTN_LEN);

	rv = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardEstablishContext: %s", pcsc_stringify_error(rv));
		return FAILED;
	}

	rv = SCardListReaders(hContext, NULL, NULL, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		SCardReleaseContext(hContext);
		return FAILED;
	}
	mszReaders = malloc(sizeof(char) * dwReaders);

	rv = SCardListReaders(hContext, NULL, mszReaders, &dwReaders);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardListReaders: %s", pcsc_stringify_error(rv));
		free(mszReaders);
		SCardReleaseContext(hContext);
		return FAILED;
	}

	for (cur_reader = mszReaders; *cur_reader != '\0' && status == FAILED;
		 cur_reader += strlen(cur_reader) + 1)
	{
		DWORD dwActiveProtocol = -1;
		const SCARD_IO_REQUEST *pioSendPci;
		SCARD_IO_REQUEST pioRecvPci;
		BYTE pbRecvBuffer[64];
		DWORD dwRecvLength;
		char imsi[SIM_IMSI_MAX_LEN + 1];
		char auts[AKA_AUTS_LEN];

		/* Use USIM CLA for IMSI access so later USIM app selection works */
		static const BYTE pbSelectMF[] = { 0x00, 0xa4, 0x00, 0x04, 0x02, 0x3f, 0x00 };
		static const BYTE pbSelectDFGSM[] = { 0x00, 0xa4, 0x00, 0x04, 0x02, 0x7f, 0x20 };
		static const BYTE pbSelectIMSI[] = { 0x00, 0xa4, 0x00, 0x04, 0x02, 0x6f, 0x07 };
		static const BYTE pbReadBinary[] = { 0x00, 0xb0, 0x00, 0x00, 0x09 };

		switch (hCard_status)
		{
			case TRANSACTION:
				SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case CONNECTED:
				SCardDisconnect(hCard, SCARD_LEAVE_CARD);
				/* FALLTHRU */
			case DISCONNECTED:
				hCard_status = DISCONNECTED;
		}

		rv = SCardConnect(hContext, cur_reader, SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwActiveProtocol);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardConnect: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = CONNECTED;

		switch (dwActiveProtocol)
		{
			case SCARD_PROTOCOL_T0:
				pioSendPci = SCARD_PCI_T0;
				break;
			case SCARD_PROTOCOL_T1:
				pioSendPci = SCARD_PCI_T1;
				break;
			default:
				DBG1(DBG_IKE, "Unknown SCARD_PROTOCOL");
				continue;
		}

		rv = SCardBeginTransaction(hCard);
		if (rv != SCARD_S_SUCCESS)
		{
			DBG1(DBG_IKE, "SCardBeginTransaction: %s", pcsc_stringify_error(rv));
			continue;
		}
		hCard_status = TRANSACTION;

		/* Check this card against requested identity using IMSI from GSM DF */
		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectMF, sizeof(pbSelectMF),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS || dwRecvLength < APDU_STATUS_LEN ||
			!apdu_has_response_data(pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN]))
		{
			continue;
		}

		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectDFGSM, sizeof(pbSelectDFGSM),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS || dwRecvLength < APDU_STATUS_LEN ||
			!apdu_has_response_data(pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN]))
		{
			continue;
		}

		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbSelectIMSI, sizeof(pbSelectIMSI),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS || dwRecvLength < APDU_STATUS_LEN ||
			!apdu_has_response_data(pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN]))
		{
			continue;
		}

		dwRecvLength = sizeof(pbRecvBuffer);
		rv = SCardTransmit(hCard, pioSendPci, pbReadBinary, sizeof(pbReadBinary),
						   &pioRecvPci, pbRecvBuffer, &dwRecvLength);
		if (rv != SCARD_S_SUCCESS || dwRecvLength < APDU_STATUS_LEN ||
			pbRecvBuffer[dwRecvLength-APDU_STATUS_LEN] != APDU_SW1_SUCCESS)
		{
			continue;
		}

		if (!decode_imsi_ef(pbRecvBuffer, dwRecvLength-APDU_STATUS_LEN, imsi))
		{
			continue;
		}
		if (!(strlen(full_nai) && strstr(full_nai, imsi)))
		{
			continue;
		}

		if (!select_usim_app(hCard, pioSendPci, &pioRecvPci))
		{
			DBG1(DBG_IKE, "matching SIM found but failed to select USIM app");
			continue;
		}

		status = run_umts_auth(hCard, pioSendPci, &pioRecvPci,
				rand, autn, ck, ik, res, res_len, auts);
		if (status == INVALID_STATE)
		{
			store_pending_auts(this, id, rand, auts);
			break;
		}
		if (status == SUCCESS)
		{
			break;
		}
	}

	switch (hCard_status)
	{
		case TRANSACTION:
			SCardEndTransaction(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case CONNECTED:
			SCardDisconnect(hCard, SCARD_LEAVE_CARD);
			/* FALLTHRU */
		case DISCONNECTED:
			hCard_status = DISCONNECTED;
	}

	rv = SCardReleaseContext(hContext);
	if (rv != SCARD_S_SUCCESS)
	{
		DBG1(DBG_IKE, "SCardReleaseContext: %s", pcsc_stringify_error(rv));
	}

	free(mszReaders);
	if (status != INVALID_STATE)
	{
		/* keep pending AUTS only for resync flow */
		clear_pending_auts(this);
	}
	return status;
}

METHOD(simaka_card_t, resync, bool,
	private_eap_sim_pcsc_card_t *this, identification_t *id,
	char rand[AKA_RAND_LEN], char auts[AKA_AUTS_LEN])
{
	if (this->pending_auts_valid && this->pending_id &&
		this->pending_id->equals(this->pending_id, id) &&
		memcmp(rand, this->pending_rand, AKA_RAND_LEN) == 0)
	{
		memcpy(auts, this->pending_auts, AKA_AUTS_LEN);
		clear_pending_auts(this);
		return TRUE;
	}
	return FALSE;
}

METHOD(eap_sim_pcsc_card_t, destroy, void,
	private_eap_sim_pcsc_card_t *this)
{
	clear_pending_auts(this);
	free(this);
}

/**
 * See header
 */
eap_sim_pcsc_card_t *eap_sim_pcsc_card_create()
{
	private_eap_sim_pcsc_card_t *this;

	INIT(this,
		.public = {
			.card = {
				.get_triplet = _get_triplet,
				.get_quintuplet = _get_quintuplet,
				.resync = _resync,
				.get_pseudonym = (void*)return_null,
				.set_pseudonym = (void*)nop,
				.get_reauth = (void*)return_null,
				.set_reauth = (void*)nop,
			},
			.destroy = _destroy,
		},
	);

	return &this->public;
}
