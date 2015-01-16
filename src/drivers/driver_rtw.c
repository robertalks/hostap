/*
 * hostapd / Driver interface for rtl871x driver
 * Copyright (c) 2010,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

#define CONFIG_MLME_OFFLOAD 1

#include "includes.h"
#include <net/if.h>
#include <sys/ioctl.h>

#include "common.h"
#include "linux_wext.h"
#include "driver.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "l2_packet/l2_packet.h"
#include "common/ieee802_11_defs.h"
#include "netlink.h"
#include "linux_ioctl.h"
#include "ap/hostapd.h"
#include "ap/ap_config.h"

#ifdef USE_KERNEL_HEADERS
/* compat-wireless does not include linux/compiler.h to 
   define __user, so define it here */
#ifndef __user
#define __user
#endif /* __user */
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   // the L2 protocols
#include <linux/if_arp.h>
#include <linux/wireless.h>
#else /* USE_KERNEL_HEADERS */
#include <net/if_arp.h>
#include <netpacket/packet.h>
#endif /* USE_KERNEL_HEADERS */

#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 0x0019
#endif

#if 0
#include "hostapd.h"
#include "driver.h"
#include "ieee802_1x.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "sta_info.h"
#include "l2_packet/l2_packet.h"

#include "wpa.h"
#include "accounting.h"
#include "ieee802_11.h"
#include "hw_features.h"
#include "radius/radius.h"
#endif

#include "driver_rtl.h"

struct rtl871x_driver_data {
	struct hostapd_data		*hapd;
	char				iface[IFNAMSIZ + 1];
	int				ifindex;
	struct l2_packet_data 		*l2_sock; // socket for sending eapol frames
	struct l2_packet_data 		*l2_sock_recv; // raw packet recv socket from bridge interface
#ifdef CONFIG_MGNT_L2SOCK
	struct l2_packet_data 		*mgnt_l2_sock; // socket for tx/rx management frames
#else
	int				mgnt_sock; // socket for tx/rx management frames
#endif
	int				ioctl_sock; // socket for ioctl() use
	int				wext_sock; // socket for wireless events
	struct netlink_data 		*netlink;
	int				we_version;
	u8				hw_mac[ETH_ALEN];
	u8				acct_mac[ETH_ALEN];
	struct hostap_sta_driver_data 	acct_data;
	
};

#ifndef CONFIG_MLME_OFFLOAD
static int rtl871x_set_iface_flags(void *priv, int dev_up)
{
	struct rtl871x_driver_data *drv = priv;
	struct ifreq ifr;

	wpa_printf(MSG_DEBUG, "%s: dev_up=%d", __func__, dev_up);

	if (drv->mgnt_sock < 0)
		return -1;

	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, IFNAMSIZ, "mgnt.%s", "wlan0");

	if (ioctl(drv->mgnt_sock, SIOCGIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}

	if (dev_up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(drv->mgnt_sock, SIOCSIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		return -1;
	}

#if 0
	if (dev_up) {
		memset(&ifr, 0, sizeof(ifr));
		os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);
		ifr.ifr_mtu = HOSTAPD_MTU;
		if (ioctl(drv->ioctl_sock, SIOCSIFMTU, &ifr) != 0) {
			perror("ioctl[SIOCSIFMTU]");
			printf("Setting MTU failed - trying to survive with "
			       "current value\n");
		}
	}
#endif

	return 0;
}
#endif

static int rtl871x_hostapd_ioctl(struct rtl871x_driver_data *drv, ieee_param *param, int len)
{	
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = len;

	if (ioctl(drv->ioctl_sock, RTL_IOCTL_HOSTAPD, &iwr) < 0) {
		perror("ioctl[RTL_IOCTL_HOSTAPD]");
		return -1;
	}

	return 0;
}

static int rtl871x_set_mode(struct rtl871x_driver_data *drv, u32 mode)
{
	struct iwreq iwr;

	if (drv->ioctl_sock < 0)
		return -1;
	
	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.mode = mode;
	
	if (ioctl(drv->ioctl_sock, SIOCSIWMODE, &iwr) < 0) {
		perror("ioctl[SIOCSIWMODE]");
		printf("Could not set interface to mode(%d)!\n", mode);
		return -1;
	}

	return 0;
	
}

static int rtl871x_get_sta_wpaie(struct rtl871x_driver_data *drv, u8 *iebuf, u8 *addr)
{	
	struct ieee_param param;

	printf("+%s, " MACSTR " is sta's address\n", __func__, MAC2STR(addr));

	memset(&param, 0, sizeof(param));
	param.cmd = RTL871X_HOSTAPD_GET_WPAIE_STA;
	memcpy(param.sta_addr, addr, ETH_ALEN);
	
	if (rtl871x_hostapd_ioctl(drv, &param, sizeof(param))) {
		printf("Could not get sta wpaie from kernel driver.\n");
		return -1;
	}


	if (param.u.wpa_ie.len > 32)
		return -1;

	memcpy(iebuf, param.u.wpa_ie.reserved, param.u.wpa_ie.len);
	
	return 0;	

}

static int rtl871x_del_sta(struct rtl871x_driver_data *drv, u8 *addr)
{
	struct hostapd_data *hapd = drv->hapd;
	
#if 1
	drv_event_disassoc(hapd, addr);
	
#else

	struct sta_info *sta;

	sta = ap_get_sta(hapd, addr);
	if (sta != NULL) 
	{
		sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
		wpa_auth_sm_event(sta->wpa_sm, WPA_DISASSOC);
		sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
		ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
		ap_free_sta(hapd, sta);
	}
	else
	{
		wpa_printf(MSG_DEBUG, "Disassociation notification for "
			   "unknown STA " MACSTR, MAC2STR(addr));
	}
#endif

	return 0;
	
}

static int rtl871x_new_sta(struct rtl871x_driver_data *drv, u8 *addr)
{
	struct hostapd_data *hapd = drv->hapd;
	int ielen = 0, res=0;
	u8 iebuf[32], *piebuf=NULL;

	memset(iebuf, 0 , sizeof(iebuf));
	if (rtl871x_get_sta_wpaie(drv, iebuf, addr)) {
		wpa_printf(MSG_DEBUG, "%s: Failed to get WPA/RSN IE: %s",
			   __func__, strerror(errno));
		goto no_ie;
	}
	
	if ((iebuf[0] == WLAN_EID_VENDOR_SPECIFIC) || (iebuf[0] == WLAN_EID_RSN) )
	{
		piebuf = iebuf;
		ielen = iebuf[1];
		
		if (ielen == 0)
			piebuf = NULL;
		else
			ielen += 2;	
	}

no_ie:
	drv_event_assoc(hapd, addr, piebuf, ielen, 0);

	if (memcmp(addr, drv->acct_mac, ETH_ALEN) == 0) {
		/* Cached accounting data is not valid anymore. */
		memset(drv->acct_mac, 0, ETH_ALEN);
		memset(&drv->acct_data, 0, sizeof(drv->acct_data));
	}

	return res;
	
}

static void rtl871x_wireless_event_wireless(struct rtl871x_driver_data *drv,
					    char *data, int len)
{
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		wpa_printf(MSG_MSGDUMP, "Wireless event: cmd=0x%x len=%d",
			   iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (drv->we_version > 18 &&
		    (iwe->cmd == IWEVMICHAELMICFAILURE ||
		     iwe->cmd == IWEVCUSTOM)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN,
			       sizeof(struct iw_event) - dlen);
		} else {
			memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		switch (iwe->cmd) {
		case IWEVEXPIRED:
			rtl871x_del_sta(drv, (u8 *)iwe->u.addr.sa_data);
			break;
		case IWEVREGISTERED:
			if (rtl871x_new_sta(drv, (u8 *)iwe->u.addr.sa_data)) {
				printf("Failed to add new sta: "MACSTR" \n", MAC2STR((u8 *)iwe->u.addr.sa_data));
			}
			break;
		case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;	
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			/* madwifi_wireless_event_wireless_custom(drv, buf); */
			free(buf);
			break;
		}

		pos += iwe->len;
	}
	
}

#if 1
static void rtl871x_wireless_event_rtm_newlink(void *ctx,
				   struct ifinfomsg *ifi, u8 *buf, size_t len)
{
	struct rtl871x_driver_data *drv = ctx;
	int attrlen, rta_len;
	struct rtattr *attr;

	if (ifi->ifi_index != drv->ifindex)
		return;

	attrlen = len;
	attr = (struct rtattr *) buf;

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			rtl871x_wireless_event_wireless(
				drv, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}

#else
static void rtl871x_wireless_event_rtm_newlink(struct rtl871x_driver_data *drv,
					       struct nlmsghdr *h, int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < (int) sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	if (ifi->ifi_index != drv->ifindex)
		return;

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			rtl871x_wireless_event_wireless(
				drv, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}
#endif

static int rtl871x_wireless_event_init(struct rtl871x_driver_data *drv)
{
	struct netlink_config *cfg;

	cfg = os_zalloc(sizeof(*cfg));
	if (cfg == NULL)
		return -1;
	cfg->ctx = drv;
	cfg->newlink_cb = rtl871x_wireless_event_rtm_newlink;
	drv->netlink = netlink_init(cfg);
	if (drv->netlink == NULL) {
		os_free(cfg);
		return -1;
	}

	return 0;
}

#if 1
static void rtl871x_handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct rtl871x_driver_data *drv = ctx;
	drv_event_eapol_rx(drv->hapd, src_addr, buf + sizeof(struct l2_ethhdr),
			   len - sizeof(struct l2_ethhdr));
}
#else
static void rtl871x_handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct rtl871x_driver_data *drv = ctx;
	struct hostapd_data *hapd = drv->hapd;
	struct sta_info *sta;

	sta = ap_get_sta(hapd, src_addr);
	if (!sta || !(sta->flags & WLAN_STA_ASSOC)) {
		printf("Data frame from not associated STA %s\n",
		       ether_sprintf(src_addr));
		/* XXX cannot happen */
		return;
	}
	ieee802_1x_receive(hapd, src_addr, buf + sizeof(struct l2_ethhdr),
			   len - sizeof(struct l2_ethhdr));
}
#endif

static int rtl871x_send_eapol_ops(void *priv, const u8 *addr, const u8 *data, size_t data_len,
		   int encrypt, const u8 *own_addr, u32 flags)
{
	struct rtl871x_driver_data *drv = priv;
	unsigned char buf[3000];
	unsigned char *bp = buf;
	struct l2_ethhdr *eth;
	size_t len;
	int status;

	printf("+rtl871x_send_eapol\n");

	/*
	 * Prepend the Ethernet header.  If the caller left us
	 * space at the front we could just insert it but since
	 * we don't know we copy to a local buffer.  Given the frequency
	 * and size of frames this probably doesn't matter.
	 */
	len = data_len + sizeof(struct l2_ethhdr);
	if (len > sizeof(buf)) {
		bp = malloc(len);
		if (bp == NULL) {
			printf("EAPOL frame discarded, cannot malloc temp "
			       "buffer of size %lu!\n", (unsigned long) len);
			return -1;
		}
	}
	
	eth = (struct l2_ethhdr *) bp;
	memcpy(eth->h_dest, addr, ETH_ALEN);
	memcpy(eth->h_source, own_addr, ETH_ALEN);
	eth->h_proto = htons(ETH_P_EAPOL);
	memcpy(eth+1, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

	status = l2_packet_send(drv->l2_sock, addr, ETH_P_EAPOL, bp, len);

	if (bp != buf)
		free(bp);
	
	return status;
	
}

#ifndef CONFIG_MLME_OFFLOAD
static void rtl871x_receive_mgnt(struct rtl871x_driver_data *drv , const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	u16 fc, type, stype;
	struct hostapd_data *hapd = drv->hapd;
#if 0
	{
		int i;
		for(i=0; i<len; i+=8)
		{
			printf("%x:%x:%x:%x:%x:%x:%x:%x\n", buf[i], buf[i+1], buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7]);
		}	

	}
#endif

	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
		return;

	mgmt = (const struct ieee80211_mgmt *)buf;

	fc = le_to_host16(mgmt->frame_control);
	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		if (stype != WLAN_FC_STYPE_BEACON)
			wpa_printf(MSG_MSGDUMP, "MGMT");
		break;
	case WLAN_FC_TYPE_CTRL:
		printf("rtl871x_receive_mgnt, CTRL\n");
		break;
	case WLAN_FC_TYPE_DATA:
		printf("rtl871x_receive_mgnt, DATA\n");
		break;
	default:
		printf("unknown frame type %d\n", type);
		break;
	}

	
}

#ifdef CONFIG_MGNT_L2SOCK
static void rtl871x_recvive_mgmt_frame(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len)
{
	struct rtl871x_driver_data *drv = ctx;

	rtl871x_receive_mgnt(drv, buf, len);
}
#else
static void rtl871x_recvive_mgmt_frame(int sock, void *eloop_ctx, void *sock_ctx)
{
#if 0
	int len;
	unsigned char buf[1024];
	struct hostapd_data *hapd = (struct hostapd_data *)eloop_ctx;
	struct rtl871x_driver_data *drv = (struct rtl871x_driver_data *)hapd->drv_priv;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv");
		return;
	}
	
	rtl871x_receive_mgnt(drv, buf, len);
#endif
}

static int rtl871x_mgnt_sock_init(struct rtl871x_driver_data *drv, const char *name)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_ll addr;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return -1;
	}

	if (eloop_register_read_sock(sock, rtl871x_recvive_mgmt_frame, drv->hapd, NULL))
	{
		printf("Could not register read socket\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
        if (ioctl(sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
        }

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	wpa_printf(MSG_DEBUG, "Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

        memset(&ifr, 0, sizeof(ifr));
        os_strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		return -1;
        }


	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		printf("Invalid HW-addr family 0x%04x\n",
		       ifr.ifr_hwaddr.sa_family);
		return -1;
	}

	return sock;
	
}
#endif
#endif

static void rtl871x_handle_tx_callback(struct hostapd_data *hapd, u8 *buf, size_t len,
			       int ok)
{
#if 0
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;
	struct sta_info *sta;

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		ieee802_11_mgmt_cb(hapd, buf, len, stype, ok);
		break;
	case WLAN_FC_TYPE_CTRL:
		printf("CTRL (TX callback) %s\n",
			   ok ? "ACK" : "fail");
		break;
	case WLAN_FC_TYPE_DATA:
		printf("DATA (TX callback) %s\n",
			   ok ? "ACK" : "fail");
		sta = ap_get_sta(hapd, hdr->addr1);
		if (sta && sta->flags & WLAN_STA_PENDING_POLL) {
			wpa_printf(MSG_DEBUG, "STA " MACSTR
				   " %s pending activity poll",
				   MAC2STR(sta->addr),
				   ok ? "ACKed" : "did not ACK");
			if (ok)
				sta->flags &= ~WLAN_STA_PENDING_POLL;
		}
		if (sta)
			ieee802_1x_tx_status(hapd, sta, buf, len, ok);
		break;
	default:
		printf("unknown TX callback frame type %d\n", type);
		break;
	}
#endif	
}	

static int rtl871x_send_mgnt(struct rtl871x_driver_data *drv, const void *msg, size_t len)
{
	return 0;
}

static int rtl871x_send_mgmt_frame_ops(void *priv, const void *msg, size_t len,
				  int flags)
{
	struct rtl871x_driver_data *drv = priv;
	int res=0;

#ifdef CONFIG_MGNT_L2SOCK
	if (drv->mgnt_l2_sock == NULL)
		return res;
		
	res = l2_packet_send(drv->mgnt_l2_sock, NULL, ETH_P_80211_RAW, msg, len);
#else
	if (drv->mgnt_sock < 0)
		return res;

	res = send(drv->mgnt_sock, msg, len, flags);
#endif
	rtl871x_send_mgnt(drv, msg, len);
	rtl871x_handle_tx_callback(drv->hapd, (u8*)msg, len, 1);

	return res;
	
}

static struct hostapd_hw_modes *rtl871x_get_hw_feature_data_ops(void *priv,
							    u16 *num_modes,
							    u16 *flags)
{
#define MAX_NUM_CHANNEL (14)
#define MAX_NUM_CHANNEL_5G (24)

	struct hostapd_hw_modes *modes;
	size_t i;
        int k;

	*num_modes = 3;
	*flags = 0;
	
	modes = os_zalloc(*num_modes * sizeof(struct hostapd_hw_modes));
	if (modes == NULL)
		return NULL;

	/* .1 */
	modes[0].mode = HOSTAPD_MODE_IEEE80211G;
	modes[0].num_channels = MAX_NUM_CHANNEL;
	modes[0].num_rates = 12;
	modes[0].channels =
		os_zalloc(MAX_NUM_CHANNEL * sizeof(struct hostapd_channel_data));
	modes[0].rates = os_zalloc(modes[0].num_rates * sizeof(int));
	if (modes[0].channels == NULL || modes[0].rates == NULL)
		goto fail;
	for (i = 0; i < MAX_NUM_CHANNEL; i++) {
		modes[0].channels[i].chan = i + 1;
		modes[0].channels[i].freq = 2412 + 5 * i;
		modes[0].channels[i].flag = 0;
		if (i >= 13)
			modes[0].channels[i].flag = HOSTAPD_CHAN_DISABLED;
	}
	modes[0].rates[0] = 10;
	modes[0].rates[1] = 20;
	modes[0].rates[2] = 55;
	modes[0].rates[3] = 110;
	modes[0].rates[4] = 60;
	modes[0].rates[5] = 90;
	modes[0].rates[6] = 120;
	modes[0].rates[7] = 180;
	modes[0].rates[8] = 240;
	modes[0].rates[9] = 360;
	modes[0].rates[10] = 480;
	modes[0].rates[11] = 540;


	/* .2 */
	modes[1].mode = HOSTAPD_MODE_IEEE80211B;
	modes[1].num_channels = MAX_NUM_CHANNEL;
	modes[1].num_rates = 4;
	modes[1].channels =
		os_zalloc(MAX_NUM_CHANNEL * sizeof(struct hostapd_channel_data));
	modes[1].rates = os_zalloc(modes[1].num_rates * sizeof(int));
	if (modes[1].channels == NULL || modes[1].rates == NULL)
		goto fail;
	for (i = 0; i < MAX_NUM_CHANNEL; i++) {
		modes[1].channels[i].chan = i + 1;
		modes[1].channels[i].freq = 2412 + 5 * i;
		modes[1].channels[i].flag = 0;
		if (i >= 11)
			modes[1].channels[i].flag = HOSTAPD_CHAN_DISABLED;
	}
	modes[1].rates[0] = 10;
	modes[1].rates[1] = 20;
	modes[1].rates[2] = 55;
	modes[1].rates[3] = 110;


	/* .3 */
	modes[2].mode = HOSTAPD_MODE_IEEE80211A;
#ifdef CONFIG_DRIVER_RTL_DFS
	modes[2].num_channels = MAX_NUM_CHANNEL_5G;
#else /* CONFIG_DRIVER_RTL_DFS */
	modes[2].num_channels = 9;
#endif /* CONFIG_DRIVER_RTL_DFS */	
	
	modes[2].num_rates = 8;
	modes[2].channels = os_zalloc(modes[2].num_channels * sizeof(struct hostapd_channel_data));
	modes[2].rates = os_zalloc(modes[2].num_rates * sizeof(int));
	if (modes[2].channels == NULL || modes[2].rates == NULL)
		goto fail;

	k = 0;
	/* 5G band1 Channel: 36, 40, 44, 48 */
	for (i=0; i < 4; i++) {
		modes[2].channels[k].chan = 36+(i*4);
		modes[2].channels[k].freq = 5180+(i*20);
		modes[2].channels[k].flag = 0;
		k++;
	}

#ifdef CONFIG_DRIVER_RTL_DFS

	/* 5G band2 Channel: 52, 56, 60, 64 */
	for (i=0; i < 4; i++) {
		modes[2].channels[k].chan = 52+(i*4);
		modes[2].channels[k].freq = 5260+(i*20);
		modes[2].channels[k].flag = 0;
		k++;
	}

	/* 5G band3 Channel: 100, 104, 108. 112, 116, 120, 124, 128, 132, 136, 140 */
	for (i=0; i < 11; i++) {
		modes[2].channels[k].chan = 100+(i*4);
		modes[2].channels[k].freq = 5500+(i*20);
		modes[2].channels[k].flag = 0;
		k++;
	}
#endif /* CONFIG_DRIVER_RTL_DFS */

	/* 5G band4 Channel: 149, 153, 157, 161, 165 */
	for (i=0; i < 5; i++) {
		modes[2].channels[k].chan = 149+(i*4);
		modes[2].channels[k].freq = 5745+(i*20);
		modes[2].channels[k].flag = 0;
		k++;
	}
	
	modes[2].rates[0] = 60;
	modes[2].rates[1] = 90;
	modes[2].rates[2] = 120;
	modes[2].rates[3] = 180;
	modes[2].rates[4] = 240;
	modes[2].rates[5] = 360;
	modes[2].rates[6] = 480;
	modes[2].rates[7] = 540;

#if 0
#define HT_CAP_INFO_LDPC_CODING_CAP		((u16) BIT(0))
#define HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET	((u16) BIT(1))
#define HT_CAP_INFO_SMPS_MASK			((u16) (BIT(2) | BIT(3)))
#define HT_CAP_INFO_SMPS_STATIC			((u16) 0)
#define HT_CAP_INFO_SMPS_DYNAMIC		((u16) BIT(2))
#define HT_CAP_INFO_SMPS_DISABLED		((u16) (BIT(2) | BIT(3)))
#define HT_CAP_INFO_GREEN_FIELD			((u16) BIT(4))
#define HT_CAP_INFO_SHORT_GI20MHZ		((u16) BIT(5))
#define HT_CAP_INFO_SHORT_GI40MHZ		((u16) BIT(6))
#define HT_CAP_INFO_TX_STBC			((u16) BIT(7))
#define HT_CAP_INFO_RX_STBC_MASK		((u16) (BIT(8) | BIT(9)))
#define HT_CAP_INFO_RX_STBC_1			((u16) BIT(8))
#define HT_CAP_INFO_RX_STBC_12			((u16) BIT(9))
#define HT_CAP_INFO_RX_STBC_123			((u16) (BIT(8) | BIT(9)))
#define HT_CAP_INFO_DELAYED_BA			((u16) BIT(10))
#define HT_CAP_INFO_MAX_AMSDU_SIZE		((u16) BIT(11))
#define HT_CAP_INFO_DSSS_CCK40MHZ		((u16) BIT(12))
#define HT_CAP_INFO_PSMP_SUPP			((u16) BIT(13))
#define HT_CAP_INFO_40MHZ_INTOLERANT		((u16) BIT(14))
#define HT_CAP_INFO_LSIG_TXOP_PROTECT_SUPPORT	((u16) BIT(15))
#endif

	/* HOSTAPD_MODE_IEEE80211G */
	modes[0].ht_capab = HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET|HT_CAP_INFO_SHORT_GI20MHZ|
			HT_CAP_INFO_SHORT_GI40MHZ|HT_CAP_INFO_MAX_AMSDU_SIZE|HT_CAP_INFO_DSSS_CCK40MHZ;
	
	modes[0].mcs_set[0]= 0xff;
	modes[0].mcs_set[1]= 0xff;
		
	/* HOSTAPD_MODE_IEEE80211B */
	modes[1].ht_capab = 0;
	
	/* HOSTAPD_MODE_IEEE80211A */
	modes[2].ht_capab = modes[0].ht_capab;
	
	modes[2].mcs_set[0]= 0xff;
	modes[2].mcs_set[1]= 0xff;
	
	return modes;

fail:
	if (modes) {
		for (i = 0; i < *num_modes; i++) {
			os_free(modes[i].channels);
			os_free(modes[i].rates);
		}
		os_free(modes);
	}
	
	return NULL;	
	
}

#if 0
static int rtl871x_sta_add_ops(const char *ifname, void *priv, const u8 *addr,
			  u16 aid, u16 capability, u8 *supp_rates,
			  size_t supp_rates_len, int flags,
			  u16 listen_interval)
{

#if 1
	printf("+%s, " MACSTR " is new sta address added\n", __func__, MAC2STR(addr));
	return 0;
#else	
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param param;
	int tx_supp_rates = 0;
	size_t i;

#define WLAN_RATE_1M BIT(0)
#define WLAN_RATE_2M BIT(1)
#define WLAN_RATE_5M5 BIT(2)
#define WLAN_RATE_11M BIT(3)

	for (i = 0; i < supp_rates_len; i++) {
		if ((supp_rates[i] & 0x7f) == 2)
			tx_supp_rates |= WLAN_RATE_1M;
		if ((supp_rates[i] & 0x7f) == 4)
			tx_supp_rates |= WLAN_RATE_2M;
		if ((supp_rates[i] & 0x7f) == 11)
			tx_supp_rates |= WLAN_RATE_5M5;
		if ((supp_rates[i] & 0x7f) == 22)
			tx_supp_rates |= WLAN_RATE_11M;
	}

	memset(&param, 0, sizeof(param));
	param.cmd = PRISM2_HOSTAPD_ADD_STA;
	memcpy(param.sta_addr, addr, ETH_ALEN);
	param.u.add_sta.aid = aid;
	param.u.add_sta.capability = capability;
	param.u.add_sta.tx_supp_rates = tx_supp_rates;
	return hostapd_ioctl(drv, &param, sizeof(param));
#endif	
}

static int rtl871x_sta_add2_ops(const char *ifname, void *priv,
			 struct hostapd_sta_add_params *params)
{
#if 0
	ieee_param param;
	struct rtl871x_driver_data *drv = priv;
	
	printf("%s\n", __func__);

	memset(&param, 0, sizeof(param));
	param.cmd = RTL871X_HOSTAPD_ADD_STA;
	memcpy(param.sta_addr, params->addr, ETH_ALEN);
	param.u.add_sta.aid = params->aid;
	param.u.add_sta.capability = params->capability;
	param.u.add_sta.flags = params->flags;

	memcpy(param.u.add_sta.tx_supp_rates, params->supp_rates, params->supp_rates_len);

#ifdef CONFIG_IEEE80211N
	if (params->ht_capabilities && params->ht_capabilities->length>0) 
	{
		struct ieee80211_ht_capability *pht_cap = (struct ieee80211_ht_capability *)&params->ht_capabilities->data;
		memcpy((u8*)&param.u.add_sta.ht_cap, (u8*)pht_cap, sizeof(struct ieee80211_ht_capability));
		
	}
#endif /* CONFIG_IEEE80211N */
	
	return rtl871x_hostapd_ioctl(drv, &param, sizeof(param));
#else
	return 0;
#endif
}
#endif

static int rtl871x_sta_remove_ops(void *priv, const u8 *addr)
{
	struct rtl871x_driver_data *drv = priv;
	struct ieee_param param;

	printf("+%s, " MACSTR " is sta address removed\n", __func__, MAC2STR(addr));

	memset(&param, 0, sizeof(param));
	param.cmd = RTL871X_HOSTAPD_REMOVE_STA;
	memcpy(param.sta_addr, addr, ETH_ALEN);
	if (rtl871x_hostapd_ioctl(drv, &param, sizeof(param))) {
		printf("Could not remove station from kernel driver.\n");
		return -1;
	}
	
	return 0;	

}

#define RTL871X_HIDDEN_SSID_SUPPORT
#ifdef RTL871X_HIDDEN_SSID_SUPPORT
static int rtl871x_set_hidden_ssid_ops(const char *iface, void *priv, u8 value)
{
	int ret;
	ieee_param pparam;	
	struct rtl871x_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;

	printf("%s\n", __func__);

	pparam.cmd = RTL871X_HOSTAPD_SET_HIDDEN_SSID;
	pparam.u.wpa_param.name = 0;
	pparam.u.wpa_param.value = value;

	ret = rtl871x_hostapd_ioctl(drv, &pparam, sizeof(ieee_param));

	return ret;	
}

static const u8 * get_ie(u8 *ies, size_t ies_len, u8 id)
{
	const u8 *end, *pos;

	pos = ies;
	end = pos + ies_len;

	while (pos + 1 < end) {
		if (pos + 2 + pos[1] > end)
			break;
		if (pos[0] == id)
			return pos;
		pos += 2 + pos[1];
	}

	return NULL;
}
#endif /* RTL871X_HIDDEN_SSID_SUPPORT */

static int rtl871x_set_beacon_ops(void *priv, struct wpa_driver_ap_params *params)
{
	int ret;
	size_t sz;
	ieee_param *pparam;
	struct rtl871x_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;

	u8 *ssid_ie;
	u8 ssid_len;
	u8 expend_len = 0;
	
	if ((params->head_len<24) ||(!params->head))
		return -1;

	printf("%s\n", __func__);


#ifdef RTL871X_HIDDEN_SSID_SUPPORT
	rtl871x_set_hidden_ssid_ops(drv->iface, priv, hapd->conf->ignore_broadcast_ssid);

	ssid_ie = get_ie((params->head+24+12), (params->head_len-24-12), WLAN_EID_SSID);
	
	if (hapd->conf->ignore_broadcast_ssid == 2) {
		ssid_len = ssid_ie[1];
		
		/* confirm the ssid_len */
		if (ssid_len != hapd->conf->ssid.ssid_len) {
			printf("%s ssid_len(%u) != hapd->conf->ssid.ssid_len(%u)!!\n", __func__
				, ssid_len, hapd->conf->ssid.ssid_len
			);
		}

		memcpy(ssid_ie+2, hapd->conf->ssid.ssid, ssid_len);
	} else if (hapd->conf->ignore_broadcast_ssid == 1) {
		expend_len = hapd->conf->ssid.ssid_len;
		printf("%s ignore_broadcast_ssid:%d, %s,%d, expend_len:%u\n", __func__
			, hapd->conf->ignore_broadcast_ssid
			, hapd->conf->ssid.ssid
			, hapd->conf->ssid.ssid_len
			, expend_len
		);		
	}
#endif /* RTL871X_HIDDEN_SSID_SUPPORT */

	sz = params->head_len+params->tail_len+12-24 + 2 + expend_len; // 12+2 = cmd+sta_addr+reserved, sizeof(ieee_param)=64, no packed
	pparam = os_zalloc(sz);
	if (pparam == NULL) {
		return -ENOMEM;
	}

	pparam->cmd = RTL871X_HOSTAPD_SET_BEACON;

	memcpy(pparam->u.bcn_ie.reserved, &hapd->conf->max_num_sta, 2); // for set max_num_sta

#ifdef RTL871X_HIDDEN_SSID_SUPPORT
	if (hapd->conf->ignore_broadcast_ssid == 1) {
		u8 *ssid_ie_next = params->head+24+12+2;
		size_t head_remain_len = params->head_len-24-12-2;

		memcpy(pparam->u.bcn_ie.buf, (params->head+24), 12); 
		
		pparam->u.bcn_ie.buf[12] = WLAN_EID_SSID;
		pparam->u.bcn_ie.buf[13] = expend_len;
		memcpy(pparam->u.bcn_ie.buf+12+2, hapd->conf->ssid.ssid, expend_len);
		
		memcpy(pparam->u.bcn_ie.buf+12+2+expend_len, ssid_ie_next, head_remain_len); // 24=beacon header len.	
		memcpy(&pparam->u.bcn_ie.buf[params->head_len-24+expend_len], params->tail, params->tail_len);
	}
	else
#endif /* RTL871X_HIDDEN_SSID_SUPPORT */
	{
		memcpy(pparam->u.bcn_ie.buf, (params->head+24), (params->head_len-24)); // 24=beacon header len.
		memcpy(&pparam->u.bcn_ie.buf[params->head_len-24], params->tail, params->tail_len);
	}
	
	ret = rtl871x_hostapd_ioctl(drv, pparam, sz);
	os_free(pparam);

	return ret;
	
}

static int rtl871x_set_key_ops(const char *ifname, void *priv, enum wpa_alg alg,
		const u8 *addr, int idx, int txkey, const u8 *seq,
		size_t seq_len, const u8 *key, size_t key_len)
{
	ieee_param *param;	
	u8 *buf;
	char *alg_str;
	size_t blen;
	int ret = 0;
	struct rtl871x_driver_data *drv = priv;

	printf("%s\n", __func__);

	blen = sizeof(*param) + key_len;
	buf = os_zalloc(blen);
	if (buf == NULL)
		return -1;

	param = (ieee_param *)buf;
	param->cmd = RTL871X_SET_ENCRYPTION;
	if (addr == NULL)
		memset(param->sta_addr, 0xff, ETH_ALEN);
	else
		memcpy(param->sta_addr, addr, ETH_ALEN);

	switch (alg) {
	case WPA_ALG_NONE:
		alg_str = "none";
		break;
	case WPA_ALG_WEP:
		alg_str = "WEP";
		break;
	case WPA_ALG_TKIP:
		alg_str = "TKIP";
		break;
	case WPA_ALG_CCMP:
		alg_str = "CCMP";
		break;
	default:
		printf("%s: unknown/unsupported algorithm %d\n",
			__func__, alg);
		return -1;
	}	
	
	os_strlcpy((char *) param->u.crypt.alg, alg_str,
		   IEEE_CRYPT_ALG_NAME_LEN);
	
	param->u.crypt.set_tx = txkey ? 1 : 0;
	param->u.crypt.idx = idx;
	param->u.crypt.key_len = key_len;
	memcpy(param->u.crypt.key, key, key_len);

	if (rtl871x_hostapd_ioctl(drv, param, blen)) {
		printf("Failed to set encryption.\n");
		ret = -1;
	}
	
	os_free(buf);

	return ret;

}

static int rtl871x_sta_deauth_ops(void *priv, const u8 *own_addr, const u8 *addr,
		   int reason)
{
	struct rtl871x_driver_data *drv = priv;
	struct ieee80211_mgmt mgmt;

	printf("+%s, " MACSTR " is deauth, reason=%d\n", __func__, MAC2STR(addr), reason);

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_DEAUTH);
	
	memcpy(mgmt.da, addr, ETH_ALEN);
	memcpy(mgmt.sa, own_addr, ETH_ALEN);
	memcpy(mgmt.bssid, own_addr, ETH_ALEN);
	mgmt.u.deauth.reason_code = host_to_le16(reason);

	return rtl871x_send_mgmt_frame_ops(drv, &mgmt, IEEE80211_HDRLEN +
				      sizeof(mgmt.u.deauth), 0);
	
}

static int rtl871x_sta_disassoc_ops(void *priv, const u8 *own_addr, const u8 *addr,
		     int reason)
{
	struct rtl871x_driver_data *drv = priv;
	struct ieee80211_mgmt mgmt;

	printf("+%s, " MACSTR " is disassoc, reason=%d\n", __func__, MAC2STR(addr), reason);

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_DISASSOC);
	
	memcpy(mgmt.da, addr, ETH_ALEN);
	memcpy(mgmt.sa, own_addr, ETH_ALEN);
	memcpy(mgmt.bssid, own_addr, ETH_ALEN);
	
	mgmt.u.disassoc.reason_code = host_to_le16(reason);
	
	return  rtl871x_send_mgmt_frame_ops(drv, &mgmt, IEEE80211_HDRLEN +
				       sizeof(mgmt.u.disassoc), 0);

}

static int rtl871x_set_wps_assoc_resp_ie(struct rtl871x_driver_data *drv, const void *ie, size_t len)
{
	int ret;
	size_t sz;
	ieee_param *pparam;

	printf("%s\n", __func__);

	sz = len + 12 + 2; // 12+2 = cmd+sta_addr+reserved, sizeof(ieee_param)=64, no packed
	pparam = os_zalloc(sz);
	if (pparam == NULL) {
		return -ENOMEM;
	}

	pparam->cmd = RTL871X_HOSTAPD_SET_WPS_ASSOC_RESP;	
		
	if (ie && len>0) {
		memcpy(pparam->u.bcn_ie.buf, ie, len);
	}

	ret = rtl871x_hostapd_ioctl(drv, pparam, sz);
	os_free(pparam);

	return ret;
	
}

static int rtl871x_set_wps_beacon_ie(struct rtl871x_driver_data *drv, const void *ie, size_t len)
{
	int ret;
	size_t sz;
	ieee_param *pparam;

	printf("%s\n", __func__);

	sz = len + 12 + 2; // 12+2 = cmd+sta_addr+reserved, sizeof(ieee_param)=64, no packed
	pparam = os_zalloc(sz);
	if (pparam == NULL) {
		return -ENOMEM;
	}

	pparam->cmd = RTL871X_HOSTAPD_SET_WPS_BEACON;	
		
	if (ie && len>0) {
		memcpy(pparam->u.bcn_ie.buf, ie, len);
	}

	ret = rtl871x_hostapd_ioctl(drv, pparam, sz);
	os_free(pparam);

	return ret;
	
}

static int rtl871x_set_wps_probe_resp_ie(struct rtl871x_driver_data *drv, const void *ie, size_t len)
{
	int ret;
	size_t sz;
	ieee_param *pparam;
	
	printf("%s\n", __func__);

	sz = len + 12 + 2; // 12+2 = cmd+sta_addr+reserved, sizeof(ieee_param)=64, no packed
	pparam = os_zalloc(sz);
	if (pparam == NULL) {
		return -ENOMEM;
	}

	pparam->cmd = RTL871X_HOSTAPD_SET_WPS_PROBE_RESP;	
		
	if (ie && len>0) {
		memcpy(pparam->u.bcn_ie.buf, ie, len);
	}

	ret = rtl871x_hostapd_ioctl(drv, pparam, sz);
	os_free(pparam);

	return ret;
	
}

static int rtl871x_set_ap_wps_ie(void *priv, const struct wpabuf *beacon,
		      const struct wpabuf *proberesp, const struct wpabuf *assocresp)
{
	struct rtl871x_driver_data *drv = priv;	

	if (rtl871x_set_wps_assoc_resp_ie(drv, assocresp ? wpabuf_head(assocresp) : NULL,
			       assocresp ? wpabuf_len(assocresp) : 0))
		return -1;

	if (rtl871x_set_wps_beacon_ie(drv, beacon ? wpabuf_head(beacon) : NULL,
			       beacon ? wpabuf_len(beacon) : 0))
		return -1;

	return rtl871x_set_wps_probe_resp_ie(drv,
				  proberesp ? wpabuf_head(proberesp) : NULL,
				  proberesp ? wpabuf_len(proberesp): 0);	

}

static int rtl871x_sta_flush_ops(void *priv)
{
	ieee_param param;
	struct rtl871x_driver_data *drv = priv;	

	memset(&param, 0, sizeof(param));
	param.cmd = RTL871X_HOSTAPD_FLUSH;	
	
	return rtl871x_hostapd_ioctl(drv, &param, sizeof(param));
}

static void *rtl871x_driver_init_ops(struct hostapd_data *hapd, struct wpa_init_params *params)
{
	struct rtl871x_driver_data *drv;
	struct ifreq ifr;
	char	ifrn_name[IFNAMSIZ + 1]; // for mgnt_l2_sock/mgnt_sock
	char brname[IFNAMSIZ];

	drv = os_zalloc(sizeof(struct rtl871x_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for rtl871x driver data\n");
		return NULL;
	}

	drv->hapd = hapd;
	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		goto bad;
	}
	os_memcpy(drv->iface, params->ifname, sizeof(drv->iface));

	linux_set_iface_flags(drv->ioctl_sock, drv->iface, 1); // set interface up

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
	if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		goto bad;
	}
	drv->ifindex = ifr.ifr_ifindex;
	printf("drv->ifindex=%d\n", drv->ifindex);

	drv->l2_sock = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL,
					rtl871x_handle_read, drv, 1);

	if (drv->l2_sock == NULL)
		goto bad;

	if (l2_packet_get_own_addr(drv->l2_sock, params->own_addr))
		goto bad;

	if (params->bridge[0]) {
		wpa_printf(MSG_DEBUG, "Configure bridge %s for EAPOL traffic.",
			   params->bridge[0]);
		drv->l2_sock_recv = l2_packet_init(params->bridge[0], NULL,
						ETH_P_EAPOL, rtl871x_handle_read, drv,
						1);
		if (drv->l2_sock_recv == NULL) {
			drv->l2_sock_recv = drv->l2_sock;
			printf("no br0 interface , let l2_sock_recv==l2_sock_xmit=0x%p\n", drv->l2_sock);	
		}
		
	} else if (linux_br_get(brname, drv->iface) == 0) {
		wpa_printf(MSG_DEBUG, "Interface in bridge %s; configure for "
			   "EAPOL receive", brname);
		drv->l2_sock_recv = l2_packet_init(brname, NULL, ETH_P_EAPOL,
						rtl871x_handle_read, drv, 1);
		if (drv->l2_sock_recv == NULL)
			goto bad;
	} else {
		drv->l2_sock_recv = drv->l2_sock;
		printf("l2_sock_recv==l2_sock_xmit=0x%p\n", drv->l2_sock);	
	}


	os_memset(ifrn_name, 0, sizeof(ifrn_name));
	snprintf(ifrn_name, sizeof(ifrn_name), "mgnt.%s", "wlan0");

#ifdef CONFIG_MGNT_L2SOCK	
	drv->mgnt_l2_sock = NULL;
	drv->mgnt_l2_sock = l2_packet_init(ifrn_name, NULL, ETH_P_80211_RAW,
				       rtl871x_recvive_mgmt_frame, drv, 1);
	if (drv->mgnt_l2_sock == NULL)
		goto bad;
#else
#ifdef CONFIG_MLME_OFFLOAD
	drv->mgnt_sock = -1;
#else
	drv->mgnt_sock = rtl871x_mgnt_sock_init(drv, ifrn_name);
	if (drv->mgnt_sock < 0) {		
		goto bad;
	}
#endif

#endif
	if (rtl871x_set_mode(drv, IW_MODE_MASTER)<0) {
		printf("Could not set interface to master mode!\n");
		goto bad;
	}

#ifndef CONFIG_MLME_OFFLOAD
	rtl871x_set_iface_flags(drv, 1); // set mgnt interface up
#endif

	if (rtl871x_wireless_event_init(drv))
		goto bad;

	os_memcpy(drv->hw_mac, params->own_addr, ETH_ALEN);

	return drv;
	
bad:

	if (drv->l2_sock_recv != NULL && drv->l2_sock_recv != drv->l2_sock)
		l2_packet_deinit(drv->l2_sock_recv);
	
	if (drv->l2_sock != NULL)
		l2_packet_deinit(drv->l2_sock);
	
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);

#ifdef CONFIG_MGNT_L2SOCK
	if ( drv->mgnt_l2_sock != NULL)
		l2_packet_deinit(drv->mgnt_l2_sock);
#else
	if (drv->mgnt_sock >= 0)
		close(drv->mgnt_sock);
#endif
	
	if (drv != NULL)
		free(drv);
	
	return NULL;
}

static void rtl871x_driver_deinit_ops(void *priv)
{
	struct rtl871x_driver_data *drv = priv;

	rtl871x_set_mode(drv, IW_MODE_INFRA);
	
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);
	
	if (drv->l2_sock_recv != NULL && drv->l2_sock_recv != drv->l2_sock)
		l2_packet_deinit(drv->l2_sock_recv);

	if (drv->l2_sock)
		l2_packet_deinit(drv->l2_sock);	
	
#ifdef CONFIG_MGNT_L2SOCK	
	if (drv->mgnt_l2_sock)
		l2_packet_deinit(drv->mgnt_l2_sock);
#else
	if (drv->mgnt_sock >= 0)
		close(drv->mgnt_sock);
#endif

	os_free(drv);
}

const struct wpa_driver_ops wpa_driver_rtw_ops = {
	.name 			= "rtl871xdrv",
	.hapd_init		= rtl871x_driver_init_ops,
	.hapd_deinit		= rtl871x_driver_deinit_ops,
	.hapd_send_eapol	= rtl871x_send_eapol_ops,
	.get_hw_feature_data 	= rtl871x_get_hw_feature_data_ops,
	.sta_remove 		= rtl871x_sta_remove_ops,
	.set_ap	 		= rtl871x_set_beacon_ops,
	.set_key 		= rtl871x_set_key_ops,
	.sta_deauth 		= rtl871x_sta_deauth_ops,
	.sta_disassoc 		= rtl871x_sta_disassoc_ops,
	.set_ap_wps_ie 		= rtl871x_set_ap_wps_ie,
	.flush			= rtl871x_sta_flush_ops,
};
