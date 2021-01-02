#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "netdissect-stdinc.h"

#include "netdissect.h"
#include "extract.h"

//#ifdef DLT_RPMSG

struct rpmsg_header {
  uint32_t src;
  uint32_t dst;
  uint32_t reserved;
  uint16_t length;
  uint16_t flags;
};

struct rpmsg_mon_header {
  uint64_t timestamp;
  uint32_t interface;
  uint16_t vq;
  uint16_t res;
  struct rpmsg_header hdr;
};

struct rpmsg_endpoint_info {
  char name[32];
  uint32_t addr;
  uint32_t flags;
};

void
rpmsg_if_print(netdissect_options *ndo, const struct pcap_pkthdr *h,
                           const u_char *p)
{
  struct rpmsg_mon_header *header = (struct rpmsg_mon_header*) p;

	ndo->ndo_protocol = "rpmsg";
	ndo->ndo_ll_hdr_len += sizeof (struct rpmsg_mon_header);
  ND_PRINT("%x -> %x flags %x, %d bytes", header->hdr.src, header->hdr.dst, header->hdr.flags, header->hdr.length);

  if(header->hdr.dst == 53) {
    struct rpmsg_endpoint_info *info = (struct rpmsg_endpoint_info*) (p + sizeof(struct rpmsg_mon_header));
    ndo->ndo_ll_hdr_len += sizeof (struct rpmsg_endpoint_info);
    ND_PRINT(", NS_ANNOUNCE %s, addr: %d, flags: %d", info->name, info->addr, info->flags);
  }

	return;
}

//#endif /* DLT_RPMSG */

