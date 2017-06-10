/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

//self defined
#define PRO_ADDR_LEN 4
#define DEFAULT_TTL 64
#define IPHEADLEN 5
#define DESTUNREACH_TYPE 3
#define PORTUNREACH_CODE 3
#define IPVERSION 4

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;
  // m_arp.dump();
  // struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) packet;
  // print_hdr_eth(packet.data());
  // print_hdrs(packet.data(), packet.size());
  struct ethernet_hdr* packEthHdr = (struct ethernet_hdr*) packet.data();
  unsigned short etherType = ethertype(packet.data());
  print_hdrs(packet);
  // bool desRouter = false;
  if(etherType == ethertype_ip) {

    printf("-----------------------------ip packet received\n");
    struct ip_hdr* packIpHdr = (struct ip_hdr*) (packet.data() + sizeof(struct ethernet_hdr));
    // struct ip_hdr* ipHdr = (struct ip_hdr*) (packet.data() + sizeof(struct ethrnet_hdr));
    //ip checksum

    // m_arp.insertArpEntry(Buffer(packEthHdr->ether_shost,  packEthHdr->ether_shost + ETHER_ADDR_LEN), packIpHdr->ip_src);

    // print_hdr_ip(packet.data() + sizeof(struct ethernet_hdr));
    uint16_t ipChecksum = ntohs(cksum((const void*)packIpHdr, sizeof(struct ip_hdr)));
    if(ipChecksum != 65535) {
      std::cout << "cksum : " << ipChecksum << std::endl;
    }
    else {
      // printf("--------------------------Insert Arp Entry for source mac and ip");
      // m_arp.insertArpEntry((Buffer)packEthHdr->ether_shost, packIpHdr->ip_src);
      const Interface* interface = findIfaceByIp(packIpHdr->ip_dst);
      if(interface != nullptr) {
        printf("-----------------------------destination is router\n");
        //destination is router
        // if(htons(ipHdr->ip) == interface->ip) {
          // desRouter =  true;
          unsigned short ipType = packIpHdr->ip_p;
          //icmp echo protocol
          if( ipType == ip_protocol_icmp) {
            struct icmp_hdr* packIcmpHdr = (struct icmp_hdr*) (packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
            if((packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr)) < 0) {
              printf("packet too small\n");
              exit(1);
            }
            // std::cout << "packet.size()" << packet.size() << std::endl;
            uint16_t icmpChecksum = ntohs(cksum((const void*)packIcmpHdr, packet.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr)));
            if(icmpChecksum != 65535) {
              printf("icmpchecksum wrong!");
              std::cout << "icmpcksum : " << icmpChecksum << std::endl;

            }
            printf("-----------------------icmp to router. echo\n");
            // print_hdr_icmp(packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
            //construct the icmp echo reply pack
            RoutingTableEntry entry = m_routingTable.lookup(packIpHdr->ip_src);
            std::shared_ptr<ArpEntry> arpEntry = m_arp.lookup(entry.gw);
            if(arpEntry == nullptr) {
              printf("-------------------Arp entry not in cache\n");
              // Buffer buf(packet.size());
              printf("queue request\n");
              m_arp.queueRequest(entry.gw, packet, entry.ifName);
            }
            else {
              Buffer buf(packet.size());
              memset(buf.data(), '\0', buf.size());
              struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();

              //ethernet header filling
              memcpy(ethHdr->ether_dhost, packEthHdr->ether_shost, ETHER_ADDR_LEN);
              const Interface* interface = findIfaceByIp(packIpHdr->ip_dst);
              memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN);
              ethHdr->ether_type = htons(ethertype_ip);

              //IP header filling
              //htons
              struct ip_hdr* ipHdr = (struct ip_hdr*) (buf.data() + sizeof(ethernet_hdr));
              ipHdr->ip_v = packIpHdr->ip_v;
              ipHdr->ip_hl = packIpHdr->ip_hl;
              ipHdr->ip_tos = packIpHdr->ip_tos;
              ipHdr->ip_len = packIpHdr->ip_len;
              ipHdr->ip_id = packIpHdr->ip_id;
              ipHdr->ip_off = packIpHdr->ip_off;
              ipHdr->ip_ttl = DEFAULT_TTL;
              ipHdr->ip_p = ip_protocol_icmp;
              ipHdr->ip_src = packIpHdr->ip_dst;
              ipHdr->ip_dst = packIpHdr->ip_src;
              ipHdr->ip_sum = 0;
              ipHdr->ip_sum = cksum((const void*) ipHdr, sizeof(struct ip_hdr));

              //icmp filling
              struct icmp_hdr* icmpHdr = (struct icmp_hdr*) (buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
              icmpHdr->icmp_type = 0;
              icmpHdr->icmp_code = 0;// echo type and code
              icmpHdr->icmp_sum = 0;
              printf("copy icmp payload and seq, id\n");
              int payloadLen = packet.size() - (sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
              if(payloadLen < 0) {
                printf("bufsize wrong\n");

                std::cout << "packet size : " << packet.size() <<"  payload len : " << payloadLen << std::endl;
                std::cout << "ethernet_hdr size : " << sizeof(struct ethernet_hdr) <<"  ip_hdr len : " << sizeof(struct ip_hdr) <<"  icmp_hdr len : " << sizeof(struct icmp_hdr) << std::endl;
                exit(1);
              }

              memcpy(buf.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr), payloadLen);

              icmpHdr->icmp_sum = cksum((const void*) icmpHdr, buf.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
              printf("---------------send icmp echo reply\n");
              print_hdrs(buf);
              // print_hdr_icmp(buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
              sendPacket(buf, inIface);
            }


          }
          else {
            printf("---------------------udp/tcp to router----- port unreachable\n");
            Buffer buf(sizeof(struct icmp_t3_hdr) + sizeof(struct ip_hdr) + sizeof(struct ethernet_hdr) +  ICMP_DATA_SIZE);
            memset(buf.data(), '\0', buf.size());
            struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
            struct ip_hdr* ipHdr = (struct ip_hdr*) (buf.data() + sizeof(ethernet_hdr));
            struct icmp_t3_hdr* icmpHdr = (struct icmp_t3_hdr*) (buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));


            //ethernet header filling
            memcpy(ethHdr->ether_dhost, packEthHdr->ether_shost, ETHER_ADDR_LEN);
            const Interface* interface = findIfaceByName(inIface);
            memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN);
            ethHdr->ether_type = htons(ethertype_ip);

            //IP header filling
            //htons
            ipHdr->ip_v = IPVERSION;
            ipHdr->ip_hl = IPHEADLEN;
            ipHdr->ip_tos = packIpHdr->ip_tos;
            ipHdr->ip_len = htons(ICMP_DATA_SIZE + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
            ipHdr->ip_id = packIpHdr->ip_id;
            ipHdr->ip_off = packIpHdr->ip_off;
            ipHdr->ip_ttl = DEFAULT_TTL;
            ipHdr->ip_p = ip_protocol_icmp;
            ipHdr->ip_src = packIpHdr->ip_dst;
            ipHdr->ip_dst = packIpHdr->ip_src;
            ipHdr->ip_sum = 0;
            ipHdr->ip_sum = cksum((const void*) ipHdr, sizeof(struct ip_hdr));

            icmpHdr->icmp_type = 3;
            icmpHdr->icmp_code = 3;
            memset(&icmpHdr->unused, 0, 4);
            memset(&icmpHdr->next_mtu, 0, 4);
            memcpy(icmpHdr->data, packIpHdr, ICMP_DATA_SIZE);
            icmpHdr->icmp_sum = 0;
            icmpHdr->icmp_sum = cksum((const void*) icmpHdr, buf.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
            print_hdrs(buf);
            sendPacket(buf, inIface);
          }
        // }
      }
      else {
        //ip pack for others
        printf("---------------------------ip packet sending to host/client\n");
         uint8_t ttl = packIpHdr->ip_ttl - 1;
        if(ttl <= 0) {
          printf("---------------------------ICMP time excceed\n");
          Buffer buf(4 + sizeof(struct icmp_hdr) + sizeof(struct ip_hdr) + sizeof(struct ethernet_hdr) + ICMP_DATA_SIZE);
          memset(buf.data(), '\0', buf.size());
          struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
          struct ip_hdr* ipHdr = (struct ip_hdr*) (buf.data() + sizeof(ethernet_hdr));
          struct icmp_hdr* icmpHdr = (struct icmp_hdr*) (buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));


          //ethernet header filling
          memcpy(ethHdr->ether_dhost, packEthHdr->ether_shost, ETHER_ADDR_LEN);
          const Interface* interface = findIfaceByName(inIface);
          memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN);
          ethHdr->ether_type = htons(ethertype_ip);

          //IP header filling
          //htons
          ipHdr->ip_v = IPVERSION;
          ipHdr->ip_hl = IPHEADLEN;
          ipHdr->ip_tos = packIpHdr->ip_tos;
          ipHdr->ip_len = htons(4 + ICMP_DATA_SIZE + sizeof(struct ip_hdr) + sizeof(struct icmp_hdr));
          ipHdr->ip_id = packIpHdr->ip_id;
          ipHdr->ip_off = packIpHdr->ip_off;
          ipHdr->ip_ttl = DEFAULT_TTL;
          ipHdr->ip_p = ip_protocol_icmp;
          ipHdr->ip_src = interface->ip;
          ipHdr->ip_dst = packIpHdr->ip_src;
          ipHdr->ip_sum = 0;
          ipHdr->ip_sum = cksum((const void*) ipHdr, sizeof(struct ip_hdr));

          icmpHdr->icmp_type = 11;
          icmpHdr->icmp_code = 0;
          memcpy(buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr) + 8, packIpHdr, ICMP_DATA_SIZE);
          icmpHdr->icmp_sum = 0;
          icmpHdr->icmp_sum = cksum((const void*) icmpHdr, buf.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
          print_hdrs(buf);
          // print_hdr_icmp(buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
          sendPacket(buf, inIface);
        }
        else {
          // try {
          //   RoutingTableEntry entry = m_routingTable.lookup(packIpHdr->ip_dst);
          // }
          // if(entry == nullptr) {
          //   printf("--------------------------icmp network unreachable!");
          //   Buffer buf(sizeof(struct icmp_t3_hdr) + sizeof(struct ip_hdr) + sizeof(struct ethernet_hdr));
          //   memset(buf.data(), '\0', buf.size());
          //   struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
          //   struct ip_hdr* ipHdr = (struct ip_hdr*) (buf.data() + sizeof(ethernet_hdr));
          //   struct icmp_t3_hdr* icmpHdr = (struct icmp_t3_hdr*) (buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));
          //
          //
          //   //ethernet header filling
          //   memcpy(ethHdr->ether_dhost, packEthHdr->ether_shost, ETHER_ADDR_LEN);
          //   const Interface* interface = findIfaceByName(inIface);
          //   memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN);
          //   ethHdr->ether_type = htons(ethertype_ip);
          //
          //   //IP header filling
          //   //htons
          //   ipHdr->ip_hl = htons(IPHEADLEN);
          //   ipHdr->ip_tos = htons(packIpHdr->ip_tos);
          //   ipHdr->ip_len = htons(ICMP_DATA_SIZE + sizeof(struct ip_hdr));
          //   ipHdr->ip_id = htons(packIpHdr->ip_id);
          //   ipHdr->ip_off = htons(packIpHdr->ip_off);
          //   ipHdr->ip_ttl = htons(DEFAULT_TTL);
          //   ipHdr->ip_p = htons(ip_protocol_icmp);
          //   ipHdr->ip_src = htons(interface->ip);
          //   ipHdr->ip_dst = htons(packIpHdr->ip_src);
          //   ipHdr->ip_sum = 0;
          //   ipHdr->ip_sum = htons(cksum((const void*) ipHdr, sizeof(struct ip_hdr)));
          //
          //   icmpHdr->icmp_type = htons(3);
          //   icmpHdr->icmp_code = htons(0);
          //   memcpy(icmpHdr->data, packIpHdr, ICMP_DATA_SIZE);
          //   icmpHdr->icmp_sum = 0;
          //   icmpHdr->icmp_sum = cksum((const void*) icmpHdr, sizeof(struct icmp_hdr));
          //
          //   sendPacket(buf, inIface);
          // }
          try {
            printf("match in router table.\n");
            RoutingTableEntry entry = m_routingTable.lookup(packIpHdr->ip_dst);
            // printf("--------------router entry found");
            // printf("arp table:\n");
            // m_arp.dump();
            std::shared_ptr<ArpEntry> arpEntry = m_arp.lookup(entry.gw);
            if(arpEntry == nullptr) {
              printf("-------------------Arp entry not in cache\n");
              // Buffer buf(packet.size());
              printf("queue request\n");
              m_arp.queueRequest(entry.gw, packet, entry.ifName);
            }
            else {
              printf("-------------------Arp entry in cache\n");
              Buffer buf(packet.size());
              memcpy(buf.data(), packet.data(), packet.size());
              struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
              struct ip_hdr* ipHdr = (struct ip_hdr*) (buf.data() + sizeof(ethernet_hdr));
              ipHdr->ip_ttl = ipHdr->ip_ttl - 1;

              //ethernet header filling
              memcpy(ethHdr->ether_dhost, (arpEntry->mac).data(), ETHER_ADDR_LEN);
              const Interface* interface = findIfaceByName(entry.ifName);
              memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN);
              ethHdr->ether_type = htons(ethertype_ip);
              ipHdr->ip_sum = 0;
              ipHdr->ip_sum = cksum((void *)ipHdr, sizeof(struct ip_hdr));
              print_hdrs(buf);
              sendPacket(buf, entry.ifName);
            }

          }
          catch(const std::runtime_error& error) {
            printf("--------------------------icmp network unreachable!\n");
            Buffer buf(sizeof(struct icmp_t3_hdr) + sizeof(struct ip_hdr) + sizeof(struct ethernet_hdr) + ICMP_DATA_SIZE);
            memset(buf.data(), '\0', buf.size());
            struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
            struct ip_hdr* ipHdr = (struct ip_hdr*) (buf.data() + sizeof(ethernet_hdr));
            struct icmp_t3_hdr* icmpHdr = (struct icmp_t3_hdr*) (buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));


            //ethernet header filling
            memcpy(ethHdr->ether_dhost, packEthHdr->ether_shost, ETHER_ADDR_LEN);
            const Interface* interface = findIfaceByName(inIface);
            memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN);
            ethHdr->ether_type = htons(ethertype_ip);

            //IP header filling
            //htons
            ipHdr->ip_v = IPVERSION;
            ipHdr->ip_hl = IPHEADLEN;
            ipHdr->ip_tos = packIpHdr->ip_tos;
            ipHdr->ip_len = htons(ICMP_DATA_SIZE + sizeof(struct ip_hdr) + sizeof(struct icmp_t3_hdr));
            ipHdr->ip_id = packIpHdr->ip_id;
            ipHdr->ip_off = packIpHdr->ip_off;
            ipHdr->ip_ttl = DEFAULT_TTL;
            ipHdr->ip_p = ip_protocol_icmp;
            ipHdr->ip_src = interface->ip;
            ipHdr->ip_dst = packIpHdr->ip_src;
            ipHdr->ip_sum = 0;
            ipHdr->ip_sum = cksum((const void*) ipHdr, sizeof(struct ip_hdr));

            icmpHdr->icmp_type = 3;
            icmpHdr->icmp_code = 0;
            memcpy(icmpHdr->data, packIpHdr, ICMP_DATA_SIZE);
            icmpHdr->icmp_sum = 0;
            icmpHdr->icmp_sum = cksum((const void*) icmpHdr, buf.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
            print_hdrs(buf);
            sendPacket(buf, inIface);
          }
        }
      }
    }
  }
  else if(etherType == ethertype_arp ){
    printf("-----------------------------arp packet received\n");
    struct arp_hdr* packArpHdr = (struct arp_hdr*) (packet.data() + sizeof(struct ethernet_hdr));
    // print_hdr_arp(packet.data() + sizeof(struct ethernet_hdr));
    // std::cout << "packArpHdr->arp_op" << ntohs(packArpHdr->arp_op) << std::endl;
    // std::cout << "arp_op_reply" << arp_op_reply << std::endl;
    if(ntohs(packArpHdr->arp_op) == arp_op_reply) {
      printf("======================arpreply received\n");
      //arpHdr for received arpPack
      struct arp_hdr* arpHdr = (struct arp_hdr*)(packet.data() + sizeof(ethernet_hdr));

      std::shared_ptr<ArpRequest> arpRequest = m_arp.insertArpEntry(Buffer(packArpHdr->arp_sha,  packArpHdr->arp_sha + ETHER_ADDR_LEN), packArpHdr->arp_sip);
      if(arpRequest != nullptr) {
        printf("-----------------send all IPpack attached to the arp pack\n");
        for(const auto& ipPacket : arpRequest->packets) {
          Buffer ip_Packet = ipPacket.packet;
          Buffer buf(ip_Packet.size());
          memcpy(buf.data(), ip_Packet.data(), ip_Packet.size());
          struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
          struct ip_hdr* ipHdr = (struct ip_hdr*) (buf.data() + sizeof(struct ethernet_hdr));
          //reduce ttl
          ipHdr->ip_ttl = ipHdr->ip_ttl - 1;
          //ethernet header changes
          memcpy(ethHdr->ether_dhost, arpHdr->arp_sha, ETHER_ADDR_LEN);
          memcpy(ethHdr->ether_shost, findIfaceByName(inIface)->addr.data(), ETHER_ADDR_LEN);
          ethHdr->ether_type = htons(ethertype_ip);
          //calculate checksum again
          ipHdr->ip_sum = 0;
          ipHdr->ip_sum = cksum((void *)ipHdr, sizeof(struct ip_hdr));
          print_hdrs(buf);
          sendPacket(buf, inIface);
        }

        m_arp.removeRequest(arpRequest);
      }
    }
    else if(ntohs(packArpHdr->arp_op) == arp_op_request) {
      printf("======================arprequest received\n");

      struct ethernet_hdr* packEthHdr = (struct ethernet_hdr*) packet.data();
      struct arp_hdr* packArpHdr = (struct arp_hdr*)(packet.data() + sizeof(ethernet_hdr));
      // print_hdr_arp(packet.data() + sizeof(struct ethernet_hdr));

      // m_arp.insertArpEntry(Buffer(packEthHdr->ether_shost,  packEthHdr->ether_shost + ETHER_ADDR_LEN), packArpHdr->arp_sip);

      if(findIfaceByName(inIface)->ip == packArpHdr->arp_tip) {
        printf("request mac of router ------------------send arpreply\n");
        Buffer buf(sizeof(struct ethernet_hdr) + sizeof(struct arp_hdr));
        struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
        struct arp_hdr* arpHdr = (struct arp_hdr*)(buf.data() + sizeof(struct ethernet_hdr));
        arpHdr->arp_hrd = htons(arp_hrd_ethernet);
        arpHdr->arp_pro = htons(ethertype_ip);
        arpHdr->arp_hln = ETHER_ADDR_LEN;
        arpHdr->arp_pln = PRO_ADDR_LEN;
        arpHdr->arp_op = htons(arp_op_reply);
        arpHdr->arp_tip = packArpHdr->arp_sip;
        arpHdr->arp_sip = packArpHdr->arp_tip;
        memcpy(arpHdr->arp_tha, packArpHdr->arp_sha, ETHER_ADDR_LEN);
        memcpy(arpHdr->arp_sha, (findIfaceByName(inIface)->addr).data(), ETHER_ADDR_LEN);

        memcpy(ethHdr->ether_dhost, packEthHdr->ether_shost, ETHER_ADDR_LEN);
        memcpy(ethHdr->ether_shost, (findIfaceByName(inIface)->addr).data(), ETHER_ADDR_LEN);
        ethHdr->ether_type = htons(ethertype_arp);
        print_hdrs(buf);
        sendPacket(buf, inIface);
      }
    }

  }
  // FILL THIS IN

}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
