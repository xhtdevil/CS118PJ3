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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

//self define
#include "core/protocol.hpp"
// #define HRDTTPE 0x0001
// #define PROTYPE 0x0800
#define PRO_ADDR_LEN 4
#define DEFAULT_TTL 64
#define IPHEADLEN 5
#define DESTUNREACH_TYPE 3
#define PORTUNREACH_CODE 3

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // std::list<std::shared_ptr<ArpEntry>> m_cacheEntries;
  for (const auto& arpRequest : m_arpRequests) {
    handle_arpreq(arpRequest);
  }
  for (auto entry = m_cacheEntries.begin(); entry != m_cacheEntries.end(); ++entry) {
    if(!(*entry)->isValid) {
      //removeCached entry
      //why need to record and remove together?
      // removeRequest(entry);
      //std::lock_guard<std::mutex> lock(m_mutex);
      m_cacheEntries.erase(entry++);
      printf("---------------------cacheEntries removed after 40s\n");
    }
  }
  // FILL THIS IN

}

void ArpCache::handle_arpreq(const std::shared_ptr<ArpRequest>& arpRequest) {
  printf("handle arpRequest.\n");
  // time_point current = (time_point)std::chrono::system_clock::now();
  auto current = steady_clock::now();
  if((current -  seconds(1)) > arpRequest->timeSent) {
    if(arpRequest->nTimesSent >= MAX_SENT_TIME) {
      //create icmp packet unreachable and remove the request from queue
      //response all packets under the request with unreachable icmp
      for(const auto& pendingPacket : arpRequest->packets) {
        Buffer ip_Packet = pendingPacket.packet;
        struct ip_hdr* packIpHdr = (struct ip_hdr*) (ip_Packet.data() + sizeof(struct ethernet_hdr));
        struct ethernet_hdr* packEthHdr = (struct ethernet_hdr*) ip_Packet.data();
        //do not send icmp pack for icmp
        struct icmp_hdr* icmpHdr = (struct icmp_hdr*)(ip_Packet.data() + sizeof(struct ethernet_hdr) + sizeof(struct ip_hdr));
        if(packIpHdr->ip_p != ip_protocol_icmp || icmpHdr->icmp_code == 8) {
          Buffer buf(sizeof(struct icmp_t3_hdr) + sizeof(struct ip_hdr) + sizeof(struct ethernet_hdr));
          memset(buf.data(), '\0', sizeof(buf));
          struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) buf.data();
          struct ip_hdr* ipHdr = (struct ip_hdr*)(buf.data() + sizeof(ethernet_hdr));
          struct icmp_t3_hdr* icmpHdr = (struct icmp_t3_hdr*) (buf.data() + sizeof(ethernet_hdr) + sizeof(ip_hdr));


          //ethernet header filling
          memcpy(ethHdr->ether_dhost, packEthHdr->ether_shost, ETHER_ADDR_LEN);
          const Interface* interface = m_router.findIfaceByName(pendingPacket.iface);
          memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN);
          ethHdr->ether_type = ethertype_ip;

          //IP header filling
          //htons
          ipHdr->ip_hl = IPHEADLEN;
          ipHdr->ip_tos = packIpHdr->ip_tos;
          ipHdr->ip_len = htons(ICMP_DATA_SIZE + sizeof(struct icmp_t3_hdr) + sizeof(struct ip_hdr));
          ipHdr->ip_id = packIpHdr->ip_id;
          ipHdr->ip_off = packIpHdr->ip_off;
          ipHdr->ip_ttl = DEFAULT_TTL;
          ipHdr->ip_p = ip_protocol_icmp;
          ipHdr->ip_src = interface->ip;
          ipHdr->ip_dst = packIpHdr->ip_src;
          ipHdr->ip_sum = 0;
          ipHdr->ip_sum = cksum((const void*) ipHdr, sizeof(struct ip_hdr));

          icmpHdr->icmp_type = 3;
          icmpHdr->icmp_code = 1;
          memcpy(icmpHdr->data, packIpHdr, ICMP_DATA_SIZE);
          icmpHdr->icmp_sum = 0;
          icmpHdr->icmp_sum = cksum((const void*) icmpHdr, buf.size() - sizeof(struct ethernet_hdr) - sizeof(struct ip_hdr));
          print_hdrs(buf);
          m_router.sendPacket(buf, interface->name);
        }
      }
      removeRequest(arpRequest);
      // m_arpRequests.remove(arpRequest);
    }
    else {
      // send arpRequest
      Buffer buf(sizeof(struct arp_hdr) + sizeof(struct ethernet_hdr));
      struct arp_hdr* arp = (struct arp_hdr*) (buf.data() + sizeof(struct ethernet_hdr));
      arp->arp_hrd = htons(arp_hrd_ethernet);
      arp->arp_pro = htons(ethertype_ip);
      arp->arp_hln = ETHER_ADDR_LEN;
      arp->arp_pln = PRO_ADDR_LEN;
      arp->arp_op = htons(arp_op_request);
      arp->arp_tip = arpRequest->ip;
      const RoutingTable& routingTable = m_router.getRoutingTable();
      struct RoutingTableEntry routingEntry = routingTable.lookup(arpRequest->ip);
      const Interface* interface = m_router.findIfaceByName(routingEntry.ifName);
      arp->arp_sip = interface->ip;
      memcpy(arp->arp_sha, (interface->addr).data(), ETHER_ADDR_LEN); //sender mac address
      memset(arp->arp_tha, 255, ETHER_ADDR_LEN);
      struct ethernet_hdr* ethHdr = (struct ethernet_hdr*) (buf.data());
      memset(ethHdr->ether_dhost, 255, ETHER_ADDR_LEN); //ethernet header destination address
      memcpy(ethHdr->ether_shost, (interface->addr).data(), ETHER_ADDR_LEN); //ethernet header source address
      ethHdr->ether_type = htons(ethertype_arp);
      print_hdrs(buf);
      m_router.sendPacket(buf, interface->name);
      arpRequest->nTimesSent += 1;
      arpRequest->timeSent = current;
    }
  }
}


//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();

}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
