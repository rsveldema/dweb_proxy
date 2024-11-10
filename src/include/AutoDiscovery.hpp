#pragma once

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string>
#include <thread>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>

#include <avahi-client/lookup.h>

#include <avahi-common/simple-watch.h>

namespace dweb
{
class AutoDiscovery
{
  public:
  void start();
  void stop();

  void client_callback(AvahiClient *c, AvahiClientState state);
  void browse_callback(AvahiServiceBrowser *b,
                       AvahiIfIndex interface,
                       AvahiProtocol protocol,
                       AvahiBrowserEvent event,
                       const char *name,
                       const char *type,
                       const char *domain,
                       AvahiLookupResultFlags flags);
  void resolve_callback(AvahiServiceResolver *r,
                        AvahiIfIndex interface,
                        AvahiProtocol protocol,
                        AvahiResolverEvent event,
                        const char *name,
                        const char *type,
                        const char *domain,
                        const char *host_name,
                        const AvahiAddress *address,
                        uint16_t port,
                        AvahiStringList *txt,
                        AvahiLookupResultFlags flags);

private:
    AvahiEntryGroup *m_group = nullptr;
    AvahiSimplePoll *m_simple_poll = nullptr;
    std::string m_name = "dweb";
    AvahiClient *m_client = nullptr;
    AvahiServiceBrowser *m_service_browser = NULL;
    std::thread m_thr;

    void create_services();
  };
} // namespace dweb