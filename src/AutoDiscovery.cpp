#include <AutoDiscovery.hpp>

#ifdef HAVE_CONFIG_H
  #include <config.h>
#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>

#include <avahi-client/client.h>
#include <avahi-client/publish.h>

#include <avahi-common/alternative.h>
#include <avahi-common/simple-watch.h>
#include <avahi-common/malloc.h>
#include <avahi-common/error.h>
#include <avahi-common/timeval.h>
#include <avahi-client/lookup.h>

#include <avahi-common/simple-watch.h>

#include "logger.hpp"

namespace dweb
{
static void entry_group_callback(AvahiEntryGroup *g,
                                 AvahiEntryGroupState state,
                                 AVAHI_GCC_UNUSED void *userdata)
{
}

void AutoDiscovery::create_services()
{
  /* If this is the first time we're called, let's create a new
   * entry group if necessary */

  if (!m_group)
  {
    if (!(m_group =
              avahi_entry_group_new(m_client, entry_group_callback, NULL)))
    {
      LOG_ERROR("avahi_entry_group_new() failed: %s\n",
                avahi_strerror(avahi_client_errno(m_client)));
      abort();
    }
  }

  /* If the group is empty (either because it was just created, or
   * because it was reset previously, add our entries.  */

  if (avahi_entry_group_is_empty(m_group))
  {
    LOG_INFO("Adding service {}", m_name);

    /* Create some random TXT data */
    char r[512];
    snprintf(r, sizeof(r), "random=%i", rand());

    /* We will now add two services and one subtype to the entry
     * group. The two services have the same name, but differ in
     * the service type (IPP vs. BSD LPR). Only services with the
     * same name should be put in the same entry group. */

    AvahiPublishFlags flags{};
    if (const auto ret = avahi_entry_group_add_service(
            m_group, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, flags, m_name.c_str(),
            "_dweb._tcp", nullptr, nullptr, 651, "test=blah", r, nullptr);
        ret < 0)
    {
      if (ret == AVAHI_ERR_COLLISION)
      {
        /* A service name collision with a local service happened. Let's
         * pick a new name */
        const auto n = avahi_alternative_service_name(m_name.c_str());
        m_name = n;

        LOG_INFO("Service name collision, renaming service to {}", m_name);

        avahi_entry_group_reset(m_group);

        create_services();
        return;
      }

      LOG_ERROR("Failed to add _dweb._tcp service: {}", avahi_strerror(ret));
      goto fail;
    }

    /* Tell the server to register the service */
    if (const auto ret = avahi_entry_group_commit(m_group); ret < 0)
    {
      LOG_ERROR("Failed to commit entry group: {}", avahi_strerror(ret));
      goto fail;
    }
  }

  return;

fail:
  avahi_simple_poll_quit(m_simple_poll);
}

void AutoDiscovery::client_callback(AvahiClient *c, AvahiClientState state)
{
  m_client = c;
  assert(c);

  switch (state)
  {
  case AVAHI_CLIENT_S_RUNNING:
    create_services();
    break;

  case AVAHI_CLIENT_FAILURE:
    LOG_ERROR("Client failure: {}", avahi_strerror(avahi_client_errno(c)));
    avahi_simple_poll_quit(m_simple_poll);
    break;

  case AVAHI_CLIENT_S_COLLISION:
    /* Let's drop our registered services. When the server is back
     * in AVAHI_SERVER_RUNNING state we will register them
     * again with the new host name. */

  case AVAHI_CLIENT_S_REGISTERING:

    /* The server records are now being established. This
     * might be caused by a host name change. We need to wait
     * for our own records to register until the host name is
     * properly esatblished. */

    if (m_group)
    {
      avahi_entry_group_reset(m_group);
    }
    break;

  case AVAHI_CLIENT_CONNECTING:;
  }
}

static void trampoline_client_callback(AvahiClient *c,
                                       AvahiClientState state,
                                       void *userdata)
{
  auto *self = (AutoDiscovery *)userdata;
  self->client_callback(c, state);
}

void AutoDiscovery::resolve_callback(AvahiServiceResolver *r,
                                     AVAHI_GCC_UNUSED AvahiIfIndex interface,
                                     AVAHI_GCC_UNUSED AvahiProtocol protocol,
                                     AvahiResolverEvent event,
                                     const char *name,
                                     const char *type,
                                     const char *domain,
                                     const char *host_name,
                                     const AvahiAddress *address,
                                     uint16_t port,
                                     AvahiStringList *txt,
                                     AvahiLookupResultFlags flags)
{
  assert(r);

  /* Called whenever a service has been resolved successfully or timed out */

  switch (event)
  {
  case AVAHI_RESOLVER_FAILURE:
  LOG_ERROR(
            "(Resolver) Failed to resolve service '{}' of type '{}' in domain "
            "'{}': {}\n",
            name, type, domain,
            avahi_strerror(
                avahi_client_errno(avahi_service_resolver_get_client(r))));
    break;

  case AVAHI_RESOLVER_FOUND: {
    LOG_INFO("Service '%s' of type '%s' in domain '%s':\n", name, type,
            domain);

    char a[AVAHI_ADDRESS_STR_MAX];
    avahi_address_snprint(a, sizeof(a), address);

    auto* t = avahi_string_list_to_string(txt);
    LOG_INFO(
            "\t{}:{} ({})\n"
            "\tTXT={}\n"
            "\tcookie is {}\n"
            "\tis_local: {}\n"
            "\tour_own: {}\n"
            "\twide_area: {}\n"
            "\tmulticast: {}\n"
            "\tcached: {}\n",
            host_name, port, a, t, avahi_string_list_get_service_cookie(txt),
            !!(flags & AVAHI_LOOKUP_RESULT_LOCAL),
            !!(flags & AVAHI_LOOKUP_RESULT_OUR_OWN),
            !!(flags & AVAHI_LOOKUP_RESULT_WIDE_AREA),
            !!(flags & AVAHI_LOOKUP_RESULT_MULTICAST),
            !!(flags & AVAHI_LOOKUP_RESULT_CACHED));

    avahi_free(t);
  }
  }

  avahi_service_resolver_free(r);
}

static void trampoline_resolve_callback(AvahiServiceResolver *r,
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
                                        AvahiLookupResultFlags flags,
                                        void *userdata)
{
  auto *self = (AutoDiscovery *)userdata;
  self->resolve_callback(r, interface, protocol, event, name, type, domain,
                         host_name, address, port, txt, flags);
}

void AutoDiscovery::browse_callback(AvahiServiceBrowser *b,
                                    AvahiIfIndex interface,
                                    AvahiProtocol protocol,
                                    AvahiBrowserEvent event,
                                    const char *name,
                                    const char *type,
                                    const char *domain,
                                    AvahiLookupResultFlags flags)
{
  /* Called whenever a new services becomes available on the LAN or is removed
   * from the LAN */

  switch (event)
  {
  case AVAHI_BROWSER_FAILURE:

    LOG_ERROR("(Browser) {}", avahi_strerror(avahi_client_errno(
                                  avahi_service_browser_get_client(b))));
    avahi_simple_poll_quit(m_simple_poll);
    return;

  case AVAHI_BROWSER_NEW: {
    LOG_INFO("(Browser) NEW: service '{}' of type '{}' in domain '%s'\n", name,
             type, domain);

    /* We ignore the returned resolver object. In the callback
       function we free it. If the server is terminated before
       the callback function is called the server will free
       the resolver for us. */

    AvahiLookupFlags flags{};
    if (!(avahi_service_resolver_new(m_client, interface, protocol, name, type,
                                     domain, AVAHI_PROTO_UNSPEC, flags,
                                     trampoline_resolve_callback, this)))
    {
      LOG_INFO("Failed to resolve service '{}': {}\n", name,
               avahi_strerror(avahi_client_errno(m_client)));
    }
    break;
  }

  case AVAHI_BROWSER_REMOVE:
    LOG_INFO("(Browser) REMOVE: service '{}' of type '{}' in domain '{}'\n",
             name, type, domain);
    break;

  case AVAHI_BROWSER_ALL_FOR_NOW:
  case AVAHI_BROWSER_CACHE_EXHAUSTED:
    LOG_INFO("(Browser) {}", event == AVAHI_BROWSER_CACHE_EXHAUSTED
                                 ? "CACHE_EXHAUSTED"
                                 : "ALL_FOR_NOW");
    break;
  }
}

static void trompoline_browse_callback(AvahiServiceBrowser *b,
                                       AvahiIfIndex interface,
                                       AvahiProtocol protocol,
                                       AvahiBrowserEvent event,
                                       const char *name,
                                       const char *type,
                                       const char *domain,
                                       AvahiLookupResultFlags flags,
                                       void *userdata)
{
  auto *self = (AutoDiscovery *)userdata;
  self->browse_callback(b, interface, protocol, event, name, type, domain,
                        flags);
}

void AutoDiscovery::start()
{
  /* Allocate main loop object */
  if (!(m_simple_poll = avahi_simple_poll_new()))
  {
    LOG_ERROR("Failed to create simple poll object.");
    abort();
  }

  int error = 0;
  AvahiClientFlags flags{};
  m_client = avahi_client_new(avahi_simple_poll_get(m_simple_poll), flags,
                              trampoline_client_callback, this, &error);

  /* Create the service browser */
  AvahiLookupFlags lookup_flags{};
  if (!(m_service_browser = avahi_service_browser_new(
            m_client, AVAHI_IF_UNSPEC, AVAHI_PROTO_UNSPEC, "_http._tcp", NULL,
            lookup_flags, trompoline_browse_callback, this)))
  {
    LOG_ERROR("Failed to create service browser: {}",
              avahi_strerror(avahi_client_errno(m_client)));
    abort();
  }

  m_thr = std::thread([this]() { avahi_simple_poll_loop(m_simple_poll); });
}

void AutoDiscovery::stop()
{
  avahi_client_free(m_client);
  avahi_simple_poll_free(m_simple_poll);
  m_thr.join();
}

} // namespace dweb