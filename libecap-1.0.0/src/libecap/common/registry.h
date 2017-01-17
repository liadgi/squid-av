/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON_REGISTRY_H
#define LIBECAP__COMMON_REGISTRY_H

#include <libecap/common/forward.h>
#include <libecap/common/memory.h>

namespace libecap {

// services call this to register themselves upon creation
// the second parameter must be the libecap library version (as provided)
// which the host application will check for compatibility
// always returns true (to simplify static initialization-driven registrations)
extern bool RegisterVersionedService(adapter::Service *s, const char *v = LIBECAP_VERSION);

// the host calls this to receive registered services (past and future)
extern void RegisterHost(const shared_ptr<host::Host> &host);

// returns registered host or throws if no host was registered
extern host::Host &MyHost();

// "x.y.z" version string of the libecap library the caller linked with
extern const char *VersionString();

} // namespace libecap

#endif
