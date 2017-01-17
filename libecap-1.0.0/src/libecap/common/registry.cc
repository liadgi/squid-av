#include <libecap/common/registry.h>
#include <libecap/common/errors.h>
#include <libecap/adapter/service.h>
#include <libecap/host/host.h>
#include <list>

namespace libecap {

typedef libecap::weak_ptr<adapter::Service> ServicePtr;
typedef std::string ServiceLibVersion; // library version used to build Service
typedef std::pair<ServiceLibVersion, ServicePtr> ServiceInfo;

typedef std::list<ServiceInfo> StagingArea;
static StagingArea TheStagingArea;

static shared_ptr<host::Host> TheHost;

static
void drainStagingArea() {
	while (TheHost && !TheStagingArea.empty()) {
		StagingArea::value_type s = TheStagingArea.front();
		TheStagingArea.pop_front();
		TheHost->noteVersionedService(s.first.c_str(), s.second);
	}
}

} // namespace libecap

bool libecap::RegisterVersionedService(adapter::Service *s, const char *v) {
	s->self.reset(s); // avoids creation of shared pointer inside ctor
	const ServiceInfo si = std::make_pair(v, s->self);
	TheStagingArea.push_back(si);
	drainStagingArea();
	return true;
}

void libecap::RegisterHost(const shared_ptr<host::Host> &host) {
	Must(host);
	Must(!TheHost);
	TheHost = host;
	drainStagingArea();
}

libecap::host::Host &libecap::MyHost() {
	Must(TheHost);
	return *TheHost;
}

const char *libecap::VersionString() {
	return LIBECAP_VERSION;
}


/*
 * This hack helps v1+ host applications to reject with a proper message a
 * service built against libecap v0. We assume that adapter modules built
 * with libecap v0 will contain libecap::RegisterService() as an undefined
 * linking symbol and will call this new implementation provided by a v1+
 * library instead of the v0 implementation. Without this hack, v1+ host
 * applications would fail to load v0 adapters due to unresolved
 * libecap::RegisterService() and, hence, would not be able to produce
 * intelligent error messages about the loading failure.
 */
namespace libecap { extern void RegisterService(adapter::Service *s); }
void libecap::RegisterService(adapter::Service *s) {
	(void)libecap::RegisterVersionedService(s, "0");
}
