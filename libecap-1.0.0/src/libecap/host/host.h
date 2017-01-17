/* (C) 2008  The Measurement Factory */

#ifndef LIBECAP__HOST__HOST_H
#define LIBECAP__HOST__HOST_H

#include <libecap/common/forward.h>
#include <libecap/common/memory.h>
#include <libecap/common/log.h>
#include <string>
#include <iosfwd>

namespace libecap {
namespace host {

// Host-provided actions that are not specific to a single eCAP transaction.
class Host {
	public:
		virtual ~Host() {}

		// About
		virtual std::string uri() const = 0; // unique across all vendors
		virtual void describe(std::ostream &os) const = 0; // free-format info

		// Service management
		virtual void noteVersionedService(const char *libEcapVersion, const weak_ptr<adapter::Service> &s) = 0;

		// Logging
		virtual std::ostream *openDebug(LogVerbosity lv) = 0;
		virtual void closeDebug(std::ostream *debug) = 0;

		// Fresh message creation, when Message::clone() is not appropriate
		virtual shared_ptr<Message> newRequest() const = 0;
		virtual shared_ptr<Message> newResponse() const = 0;
};

} // namespace host
} // namespace libecap

#endif
