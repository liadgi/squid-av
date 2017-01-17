/* (C) 2008  The Measurement Factory */

#ifndef ECAP__ADAPTER_XACTION_H
#define ECAP__ADAPTER_XACTION_H

#include <libecap/common/area.h>
#include <libecap/common/options.h>

namespace libecap {
namespace adapter {

// adapter transaction is responsible for adapting a single message
// it is created by adapter::Service::makeXaction and destroyed by
// the host either before calling start() or after calling stop()
class Xaction: public Options {
	public:
		virtual ~Xaction() {}

		// lifecycle
		virtual void start() = 0;
		virtual void stop() = 0;
		virtual void resume();

		// adapted body transmission control
		virtual void abDiscard() = 0; // host will not look at ab at all
		virtual void abMake() = 0; // host may look at ab
		virtual void abMakeMore() = 0; // host must have more ab
		virtual void abStopMaking() = 0; // host no longer needs ab
		virtual void abPause() {} // ignored by default
		virtual void abResume() {} // ignored iff abPause is

		// adapted body content extraction and consumption
		virtual Area abContent(size_type offset, size_type size) = 0;
		virtual void abContentShift(size_type size) = 0; // first size bytes

		// virgin body state notification
		virtual void noteVbContentDone(bool atEnd) = 0; // successful or not
		virtual void noteVbContentAvailable() = 0;
};

} // namespace adapter
} // namespace libecap

#endif
