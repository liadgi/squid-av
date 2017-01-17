/* (C) 2008  The Measurement Factory */

#ifndef ECAP__HOST_XACTION_H
#define ECAP__HOST_XACTION_H

#include <libecap/common/forward.h>
#include <libecap/common/area.h>
#include <libecap/common/options.h>

namespace libecap {
namespace host {

// The host side of the eCAP transaction.
// Adapter::Xaction uses this interface to get a virgin message from the host.
class Xaction: public Options {
	public:
		virtual ~Xaction() {}

		// access to messages; these methods throw if the message is missing
		virtual Message &virgin() = 0; // request or response, always present
		virtual const Message &cause() = 0; // request for the above response
		virtual Message &adapted() = 0; // returns useAdapted() message

		// adaptation decision making
		virtual void useVirgin() = 0; // use virgin; no adaptation
		virtual void useAdapted(const shared_ptr<Message> &msg) = 0; // use msg
		virtual void blockVirgin() = 0; // block or deny user access

		// adapter transaction state notifications
		virtual void adaptationDelayed(const Delay &) = 0; // needs time
		virtual void adaptationAborted() = 0; // abnormal termination
		virtual void resume() = 0; // continue the async transaction

		// virgin body transmission control
		virtual void vbDiscard() = 0; // adapter will not look at vb at all
		virtual void vbMake() = 0; // adapter may look at vb
		virtual void vbStopMaking() = 0; // adapter no longer needs vb
		virtual void vbMakeMore() = 0; // adapter must have more vb
		virtual void vbPause() {} // ignored by default
		virtual void vbResume() {} // ignored iff vbPause is

		// virgin body content extraction and consumption
		virtual Area vbContent(size_type offset, size_type size) = 0;
		virtual void vbContentShift(size_type size) = 0; // first size bytes

		// adapted body state notification
		virtual void noteAbContentDone(bool atEnd) = 0; // successful or not
		virtual void noteAbContentAvailable() = 0;
};

} // namespace host
} // namespace libecap

#endif
