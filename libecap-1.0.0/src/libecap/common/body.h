/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__BODY_H
#define LIBECAP__COMMON__BODY_H

#include <libecap/common/body_size.h>

namespace libecap {

// a message body buffer shared by the body producer and consumer
// usually implemented by the host, but can be implemented by adapters
// TODO: get rid of this class by moving BodySize info to Message
class Body {
	public:
		virtual ~Body() {}

		// stats
		virtual BodySize bodySize() const = 0;
};

} // namespace libecap

#endif
