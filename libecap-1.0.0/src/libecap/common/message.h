/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__MESSAGE_H
#define LIBECAP__COMMON__MESSAGE_H

#include <libecap/common/forward.h>
#include <libecap/common/memory.h>

namespace libecap {

// MIME-like message structure with a first line, header, body, and trailer
// only the first line and the header parts are required;
// trailer support is optional
class Message {
	public:
		virtual ~Message() {}

		// clones the header and body presence; does not copy the body itself
		virtual shared_ptr<Message> clone() const = 0;

		// always present, determines direction
		virtual FirstLine &firstLine() = 0; 
		virtual const FirstLine &firstLine() const = 0;

		virtual Header &header() = 0; // always present
		virtual const Header &header() const = 0;

		virtual void addBody() = 0;
		virtual Body *body() = 0;
		virtual const Body *body() const = 0;

		virtual void addTrailer(); // throws by default
		virtual Header *trailer() { return 0; }
		virtual const Header *trailer() const { return 0; }
};

} // namespace libecap

#endif
