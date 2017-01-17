/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__OPTIONS_H
#define LIBECAP__COMMON__OPTIONS_H

#include <libecap/common/forward.h>

namespace libecap {

// API to allow one side to read option values stored on the other side.
// Used to share configuration information (similar to ICAP OPTIONS exchange).
// Used to share transaction meta-information (similar to ICAP message header).
// Options objects and individual option values may be temporary. They must not
// be used beyond the method call that supplied or asked for them.
class Options {
	public:
		virtual ~Options() {}

		// returns the value of the named option; empty if unsupported/unknown
		// best for accessing a few known options when many options may exist
		virtual const Area option(const Name &name) const = 0;

		// calls visitor for each option name:value pair
		// accesses all options, including those w/o known-to-visitor names
		virtual void visitEachOption(NamedValueVisitor &visitor) const = 0;
};

} // namespace libecap

#endif
