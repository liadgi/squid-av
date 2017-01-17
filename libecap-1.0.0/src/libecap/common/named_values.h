/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__NAMED_VALUES_H
#define LIBECAP__COMMON__NAMED_VALUES_H

#include <libecap/common/forward.h>

namespace libecap {

// API to "visit" name:value collections such as configuration or metainfo
class NamedValueVisitor {
	public:
		virtual ~NamedValueVisitor() {}

		// will be called for each name:value pair; should throw on errors
		virtual void visit(const Name &name, const Area &value) = 0;
};

} // namespace libecap

#endif
