/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__BODY_SIZE_H
#define LIBECAP__COMMON__BODY_SIZE_H

#include <libecap/common/forward.h>
#include <stdint.h>

namespace libecap {

// maintains message body size info
class BodySize {
	public:
		typedef uint64_t size_type;

	public:
		BodySize(): size_(0), known_(false) {}
		BodySize(size_type size): size_(size), known_(true) {}

		bool known() const { return known_; }
		size_type value() const { return known() ? size_ : badSize(); }

	protected:
		size_type badSize() const; // throws

	private:
		size_type size_;
		bool known_;
};

} // namespace libecap

#endif
