/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__VERSION_H
#define LIBECAP__COMMON__VERSION_H

#include <libecap/common/forward.h>
#include <string>

namespace libecap {

// major.minor.micro version holder
class Version {
	public:
		Version(int majr_ = -1, int minr_ = -1, int micr_ = -1):
			majr(majr_), minr(minr_), micr(micr_) {}

		bool known() const { return majr >= 0; }

		bool operator ==(const Version &v) const { return known() &&
			majr == v.majr && minr == v.minr && micr == v.micr; }
		bool operator !=(const Version &v) const {
			return !(*this == v); }

	public:
		int majr; // creative spelling due to glibc defining major/minor macros
		int minr;
		int micr;
};

} // namespace libecap

#endif
