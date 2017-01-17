/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__AREA_H
#define LIBECAP__COMMON__AREA_H

#include <libecap/common/forward.h>
#include <libecap/common/memory.h>
#include <iosfwd>
#include <string>

namespace libecap {

typedef std::string::size_type size_type;
extern const size_type nsize; // same as std::string::npos

class AreaDetails;

// a continuous, fixed-size buffer area
// no zero-termination is guaranteed
class Area {
	public:
		typedef shared_ptr<AreaDetails> Details;

	public:
		static Area FromTempBuffer(const char *aStart, size_type aSize);
		static Area FromTempString(const std::string &tmp);

		Area(): start(""), size(0) {}
		Area(const char *aStart, size_type aSize):
			start(aStart), size(aSize) {}
		Area(const char *aStart, size_type aSize, const Details &aDetails):
			start(aStart), size(aSize), details(aDetails) {}

		std::string toString() const; // expensive

		// for safe conversion to bool, ignore
		typedef const size_type Area::*SafeBool;
		// false if empty; true otherwise
		operator SafeBool() const { return size ? &Area::size : 0; }

	public:
		const char *start;
		size_type size;

		Details details; // creator-defined

	private:
		bool does_not_support_comparisons() const; // not implemented
};

// this stub can be enhanced by area creators to optimize area operations
class AreaDetails {
	public:
		virtual ~AreaDetails() {}
};

std::ostream &operator <<(std::ostream &os, const Area &area);

/* make Area comparisons illegal by default */
template <typename T> bool operator ==(const Area &a, const T &) { return a.does_not_support_comparisons(); }
template <typename T> bool operator !=(const Area &a, const T &) { return a.does_not_support_comparisons(); }
template <typename T> bool operator ==(const T &, const Area &a) { return a.does_not_support_comparisons(); }
template <typename T> bool operator !=(const T &, const Area &a) { return a.does_not_support_comparisons(); }

} // namespace libecap

#endif
