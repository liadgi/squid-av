/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__NAME_H
#define LIBECAP__COMMON__NAME_H

#include <libecap/common/forward.h>
#include <string>

namespace libecap {

// a known globally unique ID and the corresponding string representing a
// protocol token constant or a similar name
// the ID is not persistent and used for optimization purposes
class Name {
	public:
		typedef int Id;
		typedef std::string Image;

	public:
		Name(); // unknown
		Name(const Image &image); // known but not identified
		Name(const Image &image, Id id); // known and usually identified

		bool identified() const { return id_ > nameUnidentified; } // known too
		bool known() const { return id_ != nameUnknown; }

		bool operator ==(const Name &name) const { return known() && (identified() ? id_ == name.id_ : image_ == name.image_); }
		bool operator !=(const Name &name) const { return !(*this == name); }

		bool operator ==(const char *image) const { return image_ == image; }
		bool operator !=(const char *image) const { return !(*this == image); }

		const Image &image() const { return image_; }

		int hostId() const { return hostId_; }
		bool assignedHostId() const;
		void assignHostId(int id) const; // throws if INT_MIN or called twice
		// TODO: add adapterId?

		static Id NextId();

	private:
		Image image_;
		Id id_;
		mutable int hostId_; // optional, maintained by host; starts as INT_MIN

		static Id TheLastId;
		enum { nameUnknown = 0, nameUnidentified = 1 };
};

} // namespace libecap

#endif
