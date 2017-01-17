#include <libecap/common/name.h>
#include <libecap/common/errors.h>
#include <climits>

libecap::Name::Id libecap::Name::TheLastId = libecap::Name::nameUnidentified;

libecap::Name::Name(): id_(libecap::Name::nameUnknown), hostId_(INT_MIN) {
}

libecap::Name::Name(const Name::Image &image): image_(image),
	id_(libecap::Name::nameUnidentified), hostId_(INT_MIN) {
}

libecap::Name::Name(const Name::Image &image, Id id): image_(image), id_(id),
	hostId_(INT_MIN) {
}

libecap::Name::Id libecap::Name::NextId() {
	return ++TheLastId;
}

bool libecap::Name::assignedHostId() const {
	return hostId_ != INT_MIN;
}

void libecap::Name::assignHostId(int id) const {
	Must(hostId_ == INT_MIN && id != INT_MIN);
	hostId_ = id;
}
