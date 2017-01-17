/* (C) 2008 The Measurement Factory */

#ifndef ECAP__COMMON__FORWARD_H
#define ECAP__COMMON__FORWARD_H

#include <libecap/common/libecap.h>

namespace libecap {

class Name;
class Area;
class Version;
class Delay;

class NamedValueVisitor;
class Options;

class Message;
class FirstLine;
class Header;
class Body;
class BodySize;
class BodyProducer;
class BodyConsumer;

namespace adapter {
	class Service;
	class Xaction;
}

namespace host {
	class Host;
	class Xaction;
}

} // namespace libecap

#endif
