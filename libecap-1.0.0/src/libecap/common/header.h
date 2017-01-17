/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__HEADER_H
#define LIBECAP__COMMON__HEADER_H

#include <libecap/common/forward.h>

namespace libecap {

class Header {
	public:
		typedef Area Value;

	public:
		virtual ~Header() {}

		virtual bool hasAny(const Name &name) const = 0;
		//virtual bool hasOne(const Name &name, const Value &value) const = 0;
		virtual Value value(const Name &name) const = 0; // empty if none

		virtual void add(const Name &name, const Value &value) = 0;
		//virtual void removeOne(const Name &name, const Value &value) = 0;
		virtual void removeAny(const Name &name) = 0;

		// visit all header fields, one by one
		virtual void visitEach(NamedValueVisitor &visitor) const = 0;

		virtual Area image() const = 0;
		virtual void parse(const Area &buf) = 0; // throws on failures
};

class FirstLine {
	public:
		virtual ~FirstLine() {}

		virtual Version version() const = 0;
		virtual void version(const Version &aVersion) = 0;
		virtual Name protocol() const = 0;
		virtual void protocol(const Name &aProtocol) = 0;
};

class RequestLine: public FirstLine {
	public:
		virtual ~RequestLine() {}

		virtual void uri(const Area &aUri) = 0;
		virtual Area uri() const = 0;

		virtual void method(const Name &aMethod) = 0;
		virtual Name method() const = 0;
};

class StatusLine: public FirstLine {
	public:
		virtual ~StatusLine() {}

		virtual void statusCode(int code) = 0;
		virtual int statusCode() const = 0;

		virtual void reasonPhrase(const Area &phrase) = 0;
		virtual Area reasonPhrase() const = 0;
};

} // namespace libecap

#endif
