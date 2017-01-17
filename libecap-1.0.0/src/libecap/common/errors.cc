/* (C) 2008 The Measurement Factory */

#include <libecap/common/errors.h>
#include <iostream>
#include <sstream>

libecap::TextException::TextException(const std::string &aMsg, const char *aFileName, int aLineNo):
	message(aMsg), theFileName(aFileName), theLineNo(aLineNo) {

	if (theFileName) {
		std::ostringstream buf;
		buf << theFileName << ':';
		if (theLineNo >= 0)
			buf << ':' << theLineNo;
		buf << ": " << aMsg;
		message = buf.str();
	}
}

libecap::TextException::~TextException() throw() {
	// can we do anything to prevent member destructors from throwing?
}

const char *libecap::TextException::what() const throw() {
	return message.c_str();
}


std::ostream &libecap::TextException::print(std::ostream &os) const {
	if (theFileName)
		os << theFileName << ':' << theLineNo << ": ";
	return os << message;
}

void libecap::Throw(const char *message, const char *fileName, int lineNo) {
	// the exception recipient should print the exception
	throw TextException(message, fileName, lineNo);
}
