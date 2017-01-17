/* (C) 2008 The Measurement Factory */

#ifndef LIBECAP__COMMON__TEXT_EXCEPTION_H
#define LIBECAP__COMMON__TEXT_EXCEPTION_H

#include <libecap/common/libecap.h>
#include <iosfwd>
#include <string>

namespace libecap {

// simple exception to report custom error messages
class TextException: public std::exception {
	public:
		TextException(const std::string &aMessage, const char *aFileName = 0, int aLineNo = -1);
		virtual ~TextException() throw();

		virtual const char *what() const throw();

		std::ostream &print(std::ostream &os) const;

	public:
		std::string message;

	protected:
		// optional location information
		const char *theFileName;
		int theLineNo;
};

inline
std::ostream &operator <<(std::ostream &os, const TextException &exx) {
	return exx.print(os);
}

extern void Throw(const char *message, const char *fileName, int lineNo);

} // namespace libecap

// Is there a way to add source code location without polluting the name space?

// Convenience macro to supply optional location arguments.
#if !defined(TextExceptionHere)
#	define TextExceptionHere(msg) libecap::TextException((msg), __FILE__, __LINE__)
#endif

// Must(condition) is like assert(condition) but throws an exception instead
#if !defined(Must)
#   define Must(cond) ((cond) ? \
		(void)0 : \
		(void)libecap::Throw(#cond, __FILE__, __LINE__))
#endif


#endif
