/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#include "Adapter.h"
#include "FileBuffer.h"
#include "Debugger.h"
#include <libecap/common/errors.h>

#include <limits.h>
#include <limits>
#include <cstring>
#include <stdlib.h>
#include <sys/stat.h>
#include <errno.h>
#if HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <sstream>
#include <vector>

static
void SysError(const char *context, const std::string &fileName,
    const int errNo,
    const char *locFile = 0, const int locLine = -1)
{
    std::string message = context;
    if (!fileName.empty()) {
        message += '(';
        message += fileName;
        message += ')';
    }
    if (errNo) {
        message += ": ";
        message += strerror(errNo);
    }
    throw libecap::TextException(message, locFile, locLine);
}

#define Here __FILE__, __LINE__
// this simple macro assumes that the caller has not corrupted the errno yet,
// including during any SysError() parameter conversions
#define SysErrorHere(context, fileName) \
    SysError((context), (fileName), errno, Here)


Adapter::FileBuffer::FileBuffer(const std::string &nameTemplate):
    stream_(0), size_(0)
{
    char fnameBuf[PATH_MAX];
    strncpy(fnameBuf, nameTemplate.c_str(), sizeof(fnameBuf));

    const int fd = mkstemp(fnameBuf);
    if (fd < 0)
        SysErrorHere("cannot create a temporary file using mkstemp", nameTemplate);

    if ((stream_ = fdopen(fd, "wb+"))) {
        name_ = fnameBuf;
        return;
    }

    const int errNo = errno; // save to avoid corrupting
    (void)unlink(fnameBuf);

    SysError("cannot open a temporary file using fdopen", name_, errNo, Here);
}

Adapter::FileBuffer::~FileBuffer()
{
    try {
        close();
        remove();
    } catch (const libecap::TextException &ex) {
        Debugger(ilCritical|flXaction) << "eClamAV: Error: " <<
            "temporary file cleanup failure: " << ex;
    }
}

libecap::Area Adapter::FileBuffer::read(const off_t pos, const size_t maxSize)
{
    Must(stream_);

    if (fseeko(stream_, pos, SEEK_SET) != 0)
        SysErrorHere("cannot position a temporary file using fseeko", name_);

    // When we require C++11, use ioBuffer.data() instead of &ioBuffer[0].
    std::vector<char> ioBuffer(maxSize);
    const size_t bytesRead = fread(&ioBuffer[0], 1, maxSize, stream_);

    if (bytesRead > 0)
        return libecap::Area::FromTempBuffer(&ioBuffer[0], bytesRead);

    if (ferror(stream_))
        SysErrorHere("cannot read a temporary file using fread", name_);

    // else we were asked to read zero bytes or read at EOF, which we ignore

    return libecap::Area();
}

void Adapter::FileBuffer::write(const libecap::Area &buf)
{
    Must(stream_);

    if (fseeko(stream_, 0, SEEK_END) != 0)
        SysErrorHere("cannot seek to the end of a temporary file using fseeko", name_);

    const size_t bytesWritten = fwrite(buf.start, 1, buf.size, stream_);
    if (bytesWritten != buf.size)
        SysErrorHere("cannot write a temporary file using fwrite", name_);

    Must(size_ <= std::numeric_limits<Size>::max() - bytesWritten); // no overflows
    size_ += bytesWritten;
}

void Adapter::FileBuffer::flush() const
{
    Must(stream_);

    if (fflush(stream_) != 0)
        SysErrorHere("cannot sync a temporary file using fflush", name_);
}

void Adapter::FileBuffer::close()
{
    if (!stream_)
        return;

    if (fclose(stream_) != 0)
        SysErrorHere("cannot close a temporary file using fclose", name_);

    stream_ = 0;
}

void Adapter::FileBuffer::remove()
{
    if (name_.empty())
        return;

    if (::remove(name_.c_str()) != 0)
        SysErrorHere("cannot remove a temporary file using remove", name_);

    name_.clear();
    size_ = 0; // TODO: even though we may still be reading and writing?
}
