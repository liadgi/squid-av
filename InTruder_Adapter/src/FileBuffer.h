/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_FILE_BUFFER_H
#define ECAP_CLAMAV_ADAPTER_FILE_BUFFER_H

#include <libecap/common/area.h>
#include <cstdio>
#include <string>

namespace Adapter {

// a temporary uniquely-named FILE-based buffer
// unless noted otherwise, all methods throw on failures
class FileBuffer
{
public:
    // creates a uniquely-named temporary file and opens it for I/O
    explicit FileBuffer(const std::string &nameTemplate);
    // closes and/or removes the file if it was not closed and/or removed before
    // does not throw; just logs a warning message if the underlying method throws
    ~FileBuffer();

    bool isOpened() const { return stream_; }

    libecap::Area read(const off_t pos, const size_t size);
    void write(const libecap::Area &buf);
    void flush() const;

    // closes the file; does not remove()
    void close();

    Size size() const { return size_; }

    // returns a real file name, created by mkstemp()
    std::string name() const { return name_; }

private:
    // removes the file from the storage index; does not close()
    void remove();

    FILE *stream_; // either opened for reading/writing or nil
    Size size_; // the total number of bytes written
    std::string name_; // name of the file
};

} // namespace Adapter

#endif
