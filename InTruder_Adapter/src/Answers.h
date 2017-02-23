/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_ANSWERS_H
#define ECAP_CLAMAV_ADAPTER_ANSWERS_H

#include "Async.h"
#include <list>

namespace Adapter {

class Service;
class Answer;

// a thread-safe queue of Antivirus Answers
class Answers
{
public:
    Answers();
    ~Answers();

    /* reference counting */
    void use();
    int abandon(); // may delete this
    int users() const; // some users may not put() their Answers yet

    // the result is ephemeral because another thread may add or remove answers
    bool empty() const;

    void put(Answer *answer);
    Answer *get();

private:
    mutable pthread_mutex_t lock; // protects all data members

    typedef std::list<Answer *> Queue;
    Queue queue; // answers ready to be delivered to the host

    int references; // number of objects pointing to us
};

} // namespace Adapter

#endif
