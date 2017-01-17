/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_TIME_H
#define ECAP_CLAMAV_ADAPTER_TIME_H

#include <sys/time.h>

/* Class of time operations based on timeval.
 * Warning!!! timeval is POD and it has no virtual destructor --
 * be careful in descending assignments.
 */
class Time: public timeval
{
public:
    static Time Zero() { return Time(0, 0); }
    static Time Now(); // gettimeofday(); throws on system errors
    static Time Max();

    Time() { tv_sec = 0; tv_usec = 0; }
    Time(const time_t sec, const long usec) { tv_sec = sec;    tv_usec = usec; }
    Time(const timeval &tv) // implicit timeval conversions are desirable
    {
        tv_sec = tv.tv_sec;
        tv_usec = tv.tv_usec;
    }

    Time &operator +=(const Time &tm);
    Time &operator -=(const Time &tm);
};

inline
Time operator +(Time tv1, const Time &tv2)
{
    return tv1 += tv2;
}

inline
Time operator -(Time tv1, const Time &tv2)
{
    return tv1 -= tv2;
}

inline
bool operator ==(const Time &t1, const Time &t2)
{
    return (t1.tv_sec == t2.tv_sec && t1.tv_usec == t2.tv_usec);
}

inline
bool operator !=(const Time &t1, const Time &t2)
{
    return (t1.tv_sec != t2.tv_sec || t1.tv_usec != t2.tv_usec);
}

inline
bool operator >=(const Time &tv1, const Time &tv2)
{
    return (tv1.tv_sec > tv2.tv_sec ||
           (tv1.tv_sec == tv2.tv_sec && tv1.tv_usec >= tv2.tv_usec));
}

inline
bool operator >(const Time &tv1, const Time &tv2)
{
    return (tv1.tv_sec > tv2.tv_sec ||
           (tv1.tv_sec == tv2.tv_sec && tv1.tv_usec > tv2.tv_usec));
}

inline
bool operator <(const Time &tv1, const Time &tv2)
{
    return (tv1.tv_sec < tv2.tv_sec ||
           (tv1.tv_sec == tv2.tv_sec && tv1.tv_usec < tv2.tv_usec));
}

inline
bool operator <=(const Time &tv1, const Time &tv2)
{
    return (tv1.tv_sec < tv2.tv_sec ||
           (tv1.tv_sec == tv2.tv_sec && tv1.tv_usec <= tv2.tv_usec));
}

#endif // ECAP_CLAMAV_ADAPTER_TIME_H
