/* eCAP ClamAV Adapter                                http://www.e-cap.org/
 * Copyright (C) 2011 The Measurement Factory.
 * Distributed under GPL v2 without any warranty.                        */

#ifndef ECAP_CLAMAV_ADAPTER_SERVICE_H
#define ECAP_CLAMAV_ADAPTER_SERVICE_H

#include "Antivirus.h"
#include "Pointers.h"
#include "Time.h"

#include <libecap/adapter/service.h>

#include <queue>
#include <list>


namespace Adapter {

using libecap::Options;

class Service: public libecap::adapter::Service
{
public:
    static Size MaxSize(); // the maximum message size we can safely support

    Service(const std::string &aMode);
    virtual ~Service();

    /* libecap::adapter::Service API */
    virtual std::string uri() const; // unique across all vendors
    virtual std::string tag() const; // changes with version and config
    virtual void describe(std::ostream &os) const; // free-format info
    virtual bool makesAsyncXactions() const;
    virtual void configure(const Options &cfg);
    virtual void reconfigure(const Options &cfg);
    virtual void start(); // expect makeXaction() calls
    virtual void stop(); // no more makeXaction() calls until start()
    virtual void retire(); // no more makeXaction() calls
    virtual void suspend(timeval &timeout); // influence host waiting time
    virtual void resume(); // kick async xactions via host::Xaction::resume
    virtual bool wantsUrl(const char *url) const;
    virtual MadeXactionPointer makeXaction(libecap::host::Xaction *hostx);

    // queues the next xaction->trickle() call, returning the queue reservation
    Timeout *wakeMeUpToTrickle(const XactionPointer &xaction, const Time &delay) const;
    // undoes wakeMeUpToTrickle() before the timeout
    void cancelTimeout(Adapter::Timeout *timeout) const;

    // this xaction does not want to be notified [about config changes] anymore
    void deregisterXaction(Xaction &xaction) const;

    // whether trickling is enabled
    bool trickling() const { return tricklingConfig_; }
    // either returns trickling configuration or, if trickling is not configured, throws
    TricklingConfig &tricklingConfig();
    const TricklingConfig &tricklingConfig() const { return const_cast<Service *>(this)->tricklingConfig(); }

    Size vbAccumulationMax() const; // do not store/analyze more

    friend class Cfgtor;

public:
    /* configuration */
    const std::string mode; // REQMOD or RESPMOD (for unique service URI)
    bool blockOnError; // whether to block when virus scanner fails
    libecap::shared_ptr<Antivirus> scanner; // virus scanner instance
    std::string tmpFileNameTemplate; // template for temporary file name generation
    bool scanAsynchronously; // whether we must use threads to scan

    Answers *answers; // queued Antivirus results, ready to be processed

protected:
    // whether we are built with pthreads support
    static bool AllowAsyncScans();

    // configuration code shared by configure and reconfigure
    void setAll(const Options &cfg);
    // handle one configuration parameter
    void setOne(const libecap::Name &name, const libecap::Area &value);

    // configure tmpFileNameTemplate
    void setTmpDir(const std::string &prefix);

    // configure tmpFileNameTemplate
    void setOnError(const std::string &allowOrBlock);

    // configure asynchronous scanning
    void setAsyncScans(const std::string &value);

    // verify that configuration is working
    void checkStagingDir();

    // update virus db if needed
    void checkpoint();

private:
    void notifyTimeouts();
    void finalizeTricklingConfig(const std::auto_ptr<TricklingConfig> &oldConfig);
    void printTricklingConfig() const;

    // either sets how long we can wait for resume() or returns false
    bool canWait(Time &waitTime) const;

    // alive Xaction objects in makeXaction() order
    typedef std::list<XactionPointer> Xactions;
    Xactions *xactions;

    // pointer comparison operator for the Timeouts container
    typedef bool (*CmpTimeoutPointers)(const Adapter::Timeout *a, const Adapter::Timeout *b);
    // pointers to Timeout objects ordered by their deadlines
    typedef std::priority_queue<Timeout *,
        std::vector<Timeout *>, // growth is expensive, but should stop
        CmpTimeoutPointers> Timeouts;
    Timeouts *timeouts; // active and deactivated timeouts

    TricklingConfig *tricklingConfig_; // current trickling parameters

    Size vbAccumulationMax_; // message_size_max part of the accumulation limit
    time_t lastDbUpdate; // last database update timestamp
    bool reconfiguring; // whether Service::reconfigure() is in progress
};

} // namespace Adapter

#endif
