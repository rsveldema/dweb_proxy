#pragma once

#include <memory>

#include <boost/asio/io_context.hpp>

namespace dweb
{
    class Server
    {
    public:
        Server();
        void run();
        void poll();

    private:
        std::unique_ptr<boost::asio::io_context> m_io_context;
    };
}