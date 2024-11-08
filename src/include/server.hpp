#pragma once

#include "logger.hpp"

#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>

namespace dweb
{
    class Server
    {
    public:
        Server();
        void run();
        void poll();

    private:
        Logger m_logger;
        std::unique_ptr<boost::asio::io_context> m_io_context;
        std::unique_ptr<boost::asio::ssl::context> m_ctx;
        std::shared_ptr<boost::asio::ip::tcp::acceptor> m_acceptor;

        void handle_session(boost::asio::ip::tcp::socket &socket);
    };
}