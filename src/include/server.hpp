#pragma once

#include "logger.hpp"

#include <memory>

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>

namespace dweb
{
using ssl_stream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket &>;

class Server
{
  public:
  Server();
  void run();
  void poll();

  private:
  Logger m_logger;
  std::shared_ptr<boost::asio::io_context> m_io_context;
  std::unique_ptr<boost::asio::ssl::context> m_ssl_ctxt;
  std::shared_ptr<boost::asio::ip::tcp::acceptor> m_acceptor;

  void handle_session(boost::asio::ip::tcp::socket &socket);

  /** @return false if we can abandon the stream */
  bool handle_single_request(int &counter,
                      boost::beast::flat_buffer &buffer,
                      ssl_stream &stream);
};
} // namespace dweb