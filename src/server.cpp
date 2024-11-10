#include <boost/asio/impl/src.hpp>
#include <boost/asio/ssl/impl/src.hpp>

#include "server.hpp"
#include <thread>

#include "logger.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/write.hpp>
#include <cstdio>
#include <fstream>

#include <request_handler.hpp>

#include <boost/certify/extensions.hpp>
#include <boost/certify/https_verification.hpp>

namespace beast = boost::beast;   // from <boost/beast.hpp>
namespace http = beast::http;     // from <boost/beast/http.hpp>
namespace net = boost::asio;      // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

std::string read_file(const std::string &path)
{
  std::ifstream inFile;
  inFile.open(path); // open the input file
  assert(inFile.is_open());

  std::stringstream strStream;
  strStream << inFile.rdbuf();
  return strStream.str();
}

inline void load_server_certificate(boost::asio::ssl::context &ssl_ctxt)
{
  /*
      The certificate was generated from bash on Ubuntu (OpenSSL 1.1.1f) using:

      openssl dhparam -out dh.pem 2048
      openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 10000 -out
     cert.pem -subj "/C=US/ST=CA/L=Los Angeles/O=Beast/CN=localhost"
  */

  auto home = getenv("HOME");
  assert(home);

  const auto cert = read_file(fmt::format("{}/certs/server.test.crt", home));
  const auto key = read_file(fmt::format("{}/certs/server.test.key", home));
  const auto dh = read_file(fmt::format("{}/certs/dh.pem", home));

  ssl_ctxt.set_password_callback(
      [](std::size_t, boost::asio::ssl::context_base::password_purpose) {
        printf("password query intercepted!\n");
        return "test";
      });

  ssl_ctxt.set_options(boost::asio::ssl::context::default_workarounds |
                       boost::asio::ssl::context::sslv3_server |
                       boost::asio::ssl::context::sslv2_server |
                       //  boost::asio::ssl::context::sslv23_server
                       boost::asio::ssl::context::no_sslv2 |
                       //   boost::asio::ssl::context::no_sslv3 |
                       boost::asio::ssl::context::single_dh_use);

  ssl_ctxt.use_certificate_chain(boost::asio::buffer(cert.data(), cert.size()));

  ssl_ctxt.use_private_key(boost::asio::buffer(key.data(), key.size()),
                           boost::asio::ssl::context::file_format::pem);

  ssl_ctxt.use_tmp_dh(boost::asio::buffer(dh.data(), dh.size()));

  boost::certify::enable_native_https_server_verification(ssl_ctxt);
  ssl_ctxt.set_verify_mode(
      boost::asio::ssl::
          verify_peer); // |
                        // boost::asio::ssl::context::verify_fail_if_no_peer_cert);
  ssl_ctxt.set_default_verify_paths();

  SSL_CTX_set_session_cache_mode(ssl_ctxt.native_handle(), SSL_SESS_CACHE_OFF);
}

namespace dweb
{
Server::Server()
{
  m_io_context = std::make_unique<boost::asio::io_context>(1);

  m_ssl_ctxt = std::make_unique<ssl::context>(ssl::context::tlsv12);

  load_server_certificate(*m_ssl_ctxt);

  m_acceptor = std::make_shared<tcp::acceptor>(
      *m_io_context, tcp::endpoint{net::ip::make_address("127.0.0.1"), 8443});
}

void fail(beast::error_code ec, char const *what)
{
  LOG_INFO("fail: {} - {}", ec.message(), what);
}

template <class Body, class Allocator>
http::message_generator create_response(
    http::request<Body, http::basic_fields<Allocator>> &&req,
    int &counter,
    std::shared_ptr<boost::asio::io_context> io_context)
{
  dweb::MessageHandler handler(io_context, req.version(), req.keep_alive(),
                               req.base().method(), req.target());

  header_map_t headers;
  for (const auto &it : req.base())
  {
    const auto k = it.name();
    const std::string v = it.value();
    headers[k] = v;
  }

  auto response = handler.get_response(req.body(), headers);

  if (auto string_response = response->to_string_response())
  {
    auto res = *string_response;
    return res;
  }

  return handler.get_internal_error_reply();
}

bool Server::handle_single_request(int &counter,
                                   beast::flat_buffer &buffer,
                                   ssl::stream<tcp::socket &> &stream)
{
  // Read a request
  beast::error_code ec;

  http::request<http::string_body> req;
  http::read(stream, buffer, req, ec);
  if (ec == http::error::end_of_stream)
  {
    LOG_INFO("end of stream");
    return false;
  }
  if (ec)
  {
    fail(ec, "read");
    return false;
  }

  auto msg = create_response(std::move(req), counter, m_io_context);

  bool keep_alive = msg.keep_alive();
  beast::write(stream, std::move(msg), ec);
  if (ec)
  {
    fail(ec, "write");
    return false;
  }

  if (!keep_alive)
  {
    LOG_INFO("not keep-alive, existing");
    return false;
  }
  return true;
}

void Server::handle_session(tcp::socket &socket)
{
  ssl::stream<tcp::socket &> stream{socket, *m_ssl_ctxt};

  LOG_INFO("new session: {}", socket.native_handle());

  beast::error_code ec;
  stream.handshake(ssl::stream_base::server, ec);
  if (ec)
  {
    return fail(ec, "handshake");
  }

  beast::flat_buffer buffer;

  LOG_INFO("everything ok, lets see what we get!");

  int counter = 0;

  while (true)
  {
    if (!handle_single_request(counter, buffer, stream))
    {
      break;
    }
  }

  stream.shutdown(ec);
  if (ec)
    return fail(ec, "shutdown");

  LOG_INFO("exiting session--------------------");
}

void Server::poll()
{
  tcp::socket socket{*m_io_context};
  m_acceptor->accept(socket);

  auto thr = std::thread([this, copy_socket = std::move(socket)]() mutable {
    handle_session(copy_socket);
    copy_socket.close();
  });
  thr.detach();
}

void Server::run()
{
  while (true)
  {
    poll();
  }
}
} // namespace dweb