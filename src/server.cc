#include <boost/asio/impl/src.hpp>
#include <boost/asio/ssl/impl/src.hpp>

#include "server.hpp"
#include <thread>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>

#include <boost/asio/co_spawn.hpp>
#include <boost/asio/detached.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/signal_set.hpp>
#include <boost/asio/write.hpp>
#include <cstdio>
#include <fstream>

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
  spdlog::error("fail: {} - {}", ec.message(), what);
}

template <class Body, class Allocator>
http::message_generator handle_request(
    http::request<Body, http::basic_fields<Allocator>> &&req)
{
  http::response<http::string_body> res{http::status::bad_request,
                                        req.version()};
  res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
  res.set(http::field::content_type, "text/html");
  res.keep_alive(req.keep_alive());
  static int counter = 0;
  res.body() = std::string("unimplemented -- ") + std::to_string(counter++);
  res.prepare_payload();
  return res;
}

void Server::handle_session(tcp::socket &socket)
{
  ssl::stream<tcp::socket &> stream{socket, *m_ssl_ctxt};

  spdlog::info("new session!");

  beast::error_code ec;
  stream.handshake(ssl::stream_base::server, ec);
  if (ec)
    return fail(ec, "handshake");

  beast::flat_buffer buffer;

  spdlog::info("everything ok, lets see what we get!");

  for (;;)
  {
    // Read a request
    http::request<http::string_body> req;
    http::read(stream, buffer, req, ec);
    if (ec == http::error::end_of_stream)
      break;
    if (ec)
      return fail(ec, "read");

    http::message_generator msg = handle_request(std::move(req));

    bool keep_alive = msg.keep_alive();
    beast::write(stream, std::move(msg), ec);
    if (ec)
      return fail(ec, "write");

    if (!keep_alive)
    {
      break;
    }
  }

  stream.shutdown(ec);
  if (ec)
    return fail(ec, "shutdown");

  spdlog::info("exiting session--------------------");
}

void Server::poll()
{
  tcp::socket socket{*m_io_context};
  m_acceptor->accept(socket);

  auto thr = std::thread([this, copy_socket = std::move(socket)]() mutable {
    handle_session(copy_socket);
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