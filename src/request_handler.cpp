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
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/write.hpp>
#include <cstdio>
#include <fstream>

#include <request_handler.hpp>

#include <boost/certify/extensions.hpp>
#include <boost/certify/https_verification.hpp>

#include <boost/url.hpp>

using namespace boost::urls;

namespace beast = boost::beast;   // from <boost/beast.hpp>
namespace http = beast::http;     // from <boost/beast/http.hpp>
namespace net = boost::asio;      // from <boost/asio.hpp>
namespace ssl = boost::asio::ssl; // from <boost/asio/ssl.hpp>
using tcp = boost::asio::ip::tcp; // from <boost/asio/ip/tcp.hpp>

namespace dweb
{

http::status Response::status() const
{
  switch (m_type)
  {
  default:
    return http::status::internal_server_error;
  case ResponseType::ERR_HOST_NOT_FOUND:
    return http::status::not_found;
  case ResponseType::ERR_BAD_URL:
    return http::status::bad_request;
  case ResponseType::ERR_OK:
    return http::status::ok;
  }
}

std::unique_ptr<string_response> Response::to_string_response()
{
  switch (m_type)
  {
  default:
  case ResponseType::ERR_BAD_URL:
  case ResponseType::ERR_HOST_NOT_FOUND: {
    auto res = std::make_unique<string_response>(status(), m_version);
    res->set(http::field::server, BOOST_BEAST_VERSION_STRING);
    res->set(http::field::content_type, "text/html");
    res->keep_alive(m_keep_alive);
    res->body() = m_error_message;
    res->prepare_payload();
    return res;
  }
  }
  return nullptr;
}

std::unique_ptr<Response> MessageHandler::get_response(
    const std::string &request_body, const header_map_t &headers)
{
  LOG_INFO("request response: '{}' - target {}", request_body, m_target);

  auto full_url_str = m_target.substr(1);
  if (full_url_str.find("://") == std::string::npos)
  {
    full_url_str = "https://" + full_url_str;
  }

  boost::system::result<url_view> r = parse_uri(full_url_str);
  if (!r.has_value())
  {
    return std::make_unique<Response>(m_version, m_keep_alive,
                                      ResponseType::ERR_BAD_URL,
                                      "bad url: " + full_url_str);
  }
  const auto url = r.value();
  const auto host = url.host();
  std::string port = url.port();
  std::string path = url.path();
  int version = 11;

  if (host == "")
  {
    // user didn't pass us the URL, lets return an error
    return std::make_unique<Response>(m_version, m_keep_alive,
                                      ResponseType::ERR_BAD_URL,
                                      "missing url to dweb-proxy: " + full_url_str);
  }

  if (port == "")
  {
    port = "443";
  }

  if (path == "")
  {
    path = "/";
  }

  LOG_INFO("HOST NAME: {}, PORT: {}, PATH: {}, INPUT: {}", host, port, path, full_url_str);

  // The SSL context is required, and holds certificates
  auto ctx = std::make_unique<ssl::context>(ssl::context::tlsv12);

  // Verify the remote server's certificate
  ctx->set_verify_mode(ssl::verify_none);

  tcp::resolver resolver(*m_io_context);
  ssl::stream<beast::tcp_stream> stream(*m_io_context, *ctx);

  // Set SNI Hostname (many hosts need this to handshake successfully)
  if (!SSL_set_tlsext_host_name(stream.native_handle(), host.c_str()))
  {
    beast::error_code ec{static_cast<int>(::ERR_get_error()),
                         net::error::get_ssl_category()};
    throw beast::system_error{ec};
  }

  try
  {
    LOG_INFO("resolving: {}, port {}", host, port);
    auto const results = resolver.resolve(host, port);
    LOG_INFO("resolved to {} addresses", results.size());
    beast::get_lowest_layer(stream).connect(results);
  }
  catch (boost::system::system_error &e)
  {
    LOG_INFO("failed to connect to server: {}", e.what());
    return std::make_unique<Response>(
        m_version, m_keep_alive, ResponseType::ERR_HOST_NOT_FOUND,
        "cannot connect to host: " + full_url_str);
  }

  try
  {
    // Perform the SSL handshake
    stream.handshake(ssl::stream_base::client);
  }
  catch (boost::system::system_error &e)
  {
    LOG_INFO("failed to do SSL handshake: {}", e.what());
    return std::make_unique<Response>(
        m_version, m_keep_alive, ResponseType::ERR_HOST_NOT_FOUND,
        "SSL handshake failed, cannot connect to host: " + full_url_str);
  }

  http::request<http::string_body> req{http::verb::get, path, version};
  req.set(http::field::host, host);
  req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);

  http::write(stream, req);

  beast::flat_buffer buffer;

  http::response<http::dynamic_body> res;

  http::read(stream, buffer, res);

  LOG_INFO("reply from remote: {} bytes", res.body().size());

  const auto cdata = res.body().cdata();
  std::vector<char> vec;
  for (auto it: cdata)
  {
    const char* data = (char*) it.data();
    const auto size = it.size();

    vec.insert(vec.end(), data, data + size);
  }

  beast::error_code ec;
  stream.shutdown(ec);

  return std::make_unique<Response>(m_version, m_keep_alive,
                                    ResponseType::ERR_OK, vec.data());
}

string_response MessageHandler::get_internal_error_reply()
{
  string_response res{http::status::internal_server_error, m_version};
  res.set(http::field::server, BOOST_BEAST_VERSION_STRING);
  res.set(http::field::content_type, "text/html");
  res.keep_alive(m_keep_alive);
  res.body() = "unhandled http reply";
  res.prepare_payload();
  return res;
}

} // namespace dweb