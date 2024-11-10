#pragma once

#include <map>
#include <string>
#include <memory>

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>

namespace dweb
{
using http_version_t = unsigned;

using string_response =
    boost::beast::http::response<boost::beast::http::string_body>;

using header_map_t = std::map<boost::beast::http::field, std::string>;

enum class ResponseType
{
  ERR_OK,
  ERR_BAD_URL,
  ERR_HOST_NOT_FOUND
};

class Response
{
  public:
  Response(const http_version_t &version,
           const bool keep_alive,
           ResponseType type,
           const std::string& error_message)
      : m_version(version),
        m_keep_alive(keep_alive),
        m_type(type),
        m_error_message(error_message)
  {
  }

  boost::beast::http::status status() const;

  std::unique_ptr<string_response> to_string_response();

  private:
  const http_version_t m_version;
  const bool m_keep_alive;
  const ResponseType m_type;
  const std::string m_error_message;
};

class MessageHandler
{
  public:
  MessageHandler(std::shared_ptr<boost::asio::io_context> io_context,
                 const http_version_t version,
                 const bool keep_alive,
                 boost::beast::http::verb method,
                 const std::string &target)
      : m_io_context(io_context),
        m_version(version),
        m_keep_alive(keep_alive),
        m_method(method),
        m_target(target)
  {
  }

  std::unique_ptr<Response> get_response(const std::string &body,
                                         const header_map_t &headers);

  string_response get_internal_error_reply();

  private:
  std::shared_ptr<boost::asio::io_context> m_io_context;
  const http_version_t m_version;
  const bool m_keep_alive;
  boost::beast::http::verb m_method;
  std::string m_target;
};
} // namespace dweb