//
// Copyright (C) 2004-2006 Maciej Sobczak, Stephen Hutton
// MySQL backend copyright (C) 2006 Pawel Aleksander Fedorynski
// Distributed under the Boost Software License, Version 1.0.
// (See accompanying file LICENSE_1_0.txt or copy at
// http://www.boost.org/LICENSE_1_0.txt)
//

#define SOCI_MYSQL_SOURCE
#include "soci/mysql/soci-mysql.h"
#include "soci/connection-parameters.h"
// std
#include <cctype>
#include <cerrno>
#include <ciso646>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <string>

#ifdef _MSC_VER
#pragma warning(disable:4355)
#endif

using namespace soci;
using namespace soci::details;
using std::string;


namespace
{ // anonymous

void skip_white(std::string::const_iterator *i,
    std::string::const_iterator const & end, bool endok)
{
    for (;;)
    {
        if (*i == end)
        {
            if (endok)
            {
                return;
            }
            
            
                throw soci_error("Unexpected end of connection string.");
            
        }
        if (std::isspace(**i) != 0)
        {
            ++*i;
        }
        else
        {
            return;
        }
    }
}

std::string param_name(std::string::const_iterator *i,
    std::string::const_iterator const & end)
{
    std::string val("");
    for (;;)
    {
        if (*i == end or ((std::isalpha(**i) == 0) and **i != '_'))
        {
            break;
        }
        val += **i;
        ++*i;
    }
    return val;
}

string param_value(string::const_iterator *i,
    string::const_iterator const & end)
{
    string err = "Malformed connection string.";
    bool quot;
    if (**i == '\'')
    {
        quot = true;
        ++*i;
    }
    else
    {
        quot = false;
    }
    string val("");
    for (;;)
    {
        if (*i == end)
        {
            if (quot)
            {
                throw soci_error(err);
            }
            else
            {
                break;
            }
        }
        if (**i == '\'')
        {
            if (quot)
            {
                ++*i;
                break;
            }
            else
            {
                throw soci_error(err);
            }
        }
        if (not quot and (std::isspace(**i) != 0))
        {
            break;
        }
        if (**i == '\\')
        {
            ++*i;
            if (*i == end)
            {
                throw soci_error(err);
            }
        }
        val += **i;
        ++*i;
    }
    return val;
}

bool valid_int(const string & s)
{
    char *tail;
    const char *cstr = s.c_str();
    errno = 0;
    long n = std::strtol(cstr, &tail, 10);
    if (errno != 0 or n > INT_MAX or n < INT_MIN)
    {
        return false;
    }
    if (*tail != '\0')
    {
        return false;
    }
    return true;
}

void parse_connect_string(const string & connectString,
    string *host, bool *host_p,
    string *user, bool *user_p,
    string *password, bool *password_p,
    string *db, bool *db_p,
    string *unix_socket, bool *unix_socket_p,
    int *port, bool *port_p,
    mysql_ssl_mode* ssl_mode, bool* ssl_mode_p,
    string *ssl_ca, bool *ssl_ca_p,
    string *ssl_cert, bool *ssl_cert_p, string *ssl_key, bool *ssl_key_p,
    int *local_infile, bool *local_infile_p,
    string *charset, bool *charset_p,
    int *timeout, bool *timeout_p)
{
    *host_p = false;
    *user_p = false;
    *password_p = false;
    *db_p = false;
    *unix_socket_p = false;
    *port_p = false;
    *ssl_mode_p = false;
    *ssl_ca_p = false;
    *ssl_cert_p = false;
    *ssl_key_p = false;
    *local_infile_p = false;
    *charset_p = false;
    *timeout_p = false;
    string err = "Malformed connection string.";
    string::const_iterator i = connectString.begin(),
        end = connectString.end();
    while (i != end)
    {
        skip_white(&i, end, true);
        if (i == end)
        {
            return;
        }
        string par = param_name(&i, end);
        skip_white(&i, end, false);
        if (*i == '=')
        {
            ++i;
        }
        else
        {
            throw soci_error(err);
        }
        skip_white(&i, end, false);
        string val = param_value(&i, end);
        if (par == "port" and not *port_p)
        {
            if (not valid_int(val))
            {
                throw soci_error(err);
            }
            *port = std::atoi(val.c_str());
            if (*port < 0)
            {
                throw soci_error(err);
            }
            *port_p = true;
        }
        else if (par == "host" and not *host_p)
        {
            *host = val;
            *host_p = true;
        }
        else if (par == "user" and not *user_p)
        {
            *user = val;
            *user_p = true;
        }
        else if ((par == "pass" or par == "password") and not *password_p)
        {
            *password = val;
            *password_p = true;
        }
        else if ((par == "db" or par == "dbname" or par == "service") and
                 not *db_p)
        {
            *db = val;
            *db_p = true;
        }
        else if (par == "unix_socket" and not *unix_socket_p)
        {
            *unix_socket = val;
            *unix_socket_p = true;
        }
        else if (par == "ssl_mode" and not *ssl_mode_p)
        {
            *ssl_mode_p = true;
            if (val == "disabled")
            {
                *ssl_mode = SSL_MODE_DISABLED;
            }
            else if (val == "preferred")
            {
                *ssl_mode = SSL_MODE_PREFERRED;
            }
            else if (val == "required")
            {
                *ssl_mode = SSL_MODE_REQUIRED;
            }
            else if (val == "verify_ca")
            {
                *ssl_mode = SSL_MODE_VERIFY_CA;
            }
            else if (val == "verify_identity")
            {
                *ssl_mode = SSL_MODE_VERIFY_IDENTITY;
            }
            else
            {
                throw soci_error(err);
            }
        }
        else if (par == "sslca" and not *ssl_ca_p)
        {
            *ssl_ca = val;
            *ssl_ca_p = true;
        }
        else if (par == "sslcert" and not *ssl_cert_p)
        {
            *ssl_cert = val;
            *ssl_cert_p = true;
        }
        else if (par == "sslkey" and not *ssl_key_p)
        {
            *ssl_key = val;
            *ssl_key_p = true;
        }
        else if (par == "local_infile" and not *local_infile_p)
        {
            if (not valid_int(val))
            {
                throw soci_error(err);
            }
            *local_infile = std::atoi(val.c_str());
            if (*local_infile != 0 and *local_infile != 1)
            {
                throw soci_error(err);
            }
            *local_infile_p = true;
        } else if (par == "charset" and not *charset_p)
        {
            *charset = val;
            *charset_p = true;
        }
        else if (par == "timeout" and not *timeout_p)
        {
            if (not valid_int(val))
            {
                throw soci_error(err);
            }
            *timeout = std::atoi(val.c_str());
            if (*timeout < 0)
            {
                throw soci_error(err);
            }
            *timeout_p = true;
        }
        else
        {
            throw soci_error(err);
        }
    }
}

} // namespace anonymous


#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wuninitialized"
#endif

#if defined(__GNUC__) && (__GNUC__ == 4) && (__GNUC_MINOR__ > 6)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif


mysql_session_backend::mysql_session_backend(
    connection_parameters const & parameters)
{
    string host, user, password, db, unix_socket, ssl_ca, ssl_cert, ssl_key,
        charset;
    mysql_ssl_mode ssl_mode = SSL_MODE_PREFERRED;
    int port = 0, timeout = 0, local_infile = 0;
    bool host_p, user_p, password_p, db_p, unix_socket_p, port_p,
        ssl_mode_p, ssl_ca_p, ssl_cert_p, ssl_key_p, local_infile_p, charset_p, timeout_p;
    parse_connect_string(parameters.get_connect_string(), &host, &host_p, &user, &user_p,
        &password, &password_p, &db, &db_p,
        &unix_socket, &unix_socket_p, &port, &port_p,
        &ssl_mode, &ssl_mode_p, &ssl_ca, &ssl_ca_p, &ssl_cert, &ssl_cert_p, &ssl_key, &ssl_key_p,
        &local_infile, &local_infile_p, &charset, &charset_p,
        &timeout, &timeout_p);
    conn_ = mysql_init(nullptr);
    if (conn_ == nullptr)
    {
        throw soci_error("mysql_init() failed.");
    }
    if (charset_p)
    {
        add_and_check_option(MYSQL_SET_CHARSET_NAME, charset.c_str());
    }
    if (timeout_p)
    {
        my_bool reconnect = 1;
        add_and_check_option(MYSQL_OPT_RECONNECT, &reconnect);

        add_and_check_option(MYSQL_OPT_CONNECT_TIMEOUT, &timeout);
        add_and_check_option(MYSQL_OPT_READ_TIMEOUT, &timeout);
        add_and_check_option(MYSQL_OPT_WRITE_TIMEOUT, &timeout);
    }
    if (ssl_mode_p)
    {
        add_and_check_option(MYSQL_OPT_SSL_MODE, &ssl_mode);
    }
    if (ssl_ca_p)
    {
        mysql_ssl_set(conn_, ssl_key_p ? ssl_key.c_str() : nullptr,
                      ssl_cert_p ? ssl_cert.c_str() : nullptr,
                      ssl_ca.c_str(), nullptr, nullptr);
    }
    if (local_infile_p and local_infile == 1)
    {
        add_and_check_option(MYSQL_OPT_LOCAL_INFILE, nullptr);
    }
    if (mysql_real_connect(conn_,
            host_p ? host.c_str() : nullptr,
            user_p ? user.c_str() : nullptr,
            password_p ? password.c_str() : nullptr,
            db_p ? db.c_str() : nullptr,
            port_p ? port : 0,
            unix_socket_p ? unix_socket.c_str() : nullptr,
#ifdef CLIENT_MULTI_RESULTS
            CLIENT_FOUND_ROWS | CLIENT_MULTI_RESULTS) == nullptr)
#else
            CLIENT_FOUND_ROWS) == NULL)
#endif
    {
        string errMsg = mysql_error(conn_);
        unsigned int errNum = mysql_errno(conn_);
        clean_up();
        throw mysql_soci_error(errMsg, errNum);
    }
}

#if defined(__GNUC__) && (__GNUC__ == 4) && (__GNUC_MINOR__ > 6)
#pragma GCC diagnostic pop
#endif

#ifdef __clang__
#pragma clang diagnostic pop
#endif



mysql_session_backend::~mysql_session_backend()
{
    clean_up();
}

namespace // unnamed
{

// helper function for hardcoded queries
void hard_exec(MYSQL *conn, const string & query)
{
    if (0 != mysql_real_query(conn, query.c_str(),
            static_cast<unsigned long>(query.size())))
    {
        throw soci_error(mysql_error(conn));
    }
}

} // namespace unnamed

void mysql_session_backend::begin()
{
    hard_exec(conn_, "BEGIN");
}

void mysql_session_backend::commit()
{
    hard_exec(conn_, "COMMIT");
}

void mysql_session_backend::rollback()
{
    hard_exec(conn_, "ROLLBACK");
}

bool mysql_session_backend::get_last_insert_id(
    session & /* s */, std::string const & /* table */, long & value)
{
    value = static_cast<long>(mysql_insert_id(conn_));

    return true;
}

void mysql_session_backend::clean_up()
{
    if (conn_ != nullptr)
    {
        mysql_close(conn_);
        conn_ = nullptr;
    }
}

void mysql_session_backend::add_and_check_option(mysql_option opt, const void *arg)
{
    if (0 != mysql_options(conn_, opt, arg))
    {
        clean_up();
        std::stringstream error;
        error << "mysql_options() failed when trying to set option = " << opt;
        throw soci_error(error.str());
    }
}

mysql_statement_backend * mysql_session_backend::make_statement_backend()
{
    return new mysql_statement_backend(*this);
}

mysql_rowid_backend * mysql_session_backend::make_rowid_backend()
{
    return new mysql_rowid_backend(*this);
}

mysql_blob_backend * mysql_session_backend::make_blob_backend()
{
    return new mysql_blob_backend(*this);
}
