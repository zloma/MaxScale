/*
 * Copyright (c) 2016 MariaDB Corporation Ab
 *
 * Use of this software is governed by the Business Source License included
 * in the LICENSE.TXT file and at www.mariadb.com/bsl11.
 *
 * Change Date: 2022-01-01
 *
 * On the date above, in accordance with the Business Source License, use
 * of this software will be governed by version 2 or later of the General
 * Public License.
 */

#include <maxscale/ccdefs.hh>

#include <new>
#include <unordered_map>
#include <set>
#include <string>
#include <algorithm>

#include <ldap.h>
#include <sasl/sasl.h>

#include <maxscale/users.h>
#include <maxscale/authenticator.h>
#include <maxscale/spinlock.hh>
#include <maxscale/log.h>
#include <maxscale/jansson.hh>
#include <maxscale/utils.hh>
#include <maxscale/adminusers.h>

namespace std
{

template<>
struct default_delete<LDAP>
{
    void operator()(LDAP* ld)
    {
        ldap_unbind_ext(ld, nullptr, nullptr);
    }
};

template<>
struct default_delete<berval>
{
    void operator()(berval* bv)
    {
        ldap_memfree(bv);
    }
};

template<>
struct default_delete<LDAPMessage>
{
    void operator()(LDAPMessage* msg)
    {
        ldap_msgfree(msg);
    }
};
}

namespace
{

struct Auth
{
    std::string user;
    std::string password;
};

int sasl_cb(LDAP* ld, unsigned flags, void* defaults, void* in)
{
    if (ld == NULL)
    {
        return LDAP_PARAM_ERROR;
    }

    Auth* auth = static_cast<Auth*>(defaults);

    for (sasl_interact_t* interact = static_cast<sasl_interact_t*>(in);
         interact->id != SASL_CB_LIST_END; interact++)
    {
        if (interact->id == SASL_CB_AUTHNAME)
        {
            interact->result = auth->user.c_str();
            interact->len = auth->user.length();
        }
        else if (interact->id == SASL_CB_PASS)
        {
            interact->result = auth->password.c_str();
            interact->len = auth->password.length();
        }
    }

    return LDAP_SUCCESS;
}

std::unique_ptr<LDAP> bind_ldap_user(const std::string& user, const std::string& password)
{
    Auth authdata {user, password};
    std::unique_ptr<LDAP> rval;
    LDAP* ld = nullptr;

    if (int err = ldap_initialize(&ld, "ldapi:///"))
    {
        MXS_ERROR("LDAP initialization failed: %s", ldap_err2string(err));
    }
    else
    {
        rval.reset(ld);

        // Boilerplate code required for all modern programs
        int protocol = LDAP_VERSION3;
        ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &protocol);

        if (int err = ldap_sasl_interactive_bind_s(ld,
                                                   NULL,
                                                   "DIGEST-MD5",
                                                   NULL,
                                                   NULL,
                                                   LDAP_SASL_QUIET,
                                                   sasl_cb,
                                                   &authdata))
        {
            MXS_INFO("LDAP bind failed: %s", ldap_err2string(err));
            rval.reset();
        }
    }

    return rval;
}

bool ldap_user_is_admin(const std::unique_ptr<LDAP>& ld)
{
    bool rval = false;
    berval* out = NULL;

    if (int err = ldap_whoami_s(ld.get(), &out, NULL, NULL))
    {
        MXS_ERROR("LDAP WHOAMI failed: %s", ldap_err2string(err));
        return false;
    }

    std::unique_ptr<berval> u_out(out);
    std::string dn(out->bv_val + 3, out->bv_len - 3);   // Remove the dn: prefix
    LDAPMessage* res;
    char member[] = "member";
    char* attrs[] = {member, nullptr};

    // NOTE: this requires that the user is able to view the contents of the group it is a part of
    //       it might be better to have a separate user for MaxScale that does the lookup to make it
    //       possible to remove read permissions on the group from the group members

    if (int err = ldap_search_ext_s(ld.get(),
                                    "cn=Admins,ou=People,dc=localhost",     // TODO: make this configurable
                                    LDAP_SCOPE_BASE,
                                    NULL,
                                    attrs,
                                    0,
                                    NULL,
                                    NULL,
                                    NULL,
                                    10,
                                    &res))
    {
        MXS_ERROR("LDAP search failed: %s", ldap_err2string(err));
        return false;
    }

    std::unique_ptr<LDAPMessage> u_res(res);
    BerElement* berptr;

    for (char* attr = ldap_first_attribute(ld.get(), res, &berptr); attr;
         attr = ldap_next_attribute(ld.get(), res, berptr))
    {
        mxb_assert_message(strcasecmp(attr, "member") == 0, "Only the member attribute should be returned");
        auto val = ldap_get_values_len(ld.get(), res, attr);

        for (int i = 0; val[i]; i++)
        {
            if (strcasecmp(dn.c_str(), val[i]->bv_val) == 0)
            {
                rval = true;
            }
        }

        ldap_value_free_len(val);
    }

    return rval;
}

static const char STR_BASIC[] = "basic";
static const char STR_ADMIN[] = "admin";

struct UserInfo
{
    UserInfo()
        : permissions(USER_ACCOUNT_BASIC)
    {
    }

    UserInfo(std::string pw, user_account_type perm)
        : password(pw)
        , permissions(perm)
    {
    }

    std::string       password;
    user_account_type permissions;
};


class Users
{
    Users(const Users&);
    Users& operator=(const Users&);

public:
    typedef std::unordered_map<std::string, UserInfo> UserMap;

    Users()
    {
    }

    ~Users()
    {
    }

    bool add(std::string user, std::string password, user_account_type perm)
    {
        mxs::SpinLockGuard guard(m_lock);
        return m_data.insert(std::make_pair(user, UserInfo(password, perm))).second;
    }

    bool remove(std::string user)
    {
        mxs::SpinLockGuard guard(m_lock);
        bool rval = false;
        UserMap::iterator it = m_data.find(user);

        if (it != m_data.end())
        {
            m_data.erase(it);
            rval = true;
        }

        return rval;
    }

    bool get(std::string user, UserInfo* output = NULL) const
    {
        mxs::SpinLockGuard guard(m_lock);
        UserMap::const_iterator it = m_data.find(user);
        bool rval = false;

        if (it != m_data.end())
        {
            rval = true;

            if (output)
            {
                *output = it->second;
            }
        }

        return rval;
    }

    int admin_count() const
    {
        return std::count_if(m_data.begin(), m_data.end(), is_admin);
    }

    bool check_permissions(const std::string& user,
                           const std::string& password,
                           user_account_type  perm) const
    {
        mxs::SpinLockGuard guard(m_lock);
        UserMap::const_iterator it = m_data.find(user);
        bool rval = false;

        if (it != m_data.end() && it->second.permissions == perm)
        {
            rval = true;
        }
        else if (auto ld = bind_ldap_user(user, password))
        {
            rval = ldap_user_is_admin(ld);
        }

        return rval;
    }

    bool set_permissions(std::string user, user_account_type perm)
    {
        mxs::SpinLockGuard guard(m_lock);
        UserMap::iterator it = m_data.find(user);
        bool rval = false;

        if (it != m_data.end())
        {
            rval = true;
            it->second.permissions = perm;
        }

        return rval;
    }

    json_t* diagnostic_json() const
    {
        mxs::SpinLockGuard guard(m_lock);
        json_t* rval = json_array();

        for (UserMap::const_iterator it = m_data.begin(); it != m_data.end(); it++)
        {
            json_t* obj = json_object();
            json_object_set_new(obj, CN_NAME, json_string(it->first.c_str()));
            json_object_set_new(obj, CN_ACCOUNT, json_string(account_type_to_str(it->second.permissions)));
            json_array_append_new(rval, obj);
        }

        return rval;
    }

    void diagnostic(DCB* dcb) const
    {
        mxs::SpinLockGuard guard(m_lock);
        if (m_data.size())
        {
            const char* sep = "";
            std::set<std::string> users;

            for (UserMap::const_iterator it = m_data.begin(); it != m_data.end(); it++)
            {
                users.insert(it->first);
            }

            for (const auto& a : users)
            {
                dcb_printf(dcb, "%s%s", sep, a.c_str());
                sep = ", ";
            }
        }
    }

    bool empty() const
    {
        mxs::SpinLockGuard guard(m_lock);
        return m_data.size() > 0;
    }

    json_t* to_json() const
    {
        json_t* arr = json_array();
        mxs::SpinLockGuard guard(m_lock);

        for (UserMap::const_iterator it = m_data.begin(); it != m_data.end(); it++)
        {
            json_t* obj = json_object();
            json_object_set_new(obj, CN_NAME, json_string(it->first.c_str()));
            json_object_set_new(obj, CN_ACCOUNT, json_string(account_type_to_str(it->second.permissions)));
            json_object_set_new(obj, CN_PASSWORD, json_string(it->second.password.c_str()));
            json_array_append_new(arr, obj);
        }

        return arr;
    }

    static Users* from_json(json_t* json)
    {
        Users* u = reinterpret_cast<Users*>(users_alloc());
        u->load_json(json);
        return u;
    }

private:

    static bool is_admin(const UserMap::value_type& value)
    {
        return value.second.permissions == USER_ACCOUNT_ADMIN;
    }

    void load_json(json_t* json)
    {
        // This function is always called in a single-threaded context
        size_t i;
        json_t* value;

        json_array_foreach(json, i, value)
        {
            json_t* name = json_object_get(value, CN_NAME);
            json_t* type = json_object_get(value, CN_ACCOUNT);
            json_t* password = json_object_get(value, CN_PASSWORD);

            if (name && json_is_string(name)
                && type && json_is_string(type)
                && password && json_is_string(password)
                && json_to_account_type(type) != USER_ACCOUNT_UNKNOWN)
            {
                add(json_string_value(name),
                    json_string_value(password),
                    json_to_account_type(type));
            }
            else
            {
                MXS_ERROR("Corrupt JSON value in users file: %s", mxs::json_dump(value).c_str());
            }
        }
    }

    mxs::SpinLock m_lock;
    UserMap       m_data;
};
}

USERS* users_alloc()
{
    Users* rval = new( std::nothrow) Users();
    MXS_OOM_IFNULL(rval);
    return reinterpret_cast<USERS*>(rval);
}

void users_free(USERS* users)
{
    Users* u = reinterpret_cast<Users*>(users);
    delete u;
}

bool users_add(USERS* users, const char* user, const char* password, enum user_account_type type)
{
    Users* u = reinterpret_cast<Users*>(users);
    return u->add(user, password, type);
}

bool users_delete(USERS* users, const char* user)
{
    Users* u = reinterpret_cast<Users*>(users);
    return u->remove(user);
}

json_t* users_to_json(USERS* users)
{
    Users* u = reinterpret_cast<Users*>(users);
    return u->to_json();
}

USERS* users_from_json(json_t* json)
{
    return reinterpret_cast<USERS*>(Users::from_json(json));
}

bool users_find(USERS* users, const char* user)
{
    Users* u = reinterpret_cast<Users*>(users);
    return u->get(user);
}

bool users_auth(USERS* users, const char* user, const char* password)
{
    Users* u = reinterpret_cast<Users*>(users);
    bool rval = false;
    UserInfo info;

    if (u->get(user, &info))
    {
        rval = info.password == mxs::crypt(password, ADMIN_SALT);
    }
    else if (password && bind_ldap_user(user, password))
    {
        rval = true;
    }

    return rval;
}

bool users_is_admin(USERS* users, const char* user, const char* password)
{
    Users* u = reinterpret_cast<Users*>(users);
    return u->check_permissions(user, password ? password : "", USER_ACCOUNT_ADMIN);
}

int users_admin_count(USERS* users)
{
    Users* u = reinterpret_cast<Users*>(users);
    return u->admin_count();
}

void users_diagnostic(DCB* dcb, USERS* users)
{
    Users* u = reinterpret_cast<Users*>(users);
    u->diagnostic(dcb);
}

json_t* users_diagnostic_json(USERS* users)
{
    Users* u = reinterpret_cast<Users*>(users);
    return u->diagnostic_json();
}

void users_default_diagnostic(DCB* dcb, SERV_LISTENER* port)
{
    if (port->users)
    {
        users_diagnostic(dcb, port->users);
    }
}

json_t* users_default_diagnostic_json(const SERV_LISTENER* port)
{
    return port->users ? users_diagnostic_json(port->users) : json_array();
}

int users_default_loadusers(SERV_LISTENER* port)
{
    users_free(port->users);
    port->users = users_alloc();
    return MXS_AUTH_LOADUSERS_OK;
}

const char* account_type_to_str(enum user_account_type type)
{
    switch (type)
    {
    case USER_ACCOUNT_BASIC:
        return STR_BASIC;

    case USER_ACCOUNT_ADMIN:
        return STR_ADMIN;

    default:
        return "unknown";
    }
}

enum user_account_type json_to_account_type(json_t* json)
{
    std::string str = json_string_value(json);

    if (str == STR_BASIC)
    {
        return USER_ACCOUNT_BASIC;
    }
    else if (str == STR_ADMIN)
    {
        return USER_ACCOUNT_ADMIN;
    }

    return USER_ACCOUNT_UNKNOWN;
}
