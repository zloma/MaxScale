/**
 * @file change_user.cpp mysql_change_user test
 *
 * - using RWSplit and user 'skysql': GRANT SELECT ON test.* TO user@'%'  identified by 'pass2';  FLUSH PRIVILEGES;
 * - create a new connection to RSplit as 'user'
 * - try INSERT expecting 'access denied'
 * - call mysql_change_user() to change user to 'skysql'
 * - try INSERT again expecting success
 * - try to execute mysql_change_user() to switch to user 'user' but use rong password (expecting access denied)
 * - try INSERT again expecting success (user should not be changed)
 */


#include <iostream>
#include <string>
#include "testconnections.h"

using std::string;
using std::cout;

const int bufsize = 512;

int main(int argc, char *argv[])
{
    TestConnections test(argc, argv);
    int ec;
    MYSQL* maxconn = test.maxscales->open_rwsplit_connection(0);

    test.repl->connect();
    test.maxscales->connect_maxscale(0);
    
    const string username = "proxy_user";
    const string proxypass = "proxy_pwd";
    const string maxscale_ip = test.maxscales->IP[0];
    char client_userhost[bufsize];
    // Send the user query directly to backend.
    if (find_field(test.repl->nodes[0], "SELECT USER();", "USER()", client_userhost))
    {
        test.assert(false, "Could not read client ip.");
        return test.global_result;
    }
    const char* client_ip = strstr(client_userhost, "@") + 1;
    cout << "Client ip is " << client_ip << "\n";
    // At this point, no query to a backend will work as proxy network hasn't been set. Do it next.
    string setting = "proxy_protocol_networks =  " + client_ip;
test.repl->stop_node(0);    
test.repl->stop_node(1);
    test.repl->stop_node(2);
    test.repl->stop_node(3);
   test.repl->stash_server_settings(0);
    test.repl->stash_server_settings(1);
    test.repl->stash_server_settings(2);
    test.repl->stash_server_settings(3);

    test.repl->add_server_setting(0, setting.c_str());
  test.repl->add_server_setting(1, setting.c_str());
  test.repl->add_server_setting(2, setting.c_str());
  test.repl->add_server_setting(3, setting.c_str());
        test.repl->start_node(0, (char *) "");
    test.repl->start_node(1, (char *) "");
    test.repl->start_node(2, (char *) "");
    test.repl->start_node(3, (char *) "");

    execute_query(test.maxscales->conn_rwsplit[0], "SELECT @@log_bin;");
    execute_query(test.maxscales->conn_rwsplit[0], "DROP USER '%s'@'%%'", username.c_str());
    execute_query(test.maxscales->conn_rwsplit[0], "DROP USER '%s'@'%s'", username.c_str(), maxscale_ip.c_str());
    execute_query(test.maxscales->conn_rwsplit[0], "DROP USER '%s'@'%s'", username.c_str(), client_ip);

    cout << "Creating user '"<< username << "' \n";
    
    test.try_query(test.maxscales->conn_rwsplit[0], (char *) "CREATE USER '%s'@'%s' identified by '%s'",
        username.c_str(), client_ip);
    test.try_query(test.maxscales->conn_rwsplit[0], (char *) "GRANT SELECT ON test.* TO '%s'@'%s'",
        username.c_str(), client_ip);
    test.try_query(test.maxscales->conn_rwsplit[0], (char *) "FLUSH PRIVILEGES;");
    test.try_query(test.maxscales->conn_rwsplit[0], (char *) "DROP TABLE IF EXISTS t1");
    test.try_query(test.maxscales->conn_rwsplit[0], (char *) "CREATE TABLE t1 (x1 int, fl int)");
/*
    Test->tprintf("Changing user... \n");
    Test->add_result(mysql_change_user(Test->maxscales->conn_rwsplit[0], (char *) "user", (char *) "pass2", (char *) "test") ,
                     "changing user failed \n");
    Test->tprintf("mysql_error is %s\n", mysql_error(Test->maxscales->conn_rwsplit[0]));

    Test->tprintf("Trying INSERT (expecting access denied)... \n");
    if ( execute_query(Test->maxscales->conn_rwsplit[0], (char *) "INSERT INTO t1 VALUES (77, 11);") == 0)
    {
        Test->add_result(1, "INSERT query succedded to user which does not have INSERT PRIVILEGES\n");
    }

    Test->tprintf("Changing user back... \n");
    Test->add_result(mysql_change_user(Test->maxscales->conn_rwsplit[0], Test->repl->user_name, Test->repl->password,
                                       (char *) "test"), "changing user failed \n");

    Test->tprintf("Trying INSERT (expecting success)... \n");
    Test->try_query(Test->maxscales->conn_rwsplit[0], (char *) "INSERT INTO t1 VALUES (77, 12);");

    Test->tprintf("Changing user with wrong password... \n");
    if (mysql_change_user(Test->maxscales->conn_rwsplit[0], (char *) "user", (char *) "wrong_pass2", (char *) "test") == 0)
    {
        Test->add_result(1, "changing user with wrong password successed! \n");
    }
    Test->tprintf("%s\n", mysql_error(Test->maxscales->conn_rwsplit[0]));
    if ((strstr(mysql_error(Test->maxscales->conn_rwsplit[0]), "Access denied for user")) == NULL)
    {
        Test->add_result(1, "There is no proper error message\n");
    }

    Test->tprintf("Trying INSERT again (expecting success - use change should fail)... \n");
    Test->try_query(Test->maxscales->conn_rwsplit[0], (char *) "INSERT INTO t1 VALUES (77, 13);");


    Test->tprintf("Changing user with wrong password using ReadConn \n");
    if (mysql_change_user(Test->maxscales->conn_slave[0], (char *) "user", (char *) "wrong_pass2", (char *) "test") == 0)
    {
        Test->add_result(1, "FAILED: changing user with wrong password successed! \n");
    }
    Test->tprintf("%s\n", mysql_error(Test->maxscales->conn_slave[0]));
    if ((strstr(mysql_error(Test->maxscales->conn_slave[0]), "Access denied for user")) == NULL)
    {
        Test->add_result(1, "There is no proper error message\n");
    }

    Test->tprintf("Changing user for ReadConn \n");
    Test->add_result(mysql_change_user(Test->maxscales->conn_slave[0], (char *) "user", (char *) "pass2", (char *) "test") ,
                     "changing user failed \n");

    Test->try_query(Test->maxscales->conn_rwsplit[0], (char *) "DROP USER user@'%%';");
    execute_query_silent(Test->maxscales->conn_rwsplit[0], "DROP TABLE test.t1");

    Test->maxscales->close_maxscale_connections(0);
    int rval = Test->global_result;
    delete Test;
    */
    return test.global_result;
}

