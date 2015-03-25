/**
 * @file sharding.cpp
 *
 * @verbatim

 @endverbatim
 * - check if Maxscale alive
 */

#include <my_config.h>
#include <iostream>
#include "testconnections.h"

int main(int argc, char *argv[])
{
    TestConnections * Test = new TestConnections(argc, argv);
    int global_result = 0;
    int i;
    char str[256];
    char user_str[256];
    char pass_str[256];

    Test->repl->stop_slaves();

    Test->restart_maxscale();

    Test->repl->connect();

    for (i = 0; i < Test->repl->N; i++) {
        sprintf(str, "CREATE USER 'user%d'@'%%' IDENTIFIED BY 'pass%d';", i, i);
        execute_query(Test->repl->nodes[i], str);

        /*
        sprintf(str, "CREATE DATABASE db%d;", i);
        execute_query(Test->repl->nodes[i], str);
        sprintf(str, "GRANT SELECT,USAGE ON db%d.* TO 'user%d'@'%%'", i, i);
        execute_query(Test->repl->nodes[i], str);
        */

        sprintf(str, "GRANT SELECT,USAGE ON test.* TO 'user%d'@'%%'", i, i);
        execute_query(Test->repl->nodes[i], str);
    }

    MYSQL * conn[Test->repl->N];
    for (i = 0; i < Test->repl->N; i++) {
        sprintf(user_str, "user%d", i);
        sprintf(pass_str, "pass%d", i);
        conn[i] = open_conn(Test->rwsplit_port, Test->maxscale_IP, user_str, pass_str);

        sprintf(str, "DROP TABLE IF EXISTS table%d", i);
        execute_query(Test->repl->nodes[i], str);
        sprintf(str, "CREATE TABLE table%d (x1 int, fl int);", i);
        execute_query(Test->repl->nodes[i], str);
    }


    //global_result += check_maxscale_alive();

    Test->copy_all_logs(); return(global_result);
}
