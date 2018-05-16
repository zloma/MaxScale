/**
 * @file FRUCT demo
 */


#include <iostream>
#include <ctime>
#include "testconnections.h"
#include "maxadmin_operations.h"
#include "sql_t1.h"
#include "fw_copy_rules.h"
#include "keepalived_func.h"

const char sql1[] = "CREATE TABLE sales ( \
                  Date DATETIME, \
                  ClientID VARCHAR(100), \
              Name VARCHAR(100), \
              Phone VARCHAR(16), \
              Sum INT \
                ); \
        INSERT INTO sales (Date, ClientID, Name, Phone, Sum) VALUES (\"2018-05-16\", \"1\", \"Alice\", \"358-50-123456\", \"100\"); \
        INSERT INTO sales (Date, ClientID, Name, Phone, Sum) VALUES (\"2018-05-17\", \"2\", \"Bob\", \"358-50-654321\", \"200\"); \
        INSERT INTO sales (Date, ClientID, Name, Phone, Sum) VALUES (\"2018-05-17\", \"3\", \"Charlie\", \"358-50-162534\", \"50\"); ";

const char sql2[] = "INSERT INTO t1 (fl, x1) VALUES(1, 2); \
                INSERT INTO t1 (fl, x1) VALUES(2, 3);\
                INSERT INTO t1 (fl, x1) VALUES(4, 5);";

int main(int argc, char *argv[])
{
    TestConnections::skip_maxscale_start(true);
    TestConnections * Test = new TestConnections(argc, argv);
    int local_result;
    char str[4096];
    char sql[4096];
    char pass_file[4096];
    char deny_file[4096];
    char rules_dir[4096];
    FILE* file;

    Test->maxscales->ssh_node_f(0, true, "cd %s;"
                                "rm -rf rules;"
                                "mkdir rules;"
                                "chown vagrant:vagrant rules",
                                Test->maxscales->access_homedir[0]);

    Test->maxscales->ssh_node_f(1, true, "cd %s;"
                                "rm -rf rules;"
                                "mkdir rules;"
                                "chown vagrant:vagrant rules",
                                Test->maxscales->access_homedir[1]);

    sprintf(rules_dir, "%s/fw/", test_dir);

    int i = 19;

    Test->set_timeout(180);
    local_result = 0;


    sprintf(str, "rules%d", i);
    copy_rules(Test, str, rules_dir, 0);
    copy_rules(Test, str, rules_dir, 1);

    Test->maxscales->copy_to_node(0, "masking.json", "/home/vagrant/rules/");
    Test->maxscales->copy_to_node(1, "masking.json", "/home/vagrant/rules/");
    Test->repl->require_gtid(true);
    Test->repl->start_replication();

    Test->tprintf("Maxscale_N %d\n", Test->maxscales->N);
    if (Test->maxscales->N < 2)
    {
        Test->tprintf("At least 2 Maxscales are needed for this test. Exiting\n");
        exit(0);
    }

    Test->tprintf("Starting Maxscale with all filters\n");
    Test->maxscales->restart_maxscale(0);
    Test->maxscales->restart_maxscale(1);
    sleep(5);
    Test->check_maxscale_alive(0);
    Test->check_maxscale_alive(1);

    // Get test client IP, replace last number in it with 253 and use it as Virtual IP
    configure_keepalived(Test, (char *) "");

    Test->maxscales->connect_rwsplit(0);

    Test->tprintf("Creating t1\n");
    create_t1(Test->maxscales->conn_rwsplit[0]);
    Test->tprintf("Creating sales'\n");
    Test->repl->connect();
    Test->tprintf(sql1);
    Test->try_query(Test->repl->nodes[0], sql1);
    Test->tprintf("Inserting inti  t1\n%s\n", sql2);
    Test->try_query(Test->repl->nodes[0], sql2);
    Test->repl->close_connections();

    sprintf(pass_file, "%s/fw/pass%d", test_dir, i);
    sprintf(deny_file, "%s/fw/deny%d", test_dir, i);

    if (Test->verbose)
    {
        Test->tprintf("Pass file: %s", pass_file);
        Test->tprintf("Deny file: %s", deny_file);
    }

    file = fopen(pass_file, "r");
    if (file != NULL)
    {
        if (Test->verbose)
        {
            Test->tprintf("********** Trying queries that should be OK ********** ");
        }
        while (fgets(sql, sizeof(sql), file))
        {
            if (strlen(sql) > 1)
            {
                if (Test->verbose)
                {
                    Test->tprintf("%s", sql);
                }
                int rv = execute_query(Test->maxscales->conn_rwsplit[0], sql);
                Test->add_result(rv, "Query should succeed: %s", sql);
                local_result += rv;
            }
        }
        fclose(file);
    }
    else
    {
        Test->add_result(1, "Error opening query file");
    }

    file = fopen(deny_file, "r");
    if (file != NULL)
    {
        if (Test->verbose)
        {
            Test->tprintf("********** Trying queries that should FAIL ********** ");
        }
        while (fgets(sql, sizeof(sql), file))
        {
            Test->set_timeout(180);
            if (strlen(sql) > 1)
            {
                if (Test->verbose)
                {
                    Test->tprintf("%s", sql);
                }
                execute_query_silent(Test->maxscales->conn_rwsplit[0], sql);
                if (mysql_errno(Test->maxscales->conn_rwsplit[0]) != 1141)
                {
                    Test->tprintf("Expected 1141, Access Denied but got %d, %s instead: %s",
                                  mysql_errno(Test->maxscales->conn_rwsplit[0]), mysql_error(Test->maxscales->conn_rwsplit[0]), sql);
                    local_result++;
                }
            }
        }
        fclose(file);
    }
    else
    {
        Test->add_result(1, "Error opening query file");
    }

    if (local_result)
    {
        Test->add_result(1, "********** rules%d test FAILED", i);
    }
    else
    {
        Test->tprintf("********** rules%d test PASSED", i);
    }

    mysql_close(Test->maxscales->conn_rwsplit[0]);




    int rval = Test->global_result;
    delete Test;
    return rval;
}
