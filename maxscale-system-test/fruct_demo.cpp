/**
 * @file FRUCT demo
 */


#include <iostream>
#include <ctime>
#include "testconnections.h"
#include "maxadmin_operations.h"
#include "sql_t1.h"
#include "fw_copy_rules.h"

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

    sprintf(rules_dir, "%s/fw/", test_dir);

    int i = 4;

    Test->set_timeout(180);
    local_result = 0;


    sprintf(str, "rules%d", i);
    copy_rules(Test, str, rules_dir);

    Test->maxscales->copy_to_node(0, "masking.json", "/home/vagrant/rules/");
    Test->repl->require_gtid(true);
    Test->repl->start_replication();
    Test->tprintf("Starting Maxscale with all filters\n");
    Test->maxscales->restart_maxscale(0);
    sleep(5);
    Test->maxscales->connect_rwsplit(0);

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
