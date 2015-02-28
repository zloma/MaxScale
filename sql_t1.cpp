#include "sql_t1.h"

/**
Executes SQL query 'sql' using 'conn' connection and print results
*/
int execute_select_query_and_check(MYSQL *conn, char *sql, unsigned long long int rows)
{
    MYSQL_RES *res;
    MYSQL_ROW row;
    unsigned long long int i;
    unsigned long long int num_fields;
    unsigned long long int int_res;
    unsigned long long int row_i=0;
    int test_result = 0;
    unsigned long long int rows_from_select=0;
    int wait_i=0;

    printf("Trying SELECT, num_of_rows=%llu\n", rows);
    int res_alloc = 0;
    if (conn != NULL) {
        rows_from_select=0;
        wait_i=0;
        while ((rows_from_select != rows) && (wait_i < 10)) {
            if(mysql_query(conn, sql) != 0)
                printf("Error: can't execute SQL-query: %s\n", mysql_error(conn));

            res = mysql_store_result(conn); res_alloc = 1;
            if(res == NULL) {printf("Error: can't get the result description\n");
                test_result = 1; mysql_free_result(res); res_alloc = 0; wait_i++; sleep(1);
            } else {
                rows_from_select = mysql_num_rows(res);
                printf("rows=%llu\n", rows_from_select);
                wait_i++;
                if (rows_from_select != rows) {
                    printf("Waiting 1 second and trying again...\n");
                    mysql_free_result(res); res_alloc = 0;
                    sleep(1);
                }
            }
        }

        if (rows_from_select != rows) {printf("SELECT returned %llu rows insted of %llu!\n", rows_from_select, rows); test_result=1;  printf("sql was %s\n", sql);} else {
            num_fields = mysql_num_fields(res);
            if (num_fields != 2) { printf("SELECT returned %llu fileds insted of 2!\n", num_fields); test_result=1; }
            if(mysql_num_rows(res) > 0)
            {
                while((row = mysql_fetch_row(res)) != NULL) {
                    for (i = 0; i < num_fields; i++) {
                        sscanf(row[i], "%llu", &int_res);
                        if ((i == 0 ) && (int_res != row_i)) {printf("SELECT returned wrong result! %llu insted of expected %llu\n", int_res, row_i); test_result=1; printf("sql was %s\n", sql);}
                    }
                    row_i++;
                }
            }
        }
        if (res_alloc != 0) {mysql_free_result(res);}} else {
        printf("FAILED: broken connection\n");
        test_result = 1;
    }

    return(test_result);
}
int create_t1(MYSQL * conn)
{
    int result = 0;
    result += execute_query(conn, "DROP TABLE IF EXISTS t1;");
    printf("Creating test table\n");
    result += execute_query(conn, "CREATE TABLE t1 (x1 int, fl int);");
    return(result);
}

int create_insert_string(char *sql, int N, int fl)
{
    char *ins1 = (char *) "INSERT INTO t1 (x1, fl) VALUES ";
    char *ins_val = (char *) "%s (%d, %d)%s";
    int i;

    sprintf(&sql[0], "%s", ins1);
    for (i = 0; i < N-1; i++) {
        sprintf(&sql[0], ins_val, sql, i, fl, ",");
    }
    sprintf(&sql[0], ins_val, sql, N-1, fl, ";");
}

int insert_into_t1(MYSQL *conn, int N)
{
    char sql[N][1000000];
    int x=16;
    int i;
    int result = 0;
    //char *ins1 = (char *) "INSERT INTO t1 (x1, fl) VALUES ";
    //char *ins_val=(char *) "%s (%d, 1)%s";

    printf("Generating long INSERTs\n");
    for (i=0; i<N; i++) {
        printf("sql %d, rows=%d\n", i, x);
        create_insert_string(sql[i], x, i);
        x = x*16;
        printf("INSERT: rwsplitter\n");
        printf("Trying INSERT, len=%lu\n", strlen(sql[i]));
        fflush(stdout);
        result += execute_query(conn,  sql[i]);
        fflush(stdout);
    }
    return(result);
}

int select_from_t1(MYSQL *conn, int N)
{
    int x=16;
    int result=0;
    int i;
    char sq[100];

    for (i=0; i<N; i++) {
        sprintf(&sq[0], "select * from t1 where fl=%d;", i);
        result += execute_select_query_and_check(conn, sq, x);
        x = x * 16;
    }
    return(result);
}

// 0 - if it does not exist
// -1 - in case of error
int check_if_t1_exists(MYSQL *conn)
{
    MYSQL_RES *res;
    MYSQL_ROW row;
    unsigned long long int num_fields;

    int t1 = 0;
    if (conn != NULL) {
        if (mysql_query(conn, "show tables;") != 0) {
            printf("Error: can't execute SQL-query: %s\n", mysql_error(conn));
            t1 = 0;
        } else {
            res = mysql_store_result(conn);
            if (res == NULL) {printf("Error: can't get the result description\n"); t1 = - 1;}
            else {
                num_fields = mysql_num_fields(res);
                if(mysql_num_rows(res) > 0)
                {
                    while((row = mysql_fetch_row(res)) != NULL) {
                        if ( (row[0] != NULL ) && (strcmp(row[0], "t1") == 0 ) ) {
                            t1 = 1;
                        }
                    }
                }
            }
            mysql_free_result(res);
        }
    } else {
        printf("FAILED: broken connection\n");
        t1 = -1;
    }
    return(t1);
}


int inset_select(TestConnections* Test, int N)
{
    int global_result = 0;
    printf("Create t1\n"); fflush(stdout);
    create_t1(Test->conn_rwsplit);
    printf("Insert data into t1\n"); fflush(stdout);
    insert_into_t1(Test->conn_rwsplit, N);

    printf("SELECT: rwsplitter\n");fflush(stdout);
    global_result += select_from_t1(Test->conn_rwsplit, N);
    printf("SELECT: master\n");fflush(stdout);
    global_result += select_from_t1(Test->conn_master, N);
    printf("SELECT: slave\n");fflush(stdout);
    global_result += select_from_t1(Test->conn_slave, N);
    printf("Sleeping to let replication happen\n");fflush(stdout);
    sleep(180);
    for (int i=0; i<Test->repl->N; i++) {
        printf("SELECT: directly from node %d\n", i);fflush(stdout);
        global_result += select_from_t1(Test->repl->nodes[i], N);
    }
    return(global_result);
}

int use_db(TestConnections* Test, char * db)
{
    int global_result = 0;
    char sql[100];

    sprintf(sql, "USE %s;", db);

    printf("selecting DB '%s' for rwsplit\n", db);
    global_result += execute_query(Test->conn_rwsplit, sql);
    printf("selecting DB '%s' for readconn master\n", db);
    global_result += execute_query(Test->conn_slave, sql);
    printf("selecting DB '%s' for readconn slave\n", db);
    global_result += execute_query(Test->conn_master, sql);
    for (int i = 0; i < Test->repl->N; i++) {
        printf("selecting DB '%s' for direct connection to node %d\n", db, i);
        global_result += execute_query(Test->repl->nodes[i], sql);
    }
    return(global_result);
}

int check_t1_table(TestConnections* Test, bool presence, char * db)
{
    char * expected;
    char * actual;
    int global_result = 0;
    if (presence) {
        expected = (char *) "";
        actual   = (char *) "NOT";
    } else {
        expected = (char *) "NOT";
        actual   = (char *) "";
    }

    global_result += use_db(Test, db);

    printf("Checking: table 't1' should %s be found in '%s' database\n", expected, db);
    if ( ((check_if_t1_exists(Test->conn_rwsplit) >  0) && (!presence) ) ||
         ((check_if_t1_exists(Test->conn_rwsplit) == 0) && (presence) ))
    {global_result++; printf("Table t1 is %s found in '%s' database using RWSplit\n", actual, db); } else {
        printf("RWSplit: ok\n");
    }
    if ( ((check_if_t1_exists(Test->conn_master) >  0) && (!presence) ) ||
         ((check_if_t1_exists(Test->conn_master) == 0) && (presence) ))
    {global_result++; printf("Table t1 is %s found in '%s' database using Readconnrouter with router option master\n", actual, db); } else {
        printf("ReadConn master: ok\n");
    }
    if ( ((check_if_t1_exists(Test->conn_slave) >  0) && (!presence) ) ||
         ((check_if_t1_exists(Test->conn_slave) == 0) && (presence) ))
    {global_result++; printf("Table t1 is %s found in '%s' database using Readconnrouter with router option slave\n", actual, db); } else {
        printf("ReadConn slave: ok\n");
    }
    printf("Sleeping to let replication happen\n");
    sleep(60);
    for (int i=0; i<Test->repl->N; i++) {
        if ( ((check_if_t1_exists(Test->repl->nodes[i]) >  0) && (!presence) ) ||
             ((check_if_t1_exists(Test->repl->nodes[i]) == 0) && (presence) ))
        {global_result++; printf("Table t1 is %s found in '%s' database using direct connect to node %d\n", actual, db, i); } else {
            printf("Node %d: ok\n", i);
        }
    }
    return(global_result);
}
