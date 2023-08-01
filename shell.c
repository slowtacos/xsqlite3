#include "shell.h"
#include <sqlite3.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>

static int callback(void *not_used, int argc, char **argv, char **colname) {
    not_used = NULL;
    
    for (int i = 0; i < argc; i++) {

        printf("%s = %s\n", colname[i], argv[i] ? argv[i] : "NULL");
    }
    
    printf("\n");
    
    return 0;
}

void shell(sqlite3 *db) {
  int delim = ';';
  char* sql_buf = NULL;
  char *sql = NULL;
  size_t sql_n = 0;
  ssize_t sql_len = 0;
  char *err = NULL;

  while(true) {
    printf("> ");
    if ((sql_len = getdelim(&sql_buf, &sql_n, delim, stdin)) == -1) {
      perror(NULL);
      return;
    }

    // get the first non newline pointer from sql_buf
    sql = sql_buf;
    while (true) {
      if (*sql != '\n')
        break;
      sql++;
    }

    if (strcmp(sql, "end;") == 0)
      break;

    if (strcmp(sql, "help;") == 0) {
      puts("end; to close and save encrypted database");
      continue;
    }

    sqlite3_exec(db, sql, callback, NULL, &err);
    if (err) {
      puts(err);
      puts("help; for hints");
    }
  }
  free(sql_buf);
}
