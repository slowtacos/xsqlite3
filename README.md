# example
- create encrypted database and fill with some data
```
$ xsqlite3 -f mydb.xdb
  password: abc
  confirm password: abc
  > create table secret(a text);
  > insert into secret(a) values('123');
  > close;
```

- open database and query
```
$ xsqlite3 -f mydb.xdb
  password: abc
  > select * from secret;
  a = 123
  > close;
```