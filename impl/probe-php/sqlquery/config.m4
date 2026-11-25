PHP_ARG_ENABLE([sqlquery],
  [whether to enable sqlquery support],
  [AS_HELP_STRING([--enable-sqlquery], [Enable sqlquery mysqlnd query instrumentation])],
  [no])

if test "$PHP_SQLQUERY" != "no"; then
  PHP_ADD_EXTENSION_DEP([sqlquery], [mysqlnd])
  PHP_ADD_EXTENSION_DEP([sqlquery], [json])
  PHP_NEW_EXTENSION([sqlquery], [sqlquery.c], [$ext_shared])
fi
