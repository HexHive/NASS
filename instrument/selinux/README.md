# Selinux

Query to check if standalone native service handle can be obtained by an app:
`select service_name from service inner join apphandle on apphandle.service_id == service.id where device == "a497c295" and app_can_get_handle == 1 and onTransact_entry!=-1 and binary_path not LIKE "%app_process64%" and onTransact_bin not LIKE "%libandroid_runtime.so%"`
