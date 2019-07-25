# nginx-practice
学习nginx之后记录一些小的demo
### [根据header中的userid进行分流](https://github.com/TyroneRenekton/nginx-practice/blob/master/ngx_http_upstream_ip_hash_module.c)
主要内容是根据userid的最后一位选服务器，比如userid=12345，则选择ip的最后一位等于5的机器
