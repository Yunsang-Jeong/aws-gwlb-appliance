# AWS GWLB APPLIANCE

AWS GWLB에 연결할 수 있는 Appliance를 Python으로 작성했습니다. PoC 목적으로 적합하며, 운영 환경에는 적합하지 않습니다.

`terraform`의 코드로 배포한다면 저널로그에서 아래와 같이 로그를 확인할 수 있습니다.

![journal](journal.png)

> `journalctl -u gwlb.service -f`
