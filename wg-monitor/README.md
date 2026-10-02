# WireGuard Monitor (Keenetic Entware)

Веб-дашборд и демон для Keenetic: следит за WireGuard-туннелями и при падении того, через который идут IPv4-маршруты, переключает маршруты / политику VPN / DNS на любой активный туннель.

## Возможности

- Список всех WireGuard-интерфейсов: online, handshake, трафик, endpoint
- Определение интерфейса, на который смотрят статические маршруты
- Автопроверка с настраиваемым интервалом (по умолчанию 5 минут, меняется в веб-UI)
- Автоfailover (можно выключить в UI)
- Ручное переключение на активный туннель
- Backup маршрутов перед сменой
- Загрузка конфигов **hidemy.name / hidethis.app** по выбранной стране (страна обязательна) и установка на Keenetic через RCI import (включая AmneziaWG 2.0)
- Опциональный автопровisioning, если нет ни одного активного WG
- Ручное обновление приложения из публичного GitHub-репозитория (кнопка в веб-UI, без автообновления)

## Требования

- Keenetic с компонентом **OPKG**
- **Entware** установлен и доступен (`/opt/bin/opkg`, shell BusyBox)
- Диск Entware в **ext2/ext3/ext4** (NTFS для Entware не подходит)
- Python3 в Entware (`opkg install python3`)
- Учётная запись с доступом к RCI (`http` / admin)

### Entware на этом роутере

На KN-1910 USB сейчас может быть NTFS — его нужно переразметить в ext4 (данные на разделе будут стёрты) либо поставить Entware во внутреннюю память:

```text
(config)> opkg disk storage:/
```

Далее по [инструкции Keenetic](https://support.keenetic.com/): каталог `install/` + `mipsel-installer.tar.gz`, после установки SSH Entware обычно на порту **222** (`root` / `keenetic`).

Пока Entware не готов, можно запустить монитор с Mac в LAN:

```bash
cd wg-monitor
chmod +x scripts/run-lan.sh
./scripts/run-lan.sh
# дашборд: http://<ip-мака>:8088/
```

## Установка на Entware

```bash
cd wg-monitor
cp config.example.json config.json   # пропишите пароль admin
chmod +x scripts/deploy.sh install.sh
./scripts/deploy.sh root@192.168.1.1 222
```

Или вручную скопируйте дерево на роутер и выполните `/opt/bin/sh /tmp/wg-monitor/install.sh`.

Дашборд: **http://192.168.1.1:8088/**

## Конфиг

`/opt/etc/wg-monitor/config.json` (права `600`):

```json
{
  "rci_url": "http://192.168.1.1",
  "username": "admin",
  "password": "YOUR_PASSWORD",
  "listen_host": "0.0.0.0",
  "listen_port": 8088,
  "check_interval_sec": 300,
  "handshake_max_age_sec": 180,
  "failover_enabled": true,
  "preference": ["Wireguard3", "Wireguard0", "Wireguard2"],
  "route_batch_size": 50,
  "policy_name": "Policy0",
  "state_path": "/opt/var/lib/wg-monitor/state.json",
  "backup_dir": "/opt/var/lib/wg-monitor",
  "hidethis_base_url": "https://hidethis.app",
  "hidethis_access_code": "YOUR_ACCESS_CODE",
  "hidethis_country": "NL",
  "hidethis_awg": 4,
  "auto_provision_enabled": false,
  "auto_provision_cooldown_sec": 3600
}
```

Поля `hidethis_*` и автопровisioning также задаются в веб-UI. **Страна обязательна** для любой загрузки: кнопка ставит на роутер все серверы только выбранной страны (уже существующие по endpoint пропускаются). `hidethis_awg`: `4` = AmneziaWG 2.0 (рекомендуется для KeeneticOS 5.x), `1` = AWG 1.0, `0` = обычный WireGuard.

Образец: `config.example.json`.

## Управление

```bash
/opt/etc/init.d/S99wg-monitor start|stop|restart|status
/opt/bin/wg-monitor --once          # одна проверка
/opt/bin/wg-monitor -v              # foreground с логом
tail -f /opt/var/log/wg-monitor.log
```

## Нагрузка

| Режим | CPU |
|---|---|
| Проверка раз в 5 мин | краткий пик ~1–3%, затем ~0% |
| Дашборд без запросов | ~0% |
| Failover ~1000+ маршрутов | редко, на десятки секунд–минуты может быть 30–80% |

## Важно

Failover переписывает **все** статические маршруты с текущего WG на новый (плюс `Policy0` и DNS). На роутере с тысячами маршрутов это долгая операция — делается только при реальном падении (или вручную).
