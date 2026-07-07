
<h1 align="center">ipload-balancing</h1>

<p align="center">
  <strong>Balanceo, rotacion y defensa para servidores Linux con multiples IPs publicas.</strong>
</p>

<p align="center">
  <img alt="Linux" src="https://img.shields.io/badge/Linux-nftables-28d8a1?style=for-the-badge">
  <img alt="Shell" src="https://img.shields.io/badge/Shell-Bash-4ea3ff?style=for-the-badge">
  <img alt="systemd" src="https://img.shields.io/badge/systemd-service-f0b84f?style=for-the-badge">
</p>

Pensado para servidores gateway, proxies propios, nodos con varias IPs publicas
o servicios donde conviene tener rotacion y reglas de contencion rapidas.

## Caracteristicas

- Balanceo SNAT entre varias IPs publicas.
- Rotacion periodica de IP activa.
- Rotacion automatica ante trafico anomalo.
- Deteccion por paquetes recibidos, bytes recibidos, conexiones `SYN-RECV` y uso
  de conntrack.
- Reglas defensivas con `nftables`.
- Bloqueo temporal de fuentes abusivas.
- Filtro opcional por pais usando listas CIDR.
- Bloqueo opcional de rangos bogon/private en entrada.
- Logs y estado via `systemd`/`journalctl`.

## Requisitos

Debian/Ubuntu:

```bash
sudo apt-get update
sudo apt-get install -y nftables iproute2 curl
```

El servidor debe tener las IPs publicas ruteadas por el proveedor. En algunos
clouds tambien hay que asociarlas desde el panel del proveedor.

## Instalacion rapida

```bash
chmod +x ./ipload-balancer.sh
sudo cp ipload-balancer.conf.example /etc/ipload-balancer.conf
sudo nano /etc/ipload-balancer.conf
```

Variables principales:

- `PUBLIC_IFACE`: interfaz publica, por ejemplo `eth0`, `ens3`, `enp1s0`.
- `LAN_CIDR`: red privada que saldra por NAT. Dejalo vacio si queres aplicar
  SNAT a todo lo que salga por la interfaz publica.
- `PUBLIC_IPS`: IPs publicas disponibles.
- `MODE`: `balance` o `rotate`.
- `PROTECTED_PORTS`: puertos donde se aplican reglas defensivas.
- `ATTACK_RX_PPS`, `ATTACK_RX_BPS`, `ATTACK_SYN_RECV`: umbrales de reaccion.

Probar reglas una vez:

```bash
sudo CONFIG_FILE=/etc/ipload-balancer.conf ./ipload-balancer.sh apply
sudo CONFIG_FILE=/etc/ipload-balancer.conf ./ipload-balancer.sh status
```

Instalar como servicio:

```bash
sudo ./ipload-balancer.sh install
sudo systemctl start ipload-balancer
sudo systemctl status ipload-balancer
```

Ver logs:

```bash
journalctl -u ipload-balancer -f
```

Eliminar las reglas creadas por el script:

```bash
sudo ipload-balancer cleanup
```

## Modos de uso

### Balanceo

Distribuye conexiones salientes entre todas las IPs configuradas.

```bash
MODE="balance"
BALANCE_METHOD="persistent"
```

Metodos disponibles:

- `random`: reparte usando seleccion aleatoria.
- `persistent`: mantiene afinidad por origen/destino.

### Rotacion

Usa una IP activa y rota cada cierto tiempo.

```bash
MODE="rotate"
ROTATE_SECONDS="300"
```

Si se supera un umbral de ataque, el daemon rota antes del tiempo configurado.

## Filtro por pais

El filtro por pais se aplica sobre los puertos definidos en `PROTECTED_PORTS`.
Usa codigos ISO de dos letras.

Permitir solo Argentina y Estados Unidos:

```bash
GEO_POLICY="allow"
GEO_COUNTRIES=("AR" "US")
```

Bloquear paises especificos:

```bash
GEO_POLICY="block"
GEO_COUNTRIES=("CN" "RU")
```

Descargar listas y aplicar:

```bash
sudo CONFIG_FILE=/etc/ipload-balancer.conf ./ipload-balancer.sh update-geo
sudo CONFIG_FILE=/etc/ipload-balancer.conf ./ipload-balancer.sh apply
```

## Comandos

```bash
./ipload-balancer.sh daemon
./ipload-balancer.sh apply
./ipload-balancer.sh rotate
./ipload-balancer.sh update-geo
./ipload-balancer.sh status
./ipload-balancer.sh cleanup
./ipload-balancer.sh install
```

## Configuracion de ejemplo

```bash
PUBLIC_IFACE="eth0"
LAN_CIDR="10.10.0.0/24"

PUBLIC_IPS=(
  "203.0.113.10"
  "203.0.113.11"
  "203.0.113.12"
)

MODE="balance"
BALANCE_METHOD="persistent"
ROTATE_SECONDS="300"

ATTACK_RX_PPS="80000"
ATTACK_RX_BPS="100000000"
ATTACK_SYN_RECV="1500"
ATTACK_CONNTRACK_USAGE="85"

ENABLE_INPUT_GUARD="yes"
PROTECTED_PORTS="22,80,443"

GEO_POLICY="off"
GEO_COUNTRIES=("AR" "US")
```
