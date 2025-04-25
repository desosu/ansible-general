# DeSoSu

## General

### Hosts file

Probar localmente:

```bash
sudo python3 plugins/modules/hosts.py tests/hosts-test-args-2.json && cat /etc/hosts
```

## Preparar

```bash
mkdir -p dist
ansible-galaxy collection build --output-path dist
ansible-galaxy collection publish dist/desosu-general-1.0.0.tar.gz
```
