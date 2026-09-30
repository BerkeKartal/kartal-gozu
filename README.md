# Kartal Gözü

*A lightweight, dependency-free way to watch many Kubernetes clusters from one
place. Agents report over short HTTPS requests (no WebSocket, no tunnel), so it
works behind strict proxies and under any URL path.*

Birden fazla Kubernetes cluster'ını tek yerden izlemek için hafif bir sunucu ve
agent. Her cluster'a küçük bir agent kurulur; agent cluster'ın durumunu merkezî
sunucuya bildirir, sunucu bunu bir API (ve ileride bir arayüz) üzerinden sunar.

## Öne çıkanlar

- **Adres serbest.** Sunucu bir alan adının kökünde de, `/devops/kartal` gibi
  herhangi bir alt path'te de **ayarsız** çalışır; proxy prefix'i kesse de
  kesmese de fark etmez.
- **Namespace serbest.** Hiçbir manifestte namespace sabit yazılı değildir;
  `kustomization.yaml` içindeki tek satırla istediğiniz yere kurulur.
- **Uzun ömürlü bağlantı yok.** Agent WebSocket veya kalıcı tünel açmaz: kısa
  HTTPS istekleriyle rapor gönderir, komutları *long-poll* ile (en fazla 25 sn)
  bekler. WebSocket'i kesen veya bağlantıları 30 sn'de sonlandıran load
  balancer'ların arkasında ek ayar gerekmeden çalışır.
- **Sıfır bağımlılık.** Sadece Go standart kütüphanesi; Kubernetes API'siyle
  kendi küçük istemcisi konuşur. Build'ler hızlıdır, internetsiz (air-gapped)
  ortamlarda modül indirmeye gerek yoktur. İki binary toplam ~15 MB.
- **Güvenli varsayılanlar.** Salt okunur başlar; restart/scale açıkça izin
  verilmedikçe çalışmaz. Secret **değerleri** hiçbir koşulda cluster dışına
  çıkmaz.

## Ne gösterir

| | Nasıl |
|---|---|
| Node'lar: hazır olma, roller, kapasite, basınç durumları, taint'ler, CPU/bellek kullanımı | Periyodik özet (varsayılan 15 sn) |
| Namespace'ler, Deployment/StatefulSet/DaemonSet'ler, Pod'lar (hazır/toplam, restart, sorun nedeni, kullanım) | Periyodik özet |
| Service, Ingress, PersistentVolumeClaim, Job, CronJob | Periyodik özet |
| ConfigMap (ve isteğe bağlı Secret) **adları** | Periyodik özet — içerik taşınmaz |
| Uyarı event'leri | Periyodik özet |
| Cluster'daki **tüm** kaynak tipleri (CRD'ler dahil) | İstek anında keşif |
| Herhangi bir tipin listesi, herhangi bir objenin tam içeriği | İstek anında (Secret değerleri maskelenir) |
| Pod logları | İstek anında |
| Restart / scale | İstek anında, izin verilirse |

CPU/bellek kullanımı için cluster'da [metrics-server](https://github.com/kubernetes-sigs/metrics-server)
kurulu olmalıdır; yoksa diğer her şey yine çalışır.

## Mimari

```
   Cluster A                         Cluster B
 ┌────────────────┐                ┌────────────────┐
 │  kartal-agent  │                │  kartal-agent  │
 └──┬─────────▲───┘                └──┬─────────▲───┘
    │ özet    │ komut                 │         │
    │ (15 sn) │ (long-poll ≤25 sn)    │         │
    ▼         │                       ▼         │
 ┌──────────────────────────────────────────────────┐
 │  kartal-server   https://ornek.org/<herhangi-path>│
 │   …/agent/v1/*   agent uç noktaları (agent token) │
 │   …/api/v1/*     yönetim API'si (admin token)     │
 └──────────────────────────────────────────────────┘
```

- Agent her aralıkta cluster özetini gzip'leyip gönderir.
- Bir komut (log, obje içeriği, kaynak listesi…) istendiğinde sunucu onu
  kuyruğa koyar; bekleyen long-poll anında uyanır, agent komutu çalıştırıp
  sonucu geri gönderir.
- Sunucu durumu bellekte tutar; agent'lar her aralıkta tam özet gönderdiği için
  sunucu yeniden başlasa bile saniyeler içinde toparlanır. Bu yüzden sunucu
  **tek replika** çalışır.

## Kurulum

### 1. Image

```sh
make image IMAGE=registry.ornek.org/library/kartal-gozu:0.1.0
docker push registry.ornek.org/library/kartal-gozu:0.1.0
```

Base image'lar değiştirilebilir (ör. özel bir mirror):
`--build-arg GO_IMAGE=... --build-arg RUNTIME_IMAGE=...`. Tek image iki
programı da içerir; varsayılan giriş `kartal-server`, agent deployment'ı
`kartal-agent` komutunu çalıştırır.

### 2. Sunucu

Her cluster için ayrı bir agent token'ı ve bir admin token'ı üretin:

```sh
openssl rand -hex 24
```

```sh
NS=kartal-gozu   # istediğiniz namespace
kubectl create namespace $NS
kubectl -n $NS create secret generic kartal-server \
  --from-literal=agent-tokens='test=<token-1>,uat=<token-2>' \
  --from-literal=admin-token='<admin-token>'
```

`deploy/server/kustomization.yaml` içinde `namespace` ve `images` alanlarını
düzenleyip:

```sh
kubectl apply -k deploy/server
```

Dışarıya açmak için örnek Traefik tanımı: `deploy/examples/traefik-ingressroute.yaml`.

### 3. Agent (her cluster'a)

```sh
NS=kartal-gozu
kubectl create namespace $NS
kubectl -n $NS create secret generic kartal-agent --from-literal=token='<o cluster'ın token'ı>'
```

`deploy/agent/deployment.yaml` içinde `KARTAL_SERVER_URL` değerini (varsa alt
path dahil) ayarlayın; isteğe bağlı olarak `KARTAL_NAMESPACES` ile izlenecek
namespace'leri sınırlayın. CRD'leri ve Secret adlarını da görmek isterseniz
`kustomization.yaml` içinde `rbac-browse.yaml` satırını açın.

```sh
kubectl apply -k deploy/agent
```

Birkaç saniye içinde cluster `GET …/api/v1/clusters` çıktısında `online` görünür.

## Yapılandırma

### Sunucu

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `KARTAL_LISTEN` | `:8080` | Dinlenecek adres |
| `KARTAL_AGENT_TOKENS` / `_FILE` | — | `cluster=token` girdileri; virgül veya satırla ayrılır, `#` yorum. Token en az 16 karakter |
| `KARTAL_ADMIN_TOKEN` / `_FILE` | — | Yönetim API'si için Bearer token |
| `KARTAL_ALLOW_ANONYMOUS` | `false` | Admin token olmadan çalışmaya izin verir (sadece yerel deneme) |
| `KARTAL_STALE_AFTER` | `1m` | Bu süre ses gelmeyen agent `offline` sayılır |
| `KARTAL_MAX_POLL_WAIT` | `25s` | Long-poll'un en uzun süresi; aradaki proxy/LB zaman aşımının altında tutun |
| `KARTAL_COMMAND_TIMEOUT` | `20s` | Yönetim çağrısının agent cevabını bekleme süresi |
| `KARTAL_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, `error` |

### Agent

| Değişken | Varsayılan | Açıklama |
|---|---|---|
| `KARTAL_SERVER_URL` | — | Sunucu adresi (kök veya alt path) |
| `KARTAL_TOKEN` / `_FILE` | — | Bu cluster'ın agent token'ı |
| `KARTAL_NAMESPACES` | *(boş = tümü)* | Virgülle ayrılmış namespace'ler; komutlar da bunlarla sınırlanır |
| `KARTAL_INTERVAL` | `15s` | Özet gönderme aralığı |
| `KARTAL_POLL_WAIT` | `25s` | Long-poll için istenen bekleme |
| `KARTAL_ALLOW_WRITE` | `false` | Restart/scale'e izin verir (`rbac-write.yaml` ile birlikte) |
| `KARTAL_INCLUDE_SECRETS` | `false` | Secret adlarını özete ekler (değerler asla gönderilmez) |
| `KARTAL_CA_FILE` | — | Sunucu özel bir CA kullanıyorsa ek CA dosyası |
| `KARTAL_INSECURE_SKIP_VERIFY` | `false` | TLS doğrulamasını kapatır (sadece deneme) |
| `KARTAL_HEALTH_LISTEN` | `:8081` | Liveness uç noktası; `off` kapatır |
| `KARTAL_KUBE_API`, `KARTAL_KUBE_TOKEN`, `KARTAL_KUBE_INSECURE` | — | Cluster dışından (geliştirme) çalıştırmak için |

## Yönetim API'si

Yollar kökte veya herhangi bir alt path'in altında çalışır ve
`Authorization: Bearer <admin-token>` ister. `{c}` cluster adıdır.

| Metot | Yol | Açıklama |
|---|---|---|
| GET | `/api/v1/clusters` | Cluster'lar, durumları, toplam kapasite/kullanım, özet sayılar |
| GET | `/api/v1/clusters/{c}` | Tek cluster özeti |
| GET | `/api/v1/clusters/{c}/{tür}` | `nodes`, `namespaces`, `workloads`, `pods`, `services`, `ingresses`, `configmaps`, `secrets`, `volumeclaims`, `jobs`, `cronjobs`, `events`; namespace'li türlerde `?namespace=` |
| GET | `/api/v1/clusters/{c}/namespaces/{ns}/pods/{pod}/logs?container=&tail=` | Pod logu (düz metin) |
| POST | `/api/v1/clusters/{c}/namespaces/{ns}/workloads/{kind}/{name}/restart` | `deployment`, `statefulset`, `daemonset` |
| POST | `/api/v1/clusters/{c}/namespaces/{ns}/workloads/{kind}/{name}/scale` | Gövde: `{"replicas": N}` |
| GET | `/api/v1/clusters/{c}/resources` | Tüm kaynak tipleri (CRD'ler dahil) |
| GET | `/api/v1/clusters/{c}/resources/{group}/{version}/{resource}?namespace=` | Herhangi bir tipin listesi; çekirdek grup için `core` |
| GET | `/api/v1/clusters/{c}/resources/{group}/{version}/{resource}/{name}?namespace=` | Herhangi bir objenin içeriği |

`/healthz` kimlik doğrulamasız cevap verir.

## Güvenlik

- Her agent token'ı tek bir cluster'a bağlıdır; özetin hangi cluster'a ait
  olduğuna içerik değil token karar verir. Token karşılaştırmaları sabit
  zamanlıdır.
- Secret değerleri, ve `kubectl apply`'ın tam kopya sakladığı
  `last-applied-configuration` annotation'ı, agent tarafından cluster'dan
  çıkmadan önce silinir. ConfigMap/Secret listeleri yalnızca metadata olarak
  çekilir.
- Agent'ın varsayılan RBAC'ı salt okumadır ve Secret içermez.
- Container'lar root olmayan kullanıcıyla, salt okunur dosya sistemiyle ve
  tüm Linux yetenekleri kapalı çalışır.

## Geliştirme

```sh
make test    # go vet + race detector ile testler
make build   # bin/ altına iki binary
```

Testler gerçek bir sunucuyu, gerçek bir agent'ı ve sahte bir Kubernetes
API'sini uçtan uca birlikte çalıştırır.

## Yol haritası

- Web arayüzü
- OIDC / LDAP ile kullanıcı girişi ve yetkilendirme
- Etkileşimli pod shell'i

## Lisans

Copyright 2026 Ozan Berke Kartal

[Apache License 2.0](LICENSE) ile lisanslanmıştır.
