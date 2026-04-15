> Legacy baseline notice: as of 2026-04-15, `docs/CONNECTIVITY-SOLVER-BASELINE.md` is the active architecture baseline for the connectivity-solver reboot. This document remains as the frozen legacy MVP execution baseline.

# WinkYou MVP 鎵ц鍩虹嚎

> 鐩殑锛氭妸褰撳墠浠撳簱涓垎鏁ｄ笖浜掔浉鍐茬獊鐨勮鍒掞紝鏀舵暃涓轰竴浠藉彲浠ョ洿鎺ユ墽琛岀殑 MVP 鍩虹嚎銆?>
> 閫傜敤鑼冨洿锛歁VP 鍒伴涓彲鐢ㄥ懡浠よ鐗堟湰鍙戝竷鍓嶃€?>
> 浼樺厛绾э細褰撴湰鏂囦欢涓?`winkplan.md`銆乣manage.md`銆乣docs/ARCHITECTURE.md`銆佸悇 TASK 鏂囨。鍐茬獊鏃讹紝浠ユ湰鏂囦欢涓哄噯锛涙棫鏂囨。鍚庣画搴斿洖鏀瑰埌涓庢湰鏂囦欢涓€鑷淬€?
---

## 涓€銆佸熀绾跨粨璁?
鏈墽琛屽熀绾垮喕缁撲互涓嬪喅绛栵細

1. MVP 鍙鐩?`Windows/Linux/macOS`锛屼笉鍖呭惈 `Android/iOS`銆?2. MVP 鍙氦浠?`CLI`锛屼笉鍖呭惈 `GUI`銆?3. MVP 鍙敮鎸?`IPv4`锛屼笉鍖呭惈 `IPv6`銆?4. MVP 鐨勫姞瀵嗛毀閬撳疄鐜板浐瀹氫负 `wireguard-go`锛屼笉鎶?`Wink Protocol v1` 绾冲叆 MVP 浜や粯鑼冨洿銆?5. MVP 鐨勭綉缁滄帴鍙ｈ兘鍔涘寘鍚?`TUN`銆乣userspace netstack`銆乣SOCKS5 fallback`锛屼笉鍖呭惈 `TAP`銆?6. MVP 鐨勪腑缁ц兘鍔涘彧鍋?`UDP TURN`锛屼笉鍋?`TCP TURN`銆?7. MVP 鐨勬帶鍒跺钩闈㈤噰鐢?`鍗曞崗璋冩湇鍔″櫒 + SQLite`锛屼笉鍋氬瀹炰緥鍚屾銆?8. MVP 鐨勭綉缁滄ā鍨嬮噰鐢?`鍗曠綉缁渀锛屼笉鍋氱綉缁滅粍銆佸绉熸埛銆丱IDC銆丄CL銆?9. Go 鐗堟湰鍩虹嚎缁熶竴涓?`Go 1.22+`銆?10. 浠ｇ爜鐩綍鍜屾帴鍙ｅ懡鍚嶄粠鏈枃浠跺紑濮嬪喕缁擄紝鍚庣画涓嶅啀鍑虹幇绗簩濂楃増鏈€?
---

## 浜屻€丮VP 鑼冨洿

### 2.1 鍖呭惈椤?
- 鑺傜偣娉ㄥ唽涓庤妭鐐瑰彂鐜?- TUN 铏氭嫙缃戝崱
- userspace netstack 鏃犳潈闄愭ā寮?- SOCKS5 闄嶇骇妯″紡
- 涓よ妭鐐瑰強澶氳妭鐐硅櫄鎷熺綉缁勭綉
- STUN 鑾峰彇鍏綉鏄犲皠
- ICE 鍊欓€変氦鎹笌杩為€氭€ф鏌?- TURN 涓户鍥為€€
- `wink up / down / status / peers / genkey / debug`
- 鍗曞崗璋冩湇鍔″櫒鑷墭绠?- 鍗曚腑缁ф湇鍔″櫒鑷墭绠?
### 2.2 鏄庣‘涓嶅湪 MVP 鍐?
- GUI 瀹㈡埛绔?- Android/iOS
- Wink Protocol v1
- AES-GCM/`cipher_suite` 鍗忓晢
- TAP 浜屽眰妯″紡
- IPv6
- 澶氬崗璋冩湇鍔″櫒
- OIDC / 鐢ㄦ埛璐︽埛浣撶郴
- 缃戠粶缁?/ 澶氱鎴?/ ACL
- TCP TURN
- 鍙椾俊鑺傜偣涓户锛坄peer relay / transit node`锛?
---

## 涓夈€佷緷璧栧浘鏀舵暃

### 3.1 妯″潡渚濊禆

| 妯″潡 | 纭緷璧?| 璇存槑 |
|------|--------|------|
| TASK-01 鍩虹璁炬柦 | 鏃?| 鍒濆鍖栦粨搴撱€侀厤缃€佹棩蹇椼€丆LI銆佺増鏈俊鎭?|
| TASK-02 缃戠粶鎺ュ彛 | TASK-01 | 鎻愪緵 TUN / userspace / proxy |
| TASK-03 闅ч亾灞?| TASK-02 | 瀵规帴 `NetworkInterface` |
| TASK-05 鍗忚皟鏈嶅姟鍣?| TASK-01 | 娉ㄥ唽銆佸彂鐜般€佷俊浠?|
| TASK-04 NAT 绌块€?| TASK-01, TASK-05 | STUN 鏈湴鍘熷瀷鍙厛琛岋紝浣?MVP 瀹屾垚蹇呴』渚濊禆 TASK-05 淇′护 |
| TASK-07 涓户鏈嶅姟 | TASK-04 | TURN 鍊欓€変笌鍥為€€閫昏緫寤虹珛鍦?NAT 妯″潡涔嬩笂 |
| TASK-06 瀹㈡埛绔牳蹇?| TASK-02, TASK-03, TASK-04, TASK-05 | 鍙厛瀹屾垚鐩磋繛鐗堥泦鎴?|

### 3.2 TASK-06 涓?TASK-07 鐨勫叧绯?
鍐荤粨鍐崇瓥锛?
- `TASK-07` 涓嶆槸 `TASK-06` 鐨勨€滃紑鍙戝惎鍔ㄥ墠缃緷璧栤€濄€?- `TASK-07` 鏄?`TASK-06` 鐨勨€淢VP 鍙戝竷闂ㄧ渚濊禆鈥濄€?
涔熷氨鏄細

- 娌℃湁 `TASK-07`锛屽彲浠ュ仛鍑衡€滅洿杩炵増瀹㈡埛绔泦鎴愨€濄€?- 娌℃湁 `TASK-07`锛屼笉鑳藉绉板畬鎴?MVP锛屽洜涓?G3鈥滅┛閫忓け璐ヨ嚜鍔ㄥ洖閫€涓户鈥濅粛鏈疄鐜般€?
---

## 鍥涖€佹墽琛岄『搴?
MVP 涓绘墽琛岀嚎鎸変互涓嬮『搴忔帹杩涳細

| 閲岀▼纰?| 妯″潡 | 鐩爣 | 瀹屾垚鏍囧織 |
|--------|------|------|----------|
| M0 | 浠撳簱鍒濆鍖?| 寤虹珛浠ｇ爜楠ㄦ灦涓庡伐鍏烽摼 | 瀛樺湪 `go.mod`銆乣cmd/`銆乣pkg/`銆乣api/`銆乣test/`銆乣deploy/`銆丆I |
| M1 | TASK-01 | 鍩虹璁炬柦鍙敤 | `wink version`銆侀厤缃姞杞姐€佹棩蹇楄緭鍑哄彲杩愯 |
| M2 | TASK-02 + TASK-03 | 鎵嬪姩鐩磋繛 | 涓よ妭鐐规墜宸ラ厤缃彲閫氳繃闅ч亾浜掗€?|
| M3 | TASK-05 | 鎺у埗骞抽潰鍙敤 | 娉ㄥ唽銆佸彂鐜般€佷俊浠ゅ彲鐢?|
| M4 | TASK-04 | 鑷姩鐩磋繛 | 閫氳繃鍗忚皟鏈嶅姟鍣ㄤ氦鎹㈠€欓€夊苟寤虹珛 P2P 杩炴帴 |
| M5 | TASK-07 | 涓户淇濆簳 | 瀵圭О NAT 鍦烘櫙鑳藉洖閫€ TURN |
| M6 | TASK-06 | 瀹㈡埛绔暣鍚?| `wink up/down/status/peers` 瀹屾暣鎵撻€?|

鍐荤粨璇存槑锛?
- 涓嶅啀閲囩敤鈥滃厛鍋氬畬鏁?NAT/ICE锛屽啀鍋氬崗璋冧俊浠も€濈殑椤哄簭銆?- 淇′护灞炰簬 NAT/ICE 鐨勭‖渚濊禆锛屽崗璋冩湇鍔″櫒蹇呴』鍏堜簬 TASK-04 MVP 浜や粯銆?
---

## 浜斻€佺洰褰曠粨鏋勫喕缁?
MVP 缁熶竴閲囩敤浠ヤ笅鐩綍缁撴瀯锛?
```text
winkyou/
鈹溾攢鈹€ cmd/
鈹?  鈹溾攢鈹€ wink/
鈹?  鈹溾攢鈹€ wink-coordinator/
鈹?  鈹斺攢鈹€ wink-relay/
鈹溾攢鈹€ pkg/
鈹?  鈹溾攢鈹€ config/
鈹?  鈹溾攢鈹€ logger/
鈹?  鈹溾攢鈹€ version/
鈹?  鈹溾攢鈹€ netif/
鈹?  鈹溾攢鈹€ tunnel/
鈹?  鈹溾攢鈹€ nat/
鈹?  鈹溾攢鈹€ coordinator/
鈹?  鈹?  鈹溾攢鈹€ client/
鈹?  鈹?  鈹斺攢鈹€ server/
鈹?  鈹溾攢鈹€ relay/
鈹?  鈹?  鈹溾攢鈹€ client/
鈹?  鈹?  鈹斺攢鈹€ server/
鈹?  鈹斺攢鈹€ client/
鈹溾攢鈹€ api/
鈹?  鈹斺攢鈹€ proto/
鈹?      鈹斺攢鈹€ coordinator.proto
鈹溾攢鈹€ deploy/
鈹?  鈹溾攢鈹€ coordinator/
鈹?  鈹斺攢鈹€ relay/
鈹溾攢鈹€ test/
鈹?  鈹溾攢鈹€ integration/
鈹?  鈹斺攢鈹€ e2e/
鈹溾攢鈹€ docs/
鈹斺攢鈹€ Makefile
```

### 5.1 鏄庣‘鎺掗櫎鐨勭洰褰曠増鏈?
浠ヤ笅甯冨眬涓嶈繘鍏?MVP 鍩虹嚎锛?
- `cmd/winkd`
- `cmd/wink-ui`
- `pkg/node`
- `pkg/network`
- `pkg/protocol`
- 椤跺眰 `platform/`

骞冲彴宸紓浠ｇ爜缁熶竴鏀惧湪瀵瑰簲鍖呭唴锛屼娇鐢?build tags 缁勭粐锛岃€屼笉鏄彟璧蜂竴濂楅《灞傜粨鏋勩€?
---

## 鍏€侀厤缃ā鍨嬪喕缁?
### 6.1 閰嶇疆鏍圭粨鏋?
MVP 閰嶇疆鏂囦欢涓嶄娇鐢?`wink:` 鏍硅妭鐐癸紝缁熶竴閲囩敤鎵佸钩椤跺眰缁撴瀯銆?
### 6.2 閰嶇疆瀛楁

```yaml
node:
  name: "my-node"

log:
  level: "info"
  format: "text"
  output: "stderr"
  file: ""

coordinator:
  url: "https://coord.example.com:443"
  timeout: 10s
  auth_key: ""
  tls:
    insecure_skip_verify: false
    ca_file: ""

netif:
  backend: "auto"      # auto|tun|userspace|proxy
  mtu: 1280

wireguard:
  private_key: ""
  listen_port: 51820

nat:
  stun_servers:
    - "stun:stun.l.google.com:19302"
  turn_servers:
    - url: "turn:relay.example.com:3478"
      username: "wink"
      password: "secret"
```

### 6.3 閰嶇疆鍐荤粨璇存槑

- `relay:` 椤跺眰閰嶇疆涓嶈繘鍏ュ鎴风閰嶇疆妯″瀷銆?- TURN 鏈嶅姟鍣ㄥ垪琛ㄧ粺涓€鏀惧湪 `nat.turn_servers`銆?- `cipher_suite` 涓嶈繘鍏?MVP 閰嶇疆銆?- `tap` 涓嶈繘鍏?`netif.backend` 鐨?MVP 鍙€夊€笺€?
### 6.4 MVP 璁よ瘉鍐荤粨

MVP 涓嶅仛鐢ㄦ埛浣撶郴锛岄噰鐢ㄦ渶灏忓寲鎺ュ叆妯″瀷锛?
- 鍗忚皟鏈嶅姟鍣ㄥ彲閰嶇疆涓€涓彲閫夌殑 `auth_key`
- 瀹㈡埛绔€氳繃 `coordinator.auth_key` 浼犲叆
- 鑻ユ湇鍔″櫒鏈惎鐢?`auth_key`锛屽垯鍏佽寮€鏀炬敞鍐?
MVP 涓嶅寘鍚細

- OIDC
- 鐢ㄦ埛鍚嶅瘑鐮?- 澶氳鑹叉潈闄愭ā鍨?
---

## 涓冦€佹帴鍙ｅ绾﹀喕缁?
鏈妭鍙畾涔?MVP 鐨勬敹鏁涙帴鍙ｏ紝涓嶈拷姹傞暱鏈熸渶浼橈紝鍙拷姹傝兘绋冲畾闆嗘垚銆?
### 7.1 netif

```go
package netif

type Config struct {
    Backend string
    MTU     int
}

type NetworkInterface interface {
    Name() string
    Type() string
    MTU() int
    Read(buf []byte) (int, error)
    Write(buf []byte) (int, error)
    Close() error
    SetIP(ip net.IP, mask net.IPMask) error
    AddRoute(dst *net.IPNet, gateway net.IP) error
    RemoveRoute(dst *net.IPNet) error
}

func New(cfg Config) (NetworkInterface, error)
```

鍐荤粨璇存槑锛?
- MVP 缁熶竴浣跨敤 `netif.New(...)`锛屼笉鍐嶅嚭鐜?`Select(...)` 涓?`SelectBackend(...)` 涓ゅ鏋勯€犲櫒銆?- 鑷姩鍚庣閫夋嫨閫昏緫鍐呰仛鍦?`netif.New(...)` 鍐呴儴銆?
### 7.2 tunnel

```go
package tunnel

type Config struct {
    Interface  netif.NetworkInterface
    PrivateKey PrivateKey
    ListenPort int
}

type Tunnel interface {
    Start() error
    Stop() error
    AddPeer(peer *PeerConfig) error
    RemovePeer(publicKey PublicKey) error
    UpdatePeerEndpoint(publicKey PublicKey, endpoint *net.UDPAddr) error
    GetPeers() []*PeerStatus
    GetStats() *TunnelStats
    Events() <-chan TunnelEvent
}

func New(cfg Config) (Tunnel, error)
```

鍐荤粨璇存槑锛?
- MVP 浜や粯鏂囦欢鍚嶇粺涓€浣跨敤 `tunnel_wggo.go`銆?- `tunnel_native.go` / `tunnel_wink.go` 灞炰簬鍚庣画杞ㄩ亾锛屼笉杩涘叆 MVP銆?
### 7.3 coordinator

`coordinator.proto` 鐨?MVP RPC 鍙喕缁撲互涓嬫帴鍙ｏ細

- `Register`
- `Heartbeat`
- `ListPeers`
- `GetPeer`
- `Signal`

鏄庣‘涓嶈繘鍏?MVP proto 鐨勬帴鍙ｏ細

- `GetTURNCredentials`

`RegisterResponse` 鍦?wire format 涓喕缁撲负锛?
```protobuf
message RegisterResponse {
  string node_id = 1;
  string virtual_ip = 2;
  int64 expires_at = 3;
  string network_cidr = 4;
}
```

鍐荤粨璇存槑锛?
- 瀹㈡埛绔繀椤讳粠 `network_cidr` 鎺ㄥ鍑烘帺鐮併€?- 瀹㈡埛绔笉寰楁湡寰?`network_mask` 瀛楁銆?
### 7.4 nat

```go
package nat

type ICEAgent interface {
    GatherCandidates(ctx context.Context) ([]Candidate, error)
    SetRemoteCandidates(candidates []Candidate) error
    Connect(ctx context.Context) (net.Conn, *CandidatePair, error)
    Close() error
}

type NATTraversal interface {
    DetectNATType(ctx context.Context) (NATType, error)
    NewICEAgent(cfg ICEConfig) (ICEAgent, error)
}

func MarshalCandidate(c Candidate) ([]byte, error)
func UnmarshalCandidate(data []byte) (Candidate, error)
```

鍐荤粨璇存槑锛?
- MVP 涓嶅啀璁╁鎴风鐩存帴绛夊緟 `Connected()` channel銆?- `ICEAgent.Connect(ctx)` 闃诲鐩村埌杩炴帴寤虹珛銆佽秴鏃舵垨澶辫触銆?- 鍊欓€夊簭鍒楀寲鐢?`nat` 鍖呰礋璐ｏ紝`coordinator` 鍙浆鍙?`[]byte payload`銆?
### 7.5 client

瀹㈡埛绔牳蹇冩寜浠ヤ笅椤哄簭闆嗘垚锛?
1. `netif.New`
2. `coordinator.NewClient`
3. `Register`
4. 浠?`network_cidr` 瑙ｆ瀽鎺╃爜骞惰皟鐢?`SetIP`
5. `tunnel.New`
6. `nat.NewICEAgent`
7. 鍊欓€夊簭鍒楀寲鍚庨€氳繃 `SendSignal` 鍙戦€?8. `ICEAgent.Connect`
9. `tunnel.AddPeer`

---

## 鍏€佷腑缁х瓥鐣ュ喕缁?
MVP 鐨?TURN 璁よ瘉绛栫暐鍐荤粨涓猴細

- 涓户鏈嶅姟鍣ㄤ娇鐢ㄩ暱鏈熷嚟璇?- 瀹㈡埛绔粠 `nat.turn_servers` 璇诲彇闈欐€佺敤鎴峰悕瀵嗙爜
- 鍗忚皟鏈嶅姟鍣ㄤ笉璐熻矗涓嬪彂 TURN 涓存椂鍑瘉

鍥犳锛?
- `TASK-07` 鍙嫭绔嬩簬鍗忚皟鏈嶅姟鍣ㄧ殑 TURN 鍑瘉 API 瀹屾垚 MVP
- `GetTURNCredentials` 淇濈暀涓哄悗缁寮洪」锛屼笉杩涘叆褰撳墠鎵ц绾?
鏈琛ュ厖锛?
- 褰撳墠 MVP 鏂囨。涓殑鈥滀腑缁р€濋粯璁ゆ寚 `TURN server relay`
- 鈥滆妭鐐?A 浣滀负 B 鍒?C 鐨勫彈淇¤浆鍙戣妭鐐光€濆畾涔変负 `peer relay / transit node`
- `peer relay` 璁捐鍙锛屼絾涓嶇撼鍏ュ綋鍓?MVP 鍐荤粨鑼冨洿锛岃 [PEER-RELAY-DESIGN.md](PEER-RELAY-DESIGN.md)

---

## 涔濄€佸彂甯冮棬绂?
浠ヤ笅闂ㄧ涓嶉€氳繃锛屽垯瀵瑰簲鑳藉姏涓嶅緱鍐欒繘 MVP 瀹ｄ紶鍙ｅ緞銆?
| 闂ㄧ | 闃诲椤?| 澶辫触鏃剁殑鍐荤粨鍔ㄤ綔 |
|------|--------|------------------|
| G1 | Windows `netstack` 鍘熷瀷楠岃瘉 | Windows 鏃犵鐞嗗憳妯″紡闄嶇骇涓?`proxy`锛屼笉瀹ｇО `userspace` |
| G2 | WinTUN 鎵撳寘涓庡畨瑁呴獙璇?| Windows TUN 寤跺悗锛孧VP 浠呭绉?Windows userspace/proxy |
| G3 | NAT 绫诲瀷涓庣┛閫忕巼閲囨牱 | 涓嶅澶栧０鏄庣┛閫忔垚鍔熺巼鎸囨爣 |
| G4 | TURN 涓户绋冲畾鎬т笌骞跺彂楠岃瘉 | 涓嶅绉扳€?00% 杩為€氣€濓紝浠呬繚鐣欏疄楠屾€у洖閫€ |
| G5 | 72 灏忔椂绋冲畾鎬ф祴璇?| 涓嶅彂甯?MVP 鐗堟湰锛屽彧淇濈暀寮€鍙戦瑙堢増 |

### 9.1 鑳藉紑宸ヤ絾涓嶈兘瓒婄骇瀹ｄ紶鐨勫唴瀹?
浠ヤ笅宸ヤ綔鍙互鍏堝仛锛屼絾鍦ㄩ棬绂侀€氳繃鍓嶄笉鑳界畻鈥滃畬鎴愪氦浠樷€濓細

- Windows 鏃犳潈闄愭ā寮?- Windows TUN 鏀寔
- NAT 鎴愬姛鐜囨寚鏍?- 鈥?00% 杩為€氣€濊〃杩?- 绋冲畾鐗堝彂甯?
---

## 鍗併€佺幇鏈夋枃妗ｅ浣曞洖鏀?
鏈墽琛屽熀绾胯鎺ュ彈鍚庯紝鏃ф枃妗ｆ寜浠ヤ笅椤哄簭鍥炴敼锛?
1. `docs/README.md`
2. `docs/ARCHITECTURE.md`
3. `docs/tasks/TASK-01..07.md`
4. `manage.md`
5. `winkplan.md`

鍥炴敼鍘熷垯锛?
- 鍙繚鐣欎竴濂椾緷璧栧浘
- 鍙繚鐣欎竴濂楃洰褰曠粨鏋?- 鍙繚鐣欎竴濂楅厤缃ā鍨?- 鍙繚鐣欎竴濂楁瀯閫犲櫒鍛藉悕
- 鑷爺鍗忚璺嚎缁х画淇濈暀锛屼絾鏄庣‘鏍囨敞涓?`post-MVP`

---

## 鍗佷竴銆佹墽琛岃捣鐐?
浠庝粖澶╁紑濮嬶紝榛樿鎵ц璧风偣鏄細

1. 寤虹珛 M0 浠撳簱楠ㄦ灦
2. 瀹屾垚 TASK-01
3. 鐩存帹 TASK-02 + TASK-03
4. 瀹屾垚 TASK-05
5. 鍐嶆帹杩?TASK-04
6. 琛ヤ笂 TASK-07
7. 鏈€鍚庡仛 TASK-06 鎬婚泦鎴?
杩欐潯绾挎槸褰撳墠浠撳簱鍐呮渶鐭€佹渶鑷唇銆佸彲钀藉湴鐨?MVP 鎵ц璺緞銆?
