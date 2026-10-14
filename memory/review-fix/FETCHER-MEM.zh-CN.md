# Fetcher MEM-1 / MEM-2 独立修复

范围：仅 FlClashYF memory worktree 的 mihomo；基线 core `e951c76d2ee9ade5cfb106edfaaafe114e0683e4`、parent `65e6323be3a4ea435a524ae5743479660010081c`。先读独立 `review/first-round.json`、parent `memory/round2/IOS-MEMORY.zh-CN.md` 和 Fetcher 全文。未改 Swift、协议、snapshot retirement/adapter lease，不 push/release/平台构建。

## 闭环

- 原生产 `NewFetcher` API 真实 RED：callback→Close 死锁、慢 callback 令 Close 等待、Close 后 Update 仍调用 Read（100 次）。`verify_fetcher.py baseline` 用 immutable git show 源码+Go overlay，不 reset/worktree替换；断言与当前 GREEN 相同。
- Fetcher 拥有唯一 terminal owner（永不 reopen，指针就是 epoch）。`Close` 在 owner final commit 后线性化取消；不 join parser、network/read、Vehicle写盘准备或 onUpdate。metadataMu 独立保留；provider锁在 owner Commit 前获取，metadata锁不跨callback。
- 一条可取消 admission channel 从 Update Read 到 parser/callback占用；关闭后等候者立即退出，任何 Fetcher 不派生 per-callback worker。外部不合作 callback只可能占用已经准入的原调用者；不会排出无限后台worker。
- `Vehicle.PrepareWrite(ctx, bytes)` 新契约：不得修改最终路径，返回具体 PreparedWrite（唯一同目录staging）；Fetcher最终只执行OS rename而非任意Vehicle closure。File/HTTP生产实现与所有测试Vehicle全部适配；旧 Write 方法仍保留，不在Close锁内调用。晚Read/parser/preparation不能rename、metadata commit、开loop/watch。write/sync/chunk preparation在锁外。
- rule parser MRS sidecar serialization/staging在锁外；owner最终rename。绑定source/payload hash的envelope、完整规则、raw失败重试和旧snapshot不变。
- HTTP Read 的订阅header和ETag也携带owner；原DB.Batch不可取消且等无关writer/fsync，不能塞进Close锁。owned entries改为 `<cache.db>.providers/{subscription,etag}-<sha256(key)>` 原子独立文件、旧DB回退；没有增加按rule截断。新实例读回和close拒绝覆盖已测试。

## 两条真实生产callback链

- Proxy：OwnedFetcher → 获取baseProvider.mutex（锁外等待）→ owner短commit替换proxies/version/healthCheck数组并准入已有异步healthcheck。Close取消healthcheck并Fetcher owner；阻塞在provider锁的旧callback复归后不可publish。订阅metadata所有runtime读写用同provider锁；Initial healthprocess幂等owner准入。
- Rule：OwnedFetcher → readyMu（锁外等待）→ owner短commit strategy/ready digest/content → unlock readyMu → AcquireRuleProviders原snapshot租约 → PrepareEmit先取得callback RW锁快照 → owner准入异步listener启动 → release lease。Close不等Acquire/ready/callback锁；Acquire阻塞晚返回不可发新event。旧strategy已commit后Close不抹掉它。原异步callback不是强制取消或drain协议；已准入listener仍可运行，旧snapshot retirement lease规则保留。

## 准确边界（不能夸大）

1. **关闭后的保证以准入/commit线性化计，不是任意closure物理停止。** callback reservation在Close前成立但线程未调度，可以在Close返回后继续执行；legacy func(V)/Parser任意自有副作用无法撤回。OwnedFetcher给已准入callback取消context；生产可见state/cache最后一步检查owner，因此revoked owner无晚发布。需要绝对停止任意外部closure时，此任务的API约束不可实现，不能宣称absolute no effect。
2. owner Commit/CommitPrepared只供审计过的最终assignment/OS rename/已准备async-launch，**禁止任意callback、等待、解析、网络、Close重入**。新构造器的onUpdate本体在锁外，legacy自Close测试必须GREEN。滥用新final-commit API运行不合作closure仍能死锁，不属于支持契约。
3. 不声称硬实时Close SLA：已进入的最终OS rename、Chtimes、watcher Start/Close依赖OS/filesystem，理论上可阻塞。修复的是不等待任意Vehicle.Write、callback、parser/网络。不可取消外部调用内存会保留到其自行返回；没有终止它的goroutine hack。
4. owned metadata额外文件每key一个，未添加quota/删除回收；与旧DB并行。失败为缓存miss、DB回退，非产品数据丢弃。未改全局cache其它写入的契约。

## 实际证据

`memory/review-fix/`：baseline-red.log、normal-green.log、lowmem-green.log、stress-green.log、vet-green.log，由真实命令输出写入；verify_fetcher.py可复跑。

- baseline 3项真实FAIL；当前同API 3项PASS，不使用expected-deadlock替代GREEN。
- resource、adapter/provider、rules/provider、tunnel、common/utils、cachefile全包 normal与 **with_low_memory** PASS（真正maxLowMemoryRuleCount=10000，非无效tag）。此前parent文档的ios_low_memory不是此repo实际budget tag，本轮已纠正脚本/CI。
- 10轮stress在normal与with_low_memory均PASS：每轮50 owners×100关闭后并发请求，callback计数每轮50，retained goroutines检查、旧read单准入、late staging清理、生产proxy/rule锁阻塞与snapshot晚emission、晚sidecar、缓存cancel。
- 真实loopbackHTTP生产订阅回调阻塞→Close，不晚ETag/subscription/proxy/metadata；不是fakeHTTP。
- 所有旧snapshot锁、retirement lease、reload matcher共享、MRS所有rule逐个匹配/大Domain/IPCIDR fidelity测试仍运行PASS。
- go vet PASS。Windows `-race` CGO=0拒绝；CGO_ENABLED=1实际失败gcc not found。**没有race GREEN**。
- `.github/workflows/fetcher-review.yaml` macos-15 workflow_dispatch gate准备：immutable RED→normal/with_low_memory/stress→CGO=1 race两个build；未推、未触发、无macOS执行结果。父仍需实际跑CI再作为race批准。

## 修复过程中的测试问题

- callback重入deadline原包围整个SideUpdate会把慢fsync当死锁；改为真实callback entered之后开始测Close，baseline仍RED。
- production proxy test initially只等parser entered会提早Close漏测callback；改为metadata已commit后Close，真实未拥有owner的productioncallback确为RED，最终GREEN。
- low-memory parser在解析前也AcquireRuleProviders查reuse；emission测试只在strategy已经commit后hold租约，确保验的是late event而非提前cancel解析。未删保留strategy断言。
